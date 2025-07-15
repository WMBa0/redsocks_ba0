/* redsocks - 透明TCP到代理的重定向器 */
/* 版权所有 (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru> */

#include <stdlib.h>
#include <search.h> // 用于树结构操作(tsearch/tfind)
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

// 自定义头文件
#include "list.h"	// Linux内核风格链表实现
#include "log.h"	// 日志记录功能
#include "socks5.h" // SOCKS5协议实现
#include "parser.h" // 配置文件解析
#include "main.h"
#include "redsocks.h"
#include "redudp.h"
#include "libc-compat.h"

/* 日志宏定义 */
#define redudp_log_error(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &(client)->clientaddr, get_destaddr(client), prio, ##msg)

#define redudp_log_errno(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &(client)->clientaddr, get_destaddr(client), prio, ##msg)

/* 前向声明 */
static void redudp_pkt_from_socks(int fd, short what, void *_arg);
static void redudp_drop_client(redudp_client *client);
static void redudp_fini_instance(redudp_instance *instance);
static int redudp_fini();
static int redudp_transparent(int fd);

/* SOCKS5 UDP关联响应结构 */
typedef struct redudp_expected_assoc_reply_t
{
	socks5_reply h;		 // SOCKS5响应头
	socks5_addr_ipv4 ip; // 服务器返回的UDP中继地址(IPv4格式)
} PACKED redudp_expected_assoc_reply;

/* UDP套接字管理结构 */
struct bound_udp4_key
{
	struct in_addr sin_addr; // IP地址
	uint16_t sin_port;		 // 端口号
};

struct bound_udp4
{
	struct bound_udp4_key key; // 作为键值(IP+端口)
	int ref;				   // 引用计数
	int fd;					   // 套接字描述符
};

/***********************************************************************
 * 辅助函数
 */

static void *root_bound_udp4 = NULL; // 全局UDP套接字树的根节点

/* 比较两个UDP套接字键值 */
static int bound_udp4_cmp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct bound_udp4_key));
}

/* 从sockaddr_in生成键值 */
static void bound_udp4_mkkey(struct bound_udp4_key *key, const struct sockaddr_in *addr)
{
	memset(key, 0, sizeof(*key));
	key->sin_addr = addr->sin_addr; // 复制IP地址
	key->sin_port = addr->sin_port; // 复制端口号
}

/* 获取或创建绑定的UDP套接字 */
static int bound_udp4_get(const struct sockaddr_in *addr)
{
	log_error(LOG_NOTICE, "[*] bound_udp4_get 获取或创建绑定的UDP套接字");
	struct bound_udp4_key key;
	struct bound_udp4 *node, **pnode;

	// 生成查找键
	bound_udp4_mkkey(&key, addr);

	// 先在树中查找是否已存在
	pnode = tfind(&key, &root_bound_udp4, bound_udp4_cmp);
	if (pnode)
	{
		assert((*pnode)->ref > 0);
		(*pnode)->ref++;	 // 增加引用计数
		return (*pnode)->fd; // 返回现有套接字
	}

	// 创建新节点
	node = calloc(1, sizeof(*node));
	if (!node)
	{
		log_errno(LOG_ERR, "calloc失败");
		goto fail;
	}

	// 初始化节点数据
	node->key = key;
	node->ref = 1;
	node->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (node->fd == -1)
	{
		log_errno(LOG_ERR, "创建socket失败");
		goto fail;
	}

	// 设置透明代理模式
	if (0 != redudp_transparent(node->fd))
		goto fail;

	// 绑定到指定地址
	if (0 != bind(node->fd, (struct sockaddr *)addr, sizeof(*addr)))
	{
		log_errno(LOG_ERR, "绑定地址失败");
		goto fail;
	}

	// 将节点插入树中
	pnode = tsearch(node, &root_bound_udp4, bound_udp4_cmp);
	if (!pnode)
	{
		log_errno(LOG_ERR, "tsearch插入失败");
		goto fail;
	}
	assert(node == *pnode);

	return node->fd; // 返回新套接字

fail:
	// 错误处理
	if (node)
	{
		if (node->fd != -1)
			redsocks_close(node->fd);
		free(node);
	}
	return -1;
}

/* 释放UDP套接字 */
static void bound_udp4_put(const struct sockaddr_in *addr)
{
	log_error(LOG_NOTICE, "[*] bound_udp4_put 释放UDP套接字");

	struct bound_udp4_key key;
	struct bound_udp4 **pnode, *node;
	void *parent;

	// 生成查找键
	bound_udp4_mkkey(&key, addr);

	// 查找节点
	pnode = tfind(&key, &root_bound_udp4, bound_udp4_cmp);
	assert(pnode && (*pnode)->ref > 0);

	node = *pnode;

	// 减少引用计数
	node->ref--;
	if (node->ref) // 如果还有引用则直接返回
		return;

	// 从树中删除节点
	parent = tdelete(node, &root_bound_udp4, bound_udp4_cmp);
	assert(parent);

	// 关闭套接字并释放内存
	redsocks_close(node->fd);
	free(node);
}

/* 设置套接字为透明模式 */
static int redudp_transparent(int fd)
{
	log_error(LOG_NOTICE, "[*] redudp_transparent 设置套接字为透明模式");

	int on = 1;
	int error = setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));
	if (error)
		log_errno(LOG_ERR, "设置IP_TRANSPARENT失败");
	return error;
}

/* 检查是否启用透明代理 */
static int do_tproxy(redudp_instance *instance)
{
	// 当目标地址为0时启用透明模式
	return instance->config.destaddr.sin_addr.s_addr == 0;
}

/* 获取客户端的目标地址 */
static struct sockaddr_in *get_destaddr(redudp_client *client)
{
	//log_error(LOG_NOTICE, "[*] get_destaddr 获取客户端的目标地址");

	// 根据是否透明代理返回不同的目标地址
	if (do_tproxy(client->instance))
		return &client->destaddr;
	else
		return &client->instance->config.destaddr;
}

/* 填充SOCKS5 UDP头部 */
static void redudp_fill_preamble(socks5_udp_preabmle *preamble, redudp_client *client)
{
	log_error(LOG_NOTICE, "[*] redudp_fill_preamble 填充SOCKS5 UDP头部");

	preamble->reserved = 0;
	preamble->frag_no = 0;									   /* 不支持分片 */
	preamble->addrtype = socks5_addrtype_ipv4;				   // 固定使用IPv4地址类型
	preamble->ip.addr = get_destaddr(client)->sin_addr.s_addr; // 目标IP
	preamble->ip.port = get_destaddr(client)->sin_port;		   // 目标端口
}

/* 生成SOCKS5方法选择请求 */
static struct evbuffer *socks5_mkmethods_plain_wrapper(void *p)
{
	int *do_password = p;
	return socks5_mkmethods_plain(*do_password);
}

/* 生成SOCKS5密码认证请求 */
static struct evbuffer *socks5_mkpassword_plain_wrapper(void *p)
{
	redudp_instance *self = p;
	return socks5_mkpassword_plain(self->config.login, self->config.password);
}

/* 生成SOCKS5 UDP关联请求 */
static struct evbuffer *socks5_mkassociate(void *p)
{
	struct sockaddr_in sa;
	p = p; /* 避免编译器警告 */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	return socks5_mkcommand_plain(socks5_cmd_udp_associate, &sa);
}

/***********************************************************************
 * 核心逻辑
 */

/* 释放客户端资源 */
static void redudp_drop_client(redudp_client *client)
{
	redudp_log_error(client, LOG_INFO, "正在释放客户端...");
	enqueued_packet *q, *tmp;

	// 1. 移除超时事件
	if (event_initialized(&client->timeout))
	{
		if (event_del(&client->timeout) == -1)
			redudp_log_errno(client, LOG_ERR, "移除超时事件失败");
	}

	// 2. 释放中继连接
	if (client->relay)
		redsocks_bufferevent_free(client->relay);

	// 3. 移除UDP中继事件并关闭套接字
	if (event_initialized(&client->udprelay))
	{
		int fd = event_get_fd(&client->udprelay);
		if (event_del(&client->udprelay) == -1)
			redudp_log_errno(client, LOG_ERR, "移除UDP中继事件失败");
		redsocks_close(fd);
	}

	// 4. 释放绑定的发送套接字
	if (client->sender_fd != -1)
		bound_udp4_put(&client->destaddr);

	// 5. 释放队列中的数据包
	list_for_each_entry_safe(q, tmp, &client->queue, list)
	{
		list_del(&q->list);
		free(q);
	}

	// 6. 从实例列表中移除并释放内存
	list_del(&client->list);
	free(client);
}

/* 重置客户端超时计时器 */
static void redudp_bump_timeout(redudp_client *client)
{
	struct timeval tv;
	tv.tv_sec = client->instance->config.udp_timeout; // 获取配置的超时时间
	tv.tv_usec = 0;

	// 重新设置超时事件
	if (event_add(&client->timeout, &tv) != 0)
	{
		redudp_log_error(client, LOG_WARNING, "设置超时事件失败");
		redudp_drop_client(client); // 失败则释放客户端
	}
}

/* 转发数据包到SOCKS5服务器 */
static void redudp_forward_pkt(redudp_client *client, char *buf, size_t pktlen)
{

	
	log_error(LOG_NOTICE, "[*] redudp_forward_pkt 转发数据包到SOCKS5服务器 ");

	socks5_udp_preabmle req;
	struct msghdr msg;
	struct iovec io[2];
	ssize_t outgoing, fwdlen = pktlen + sizeof(req);

	redudp_fill_preamble(&req, client);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &client->udprelayaddr;
	msg.msg_namelen = sizeof(client->udprelayaddr);
	msg.msg_iov = io;
	msg.msg_iovlen = SIZEOF_ARRAY(io);

	io[0].iov_base = &req;
	io[0].iov_len = sizeof(req);
	io[1].iov_base = buf;
	io[1].iov_len = pktlen;

	outgoing = sendmsg(event_get_fd(&client->udprelay), &msg, 0);
	if (outgoing == -1)
	{
		redudp_log_errno(client, LOG_WARNING, "代理发送失败");
	}
	else if (outgoing != fwdlen)
	{
		redudp_log_error(client, LOG_WARNING, "代理发送不完整，预期 %zd 实际 %zd",
						 fwdlen, outgoing);
	}
}

/* 将数据包加入队列 */
static int redudp_enqeue_pkt(redudp_client *client, char *buf, size_t pktlen)
{
	enqueued_packet *q = NULL;

	redudp_log_error(client, LOG_DEBUG, "<跟踪>");

	// 检查队列是否已满
	if (client->queue_len >= client->instance->config.max_pktqueue)
	{
		redudp_log_error(client, LOG_WARNING, "队列已满(%u个包)，丢弃新包", client->queue_len);
		return -1;
	}

	// 分配包内存(结构体+数据)
	q = calloc(1, sizeof(enqueued_packet) + pktlen);
	if (!q)
	{
		redudp_log_errno(client, LOG_ERR, "分配队列包内存失败");
		return -1;
	}

	// 填充包数据
	q->len = pktlen;
	memcpy(q->data, buf, pktlen);
	client->queue_len += 1;
	list_add_tail(&q->list, &client->queue); // 加入队列尾部
	return 0;
}

/* 发送队列中的所有数据包 */
static void redudp_flush_queue(redudp_client *client)
{
	enqueued_packet *q, *tmp;
	redudp_log_error(client, LOG_INFO, "启动UDP中继");

	// 遍历队列并发送每个包
	list_for_each_entry_safe(q, tmp, &client->queue, list)
	{
		redudp_forward_pkt(client, q->data, q->len);
		list_del(&q->list); // 从队列移除
		free(q);			// 释放内存
	}
	client->queue_len = 0;
	assert(list_empty(&client->queue)); // 确保队列已空
}

/* 处理SOCKS5关联响应 */
static void redudp_read_assoc_reply(struct bufferevent *buffev, void *_arg)
{
	log_error(LOG_NOTICE, "[*] redudp_read_assoc_reply 处理SOCKS5关联响应");
	redudp_client *client = _arg;
	redudp_expected_assoc_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int fd = -1;
	int error;
	redudp_log_error(client, LOG_DEBUG, "<跟踪>");

	// 1. 检查响应长度
	if (read != sizeof(reply))
	{
		redudp_log_errno(client, LOG_NOTICE, "响应长度不符，预期 %zu 字节，实际 %i 字节", sizeof(reply), read);
		goto fail;
	}

	// 2. 检查协议版本
	if (reply.h.ver != socks5_ver)
	{
		redudp_log_error(client, LOG_NOTICE, "非法的SOCKS5版本: %u", reply.h.ver);
		goto fail;
	}

	// 3. 检查状态码
	if (reply.h.status != socks5_status_succeeded)
	{
		redudp_log_error(client, LOG_NOTICE, "SOCKS5错误状态: \"%s\" (%i)",
						 socks5_status_to_str(reply.h.status), reply.h.status);
		goto fail;
	}

	// 4. 检查地址类型
	if (reply.h.addrtype != socks5_addrtype_ipv4)
	{
		redudp_log_error(client, LOG_NOTICE, "非法的地址类型: %u", reply.h.addrtype);
		goto fail;
	}

	// 5. 保存服务器返回的UDP中继地址
	client->udprelayaddr.sin_family = AF_INET;
	client->udprelayaddr.sin_port = reply.ip.port;
	client->udprelayaddr.sin_addr.s_addr = reply.ip.addr;

	// 6. 创建UDP套接字
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		redudp_log_errno(client, LOG_ERR, "创建UDP套接字失败");
		goto fail;
	}

	// 7. 连接到SOCKS5服务器指定的UDP中继地址
	error = connect(fd, (struct sockaddr *)&client->udprelayaddr, sizeof(client->udprelayaddr));
	if (error)
	{
		redudp_log_errno(client, LOG_NOTICE, "连接UDP中继失败");
		goto fail;
	}

	// 8. 设置UDP中继事件处理器
	event_set(&client->udprelay, fd, EV_READ | EV_PERSIST, redudp_pkt_from_socks, client);
	error = event_add(&client->udprelay, NULL);
	if (error)
	{
		redudp_log_errno(client, LOG_ERR, "添加UDP中继事件失败");
		goto fail;
	}

	// 9. 发送队列中缓存的数据包
	redudp_flush_queue(client);
	return;

fail:
	// 错误处理
	if (fd != -1)
		redsocks_close(fd);
	redudp_drop_client(client);
}

/* 处理SOCKS5认证响应 */
static void redudp_read_auth_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_auth_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int error;
	redudp_log_error(client, LOG_DEBUG, "<跟踪>");

	// 1. 检查响应长度
	if (read != sizeof(reply))
	{
		redudp_log_errno(client, LOG_NOTICE, "响应长度不符，预期 %zu 字节，实际 %i 字节", sizeof(reply), read);
		goto fail;
	}

	// 2. 检查认证结果
	if (reply.ver != socks5_password_ver || reply.status != socks5_password_passed)
	{
		redudp_log_error(client, LOG_NOTICE, "认证失败，版本: %u，错误码: %u", reply.ver, reply.status);
		goto fail;
	}

	// 3. 发送UDP关联请求
	error = redsocks_write_helper_ex_plain(
		client->relay, NULL, socks5_mkassociate, NULL, 0,
		sizeof(redudp_expected_assoc_reply), sizeof(redudp_expected_assoc_reply));
	if (error)
		goto fail;

	// 4. 设置下一步读取关联响应
	client->relay->readcb = redudp_read_assoc_reply;
	return;

fail:
	redudp_drop_client(client);
}

/* 处理SOCKS5方法选择响应 */
static void redudp_read_auth_methods(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	socks5_method_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	const char *error = NULL;
	int ierror = 0;
	redudp_log_error(client, LOG_DEBUG, "<跟踪>");

	// 1. 检查响应长度
	if (read != sizeof(reply))
	{
		redudp_log_errno(client, LOG_NOTICE, "响应长度不符，预期 %zu 字节，实际 %i 字节", sizeof(reply), read);
		goto fail;
	}

	// 2. 检查认证方法
	error = socks5_is_known_auth_method(&reply, do_password);
	if (error)
	{
		redudp_log_error(client, LOG_NOTICE, "认证方法错误: %s", error);
		goto fail;
	}
	else if (reply.method == socks5_auth_none)
	{
		// 3. 无认证直接发送UDP关联请求
		ierror = redsocks_write_helper_ex_plain(
			client->relay, NULL, socks5_mkassociate, NULL, 0,
			sizeof(redudp_expected_assoc_reply), sizeof(redudp_expected_assoc_reply));
		if (ierror)
			goto fail;

		client->relay->readcb = redudp_read_assoc_reply;
	}
	else if (reply.method == socks5_auth_password)
	{
		// 4. 需要密码认证
		ierror = redsocks_write_helper_ex_plain(
			client->relay, NULL, socks5_mkpassword_plain_wrapper, client->instance, 0,
			sizeof(socks5_auth_reply), sizeof(socks5_auth_reply));
		if (ierror)
			goto fail;

		client->relay->readcb = redudp_read_auth_reply;
	}

	return;

fail:
	redudp_drop_client(client);
}

/* 处理SOCKS5连接建立事件 */
static void redudp_relay_connected(struct bufferevent *buffev, void *_arg)
{
	log_error(LOG_NOTICE,"[*] redudp_relay_connected 处理SOCKS5连接建立事件");

	redudp_client *client = _arg;
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	int error;
	char relayaddr_str[RED_INET_ADDRSTRLEN];
	redudp_log_error(client, LOG_DEBUG, "通过 %s 连接",
					 red_inet_ntop(&client->instance->config.relayaddr, relayaddr_str, sizeof(relayaddr_str)));

	// 1. 检查连接状态
	if (!red_is_socket_connected_ok(buffev))
	{
		redudp_log_errno(client, LOG_NOTICE, "连接检查失败");
		goto fail;
	}

	// 2. 发送认证方法请求 
	error = redsocks_write_helper_ex_plain(
		client->relay, NULL, socks5_mkmethods_plain_wrapper, &do_password, 0,
		sizeof(socks5_method_reply), sizeof(socks5_method_reply));
	if (error)
		goto fail;

	// 3. 设置下一步处理方法选择响应
	client->relay->readcb = redudp_read_auth_methods;
	client->relay->writecb = 0;
	return;

fail:
	redudp_drop_client(client);
}

/* 处理SOCKS5连接错误 */
static void redudp_relay_error(struct bufferevent *buffev, short what, void *_arg)
{
	redudp_client *client = _arg;
	redudp_log_error(client, LOG_NOTICE, "SOCKS5中继错误");
	redudp_drop_client(client);
}

/* 处理客户端超时 */
static void redudp_timeout(int fd, short what, void *_arg)
{
	redudp_client *client = _arg;
	redudp_log_error(client, LOG_INFO, "客户端超时. 首次: %li, 最后客户端活动: %li, 最后中继活动: %li.",
					 client->first_event, client->last_client_event, client->last_relay_event);
	redudp_drop_client(client);
}

/* 处理客户端的第一个数据包 */
static void redudp_first_pkt_from_client(redudp_instance *self, struct sockaddr_in *clientaddr, struct sockaddr_in *destaddr, char *buf, size_t pktlen)
{
	// 1. 分配客户端结构
	redudp_client *client = calloc(1, sizeof(*client));
	if (!client)
	{
		log_errno(LOG_WARNING, "分配客户端内存失败");
		return;
	}

	// 2. 初始化客户端
	INIT_LIST_HEAD(&client->list);
	INIT_LIST_HEAD(&client->queue);
	client->instance = self;
	memcpy(&client->clientaddr, clientaddr, sizeof(*clientaddr));
	if (destaddr)
		memcpy(&client->destaddr, destaddr, sizeof(client->destaddr));

	// 3. 设置超时处理器
	evtimer_set(&client->timeout, redudp_timeout, client);
	client->sender_fd = -1; // 延迟创建发送套接字

	// 4. 连接SOCKS5服务器
	client->relay = red_connect_relay(&client->instance->config.relayaddr,
									  redudp_relay_connected, redudp_relay_error, client);
	if (!client->relay)
		goto fail;

	// 5. 初始化时间戳
	if (redsocks_time(&client->first_event) == (time_t)-1)
		goto fail;
	client->last_client_event = client->first_event;

	// 6. 设置超时
	redudp_bump_timeout(client);

	// 7. 将数据包加入队列
	if (redudp_enqeue_pkt(client, buf, pktlen) == -1)
		goto fail;

	// 8. 添加到实例列表
	list_add(&client->list, &self->clients);
	redudp_log_error(client, LOG_INFO, "收到客户端的第一个包");
	return;

fail:
	redudp_drop_client(client);
}

/* 打印十六进制数据的辅助函数 */
static void print_hex_dump(const char *title, const void *data, size_t len)
{
	const unsigned char *buf = (const unsigned char *)data;
	size_t i, j;

	log_error(LOG_DEBUG, "====== %s (长度: %zu) ======", title, len);

	for (i = 0; i < len; i += 16)
	{
		char hex[512] = {0};
		char ascii[20] = {0};
		size_t line_len = (len - i) > 16 ? 16 : (len - i);

		// 构建十六进制部分
		for (j = 0; j < line_len; j++)
		{
			char byte[4];
			snprintf(byte, sizeof(byte), "%02x ", buf[i + j]);
			strcat(hex, byte);
		}

		// 填充对齐
		for (; j < 16; j++)
		{
			strcat(hex, "   ");
		}

		// 构建ASCII部分
		for (j = 0; j < line_len; j++)
		{
			ascii[j] = isprint(buf[i + j]) ? buf[i + j] : '.';
		}

		log_error(LOG_DEBUG, "0x%04zx: %s |%s|", i, hex, ascii);
	}
}

/* 处理来自SOCKS5服务器的数据包 */
static void redudp_pkt_from_socks(int fd, short what, void *_arg)
{
	log_error(LOG_NOTICE, "[*] redudp_pkt_from_socks 处理来自SOCKS5服务器的数据包");
	redudp_client *client = _arg;
	union
	{
		char buf[0xFFFF]; // UDP最大包长度
		socks5_udp_preabmle header;
	} pkt;
	ssize_t pktlen, fwdlen, outgoing;
	struct sockaddr_in udprelayaddr;

	assert(fd == event_get_fd(&client->udprelay));

	// 1. 接收数据包
	pktlen = red_recv_udp_pkt(fd, pkt.buf, sizeof(pkt.buf), &udprelayaddr, NULL);
	if (pktlen == -1)
		return;

	// 打印接收到的原始数据包(十六进制)
	print_hex_dump("响应UDP数据包", pkt.buf, pktlen);


	// 2. 校验来源地址
	if (memcmp(&udprelayaddr, &client->udprelayaddr, sizeof(udprelayaddr)) != 0)
	{
		char buf[RED_INET_ADDRSTRLEN];
		redudp_log_error(client, LOG_NOTICE, "收到来自非预期地址 %s 的包",
						 red_inet_ntop(&udprelayaddr, buf, sizeof(buf)));
		return;
	}

	// 3. 检查分片(不支持)
	if (pkt.header.frag_no != 0)
	{
		redudp_log_error(client, LOG_WARNING, "收到分片 #%u，不支持分片!", pkt.header.frag_no);
		return;
	}

	// 4. 检查地址类型
	if (pkt.header.addrtype != socks5_addrtype_ipv4)
	{
		redudp_log_error(client, LOG_NOTICE, "收到非IPv4地址类型: #%u", pkt.header.addrtype);
		return;
	}

	// 5. 校验目标地址
	if (pkt.header.ip.port != get_destaddr(client)->sin_port ||
		pkt.header.ip.addr != get_destaddr(client)->sin_addr.s_addr)
	{
		char buf[RED_INET_ADDRSTRLEN];
		struct sockaddr_in pktaddr = {
			.sin_family = AF_INET,
			.sin_addr = {pkt.header.ip.addr},
			.sin_port = pkt.header.ip.port,
		};
		redudp_log_error(client, LOG_NOTICE, "SOCKS5服务器中继了非预期地址 %s 的包",
						 red_inet_ntop(&pktaddr, buf, sizeof(buf)));
		return;
	}

	// 6. 更新活动时间
	redsocks_time(&client->last_relay_event);
	redudp_bump_timeout(client);

	// 7. 透明代理模式下创建发送套接字
	if (do_tproxy(client->instance) && client->sender_fd == -1)
	{
		client->sender_fd = bound_udp4_get(&client->destaddr);
		if (client->sender_fd == -1)
		{
			redudp_log_error(client, LOG_WARNING, "获取绑定UDP套接字失败");
			return;
		}
	}

	// 8. 转发数据给原始客户端
	fwdlen = pktlen - sizeof(pkt.header);
	outgoing = sendto(do_tproxy(client->instance)
						  ? client->sender_fd
						  : event_get_fd(&client->instance->listener),
					  pkt.buf + sizeof(pkt.header), fwdlen, 0,
					  (struct sockaddr *)&client->clientaddr, sizeof(client->clientaddr));
	if (outgoing != fwdlen)
	{
		redudp_log_error(client, LOG_WARNING, "发送不完整，预期发送 %zd 字节，实际发送 %zd 字节", fwdlen, outgoing);
		return;
	}
}

/* 处理来自客户端的数据包 */
static void redudp_pkt_from_client(int fd, short what, void *_arg)
{
	log_error(LOG_NOTICE, "[*] redudp_pkt_from_client 处理来自客户端的数据包");

	redudp_instance *self = _arg;
	struct sockaddr_in clientaddr, destaddr, *pdestaddr;
	char buf[0xFFFF]; // UDP最大包长度
	ssize_t pktlen;
	redudp_client *tmp, *client = NULL;

	pdestaddr = do_tproxy(self) ? &destaddr : NULL;

	assert(fd == event_get_fd(&self->listener));

	// 1. 接收数据包
	pktlen = red_recv_udp_pkt(fd, buf, sizeof(buf), &clientaddr, pdestaddr);
	if (pktlen == -1)
	{
		return;
	}


	// 转换地址为可读格式
    char client_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientaddr.sin_addr, client_ip, sizeof(client_ip));
    

    // 打印连接信息
    if (pdestaddr) {
        inet_ntop(AF_INET, &pdestaddr->sin_addr, dest_ip, sizeof(dest_ip));
        log_error(LOG_NOTICE, "客户端 %s:%d => 目标 %s:%d (大小: %zd字节)",
                 client_ip, 
                 ntohs(clientaddr.sin_port),
                 dest_ip,
                 ntohs(pdestaddr->sin_port),
                 pktlen);
    } else {
        log_error(LOG_NOTICE, "客户端 %s:%d => 默认目标 (大小: %zd字节)",
                 client_ip,
                 ntohs(clientaddr.sin_port),
                 pktlen);
    }
	// 打印客户端信息
	log_error(LOG_NOTICE, "客户端IP: %s, 端口: %d, 数据包大小: %zd字节",
			  client_ip,
			  ntohs(clientaddr.sin_port),
			  pktlen);

	// 打印接收到的原始数据包(十六进制)
	print_hex_dump("原始UDP数据包", buf, pktlen);

	// 2. 查找现有客户端
	list_for_each_entry(tmp, &self->clients, list)
	{
		if (0 == memcmp(&clientaddr, &tmp->clientaddr, sizeof(clientaddr)))
		{
			client = tmp;
			break;
		}
	}

	if (client)
	{
		// 3. 更新活动时间并处理包
		redsocks_time(&client->last_client_event);
		redudp_bump_timeout(client);

		if (event_initialized(&client->udprelay))
		{
			log_error(LOG_NOTICE, "[*] 直接转发");
			redudp_forward_pkt(client, buf, pktlen); // 直接转发
		}
		else
		{
			log_error(LOG_NOTICE, "[*] 加入消息队列");
			redudp_enqeue_pkt(client, buf, pktlen); // 加入队列
		}
	}
	else
	{
		// 4. 新客户端，创建结构
		redudp_first_pkt_from_client(self, &clientaddr, pdestaddr, buf, pktlen);
	}
}

/***********************************************************************
 * 初始化与关闭
 */

/* 配置项定义 */
static parser_entry redudp_entries[] = {
	{.key = "local_ip", .type = pt_in_addr},		  // 本地监听IP
	{.key = "local_port", .type = pt_uint16},		  // 本地监听端口
	{.key = "ip", .type = pt_in_addr},				  // SOCKS5服务器IP
	{.key = "port", .type = pt_uint16},				  // SOCKS5服务器端口
	{.key = "login", .type = pt_pchar},				  // 认证用户名
	{.key = "password", .type = pt_pchar},			  // 认证密码
	{.key = "dest_ip", .type = pt_in_addr},			  // 目标IP(透明代理时留空)
	{.key = "dest_port", .type = pt_uint16},		  // 目标端口
	{.key = "udp_timeout", .type = pt_uint16},		  // UDP超时时间(秒)
	{.key = "udp_timeout_stream", .type = pt_uint16}, // 流超时时间(秒)
	{}												  // 结束标记
};

/* 实例列表 */
static list_head instances = LIST_HEAD_INIT(instances);

/* 解析配置段入口 */
static int redudp_onenter(parser_section *section)
{
	// 1. 分配实例内存
	redudp_instance *instance = calloc(1, sizeof(*instance));
	if (!instance)
	{
		parser_error(section->context, "内存不足");
		return -1;
	}

	// 2. 初始化实例
	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->clients);

	// 3. 设置默认配置
	instance->config.bindaddr.sin_family = AF_INET;
	instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 默认本地回环
	instance->config.relayaddr.sin_family = AF_INET;
	instance->config.relayaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.destaddr.sin_family = AF_INET;
	instance->config.max_pktqueue = 5;		   // 默认队列大小
	instance->config.udp_timeout = 30;		   // 默认UDP超时
	instance->config.udp_timeout_stream = 180; // 默认流超时

	// 4. 设置配置项指针
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
	{
		entry->addr =
			(strcmp(entry->key, "local_ip") == 0) ? (void *)&instance->config.bindaddr.sin_addr : (strcmp(entry->key, "local_port") == 0)		? (void *)&instance->config.bindaddr.sin_port
																							  : (strcmp(entry->key, "ip") == 0)					? (void *)&instance->config.relayaddr.sin_addr
																							  : (strcmp(entry->key, "port") == 0)				? (void *)&instance->config.relayaddr.sin_port
																							  : (strcmp(entry->key, "login") == 0)				? (void *)&instance->config.login
																							  : (strcmp(entry->key, "password") == 0)			? (void *)&instance->config.password
																							  : (strcmp(entry->key, "dest_ip") == 0)			? (void *)&instance->config.destaddr.sin_addr
																							  : (strcmp(entry->key, "dest_port") == 0)			? (void *)&instance->config.destaddr.sin_port
																							  : (strcmp(entry->key, "max_pktqueue") == 0)		? (void *)&instance->config.max_pktqueue
																							  : (strcmp(entry->key, "udp_timeout") == 0)		? (void *)&instance->config.udp_timeout
																							  : (strcmp(entry->key, "udp_timeout_stream") == 0) ? (void *)&instance->config.udp_timeout_stream
																																				: NULL;
	}

	section->data = instance;
	return 0;
}

/* 解析配置段结束 */
static int redudp_onexit(parser_section *section)
{
	redudp_instance *instance = section->data;

	section->data = NULL;

	// 1. 重置配置项指针
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	// 2. 转换端口号为网络字节序
	instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
	instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);
	instance->config.destaddr.sin_port = htons(instance->config.destaddr.sin_port);

	// 3. 验证超时设置
	if (instance->config.udp_timeout_stream < instance->config.udp_timeout)
	{
		parser_error(section->context, "流超时应不小于UDP超时");
		return -1;
	}

	// 4. 添加到全局实例列表
	list_add(&instance->list, &instances);

	return 0;
}

/* 初始化redudp实例 */
static int redudp_init_instance(redudp_instance *instance)
{
	int error;
	int fd = -1;

	// 1. 创建UDP套接字
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		log_errno(LOG_ERR, "创建socket失败");
		goto fail;
	}

	// 2. 透明代理模式设置
	if (do_tproxy(instance))
	{
		int on = 1;
		char buf[RED_INET_ADDRSTRLEN];

		// 启用透明模式
		if (0 != redudp_transparent(fd))
			goto fail;

		// 获取原始目标地址
		error = setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
		if (error)
		{
			log_errno(LOG_ERR, "设置IP_RECVORIGDSTADDR失败");
			goto fail;
		}

		log_error(LOG_DEBUG, "redudp @ %s: TPROXY模式",
				  red_inet_ntop(&instance->config.bindaddr, buf, sizeof(buf)));
	}
	else
	{
		char buf1[RED_INET_ADDRSTRLEN], buf2[RED_INET_ADDRSTRLEN];
		log_error(LOG_DEBUG, "redudp @ %s: 目标地址=%s",
				  red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)),
				  red_inet_ntop(&instance->config.destaddr, buf2, sizeof(buf2)));
	}

	// 3. 绑定到配置地址
	error = bind(fd, (struct sockaddr *)&instance->config.bindaddr, sizeof(instance->config.bindaddr));
	if (error)
	{
		log_errno(LOG_ERR, "绑定地址失败");
		goto fail;
	}

	// 4. 设置非阻塞模式
	error = fcntl_nonblock(fd);
	if (error)
	{
		log_errno(LOG_ERR, "设置非阻塞失败");
		goto fail;
	}

	// 5. 注册事件处理器
	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, redudp_pkt_from_client, instance);
	error = event_add(&instance->listener, NULL);
	if (error)
	{
		log_errno(LOG_ERR, "添加事件失败");
		goto fail;
	}

	return 0;

fail:
	redudp_fini_instance(instance);
	if (fd != -1)
	{
		redsocks_close(fd);
	}
	return -1;
}

/* 释放redudp实例 */
static void redudp_fini_instance(redudp_instance *instance)
{
	// 1. 清理所有客户端
	if (!list_empty(&instance->clients))
	{
		redudp_client *tmp, *client = NULL;
		log_error(LOG_WARNING, "关闭时仍有连接的客户端! 正在断开...");
		list_for_each_entry_safe(client, tmp, &instance->clients, list)
		{
			redudp_drop_client(client);
		}
	}

	// 2. 清理监听器
	if (event_initialized(&instance->listener))
	{
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "移除事件失败");
		redsocks_close(event_get_fd(&instance->listener));
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	// 3. 从全局列表移除
	list_del(&instance->list);

	// 4. 释放认证信息
	free(instance->config.login);
	free(instance->config.password);

	// 5. 释放实例内存
	memset(instance, 0, sizeof(*instance));
	free(instance);
}

/* 初始化所有redudp实例 */
static int redudp_init()
{
	redudp_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
	{
		if (redudp_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	redudp_fini();
	return -1;
}

/* 关闭所有redudp实例 */
static int redudp_fini()
{
	redudp_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		redudp_fini_instance(instance);

	return 0;
}

/* 配置段定义 */
static parser_section redudp_conf_section = {
	.name = "redudp",		   // 配置段名称
	.entries = redudp_entries, // 配置项定义
	.onenter = redudp_onenter, // 进入配置段回调
	.onexit = redudp_onexit	   // 退出配置段回调
};

/* 子系统定义 */
app_subsys redudp_subsys = {
	.init = redudp_init,				 // 初始化函数
	.fini = redudp_fini,				 // 关闭函数
	.conf_section = &redudp_conf_section // 配置段
};

/* vim: set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim: set foldmethod=marker foldlevel=32 foldmarker={,}: */