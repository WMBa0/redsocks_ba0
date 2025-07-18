/*
 * redsocks - 透明TCP到代理的重定向器
 * 版权所有 (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * 根据Apache许可证2.0版（"许可证"）授权;
 * 除非符合许可证，否则不得使用此文件。
 * 您可以在以下位置获取许可证副本：
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 除非适用法律要求或书面同意，按"原样"分发软件，
 * 没有任何明示或暗示的保证或条件。
 * 详见许可证中特定语言规定的权限和限制。
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include "utils.h"
#include "log.h"
#include "redsocks.h"
#include "socks5.h"

/* SOCKS5协议客户端状态定义 */
typedef enum socks5_state_t
{
	socks5_new,			 // 初始状态，尚未开始握手
	socks5_method_sent,	 // 已发送认证方法请求
	socks5_auth_sent,	 // 已发送认证信息
	socks5_request_sent, // 已发送连接请求
	socks5_skip_domain,	 // 需要跳过域名信息（当返回类型为域名时）
	socks5_skip_address, // 需要跳过地址信息
	socks5_MAX,			 // 状态枚举最大值
} socks5_state;

/* SOCKS5客户端私有数据结构 */
typedef struct socks5_client_t
{
	int do_password; // 是否启用密码认证（1表示启用）
	int to_skip;	 // 需要跳过的字节数（处理服务器响应时使用）
} socks5_client;

/* SOCKS5协议状态码描述 */
const char *socks5_strstatus[] = {
	"成功",				// 0x00
	"服务器故障",		// 0x01
	"规则不允许的连接", // 0x02
	"网络不可达",		// 0x03
	"主机不可达",		// 0x04
	"连接被拒绝",		// 0x05
	"TTL过期",			// 0x06
	"不支持的命令",		// 0x07
	"不支持的地址类型", // 0x08
};
const size_t socks5_strstatus_len = SIZEOF_ARRAY(socks5_strstatus);

/**
 * 将SOCKS5状态码转换为可读字符串
 * @param socks5_status SOCKS5状态码
 * @return 状态描述字符串
 */
const char *socks5_status_to_str(int socks5_status)
{
	// 检查状态码是否在有效范围内
	if (0 <= socks5_status && socks5_status < socks5_strstatus_len)
	{
		return socks5_strstatus[socks5_status];
	}
	else
	{
		return ""; // 未知状态码返回空字符串
	}
}

/**
 * 验证SOCKS5认证凭据是否有效
 * @param login 用户名
 * @param password 密码
 * @return 验证结果（true表示有效）
 */
bool socks5_is_valid_cred(const char *login, const char *password)
{
	// 检查用户名和密码是否存在
	if (!login || !password)
		return false;

	// 检查用户名长度是否符合RFC 1929规范（最大255字节）
	if (strlen(login) > 255)
	{
		log_error(LOG_WARNING, "SOCKS5用户名不能超过255字符，<%s>过长", login);
		return false;
	}

	// 检查密码长度是否符合RFC 1929规范（最大255字节）
	if (strlen(password) > 255)
	{
		log_error(LOG_WARNING, "SOCKS5密码不能超过255字符，<%s>过长", password);
		return false;
	}

	return true;
}

/**
 * SOCKS5实例初始化函数
 * @param instance redsocks实例
 */
static void socks5_instance_init(redsocks_instance *instance)
{
	redsocks_config *config = &instance->config;

	// 检查是否配置了用户名或密码
	if (config->login || config->password)
	{
		bool deauth = false;

		// 必须同时配置用户名和密码
		if (config->login && config->password)
		{
			deauth = !socks5_is_valid_cred(config->login, config->password);
		}
		else
		{
			log_error(LOG_WARNING, "SOCKS5需要同时配置用户名和密码，或者都不配置");
			deauth = true;
		}

		// 如果认证配置无效，清除配置
		if (deauth)
		{
			free(config->login);
			free(config->password);
			config->login = config->password = NULL;
		}
	}
}

/**
 * SOCKS5客户端初始化函数
 * @param client redsocks客户端
 */
static void socks5_client_init(redsocks_client *client)
{
	// 获取客户端私有数据
	socks5_client *socks5 = red_payload(client);
	const redsocks_config *config = &client->instance->config;

	// 初始化状态
	client->state = socks5_new;

	// 设置是否启用密码认证
	socks5->do_password = (config->login && config->password) ? 1 : 0;
}

/**
 * 构造SOCKS5认证方法请求
 * @param client redsocks客户端
 * @return 包含请求的evbuffer
 */
static struct evbuffer *socks5_mkmethods(redsocks_client *client)
{
	socks5_client *socks5 = red_payload(client);
	return socks5_mkmethods_plain(socks5->do_password);
}

/**
 * 构造SOCKS5认证方法请求（底层实现）
 * @param do_password 是否启用密码认证
 * @return 包含请求的evbuffer
 */
struct evbuffer *socks5_mkmethods_plain(int do_password)
{
	// 验证参数有效性
	assert(do_password == 0 || do_password == 1);

	// 计算请求长度（基础长度+可能的密码方法）
	int len = sizeof(socks5_method_req) + do_password;
	socks5_method_req *req = calloc(1, len);

	// 填充请求结构
	req->ver = socks5_ver;				// SOCKS5版本号固定为5
	req->num_methods = 1 + do_password; // 支持的方法数量

	// 总是支持无认证
	req->methods[0] = socks5_auth_none;

	// 如果启用密码认证，添加密码方法
	if (do_password)
		req->methods[1] = socks5_auth_password;

	// 将请求包装为evbuffer
	struct evbuffer *ret = mkevbuffer(req, len);
	free(req);
	return ret;
}

/**
 * 构造SOCKS5密码认证请求
 * @param client redsocks客户端
 * @return 包含请求的evbuffer
 */
static struct evbuffer *socks5_mkpassword(redsocks_client *client)
{
	return socks5_mkpassword_plain(
		client->instance->config.login,
		client->instance->config.password);
}

/**
 * 构造SOCKS5密码认证请求（底层实现）
 * @param login 用户名
 * @param password 密码
 * @return 包含请求的evbuffer
 */
struct evbuffer *socks5_mkpassword_plain(const char *login, const char *password)
{
	size_t ulen = strlen(login);
	size_t plen = strlen(password);

	// 计算请求长度：版本(1) + 用户长度(1) + 用户名 + 密码长度(1) + 密码
	size_t length = 1 + 1 + ulen + 1 + plen;
	uint8_t req[length];

	// 填充请求结构
	req[0] = socks5_password_ver;			// 密码子协商版本（固定为1）
	req[1] = ulen;							// 用户名长度
	memcpy(&req[2], login, ulen);			// 用户名
	req[2 + ulen] = plen;					// 密码长度
	memcpy(&req[3 + ulen], password, plen); // 密码

	return mkevbuffer(req, length);
}
/**
 * 打印SOCKS5请求数据（十六进制和解析格式）
 */
static void print_socks5_request(const void *data, size_t len, int cmd, const struct sockaddr_in *destaddr)
{
	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &destaddr->sin_addr, ip_str, sizeof(ip_str));
	uint16_t port = ntohs(destaddr->sin_port);

	// 打印基本信息
	printf("\n====== SOCKS5 Request ======\n");
	printf("Command: %s\n", cmd == socks5_cmd_connect ? "CONNECT" : cmd == socks5_cmd_bind ? "BIND"
																						   : "UDP_ASSOCIATE");
	printf("Target: %s:%d\n", ip_str, port);

	// 打印十六进制数据
	printf("Hex Dump (%zu bytes):\n", len);
	const uint8_t *bytes = data;
	for (size_t i = 0; i < len; i++)
	{
		printf("%02x ", bytes[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n");

	// 解析结构体字段
	if (len >= sizeof(socks5_req))
	{
		const socks5_req *req = data;
		printf("\nParsed Structure:\n");
		printf("  Version: 0x%02x\n", req->ver);
		printf("  Command: 0x%02x", req->cmd);
		switch (req->cmd)
		{
		case socks5_cmd_connect:
			printf(" (CONNECT)\n");
			break;
		case socks5_cmd_bind:
			printf(" (BIND)\n");
			break;
		case socks5_cmd_udp_associate:
			printf(" (UDP_ASSOCIATE)\n");
			break;
		default:
			printf(" (Unknown)\n");
		}
		printf("  Reserved: 0x%02x\n", req->reserved);
		printf("  AddrType: 0x%02x", req->addrtype);
		switch (req->addrtype)
		{
		case socks5_addrtype_ipv4:
			printf(" (IPv4)\n");
			break;
		case socks5_addrtype_ipv6:
			printf(" (IPv6)\n");
			break;
		case socks5_addrtype_domain:
			printf(" (DOMAIN)\n");
			break;
		default:
			printf(" (Unknown)\n");
		}

		// 打印地址信息
		if (req->addrtype == socks5_addrtype_ipv4 && len >= sizeof(socks5_req) + sizeof(socks5_addr_ipv4))
		{
			const socks5_addr_ipv4 *addr = (const socks5_addr_ipv4 *)(req + 1);
			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &addr->addr, ip, sizeof(ip));
			printf("  IPv4: %s\n", ip);
			printf("  Port: %d\n", ntohs(addr->port));
		}
	}
	printf("============================\n\n");
}

static void print_socks5_request_ex(const void *data, size_t len, int cmd)
{
	const socks5_req *req = data;

	printf("\n====== SOCKS5 Request ======\n");
	printf("Version: 0x%02x\n", req->ver);
	printf("Command: %s (0x%02x)\n",
		   req->cmd == socks5_cmd_connect ? "CONNECT" : req->cmd == socks5_cmd_bind ? "BIND"
																					: "UDP_ASSOCIATE",
		   req->cmd);

	printf("Address Type: ");
	switch (req->addrtype)
	{
	case socks5_addrtype_ipv4:
	{
		const socks5_addr_ipv4 *addr = (const socks5_addr_ipv4 *)(req + 1);
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &addr->addr, ip, sizeof(ip));
		printf("IPv4 (%s:%d)\n", ip, ntohs(addr->port));
		break;
	}
	case socks5_addrtype_domain:
	{
		const uint8_t *p = (const uint8_t *)(req + 1);
		uint8_t domain_len = *p++;
		char domain[256];
		memcpy(domain, p, domain_len);
		domain[domain_len] = '\0';
		uint16_t port = ntohs(*(uint16_t *)(p + domain_len));
		printf("DOMAIN (%s:%d)\n", domain, port);
		break;
	}
	default:
		printf("Unknown (0x%02x)\n", req->addrtype);
	}

	printf("Hex Dump:\n");
	for (size_t i = 0; i < len; i++)
	{
		printf("%02x ", ((const uint8_t *)data)[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n============================\n\n");
}

/**
 * 仅打印SOCKS5请求的原始字节
 * @param data 请求数据指针
 * @param len 数据长度
 */
void print_raw_socks5_request(const void *data, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)data;
	printf("SOCKS5 Raw Request (%zu bytes): ", len);
	for (size_t i = 0; i < len; i++)
	{
		printf("%02X ", bytes[i]);
	}
	printf("\n");
}

/**
 * 构造SOCKS5命令请求（连接/绑定等）
 * @param socks5_cmd 命令类型
 * @param destaddr 目标地址
 * @return 包含请求的evbuffer
 */
struct evbuffer *socks5_mkcommand_plain(int socks5_cmd, const struct sockaddr_in *destaddr)
{
	// 使用PACKED确保结构体紧密排列
	struct
	{
		socks5_req head;
		socks5_addr_ipv4 ip;
	} PACKED req;

	// 只支持IPv4地址
	assert(destaddr->sin_family == AF_INET);

	// 填充请求头
	req.head.ver = socks5_ver;				  // 版本号
	req.head.cmd = socks5_cmd;				  // 命令类型
	req.head.reserved = 0;					  // 保留字段
	req.head.addrtype = socks5_addrtype_ipv4; // 地址类型

	// 填充地址信息
	req.ip.addr = destaddr->sin_addr.s_addr; // 目标IP
	req.ip.port = destaddr->sin_port;		 // 目标端口

	// 打印请求数据（调试用）
	// print_socks5_request(&req, sizeof(req), socks5_cmd, destaddr);

	return mkevbuffer(&req, sizeof(req));
}

/**
 * 构造SOCKS5命令请求（支持域名）
 * @param socks5_cmd 命令类型
 * @param destaddr 目标地址
 * @param hostname 域名（可选）
 * @return 包含请求的evbuffer
 */
struct evbuffer *socks5_mkcommand_plain_ex(int socks5_cmd,
										   const struct sockaddr_in *destaddr,
										   const char *domain)
{
	if (domain && strlen(domain) > 0)
	{
		size_t domain_len = strlen(domain);
		if (domain_len > 255)
		{
			log_error(LOG_ERR, "Domain too long: %s", domain);
			return NULL;
		}

		// 构造带域名的请求
		size_t len = sizeof(socks5_req) + 1 + domain_len + 2;
		uint8_t *buf = malloc(len);
		socks5_req *req = (socks5_req *)buf;

		req->ver = socks5_ver;
		req->cmd = socks5_cmd;
		req->reserved = 0;
		req->addrtype = socks5_addrtype_domain; // 0x03=DOMAIN

		uint8_t *p = buf + sizeof(socks5_req);
		*p++ = (uint8_t)domain_len;
		memcpy(p, domain, domain_len);
		p += domain_len;
		// 直接写入端口号，sin_port已经是网络字节序

		*p++ = destaddr->sin_port & 0xFF;
		*p++ = (destaddr->sin_port >> 8) & 0xFF;
		

		struct evbuffer *evb = mkevbuffer(buf, len);
		// print_socks5_request_ex(&req,sizeof(req),socks5_cmd);

		print_raw_socks5_request(buf, len);
		free(buf);
		return evb;
	}
	else
	{
		// 原始IP模式
		struct
		{
			socks5_req head;
			socks5_addr_ipv4 ip;
		} PACKED req;

		req.head.ver = socks5_ver;
		req.head.cmd = socks5_cmd;
		req.head.reserved = 0;
		req.head.addrtype = socks5_addrtype_ipv4;
		req.ip.addr = destaddr->sin_addr.s_addr;
		req.ip.port = destaddr->sin_port;
		return mkevbuffer(&req, sizeof(req));
	}
}

/**
 * 构造SOCKS5连接请求
 * @param client redsocks客户端
 * @return 包含请求的evbuffer
 */
static struct evbuffer *socks5_mkconnect(redsocks_client *client)
{
	// 原版
	// return socks5_mkcommand_plain(socks5_cmd_connect, &client->destaddr);

	// 获取域名
	const char *domain = get_domain_by_ip(&client->destaddr);

	char ip_str[INET_ADDRSTRLEN];
	struct sockaddr_in *addr = &client->destaddr;
	inet_ntop(addr->sin_family, &addr->sin_addr, ip_str, sizeof(ip_str));

	if (domain)
	{
		printf("[*] 存在域名 进行域名替换：%s -> %s \n", ip_str, domain);
		// 构造带域名的SOCKS5请求
		return socks5_mkcommand_plain_ex(
			socks5_cmd_connect,
			&client->destaddr,
			domain);
	}
	else
	{
		// 回退到原始IP模式
		return socks5_mkcommand_plain(
			socks5_cmd_connect,
			&client->destaddr);
	}
}

/**
 * SOCKS5写回调函数
 * @param buffev 缓冲区事件
 * @param _arg 客户端参数
 */
static void socks5_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	// 更新客户端活动时间
	redsocks_touch_client(client);

	// 初始状态发送认证方法请求
	if (client->state == socks5_new)
	{
		redsocks_write_helper(
			buffev,
			client,
			socks5_mkmethods,			// 构造方法请求
			socks5_method_sent,			// 下一个状态
			sizeof(socks5_method_reply) // 预期响应长度
		);
	}
}

/**
 * 验证SOCKS5服务器返回的认证方法是否有效
 * @param reply 服务器响应
 * @param do_password 是否支持密码认证
 * @return 错误信息（NULL表示有效）
 */
const char *socks5_is_known_auth_method(socks5_method_reply *reply, int do_password)
{
	if (reply->ver != socks5_ver)
		return "SOCKS5服务器返回了意外的认证方法版本";
	else if (reply->method == socks5_auth_invalid)
		return "SOCKS5服务器拒绝了所有认证方法";
	else if (reply->method != socks5_auth_none &&
			 !(reply->method == socks5_auth_password && do_password))
		return "SOCKS5服务器请求了意外的认证方法";
	else
		return NULL; // 认证方法有效
}

/**
 * 处理SOCKS5认证方法响应
 * @param buffev 缓冲区事件
 * @param client redsocks客户端
 * @param socks5 SOCKS5客户端数据
 */
static void socks5_read_auth_methods(struct bufferevent *buffev,
									 redsocks_client *client,
									 socks5_client *socks5)
{
	socks5_method_reply reply;
	const char *error = NULL;

	// 读取预期长度的响应数据
	if (redsocks_read_expected(client, buffev->input, &reply,
							   sizes_equal, sizeof(reply)) < 0)
		return;

	// 验证认证方法是否有效
	error = socks5_is_known_auth_method(&reply, socks5->do_password);
	if (error)
	{
		// 无效认证方法，记录错误并断开连接
		redsocks_log_error(client, LOG_NOTICE,
						   "socks5_is_known_auth_method: %s", error);
		redsocks_drop_client(client);
	}
	else if (reply.method == socks5_auth_none)
	{
		// 无认证直接发送连接请求
		redsocks_write_helper(
			buffev,
			client,
			socks5_mkconnect,	 // 构造连接请求
			socks5_request_sent, // 下一个状态
			sizeof(socks5_reply) // 预期响应长度
		);
	}
	else if (reply.method == socks5_auth_password)
	{
		// 需要密码认证，发送认证信息
		redsocks_write_helper(
			buffev,
			client,
			socks5_mkpassword,		  // 构造密码认证请求
			socks5_auth_sent,		  // 下一个状态
			sizeof(socks5_auth_reply) // 预期响应长度
		);
	}
}

/**
 * 处理SOCKS5密码认证响应
 * @param buffev 缓冲区事件
 * @param client redsocks客户端
 * @param socks5 SOCKS5客户端数据
 */
static void socks5_read_auth_reply(struct bufferevent *buffev,
								   redsocks_client *client,
								   socks5_client *socks5)
{
	socks5_auth_reply reply;

	// 读取认证响应
	if (redsocks_read_expected(client, buffev->input, &reply,
							   sizes_equal, sizeof(reply)) < 0)
		return;

	// 检查版本号
	if (reply.ver != socks5_password_ver)
	{
		redsocks_log_error(client, LOG_NOTICE,
						   "SOCKS5服务器返回了意外的认证版本 %d", reply.ver);
		redsocks_drop_client(client);
	}
	else if (reply.status == socks5_password_passed)
	{
		// 认证通过，发送连接请求
		redsocks_write_helper(
			buffev,
			client,
			socks5_mkconnect,	 // 构造连接请求
			socks5_request_sent, // 下一个状态
			sizeof(socks5_reply) // 预期响应长度
		);
	}
	else
	{
		// 认证失败
		redsocks_log_error(client, LOG_NOTICE,
						   "SOCKS5认证失败，状态码 %i", reply.status);
		redsocks_drop_client(client);
	}
}

/**
 * 处理SOCKS5命令响应
 * @param buffev 缓冲区事件
 * @param client redsocks客户端
 * @param socks5 SOCKS5客户端数据
 */
static void socks5_read_reply(struct bufferevent *buffev,
							  redsocks_client *client,
							  socks5_client *socks5)
{
	socks5_reply reply;

	// 读取响应头部（可能包含变长数据）
	if (redsocks_read_expected(client, buffev->input, &reply,
							   sizes_greater_equal, sizeof(reply)) < 0)
		return;

	// 检查版本号
	if (reply.ver != socks5_ver)
	{
		redsocks_log_error(client, LOG_NOTICE,
						   "SOCKS5服务器返回了意外的协议版本");
		redsocks_drop_client(client);
	}
	else if (reply.status == socks5_status_succeeded)
	{
		// 命令执行成功，处理返回的地址信息
		socks5_state nextstate;
		size_t len;

		// 根据返回的地址类型处理
		if (reply.addrtype == socks5_addrtype_ipv4)
		{
			// IPv4地址，需要跳过4字节IP和2字节端口
			len = socks5->to_skip = sizeof(socks5_addr_ipv4);
			nextstate = socks5_skip_address;
		}
		else if (reply.addrtype == socks5_addrtype_ipv6)
		{
			// IPv6地址，需要跳过16字节IP和2字节端口
			len = socks5->to_skip = sizeof(socks5_addr_ipv6);
			nextstate = socks5_skip_address;
		}
		else if (reply.addrtype == socks5_addrtype_domain)
		{
			// 域名地址，先读取1字节长度
			socks5_addr_domain domain;
			len = sizeof(domain.size);
			nextstate = socks5_skip_domain;
		}
		else
		{
			// 不支持的地址类型
			redsocks_log_error(client, LOG_NOTICE,
							   "SOCKS5服务器返回了意外的地址类型");
			redsocks_drop_client(client);
			return;
		}

		// 准备读取剩余数据
		redsocks_write_helper(
			buffev,
			client,
			NULL,	   // 不需要发送数据
			nextstate, // 下一个状态
			len		   // 预期数据长度
		);
	}
	else
	{
		// 命令执行失败
		redsocks_log_error(client, LOG_NOTICE,
						   "SOCKS5服务器状态: %s (%i)",
						   (reply.status < SIZEOF_ARRAY(socks5_strstatus))
							   ? socks5_strstatus[reply.status]
							   : "?",
						   reply.status);
		redsocks_drop_client(client);
	}
}

/**
 * SOCKS5读回调函数（状态机驱动）
 * @param buffev 缓冲区事件
 * @param _arg 客户端参数
 */
static void socks5_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	socks5_client *socks5 = red_payload(client);

	// 更新客户端活动时间
	redsocks_touch_client(client);

	// 根据当前状态处理响应
	switch (client->state)
	{
	case socks5_method_sent: // 已发送认证方法
		socks5_read_auth_methods(buffev, client, socks5);
		break;

	case socks5_auth_sent: // 已发送认证信息
		socks5_read_auth_reply(buffev, client, socks5);
		break;

	case socks5_request_sent:

		// 已发送连接请求
		socks5_read_reply(buffev, client, socks5);
		break;

	case socks5_skip_domain: // 需要跳过域名信息
	{
		socks5_addr_ipv4 ipv4; // 所有地址类型的端口字段大小相同
		uint8_t size;

		// 读取域名长度
		if (redsocks_read_expected(client, buffev->input, &size,
								   sizes_greater_equal, sizeof(size)) < 0)
			return;

		// 计算需要跳过的总字节数（域名长度 + 端口长度）
		socks5->to_skip = size + sizeof(ipv4.port);

		// 准备跳过地址数据
		redsocks_write_helper(
			buffev,
			client,
			NULL,				 // 不需要发送数据
			socks5_skip_address, // 下一个状态
			socks5->to_skip		 // 需要跳过的字节数
		);
	}
	break;

	case socks5_skip_address: // 需要跳过地址信息
	{
		uint8_t data[socks5->to_skip];

		// 读取并丢弃地址数据
		if (redsocks_read_expected(client, buffev->input, data,
								   sizes_greater_equal, socks5->to_skip) < 0)
			return;

		// 开始数据中继
		redsocks_start_relay(client);
	}
	break;

	default: // 未知状态，断开连接
		redsocks_drop_client(client);
	}
}

/* SOCKS5协议子系统定义 */
relay_subsys socks5_subsys =
	{
		.name = "socks5",					   // 协议名称
		.payload_len = sizeof(socks5_client),  // 每个客户端的私有数据大小
		.instance_payload_len = 0,			   // 每个实例的私有数据大小
		.readcb = socks5_read_cb,			   // 读回调函数
		.writecb = socks5_write_cb,			   // 写回调函数
		.init = socks5_client_init,			   // 客户端初始化函数
		.instance_init = socks5_instance_init, // 实例初始化函数
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */