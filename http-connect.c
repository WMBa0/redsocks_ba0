/* redsocks - 透明 TCP 到代理的重定向器
 * 版权所有 (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * 根据 Apache 许可证 2.0 版本授权（"许可证"）；除非符合许可证，
 * 否则不得使用此文件。您可以在以下网址获取许可证副本：
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 除非适用法律要求或书面同意，否则按"原样"分发软件，
 * 没有任何明示或暗示的保证或条件。请参阅许可证了解
 * 特定语言下的权限和限制。
 *
 * redsocks 的 HTTP-CONNECT 上游模块
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "redsocks.h"
#include "http-auth.h"
#include "debugcor.h" //add....

// LogLevel current_log_level = LOG_LEVEL_DEBUG;  // 实际定义

// HTTP-CONNECT 状态枚举
typedef enum httpc_state_t
{
	httpc_new,			   // 初始状态
	httpc_request_sent,	   // 已发送CONNECT请求
	httpc_reply_came,	   // 收到200 OK回复，正在跳过头部...
	httpc_headers_skipped, // 头部已跳过，开始数据传输
	httpc_no_way,		   // 代理无法处理请求
	httpc_MAX,			   // 状态最大值
} httpc_state;

// HTTP头部高水位标记（最大缓冲区大小）
#define HTTP_HEAD_WM_HIGH 4096 // 这应该足够容纳一行HTTP数据

// 初始化客户端状态
static void httpc_client_init(redsocks_client *client)
{
	client->state = httpc_new;
}

// 清理实例资源
static void httpc_instance_fini(redsocks_instance *instance)
{
	http_auth *auth = red_http_auth(instance);
	free(auth->last_auth_query);
	auth->last_auth_query = NULL;
}

// 创建CONNECT请求
static struct evbuffer *httpc_mkconnect(redsocks_client *client);

// 外部声明的认证头常量
extern const char *auth_request_header;
extern const char *auth_response_header;

// 读取回调函数
static void httpc_read_cb(struct bufferevent *buffev, void *_arg)
{
	LOG_DEBUG_C("[*]httpc - READ \n");
	redsocks_client *client = _arg;

	// 验证参数和状态
	assert(client->relay == buffev);
	assert(client->state == httpc_request_sent || client->state == httpc_reply_came);

	// 更新客户端活动时间
	redsocks_touch_client(client);

	// 处理错误转发时的缓冲区
	struct evbuffer *tee = NULL;
	const bool do_errtee = client->instance->config.on_proxy_fail == ONFAIL_FORWARD_HTTP_ERR;

	// 处理请求已发送状态
	if (client->state == httpc_request_sent)
	{
		size_t len = evbuffer_get_length(buffev->input);
		char *line = redsocks_evbuffer_readline(buffev->input);
		if (line)
		{
			unsigned int code;
			// 解析HTTP响应码
			if (sscanf(line, "HTTP/%*u.%*u %u", &code) == 1)
			{
				if (code == 407)
				{ // 需要认证
					http_auth *auth = red_http_auth(client->instance);

					if (auth->last_auth_query != NULL && auth->last_auth_count == 1)
					{
						redsocks_log_error(client, LOG_NOTICE, "HTTP代理认证失败: %s", line);
						client->state = httpc_no_way;
					}
					else if (client->instance->config.login == NULL || client->instance->config.password == NULL)
					{
						redsocks_log_error(client, LOG_NOTICE, "HTTP代理需要认证，但未配置用户名/密码: %s", line);
						client->state = httpc_no_way;
					}
					else
					{
						if (do_errtee)
							tee = evbuffer_new();
						// 获取认证请求头
						char *auth_request = http_auth_request_header(buffev->input, tee);
						if (!auth_request)
						{
							redsocks_log_error(client, LOG_NOTICE, "HTTP代理需要认证，但未找到<%s>头: %s", auth_request_header, line);
							client->state = httpc_no_way;
						}
						else
						{
							free(line);
							if (tee)
								evbuffer_free(tee);
							free(auth->last_auth_query);
							char *ptr = auth_request;

							ptr += strlen(auth_request_header);
							while (isspace(*ptr))
								ptr++;

							// 保存认证查询信息
							size_t last_auth_query_len = strlen(ptr) + 1;
							auth->last_auth_query = calloc(last_auth_query_len, 1);
							memcpy(auth->last_auth_query, ptr, last_auth_query_len);
							auth->last_auth_count = 0;

							free(auth_request);

							// 禁用写事件并重新连接
							if (bufferevent_disable(client->relay, EV_WRITE))
							{
								redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
								return;
							}

							redsocks_bufferevent_free(client->relay);
							client->state = httpc_new;
							redsocks_connect_relay(client);
							return;
						}
					}
				}
				else if (200 <= code && code <= 299)
				{ // 成功响应
					client->state = httpc_reply_came;
				}
				else
				{ // 其他错误
					redsocks_log_error(client, LOG_NOTICE, "HTTP代理错误: %s", line);
					client->state = httpc_no_way;
				}
			}
			else
			{ // 无效的第一行
				redsocks_log_error(client, LOG_NOTICE, "HTTP代理无效的第一行: %s", line);
				client->state = httpc_no_way;
			}
			// 如果需要转发错误，将错误信息写入客户端
			if (do_errtee && client->state == httpc_no_way)
			{
				if (bufferevent_write(client->client, line, strlen(line)) != 0 ||
					bufferevent_write(client->client, "\r\n", 2) != 0)
				{
					redsocks_log_errno(client, LOG_NOTICE, "bufferevent_write");
					goto fail;
				}
			}
			free(line);
		}
		else if (len >= HTTP_HEAD_WM_HIGH)
		{ // 响应过长
			redsocks_log_error(client, LOG_NOTICE, "HTTP代理响应过长, %zu 字节", len);
			client->state = httpc_no_way;
		}
	}

	// 处理需要转发错误的情况
	if (do_errtee && client->state == httpc_no_way)
	{
		if (tee)
		{
			if (bufferevent_write_buffer(client->client, tee) != 0)
			{
				redsocks_log_errno(client, LOG_NOTICE, "bufferevent_write_buffer");
				goto fail;
			}
		}
		// 关闭连接并清理
		redsocks_shutdown(client, client->client, SHUT_RD);
		const size_t avail = evbuffer_get_length(client->client->input);
		if (avail)
		{
			if (evbuffer_drain(client->client->input, avail) != 0)
			{
				redsocks_log_errno(client, LOG_NOTICE, "evbuffer_drain");
				goto fail;
			}
		}
		redsocks_shutdown(client, client->relay, SHUT_WR);
		client->state = httpc_headers_skipped;
	}

fail:
	if (tee)
	{
		evbuffer_free(tee);
	}

	// 处理无法继续的情况
	if (client->state == httpc_no_way)
	{
		redsocks_drop_client(client);
		return;
	}

	// 跳过HTTP头部
	while (client->state == httpc_reply_came)
	{
		char *line = redsocks_evbuffer_readline(buffev->input);
		if (line)
		{
			if (strlen(line) == 0)
			{ // 空行表示头部结束
				client->state = httpc_headers_skipped;
			}
			free(line);
		}
		else
		{
			break;
		}
	}

	// 头部处理完成后开始中继
	if (client->state == httpc_headers_skipped)
	{
		redsocks_start_relay(client);
	}
}

// 创建CONNECT请求
static struct evbuffer *httpc_mkconnect(redsocks_client *client)
{
	struct evbuffer *buff = NULL, *retval = NULL;
	char *auth_string = NULL;
	int len;

	buff = evbuffer_new();
	if (!buff)
	{
		redsocks_log_errno(client, LOG_ERR, "evbuffer_new");
		goto fail;
	}

	http_auth *auth = red_http_auth(client->instance);
	++auth->last_auth_count;

	const char *auth_scheme = NULL;

	// 处理认证信息
	if (auth->last_auth_query != NULL)
	{
		if (strncasecmp(auth->last_auth_query, "Basic", 5) == 0)
		{
			auth_string = basic_authentication_encode(client->instance->config.login, client->instance->config.password);
			auth_scheme = "Basic";
		}
		else if (strncasecmp(auth->last_auth_query, "Digest", 6) == 0)
		{
			// 计算URI
			char uri[128];
			snprintf(uri, 128, "%s:%u", inet_ntoa(client->destaddr.sin_addr), ntohs(client->destaddr.sin_port));

			// 生成随机字符串用于cnonce
			char cnounce[17];
			snprintf(cnounce, sizeof(cnounce), "%08x%08x", red_randui32(), red_randui32());

			auth_string = digest_authentication_encode(auth->last_auth_query + 7,										  // 认证行
													   client->instance->config.login, client->instance->config.password, // 用户名和密码
													   "CONNECT", uri, auth->last_auth_count, cnounce);					  // 方法、路径、nc和cnonce
			auth_scheme = "Digest";
		}
	}
	// 获取域名
	const char *domain = get_domain_by_ip(&client->destaddr);

	if (domain && strlen(domain) > 0)
	{
		char ip_str[INET_ADDRSTRLEN];
		struct sockaddr_in *addr = &client->destaddr;
		inet_ntop(addr->sin_family, &addr->sin_addr, ip_str, sizeof(ip_str));
		printf("[*] http-connect 存在域名 进行域名替换：%s -> %s \n", ip_str, domain);

		// 添加CONNECT请求行
		len = evbuffer_add_printf(buff, "CONNECT %s:%u HTTP/1.0\r\n",
								  domain,
								  ntohs(client->destaddr.sin_port));
		if (len < 0)
		{
			redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
			goto fail;
		}
	}
	else
	{
		// 添加CONNECT请求行
		len = evbuffer_add_printf(buff, "CONNECT %s:%u HTTP/1.0\r\n",
								  inet_ntoa(client->destaddr.sin_addr),
								  ntohs(client->destaddr.sin_port));
		if (len < 0)
		{
			redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
			goto fail;
		}
	}

	// 添加认证头
	if (auth_string)
	{
		len = evbuffer_add_printf(buff, "%s %s %s\r\n",
								  auth_response_header, auth_scheme, auth_string);
		if (len < 0)
		{
			redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
			goto fail;
		}
		free(auth_string);
		auth_string = NULL;
	}

	// 添加源地址披露头
	const enum disclose_src_e disclose_src = client->instance->config.disclose_src;
	if (disclose_src != DISCLOSE_NONE)
	{
		char clientip[INET_ADDRSTRLEN];
		const char *ip = inet_ntop(client->clientaddr.sin_family, &client->clientaddr.sin_addr, clientip, sizeof(clientip));
		if (!ip)
		{
			redsocks_log_errno(client, LOG_ERR, "inet_ntop");
			goto fail;
		}
		if (disclose_src == DISCLOSE_X_FORWARDED_FOR)
		{
			len = evbuffer_add_printf(buff, "X-Forwarded-For: %s\r\n", ip);
		}
		else if (disclose_src == DISCLOSE_FORWARDED_IP)
		{
			len = evbuffer_add_printf(buff, "Forwarded: for=%s\r\n", ip);
		}
		else if (disclose_src == DISCLOSE_FORWARDED_IPPORT)
		{
			len = evbuffer_add_printf(buff, "Forwarded: for=\"%s:%d\"\r\n", ip,
									  ntohs(client->clientaddr.sin_port));
		}
		if (len < 0)
		{
			redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
			goto fail;
		}
	}

	// 添加结束标记
	len = evbuffer_add(buff, "\r\n", 2);
	if (len < 0)
	{
		redsocks_log_errno(client, LOG_ERR, "evbufer_add");
		goto fail;
	}

	retval = buff;
	buff = NULL;

fail:
	// 清理资源
	if (auth_string)
		free(auth_string);
	if (buff)
		evbuffer_free(buff);
	return retval;
}

// 写入回调函数
static void httpc_write_cb(struct bufferevent *buffev, void *_arg)
{
	LOG_DEBUG_C("[*] httpc - WRITE \n");
	redsocks_client *client = _arg;

	// 更新客户端活动时间
	redsocks_touch_client(client);

	// 根据状态处理写入
	if (client->state == httpc_new)
	{
		redsocks_write_helper_ex(
			buffev, client,
			httpc_mkconnect, httpc_request_sent, 1, HTTP_HEAD_WM_HIGH);
	}
	else if (client->state >= httpc_request_sent)
	{
		bufferevent_disable(buffev, EV_WRITE);
	}
}

// HTTP-CONNECT 子系统定义
relay_subsys http_connect_subsys =
	{
		.name = "http-connect",					   // 子系统名称
		.payload_len = 0,						   // 客户端负载长度
		.instance_payload_len = sizeof(http_auth), // 实例负载长度
		.readcb = httpc_read_cb,				   // 读取回调
		.writecb = httpc_write_cb,				   // 写入回调
		.init = httpc_client_init,				   // 初始化函数
		.instance_fini = httpc_instance_fini,	   // 实例清理函数
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */