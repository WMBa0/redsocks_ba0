/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

// 包含必要的系统头文件
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <event.h>
#include <uthash.h> // 哈希表库
#include <pthread.h>

// 包含项目自定义头文件
#include "list.h"
#include "parser.h"
#include "log.h"
#include "main.h"
#include "base.h"
#include "redsocks.h"
#include "utils.h"
#include "libevent-compat.h"
#include "debug.h"

// 定义中继缓冲区大小
#define REDSOCKS_RELAY_HALFBUFF 4096

// 定义泵(pump)状态枚举
enum pump_state_t
{
    pump_active = -1,
    pump_MAX = 0,
};

// 函数声明
static const char *redsocks_event_str(unsigned short what);
static int redsocks_start_bufferpump(redsocks_client *client);
static int redsocks_start_splicepump(redsocks_client *client);
static void redsocks_conn_list_del(redsocks_client *client);

// 声明外部中继子系统
extern relay_subsys http_connect_subsys;
extern relay_subsys http_relay_subsys;
extern relay_subsys socks4_subsys;
extern relay_subsys socks5_subsys;

// 中继子系统数组
static relay_subsys *relay_subsystems[] = {
    &http_connect_subsys,
    &http_relay_subsys,
    &socks4_subsys,
    &socks5_subsys,
};

// 实例链表头
static list_head instances = LIST_HEAD_INIT(instances);

// 连接压力管理变量
static uint32_t redsocks_conn;         // 当前连接数
static uint32_t accept_backoff_ms;     // 接受连接的退避时间(毫秒)
static struct event accept_backoff_ev; // 退避事件

// 配置解析条目
static parser_entry redsocks_entries[] = {
    {.key = "local_ip", .type = pt_in_addr},
    {.key = "local_port", .type = pt_uint16},
    {.key = "ip", .type = pt_in_addr},
    {.key = "port", .type = pt_uint16},
    {.key = "type", .type = pt_pchar},
    {.key = "login", .type = pt_pchar},
    {.key = "password", .type = pt_pchar},
    {.key = "listenq", .type = pt_uint16},
    {.key = "splice", .type = pt_bool},
    {.key = "disclose_src", .type = pt_disclose_src},
    {.key = "on_proxy_fail", .type = pt_on_proxy_fail},
    {}};

/* 新增：用于存储IP和域名的映射关系 */
typedef struct
{
    char ip[16];       // IPv4地址字符串
    char domain[256];  // 域名
    UT_hash_handle hh; // uthash哈希表处理
} ip_domain_map;

static ip_domain_map *domain_table = NULL; // 全局域名映射表

/* 解析TLS ClientHello中的SNI（Server Name Indication）*/
void parse_sni(const unsigned char *data, size_t len, redsocks_client *client)
{
    /* TLS Record Layer格式：
     * [0]:   0x16 (Handshake类型)
     * [1-2]: 版本号
     * [3-4]: 记录长度
     * [5]:   0x01 (ClientHello)
     * [6-8]: 握手消息长度
     * [9-10]: 客户端版本号
     * [11-42]: 随机数(32字节)
     * 之后是会话ID、加密套件等，最后是扩展
     */

    // 基本校验
    if (len < 43 || data[0] != 0x16 || data[5] != 0x01)
    {
        log_error(LOG_DEBUG, "Invalid TLS ClientHello packet");
        return;
    }

    // 计算扩展开始位置
    size_t offset = 43; // TLS头部(5) + Handshake头部(4) + 版本(2) + 随机数(32)

    // 会话ID长度 (1字节长度 + 变长数据)
    if (offset + 1 > len)
        return;
    uint8_t session_id_len = data[offset];
    offset += 1 + session_id_len;

    // 加密套件长度 (2字节长度 + 变长数据)
    if (offset + 2 > len)
        return;
    uint16_t cipher_suites_len = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipher_suites_len;

    // 压缩方法长度 (1字节长度 + 变长数据)
    if (offset + 1 > len)
        return;
    uint8_t compression_methods_len = data[offset];
    offset += 1 + compression_methods_len;

    // 扩展开始位置 (如果有)
    if (offset + 2 > len)
        return;
    // uint16_t extensions_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    // 遍历扩展
    while (offset + 4 <= len)
    {
        uint16_t ext_type = (data[offset] << 8) | data[offset + 1];
        uint16_t ext_len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_len > len)
        {
            break; // 扩展长度越界
        }

        if (ext_type == 0x0000)
        { // SNI扩展
            if (ext_len < 2)
                continue;

            // SNI列表长度 (2字节)
            uint16_t sni_list_len = (data[offset] << 8) | data[offset + 1];
            offset += 2;

            if (sni_list_len < 3)
                continue;

            // 第一个SNI条目
            uint8_t name_type = data[offset];
            uint16_t name_len = (data[offset + 1] << 8) | data[offset + 2];
            offset += 3;

            if (name_type != 0x00 || name_len == 0 || offset + name_len > len)
            {
                continue; // 只处理host_name类型
            }

            // 提取域名
            char domain[name_len + 1];
            memcpy(domain, &data[offset], name_len);
            domain[name_len] = '\0';

            // 获取客户端目标IP
            char ip_str[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &client->destaddr.sin_addr, ip_str, sizeof(ip_str));

            // 更新映射表
            ip_domain_map *entry = NULL;

            HASH_FIND_STR(domain_table, ip_str, entry);
            if (!entry)
            {
                entry = malloc(sizeof(ip_domain_map));
                strncpy(entry->ip, ip_str, INET_ADDRSTRLEN - 1);
                strncpy(entry->domain, domain, name_len);
                entry->ip[INET_ADDRSTRLEN - 1] = '\0';
                entry->domain[name_len] = '\0';
                HASH_ADD_STR(domain_table, ip, entry);

                printf("记录 HTTPS SNI: %s -> %s\n", domain, ip_str);
            }
            else if (strcmp(entry->domain, domain) != 0)
            {
                // IP已存在但域名不同，更新域名
                strncpy(entry->domain, domain, name_len);
                entry->domain[name_len] = '\0';
                printf("更新 HTTPS SNI Updated: %s -> %s\n", domain, ip_str);
            }

            break;
        }

        offset += ext_len;
    }
}

/* 解析HTTP Host头 */
void parse_host_header(const char *data, size_t len, redsocks_client *client)
{
    const char *host_prefix = "Host: ";
    const char *header_end = "\r\n";

    const char *host_start = strstr(data, host_prefix);
    if (!host_start)
        return;

    host_start += strlen(host_prefix);
    const char *host_end = strstr(host_start, header_end);
    if (!host_end)
        return;

    size_t host_len = host_end - host_start;
    char host[host_len + 1];
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    // 记录到映射表
    ip_domain_map *entry;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->destaddr.sin_addr, ip_str, sizeof(ip_str));

    HASH_FIND_STR(domain_table, ip_str, entry);
    if (!entry)
    {
        entry = malloc(sizeof(ip_domain_map));
        strcpy(entry->ip, ip_str);
        strcpy(entry->domain, host);
        HASH_ADD_STR(domain_table, ip, entry);
    }

    // redsocks_log_error(client, LOG_DEBUG, "Host header: %s -> %s", host, ip_str);
    log_error(LOG_NOTICE, "HTTP : Host header: %s -> %s", host, ip_str);
}

// 识别 buffev 成员
void parse_sni_from_bufferevent(struct bufferevent *buffev, redsocks_client *client)
{
    log_error(LOG_NOTICE, "[*] parse_sni_from_bufferevent 触发");

    if (!buffev || !client)
    {
        redsocks_log_error(client, LOG_ERR, "Invalid arguments");
        return;
    }

    // 获取输入缓冲区
    struct evbuffer *input = bufferevent_get_input(buffev);
    size_t len = evbuffer_get_length(input);

    // 检查最小TLS头长度
    if (len < 5)
    {
        redsocks_log_error(client, LOG_DEBUG, "Incomplete TLS header (%zu bytes)", len);
        return;
    }

    // struct evbuffer *input = bufferevent_get_input(buffev);
    // size_t len = evbuffer_get_length(input);
    if (len > 0)
    {
        // 获取数据指针（不消费缓冲区）
        unsigned char *data = evbuffer_pullup(input, len);
        log_error(LOG_NOTICE, "Current input buffer (%zu bytes):\n", len);
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }

    // 提取数据（不消费缓冲区）
    unsigned char *data = evbuffer_pullup(input, len);
    if (!data)
    {
        redsocks_log_errno(client, LOG_ERR, "evbuffer_pullup failed");
        return;
    }

    // 解析SNI
    parse_sni(data, len, client);
}

/* 根据域名选择代理（示例函数） */
void route_by_domain(redsocks_client *client)
{
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->destaddr.sin_addr, ip_str, sizeof(ip_str));

    ip_domain_map *entry;
    HASH_FIND_STR(domain_table, ip_str, entry);

    if (entry)
    {
        if (strstr(entry->domain, "www.baidu.com"))
        {
            // 使用代理A
            // client->instance->config.relayaddr.sin_addr.s_addr = inet_addr("1.2.3.4");
            log_error(LOG_NOTICE, "[*] www.baidu.com 域名 代理处理");
        }
        else if (strstr(entry->domain, "github.com"))
        {
            // 使用代理B
            // client->instance->config.relayaddr.sin_addr.s_addr = inet_addr("5.6.7.8");
            log_error(LOG_NOTICE, "[*] github.com 域名 代理处理");
        }
    }
    else
    {
        log_error(LOG_NOTICE, "[*]  %s 没有映射表", ip_str);
    }
}

// 检查系统是否支持splice
static bool is_splice_good()
{
    LOG_DEBUG_C("支持 splice模式 \n");
    struct utsname u;
    if (uname(&u) != 0)
    {
        return false;
    }

    unsigned long int v[4] = {0, 0, 0, 0};
    char *rel = u.release;
    for (int i = 0; i < SIZEOF_ARRAY(v); ++i)
    {
        v[i] = strtoul(rel, &rel, 0);
        while (*rel && !isdigit(*rel))
            ++rel;
    }

    // haproxy假设splice在2.6.27.13+版本上工作正常
    return (v[0] > 2) ||
           (v[0] == 2 && v[1] > 6) ||
           (v[0] == 2 && v[1] == 6 && v[2] > 27) ||
           (v[0] == 2 && v[1] == 6 && v[2] == 27 && v[3] >= 13);
}

// 进入配置节时的回调函数
static int redsocks_onenter(parser_section *section)
{
    // 计算实例负载长度
    int instance_payload_len = 0;
    relay_subsys **ss;
    FOREACH(ss, relay_subsystems)
    if (instance_payload_len < (*ss)->instance_payload_len)
        instance_payload_len = (*ss)->instance_payload_len;

    // 分配实例内存
    redsocks_instance *instance = calloc(1, sizeof(*instance) + instance_payload_len);
    if (!instance)
    {
        parser_error(section->context, "Not enough memory");
        return -1;
    }

    // 初始化实例
    INIT_LIST_HEAD(&instance->list);
    INIT_LIST_HEAD(&instance->clients);
    instance->config.bindaddr.sin_family = AF_INET;
    instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.relayaddr.sin_family = AF_INET;
    instance->config.relayaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.listenq = SOMAXCONN;           // 默认监听队列长度
    instance->config.use_splice = is_splice_good(); // 是否使用splice

    instance->config.disclose_src = DISCLOSE_NONE; // 默认不披露源地址
    instance->config.on_proxy_fail = ONFAIL_CLOSE; // 代理失败时关闭连接

    // 设置配置项地址
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
    {
        entry->addr = (strcmp(entry->key, "local_ip") == 0) ? (void *)&instance->config.bindaddr.sin_addr : (strcmp(entry->key, "local_port") == 0)  ? (void *)&instance->config.bindaddr.sin_port
                                                                                                        : (strcmp(entry->key, "ip") == 0)            ? (void *)&instance->config.relayaddr.sin_addr
                                                                                                        : (strcmp(entry->key, "port") == 0)          ? (void *)&instance->config.relayaddr.sin_port
                                                                                                        : (strcmp(entry->key, "type") == 0)          ? (void *)&instance->config.type
                                                                                                        : (strcmp(entry->key, "login") == 0)         ? (void *)&instance->config.login
                                                                                                        : (strcmp(entry->key, "password") == 0)      ? (void *)&instance->config.password
                                                                                                        : (strcmp(entry->key, "listenq") == 0)       ? (void *)&instance->config.listenq
                                                                                                        : (strcmp(entry->key, "splice") == 0)        ? (void *)&instance->config.use_splice
                                                                                                        : (strcmp(entry->key, "disclose_src") == 0)  ? (void *)&instance->config.disclose_src
                                                                                                        : (strcmp(entry->key, "on_proxy_fail") == 0) ? (void *)&instance->config.on_proxy_fail
                                                                                                                                                     : NULL;
    }
    section->data = instance;
    return 0;
}

// 退出配置节时的回调函数
static int redsocks_onexit(parser_section *section)
{
    redsocks_instance *instance = section->data;
    section->data = NULL;

    // 重置配置项地址
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    // 转换端口号为网络字节序
    instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
    instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);

    // 验证类型配置
    if (instance->config.type)
    {
        relay_subsys **ss;
        FOREACH(ss, relay_subsystems)
        {
            if (!strcmp((*ss)->name, instance->config.type))
            {
                instance->relay_ss = *ss;
                list_add(&instance->list, &instances);
                break;
            }
        }
        if (!instance->relay_ss)
        {
            parser_error(section->context, "invalid `type` <%s> for redsocks", instance->config.type);
            return -1;
        }
    }
    else
    {
        parser_error(section->context, "no `type` for redsocks");
        return -1;
    }

    // 验证disclose_src配置
    if (instance->config.disclose_src != DISCLOSE_NONE && instance->relay_ss != &http_connect_subsys)
    {
        parser_error(section->context, "only `http-connect` supports `disclose_src` at the moment");
        return -1;
    }

    // 验证on_proxy_fail配置
    if (instance->config.on_proxy_fail != ONFAIL_CLOSE && instance->relay_ss != &http_connect_subsys)
    {
        parser_error(section->context, "only `http-connect` supports `on_proxy_fail` at the moment");
        return -1;
    }

    return 0;
}

// 配置节定义
static parser_section redsocks_conf_section = {
    .name = "redsocks",
    .entries = redsocks_entries,
    .onenter = redsocks_onenter,
    .onexit = redsocks_onexit};

// 日志写入函数
void redsocks_log_write_plain(
    const char *file, int line, const char *func, int do_errno,
    const struct sockaddr_in *clientaddr, const struct sockaddr_in *destaddr,
    int priority, const char *orig_fmt, ...)
{
    if (!should_log(priority))
        return;

    int saved_errno = errno;
    struct evbuffer *fmt = evbuffer_new();
    va_list ap;
    char clientaddr_str[RED_INET_ADDRSTRLEN], destaddr_str[RED_INET_ADDRSTRLEN];

    if (!fmt)
    {
        log_errno(LOG_ERR, "evbuffer_new()");
        // no return, as I have to call va_start/va_end
    }

    if (fmt)
    {
        evbuffer_add_printf(fmt, "[%s->%s]: %s",
                            red_inet_ntop(clientaddr, clientaddr_str, sizeof(clientaddr_str)),
                            red_inet_ntop(destaddr, destaddr_str, sizeof(destaddr_str)),
                            orig_fmt);
    }

    va_start(ap, orig_fmt);
    if (fmt)
    {
        errno = saved_errno;
        _log_vwrite(file, line, func, do_errno, priority, (const char *)evbuffer_pullup(fmt, -1), ap);
        evbuffer_free(fmt);
    }
    va_end(ap);
}

// 更新客户端活动时间
void redsocks_touch_client(redsocks_client *client)
{
    redsocks_gettimeofday(&client->last_event);
}

// 检查是否双方都已关闭
static bool shut_both(redsocks_client *client)
{
    return client->relay_evshut == (EV_READ | EV_WRITE) && client->client_evshut == (EV_READ | EV_WRITE);
}

// 获取缓冲区优先级
static int bufprio(redsocks_client *client, struct bufferevent *buffev)
{
    // 客户端错误记录为LOG_INFO，服务器错误记录为LOG_NOTICE
    return (buffev == client->client) ? LOG_INFO : LOG_NOTICE;
}

// 获取缓冲区名称
static const char *bufname(redsocks_client *client, struct bufferevent *buf)
{
    assert(buf == client->client || buf == client->relay);
    return buf == client->client ? "client" : "relay";
}

// 中继读取回调
static void redsocks_relay_readcb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{

    log_error(LOG_NOTICE, "[*] redsocks_relay_readcb 中继读取回调");

    if (evbuffer_get_length(to->output) < to->wm_write.high)
    {
        if (bufferevent_write_buffer(to, from->input) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
    }
    else
    {
        if (bufferevent_get_enabled(from) & EV_READ)
        {
            redsocks_log_error(client, LOG_DEBUG, "backpressure: bufferevent_disable(%s, EV_READ)", bufname(client, from));
            if (bufferevent_disable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
        }
    }
}

// 中继写入回调
static void redsocks_relay_writecb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
    log_error(LOG_NOTICE, "[*] redsocks_relay_writecb 中继写入回调");

    assert(from == client->client || from == client->relay);
    char from_eof = (from == client->client ? client->client_evshut : client->relay_evshut) & EV_READ;

    if (evbuffer_get_length(from->input) == 0 && from_eof)
    {
        redsocks_shutdown(client, to, SHUT_WR);
    }
    else if (evbuffer_get_length(to->output) < to->wm_write.high)
    {
        if (bufferevent_write_buffer(to, from->input) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (!from_eof && !(bufferevent_get_enabled(from) & EV_READ))
        {
            redsocks_log_error(client, LOG_DEBUG, "backpressure: bufferevent_enable(%s, EV_READ)", bufname(client, from));
            if (bufferevent_enable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }
    }
}

// 中继读取回调包装
static void redsocks_relay_relayreadcb(struct bufferevent *from, void *_client)
{
    log_error(LOG_NOTICE, "[*] redsocks_relay_relayreadcb 中继读取回调包装");

    redsocks_client *client = _client;

    redsocks_touch_client(client);

    redsocks_relay_readcb(client, client->relay, client->client);
}

// 中继写入回调包装
static void redsocks_relay_relaywritecb(struct bufferevent *to, void *_client)
{
    // log_error(LOG_NOTICE, "[*] redsocks_relay_relaywritecb 中继写入回调包装");
    LOG_DEBUG_C("[*] relay 中继写入回调包装 \n");
    redsocks_client *client = _client;
    // 根据端口选择
    redsocks_touch_client(client);

    redsocks_relay_writecb(client, client->client, client->relay);
}

// 客户端读取回调
static void redsocks_relay_clientreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    redsocks_touch_client(client);
    LOG_DEBUG_C("[*] relay 客户端读取回调 \n");
    // 继续正常的数据转发
    redsocks_relay_readcb(client, client->client, client->relay);
}

// 客户端写入回调
static void redsocks_relay_clientwritecb(struct bufferevent *to, void *_client)
{
    LOG_DEBUG_C("[*] relay 客户端写入回调 \n");

    redsocks_client *client = _client;
    redsocks_touch_client(client);

    char destaddr_str[RED_INET_ADDRSTRLEN];
    char *destIP = red_inet_ntop(&(client)->destaddr, destaddr_str, sizeof(destaddr_str));
    // 检查目标端口并解析内容
    if (client->destaddr.sin_port == htons(443))
    {

        LOG_DEBUG_C("[*] HTTPS 443 请求：%s\n", destIP);

        // HTTPS流量：解析SNI
        struct evbuffer *input = bufferevent_get_input(to);
        size_t len = evbuffer_get_length(input);
        unsigned char *data = evbuffer_pullup(input, len);
        if (data)
        {
            parse_sni(data, len, client);
        }
        else
        {
            //  LOG_DEBUG_C("[*] HTTPS 数据为空\n");
        }
    }
    else if (client->destaddr.sin_port == htons(80))
    {

        LOG_DEBUG_C("[*] 80 请求：%s \n", destIP);
        // HTTP流量：解析Host头
        struct evbuffer *input = bufferevent_get_input(to);
        size_t len = evbuffer_get_length(input);
        unsigned char *data = evbuffer_pullup(input, len);
        if (data)
        {
            parse_host_header((const char *)data, len, client);
        }
        else
        {
            LOG_DEBUG_C("[*] HTTP 数据为空\n");
        }
    }

    redsocks_relay_writecb(client, client->relay, client->client);
}

// 启动客户端与代理服务器之间的数据中继
// 参数: client - 包含客户端和代理连接信息的结构体
void redsocks_start_relay(redsocks_client *client)
{
    // 打印调试日志，标记中继启动
    log_error(LOG_NOTICE, "[*] redsocks_start_relay  启动中继");

    // 如果relay子系统有清理函数，先执行清理
    if (client->instance->relay_ss->fini)
        client->instance->relay_ss->fini(client);

    // 设置客户端状态为活跃泵(pump_active)
    client->state = pump_active;
    // use_splice = false;
    //  根据配置选择使用splice零拷贝或普通缓冲区模式启动数据泵
    //  条件运算符?:判断使用哪种模式
    int error = ((client->instance->config.use_splice) ? redsocks_start_splicepump : // 使用splice模式
                     redsocks_start_bufferpump)(client);                             // 使用缓冲区模式

    // 检查启动是否成功
    if (!error)
        // 成功日志，中继通道建立
        log_error(LOG_NOTICE, "[*] 中继通道已建立");
    else
        // 失败则丢弃客户端连接
        redsocks_drop_client(client);
}

// 启动缓冲区泵
static int redsocks_start_bufferpump(redsocks_client *client)
{
    log_error(LOG_NOTICE, "[*] redsocks_start_bufferpump  启动缓冲区泵");
    // 设置水位标记
    bufferevent_setwatermark(client->client, EV_READ | EV_WRITE, 0, REDSOCKS_RELAY_HALFBUFF);
    bufferevent_setwatermark(client->relay, EV_READ | EV_WRITE, 0, REDSOCKS_RELAY_HALFBUFF);
    log_error(LOG_NOTICE, "into redsocks_start_bufferpump");

    // 设置回调函数
    client->client->readcb = redsocks_relay_clientreadcb;
    client->client->writecb = redsocks_relay_clientwritecb;
    client->relay->readcb = redsocks_relay_relayreadcb;
    client->relay->writecb = redsocks_relay_relaywritecb;

    // 启用缓冲区事件
    int error = bufferevent_enable(client->client, (EV_READ | EV_WRITE) & ~(client->client_evshut));
    if (!error)
        error = bufferevent_enable(client->relay, (EV_READ | EV_WRITE) & ~(client->relay_evshut));
    if (error)
        redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    return error;
}

// 获取管道优先级
static int pipeprio(redsocks_pump *pump, int fd)
{
    return (fd == event_get_fd(&pump->client_read)) ? LOG_INFO : LOG_NOTICE;
}

// 获取管道名称
static const char *pipename(redsocks_pump *pump, int fd)
{
    return (fd == event_get_fd(&pump->client_read)) ? "client" : "relay";
}

// 释放未使用的缓冲区事件
static void bufferevent_free_unused(struct bufferevent **p)
{
    if (*p && !evbuffer_get_length((*p)->input) && !evbuffer_get_length((*p)->output))
    {
        bufferevent_free(*p);
        *p = NULL;
    }
}

// 检查是否为阻塞错误
static bool would_block(int e)
{
    return e == EAGAIN || e == EWOULDBLOCK;
}

// 定义splice写入上下文结构
typedef struct redsplice_write_ctx_t
{
    // 按顺序清空ebsrc[0], ebsrc[1], pisrc
    struct evbuffer *ebsrc[2];
    splice_pipe *pisrc;
    struct event *evsrc;
    struct event *evdst;
    const evshut_t *shut_src;
    evshut_t *shut_dst;
} redsplice_write_ctx;

// splice写入回调
static void redsplice_write_cb(redsocks_pump *pump, redsplice_write_ctx *c, int out)
{
    LOG_DEBUG_C("splice写入回调 \n");
    bool has_data = false; // 有待写入的数据
    bool can_write = true; // 套接字似乎可写

    // 遍历所有数据源
    for (int i = 0; i < SIZEOF_ARRAY(c->ebsrc); ++i)
    {
        struct evbuffer *ebsrc = c->ebsrc[i];
        if (ebsrc)
        {
            const size_t avail = evbuffer_get_length(ebsrc);
            has_data = !!avail;
            if (avail)
            {
                const ssize_t sent = evbuffer_write(ebsrc, out);
                if (sent == -1)
                {
                    if (would_block(errno))
                    { // 短(零)写入
                        can_write = false;
                        goto decide;
                    }
                    else
                    {
                        redsocks_log_errno(&pump->c, pipeprio(pump, out), "evbuffer_write(to %s, %zu)", pipename(pump, out), avail);
                        redsocks_drop_client(&pump->c);
                        return;
                    }
                }
                else if (avail == sent)
                {
                    has_data = false; // 除非另有说明
                }
                else
                { // 短写入
                    can_write = false;
                    goto decide;
                }
            }
        }
    }

    // 处理管道数据
    do
    {
        has_data = !!c->pisrc->size;
        const size_t avail = c->pisrc->size;
        if (avail)
        {
            //
            const ssize_t sent = splice(c->pisrc->read, NULL, out, NULL, avail, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (sent == -1)
            {
                if (would_block(errno))
                { // 短(零)写入
                    can_write = false;
                    goto decide;
                }
                else
                {
                    redsocks_log_errno(&pump->c, pipeprio(pump, out), "splice(to %s)", pipename(pump, out));
                    redsocks_drop_client(&pump->c);
                    return;
                }
            }
            else
            {
                c->pisrc->size -= sent;
                if (avail == sent)
                {
                    has_data = false;
                }
                else
                { // 短写入
                    can_write = false;
                    goto decide;
                }
            }
        }
    } while (0);

decide:
    // 处理EOF情况
    if (!has_data && (*c->shut_src & EV_READ) && !(*c->shut_dst & EV_WRITE))
    {
        if (shutdown(out, SHUT_WR) != 0)
        {
            redsocks_log_errno(&pump->c, LOG_ERR, "shutdown(%s, SHUT_WR)", pipename(pump, out));
        }
        *c->shut_dst |= EV_WRITE;
        can_write = false;
        assert(!c->pisrc->size);
        redsocks_close(c->pisrc->read);
        c->pisrc->read = -1;
        redsocks_close(c->pisrc->write);
        c->pisrc->write = -1;
        if (shut_both(&pump->c))
        {
            redsocks_drop_client(&pump->c);
            return;
        }
    }

    assert(!(can_write && has_data)); // 不完整的写入到可写套接字

    // 根据情况添加/删除事件
    if (!can_write && has_data)
    {
        if (event_pending(c->evsrc, EV_READ, NULL))
            redsocks_log_error(&pump->c, LOG_DEBUG, "backpressure: event_del(%s_read)", pipename(pump, event_get_fd(c->evsrc)));
        redsocks_event_del(&pump->c, c->evsrc);
        redsocks_event_add(&pump->c, c->evdst);
    }
    else if (can_write && !has_data)
    {
        if (!event_pending(c->evsrc, EV_READ, NULL))
            redsocks_log_error(&pump->c, LOG_DEBUG, "backpressure: event_add(%s_read)", pipename(pump, event_get_fd(c->evsrc)));
        redsocks_event_add(&pump->c, c->evsrc);
        redsocks_event_del(&pump->c, c->evdst);
    }
    else if (!can_write && !has_data)
    { // 类似EOF的情况
        redsocks_event_del(&pump->c, c->evsrc);
        redsocks_event_del(&pump->c, c->evdst);
    }
}

// 定义splice读取上下文结构
typedef struct redsplice_read_ctx_t
{
    splice_pipe *dst;
    struct event *evsrc;
    struct event *evdst;
    evshut_t *shut_src;
} redsplice_read_ctx;
// 打印前 16 个字节（但不消耗数据）
void peek_first_16_bytes(int in)
{
    int pipefd[2];
    if (pipe(pipefd) < 0)
    {
        perror("pipe failed");
        return;
    }

    // 使用 tee 复制数据到临时管道（不消耗 in 的数据）
    ssize_t got = tee(in, pipefd[1], 16, SPLICE_F_NONBLOCK);
    if (got <= 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        if (got == 0)
            printf("No data available (EOF)\n");
        else
            perror("tee failed");
        return;
    }

    // 读取临时管道的前 16 字节并打印
    char buf[16];
    ssize_t bytes_read = read(pipefd[0], buf, sizeof(buf));
    close(pipefd[0]);
    close(pipefd[1]);

    if (bytes_read > 0)
    {
        printf("First %zd bytes: ", bytes_read);
        for (ssize_t i = 0; i < bytes_read; i++)
        {
            printf("%02x ", (unsigned char)buf[i]); // 16进制打印
        }
        printf("\n");
    }
}

// splice读取回调
static void redsplice_read_cb(redsocks_pump *pump, redsplice_read_ctx *c, int in)
{
    /* 1. 调试日志 */
    LOG_DEBUG_C("[*] 客户端读取回调（发送splice） \n");

    /* 2. 设置管道传输参数 */
    const size_t pipesize = 1048576; // 默认管道容量（1MB，来自系统配置fs.pipe-max-size）

    redsocks_client client = pump->c;
    char destaddr_str[RED_INET_ADDRSTRLEN];
    char *destIP = red_inet_ntop(&client.destaddr, destaddr_str, sizeof(destaddr_str));
    // 检查目标端口并解析内容
    if (client.destaddr.sin_port == htons(443))
    {
        char buf[255];
        ssize_t bytes_read = recv(in, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
        printf("[*] HTTPS 443 请求：%s\n", destIP);

        // HTTPS流量：解析SNI
        
        if (bytes_read)
        {
            parse_sni(buf, bytes_read, &client);
        }
        else
        {
            //  LOG_DEBUG_C("[*] HTTPS 数据为空\n");
        }
    }
    else if (client.destaddr.sin_port == htons(80))
    {

        printf("[*] 80 请求：%s \n", destIP);
        // HTTP流量：解析Host头
        // struct evbuffer *input = bufferevent_get_input(to);
        // size_t len = evbuffer_get_length(input);
        // unsigned char *data = evbuffer_pullup(input, len);
        // if (data)
        // {
        //     parse_host_header((const char *)data, len, client);
        // }
        // else
        // {
        //     LOG_DEBUG_C("[*] HTTP 数据为空\n");
        // }
    }

    /* 3. 执行零拷贝数据转移 */
    const ssize_t got = splice(
        in, NULL,             // 输入：源文件描述符（客户端或代理Socket）
        c->dst->write, NULL,  // 输出：目标管道写端
        pipesize,             // 最大传输量
        SPLICE_F_MOVE |       // 允许内核移动内存页
            SPLICE_F_NONBLOCK // 非阻塞模式
    );
    /* 4. 错误处理 */
    if (got == -1)
    {
        if (would_block(errno))
        {
            // 情况4.1：管道已满（背压控制）
            if (!event_pending(c->evsrc, EV_READ, NULL))
                redsocks_log_error(&pump->c, LOG_DEBUG, "backpressure: event_del(%s_read)",
                                   pipename(pump, event_get_fd(c->evsrc)));
            redsocks_event_del(&pump->c, c->evsrc); // 暂停读取事件
        }
        else
        {
            // 情况4.2：严重错误（如连接断开）
            redsocks_log_errno(&pump->c, pipeprio(pump, in), "splice(from %s)",
                               pipename(pump, in));
            redsocks_drop_client(&pump->c); // 终止连接
        }
        return;
    }

    /* 5. EOF处理 */
    if (got == 0)
    {
        if (shutdown(in, SHUT_RD) != 0 && errno != ENOTCONN)
        {
            redsocks_log_errno(&pump->c, LOG_DEBUG, "shutdown(%s, SHUT_RD) after EOF",
                               pipename(pump, in));
        }
        *c->shut_src |= EV_READ;                // 标记连接半关闭
        redsocks_event_del(&pump->c, c->evsrc); // 移除读取监听
    }
    /* 6. 正常数据传输 */
    else
    {
        c->dst->size += got;                 // 更新管道数据量统计
        event_active(c->evdst, EV_WRITE, 0); // 触发写入事件
    }
}

// 更新泵的活动时间
static void redsocks_touch_pump(redsocks_pump *pump)
{
    redsocks_touch_client(&pump->c);
    bufferevent_free_unused(&pump->c.client);
    bufferevent_free_unused(&pump->c.relay);
}

// 中继读取回调
static void redsplice_relay_read(int fd, short what, void *_pump)
{
    LOG_DEBUG_C("[*] 中继读取回调 \n");
    redsocks_pump *pump = _pump;
    assert(fd == event_get_fd(&pump->relay_read) && (what & EV_READ));
    redsocks_touch_pump(pump);
    redsplice_read_ctx c = {
        .dst = &pump->reply,
        .evsrc = &pump->relay_read,
        .evdst = &pump->client_write,
        .shut_src = &pump->c.relay_evshut,
    };
    redsplice_read_cb(pump, &c, fd);
}

// 客户端Socket数据到达时的回调函数，负责将客户端数据通过内核管道零拷贝转发到代理服务器方向
static void redsplice_client_read(int fd, short what, void *_pump)
{
    /* 1. 调试日志输出 */
    LOG_DEBUG_C(" [*] 客户端读取回调 \n");

    /* 2. 获取泵上下文 */
    redsocks_pump *pump = _pump;

    /* 3. 断言校验（防御性编程） */
    assert(fd == event_get_fd(&pump->client_read) && (what & EV_READ));

    /* 4. 更新活动时间戳 */
    redsocks_touch_pump(pump);

    /* 5. 构造读取上下文结构体 */
    redsplice_read_ctx c = {
        .dst = &pump->request,              // 目标管道：request（客户端→代理方向）
        .evsrc = &pump->client_read,        // 事件源：客户端读取事件
        .evdst = &pump->relay_write,        // 事件目标：代理写入事件（用于反压控制）
        .shut_src = &pump->c.client_evshut, // 客户端关闭状态标记
    };

    /* 6. 调用核心读取处理函数 */
    redsplice_read_cb(pump, &c, fd);
}

// 中继写入回调
static void redsplice_relay_write(int fd, short what, void *_pump)
{
    LOG_DEBUG_C(" 中继写入回调 \n");
    redsocks_pump *pump = _pump;
    assert(fd == event_get_fd(&pump->relay_write) && (what & EV_WRITE));
    redsocks_touch_pump(pump);
    redsplice_write_ctx c = {
        .ebsrc = {
            pump->c.relay ? pump->c.relay->output : NULL,
            pump->c.client ? pump->c.client->input : NULL,
        },
        .pisrc = &pump->request,
        .evsrc = &pump->client_read,
        .evdst = &pump->relay_write,
        .shut_src = &pump->c.client_evshut,
        .shut_dst = &pump->c.relay_evshut,
    };
    redsplice_write_cb(pump, &c, fd);
}

// 客户端写入回调
static void redsplice_client_write(int fd, short what, void *_pump)
{
    LOG_DEBUG_C("[*]  客户端写入回调\n");
    redsocks_pump *pump = _pump;
    assert(fd == event_get_fd(&pump->client_write) && (what & EV_WRITE));
    redsocks_touch_pump(pump);
    redsplice_write_ctx c = {
        .ebsrc = {
            pump->c.client ? pump->c.client->output : NULL,
            pump->c.relay ? pump->c.relay->input : NULL,
        },
        .pisrc = &pump->reply,
        .evsrc = &pump->relay_read,
        .evdst = &pump->client_write,
        .shut_src = &pump->c.relay_evshut,
        .shut_dst = &pump->c.client_evshut,
    };
    redsplice_write_cb(pump, &c, fd);
}

/**
 * 启动splice零拷贝数据泵
 * @param client 客户端连接上下文
 * @return 成功返回0，失败返回-1并记录错误日志
 */
static int redsocks_start_splicepump(redsocks_client *client)
{
    /* === 阶段1：禁用传统缓冲模式 === */
    // 禁用客户端Socket的读写事件（停止bufferevent的数据处理）
    int error = bufferevent_disable(client->client, EV_READ | EV_WRITE);
    if (!error)
        error = bufferevent_disable(client->relay, EV_READ | EV_WRITE); // 禁用代理端Socket
    if (error)
    {
        redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
        return error;
    }

    /* === 阶段2：准备内核资源 === */
    // 解冻缓冲区以获取底层Socket控制权
    // 参数说明：
    // 0 = 解冻输入方向（读取），1 = 解冻输出方向（写入）
    evbuffer_unfreeze(client->client->input, 0);  // 客户端接收缓冲区
    evbuffer_unfreeze(client->client->output, 1); // 客户端发送缓冲区
    evbuffer_unfreeze(client->relay->input, 0);   // 代理接收缓冲区
    evbuffer_unfreeze(client->relay->output, 1);  // 代理发送缓冲区

    /* === 阶段3：初始化splice泵 === */
    // 获取splice泵上下文（包含两个管道和事件处理器）
    redsocks_pump *pump = red_pump(client);

    // 创建非阻塞管道（request方向：client → relay）
    if (!error)
        error = pipe2(&pump->request.read, O_NONBLOCK);
    // 创建非阻塞管道（reply方向：relay → client）
    if (!error)
        error = pipe2(&pump->reply.read, O_NONBLOCK);
    if (error)
    {
        redsocks_log_errno(client, LOG_ERR, "pipe2");
        goto fail;
    }

    /* === 阶段4：设置事件处理器 === */
    struct event_base *base = NULL;                          // 使用默认事件基
    const int relay_fd = bufferevent_getfd(client->relay);   // 获取代理Socket真实fd
    const int client_fd = bufferevent_getfd(client->client); // 获取客户端Socket真实fd

    // 注册四个核心事件：
    // 1. 客户端数据可读事件
    if (!error)
        error = event_assign(&pump->client_read, base, client_fd,
                             EV_READ | EV_PERSIST, redsplice_client_read, pump);
    // 2. 客户端可写事件（用于反压控制）
    if (!error)
        error = event_assign(&pump->client_write, base, client_fd,
                             EV_WRITE | EV_PERSIST, redsplice_client_write, pump);
    // 3. 代理端数据可读事件
    if (!error)
        error = event_assign(&pump->relay_read, base, relay_fd,
                             EV_READ | EV_PERSIST, redsplice_relay_read, pump);
    // 4. 代理端可写事件（用于反压控制）
    if (!error)
        error = event_assign(&pump->relay_write, base, relay_fd,
                             EV_WRITE | EV_PERSIST, redsplice_relay_write, pump);
    if (error)
    {
        redsocks_log_errno(client, LOG_ERR, "event_assign");
        goto fail;
    }

    /* === 阶段5：移交控制权 === */
    // 从bufferevent中分离Socket描述符（避免双重控制）
    redsocks_bufferevent_dropfd(client, client->relay);
    redsocks_bufferevent_dropfd(client, client->client);

    /* === 阶段6：启动数据泵 === */
    // 立即触发写事件（处理可能的残留数据）
    event_active(&pump->client_write, EV_WRITE, 0);
    event_active(&pump->relay_write, EV_WRITE, 0);

    // 注册读事件监听（开始接收新数据）
    redsocks_event_add(&pump->c, &pump->client_read);
    redsocks_event_add(&pump->c, &pump->relay_read);

    return 0; // 成功

fail:
    // 错误处理：关闭已创建的管道
    if (pump->request.read != -1)
        close(pump->request.read);
    if (pump->reply.read != -1)
        close(pump->reply.read);
    return -1;
}

// 检查目标地址是否为回环地址
static bool has_loopback_destination(redsocks_client *client)
{
    const uint32_t net = ntohl(client->destaddr.sin_addr.s_addr) >> 24;
    return 0 == memcmp(&client->destaddr.sin_addr, &client->instance->config.relayaddr.sin_addr, sizeof(client->destaddr.sin_addr)) || net == 127 || net == 0;
}

// 关闭并释放客户端连接
void redsocks_drop_client(redsocks_client *client)
{
    log_error(LOG_NOTICE, "[*] redsocks_drop_client 关闭客户端连接");
    if (shut_both(client))
    {
        redsocks_log_error(client, LOG_INFO, "connection closed");
    }
    else
    {
        if (has_loopback_destination(client))
        {
            static time_t last = 0;
            const time_t now = redsocks_time(NULL);
            if (now - last >= 3600)
            {
                // 每小时记录一次此警告以节省调试时间，但在某些情况下可能是有效流量
                redsocks_log_error(client, LOG_NOTICE, "client tries to connect to the proxy using proxy! Usual proxy security policy is to drop alike connection");
                last = now;
            }
        }

        struct timeval now, idle;
        redsocks_gettimeofday(&now); // FIXME: 使用CLOCK_MONOTONIC
        timersub(&now, &client->last_event, &idle);
        redsocks_log_error(client, LOG_INFO, "dropping client (%s), relay (%s), idle %ld.%06lds",
                           redsocks_event_str((~client->client_evshut) & (EV_READ | EV_WRITE)),
                           redsocks_event_str((~client->relay_evshut) & (EV_READ | EV_WRITE)),
                           idle.tv_sec, idle.tv_usec);
    }

    if (client->instance->relay_ss->fini)
        client->instance->relay_ss->fini(client);

    if (client->client)
        redsocks_bufferevent_free(client->client);

    if (client->relay)
        redsocks_bufferevent_free(client->relay);

    if (client->instance->config.use_splice)
    {
        redsocks_pump *pump = red_pump(client);

        if (pump->request.read != -1)
            redsocks_close(pump->request.read);
        if (pump->request.write != -1)
            redsocks_close(pump->request.write);
        if (pump->reply.read != -1)
            redsocks_close(pump->reply.read);
        if (pump->reply.write != -1)
            redsocks_close(pump->reply.write);

        // redsocks_close 可能会记录错误，如果某些事件未正确初始化
        int fd = -1;
        if (event_initialized(&pump->client_read))
        {
            fd = event_get_fd(&pump->client_read);
            redsocks_event_del(&pump->c, &pump->client_read);
        }
        if (event_initialized(&pump->client_write))
        {
            redsocks_event_del(&pump->c, &pump->client_write);
        }
        if (fd != -1)
            redsocks_close(fd);

        fd = -1;
        if (event_initialized(&pump->relay_read))
        {
            fd = event_get_fd(&pump->relay_read);
            redsocks_event_del(&pump->c, &pump->relay_read);
        }
        if (event_initialized(&pump->relay_write))
        {
            redsocks_event_del(&pump->c, &pump->relay_write);
        }
        if (fd != -1)
        {
            redsocks_close(fd);
        }
    }
    redsocks_conn_list_del(client);
    free(client);
}

// 关闭连接的一端或两端
void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how)
{
    log_error(LOG_NOTICE, "[*] redsocks_shutdown  关闭连接的一端或两端");

    short evhow = 0;
    const char *strev, *strhow = NULL, *strevhow = NULL;
    unsigned short *pevshut;

    assert(how == SHUT_RD || how == SHUT_WR || how == SHUT_RDWR);
    assert(buffev == client->client || buffev == client->relay);
    assert(event_get_fd(&buffev->ev_read) == event_get_fd(&buffev->ev_write));

    if (how == SHUT_RD)
    {
        strhow = "SHUT_RD";
        evhow = EV_READ;
        strevhow = "EV_READ";
    }
    else if (how == SHUT_WR)
    {
        strhow = "SHUT_WR";
        evhow = EV_WRITE;
        strevhow = "EV_WRITE";
    }
    else if (how == SHUT_RDWR)
    {
        strhow = "SHUT_RDWR";
        evhow = EV_READ | EV_WRITE;
        strevhow = "EV_READ|EV_WRITE";
    }

    assert(strhow && strevhow);

    strev = bufname(client, buffev);
    pevshut = buffev == client->client ? &client->client_evshut : &client->relay_evshut;

    // 如果EV_WRITE已经关闭，并且我们要关闭读取端，那么我们要么中止数据流(不良行为)，要么确认EOF
    // 在这种情况下，套接字已经SHUT_RD
    if (!(how == SHUT_RD && (*pevshut & EV_WRITE)))
    {
        if (shutdown(event_get_fd(&buffev->ev_read), how) != 0)
            redsocks_log_errno(client, LOG_ERR, "shutdown(%s, %s)", strev, strhow);
    }
    else
    {
        redsocks_log_error(client, LOG_DEBUG, "ignored shutdown(%s, %s)", strev, strhow);
    }

    redsocks_log_error(client, LOG_DEBUG, "shutdown: bufferevent_disable(%s, %s)", strev, strevhow);
    if (bufferevent_disable(buffev, evhow) != 0)
        redsocks_log_errno(client, LOG_ERR, "bufferevent_disable(%s, %s)", strev, strevhow);

    *pevshut |= evhow;

    if (shut_both(client))
    {
        redsocks_log_error(client, LOG_DEBUG, "both client and server disconnected");
        redsocks_drop_client(client);
    }
}

// 获取套接字错误号
static int redsocks_socket_geterrno(redsocks_client *client, struct bufferevent *buffev)
{
    int pseudo_errno = red_socket_geterrno(buffev);
    if (pseudo_errno == -1)
    {
        redsocks_log_errno(client, LOG_ERR, "red_socket_geterrno");
        return -1;
    }
    return pseudo_errno;
}

// 错误事件回调
static void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg)
{
    log_error(LOG_NOTICE, "[*] redsocks_event_error 错误事件回调");
    redsocks_client *client = _arg;
    assert(buffev == client->relay || buffev == client->client);
    const int bakerrno = errno;

    redsocks_touch_client(client);

    if (what == (EVBUFFER_READ | EVBUFFER_EOF))
    {
        struct bufferevent *antiev;
        if (buffev == client->relay)
            antiev = client->client;
        else
            antiev = client->relay;

        redsocks_shutdown(client, buffev, SHUT_RD);

        // 如果客户端已经发送EOF且泵未激活(中继正在激活)，代码不应关闭写管道
        if (client->state == pump_active && antiev != NULL && evbuffer_get_length(antiev->output) == 0)
            redsocks_shutdown(client, antiev, SHUT_WR);
    }
    else
    {
        const int sockrrno = redsocks_socket_geterrno(client, buffev);
        const char *errsrc = "";
        if (sockrrno != -1 && sockrrno != 0)
        {
            errno = sockrrno;
            errsrc = "socket ";
        }
        else
        {
            errno = bakerrno;
        }
        redsocks_log_errno(client, bufprio(client, buffev), "%s %serror, code " event_fmt_str,
                           bufname(client, buffev),
                           errsrc,
                           event_fmt(what));
        redsocks_drop_client(client);
    }
}

// 大小比较函数
int sizes_equal(size_t a, size_t b)
{
    return a == b;
}

int sizes_greater_equal(size_t a, size_t b)
{
    return a >= b;
}

// 读取预期数量的数据
int redsocks_read_expected(redsocks_client *client, struct evbuffer *input, void *data, size_comparator comparator, size_t expected)
{
    size_t len = evbuffer_get_length(input);
    if (comparator(len, expected))
    {
        int read = evbuffer_remove(input, data, expected);
        UNUSED(read);
        assert(read == expected);
        return 0;
    }
    else
    {
        redsocks_log_error(client, LOG_NOTICE, "Can't get expected amount of data");
        redsocks_drop_client(client);
        return -1;
    }
}

// 创建evbuffer
struct evbuffer *mkevbuffer(void *data, size_t len)
{
    struct evbuffer *buff = NULL, *retval = NULL;

    buff = evbuffer_new();
    if (!buff)
    {
        log_errno(LOG_ERR, "evbuffer_new");
        goto fail;
    }

    if (evbuffer_add(buff, data, len) < 0)
    {
        log_errno(LOG_ERR, "evbuffer_add");
        goto fail;
    }

    retval = buff;
    buff = NULL;

fail:
    if (buff)
        evbuffer_free(buff);
    return retval;
}

// 写入辅助函数(带额外参数)
int redsocks_write_helper_ex(
    struct bufferevent *buffev, redsocks_client *client,
    redsocks_message_maker mkmessage, int state, size_t wm_low, size_t wm_high)
{
    assert(client);
    return redsocks_write_helper_ex_plain(buffev, client, (redsocks_message_maker_plain)mkmessage,
                                          client, state, wm_low, wm_high);
}

// 写入辅助函数(普通版本)
int redsocks_write_helper_ex_plain(
    struct bufferevent *buffev, redsocks_client *client,
    redsocks_message_maker_plain mkmessage, void *p, int state, size_t wm_low, size_t wm_high)
{
    int len;
    struct evbuffer *buff = NULL;
    int drop = 1;

    if (mkmessage)
    {
        buff = mkmessage(p);
        if (!buff)
            goto fail;

        assert(!client || buffev == client->relay);
        len = bufferevent_write_buffer(buffev, buff);
        if (len < 0)
        {
            if (client)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
            else
                log_errno(LOG_ERR, "bufferevent_write_buffer");
            goto fail;
        }
    }

    if (client)
        client->state = state;
    bufferevent_setwatermark(buffev, EV_READ, wm_low, wm_high);
    bufferevent_enable(buffev, EV_READ);
    drop = 0;

fail:
    if (buff)
        evbuffer_free(buff);
    if (drop && client)
        redsocks_drop_client(client);
    return drop ? -1 : 0;
}

// 写入辅助函数(简化版本)
int redsocks_write_helper(
    struct bufferevent *buffev, redsocks_client *client,
    redsocks_message_maker mkmessage, int state, size_t wm_only)
{
    assert(client);
    return redsocks_write_helper_ex(buffev, client, mkmessage, state, wm_only, wm_only);
}

// 中继连接建立回调 (太早了 没有数据)
static void redsocks_relay_connected(struct bufferevent *buffev, void *_arg)
{
    // log_error(LOG_NOTICE, "[*] redsocks_relay_connected 中继连接建立回调");
    redsocks_client *client = _arg;

    assert(buffev == client->relay);

    redsocks_touch_client(client);

    char destaddr_str[RED_INET_ADDRSTRLEN];
    char *destIP = red_inet_ntop(&(client)->destaddr, destaddr_str, sizeof(destaddr_str));
    // 检查目标端口并解析内容
    if (client->destaddr.sin_port == htons(443))
    {
        LOG_DEBUG_C("[*] HTTPS 请求：%s \n", destIP);
    }
    else if (client->destaddr.sin_port == htons(80))
    {
        LOG_DEBUG_C("[*] HTTP  请求：%s \n", destIP);
    }

    // 在连接建立后根据域名选择代理
    // route_by_domain(client);

    if (!red_is_socket_connected_ok(buffev))
    {
        redsocks_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
        goto fail;
    }

    client->relay->readcb = client->instance->relay_ss->readcb;
    client->relay->writecb = client->instance->relay_ss->writecb;
    client->relay->writecb(buffev, _arg);
    return;

fail:
    redsocks_drop_client(client);
}

// 连接代理服务器
void redsocks_connect_relay(redsocks_client *client)
{
    log_error(LOG_NOTICE, "[*] redsocks_connect_relay 连接代理服务器");

    // 获取目标地址和当前代理地址
    char destaddr_str[RED_INET_ADDRSTRLEN];
    char destrelay_addr[RED_INET_ADDRSTRLEN];
    char *destIP = red_inet_ntop(&(client)->destaddr, destaddr_str, sizeof(destaddr_str));
    char *dest_rlay_IP = red_inet_ntop(&client->instance->config.relayaddr, destrelay_addr, sizeof(destrelay_addr));

    printf("[*] 客户端请求IP：%s\n", destIP);
    printf("[*] 当前代理服务器IP: %s\n", dest_rlay_IP);

    // 1. 检查IP/域名映射表
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client->destaddr.sin_addr, ip_str, sizeof(ip_str));
    ip_domain_map *entry = NULL;
    HASH_FIND_STR(domain_table, ip_str, entry);

    // route_by_domain(client);
    // ip_domain_map *entry;
    // HASH_FIND_STR(domain_table, ip_str, entry);

    // 2. 保存原始代理配置（用于回退）
    struct sockaddr_in original_relay = client->instance->config.relayaddr;

    // 3. 根据域名选择代理
    if (entry)
    {
        printf("[*] 找到域名映射: %s -> %s\n", entry->domain, entry->ip);

        if (strstr(entry->domain, "baidu.com") ||
            strstr(entry->domain, "qq.com") ||
            strstr(entry->domain, "taobao.com"))
        {
            // 国内代理服务器地址：
            char *proxy_ip = "192.168.3.142";
            uint16_t proxy_port = 8000;
            // client->instance->config.relayaddr.sin_port = htons(proxy_port);              // 设置端口（需转换为网络字节序）

            // 国内网站使用国内代理
            // inet_pton(AF_INET,proxy_ip, &client->instance->config.relayaddr.sin_addr);
            printf("[*] %s -> %s 使用国内代理 %s:%d\n", entry->domain, entry->ip, proxy_ip, proxy_port);
        }
        else
        {
            // 其他网站使用国外代理
            // char *proxy_ip="1.2.3.4";
            // inet_pton(AF_INET, proxy_ip, &client->instance->config.relayaddr.sin_addr);
            printf("[*] %s -> %s 使用国外代理\n", entry->domain, entry->ip);
        }
    }
    else
    {
        printf("[*] 没有找到域名映射 使用默认代理 %s\n", dest_rlay_IP);
    }

    // 5. 连接代理服务器
    client->relay = red_connect_relay(&client->instance->config.relayaddr,
                                      redsocks_relay_connected,
                                      redsocks_event_error,
                                      client);

    // 6. 如果连接失败，尝试回退到原始代理
    if (!client->relay)
    {
        printf("[*] 代理连接失败，尝试回退到默认代理");

        // 恢复原始代理配置
        client->instance->config.relayaddr = original_relay;

        client->relay = red_connect_relay(&client->instance->config.relayaddr,
                                          redsocks_relay_connected,
                                          redsocks_event_error,
                                          client);
        if (!client->relay)
        {
            printf("[*] 回退代理连接也失败");
            redsocks_drop_client(client);
        }
    }
}

// 丢弃空闲连接
static struct timeval drop_idle_connections()
{
    assert(connpres_idle_timeout() > 0);
    struct timeval now, zero, max_idle, best_next;
    gettimeofday(&now, NULL); // FIXME: 使用CLOCK_MONOTONIC
    timerclear(&zero);
    timerclear(&max_idle);
    max_idle.tv_sec = connpres_idle_timeout();
    best_next = max_idle;

    redsocks_instance *instance;
    list_for_each_entry(instance, &instances, list)
    {
        redsocks_client *tmp, *client;
        list_for_each_entry_safe(client, tmp, &instance->clients, list)
        {
            struct timeval idle;
            timersub(&now, &client->last_event, &idle);
            if (timercmp(&idle, &zero, <=) || timercmp(&max_idle, &idle, <=))
            {
                redsocks_drop_client(client);
                best_next = zero;
            }
            else
            {
                struct timeval delay;
                timersub(&max_idle, &idle, &delay);
                if (timercmp(&delay, &best_next, <))
                {
                    best_next = delay;
                }
            }
        }
    }
    return best_next;
}

// 检查连接压力是否持续
static bool conn_pressure_ongoing()
{
    if (redsocks_conn >= redsocks_conn_max())
        return true;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return true;
    close(fd);
    return false;
}

// 处理连接压力
static void conn_pressure()
{
    struct timeval next;
    timerclear(&next);

    if (connpres_idle_timeout())
    {
        next = drop_idle_connections();
        if (!timerisset(&next))
        {
            log_error(LOG_WARNING, "dropped connections idle for %d+ seconds", connpres_idle_timeout());
            return; // 压力已解决
        }
    }

    accept_backoff_ms = (accept_backoff_ms << 1) + 1;
    clamp_value(accept_backoff_ms, 1, max_accept_backoff_ms());
    uint32_t delay = (red_randui32() % accept_backoff_ms) + 1;
    struct timeval tvdelay = {delay / 1000, (delay % 1000) * 1000};

    if (timerisset(&next) && timercmp(&next, &tvdelay, <))
    {
        tvdelay = next;
    }

    log_error(LOG_WARNING, "accept: backing off for %ld.%06lds", tvdelay.tv_sec, tvdelay.tv_usec);

    if (event_add(&accept_backoff_ev, &tvdelay) != 0)
        log_errno(LOG_ERR, "event_add");

    redsocks_instance *self = NULL;
    list_for_each_entry(self, &instances, list)
    {
        if (event_del(&self->listener) != 0)
            log_errno(LOG_ERR, "event_del");
    }
}

// 如果没有空闲连接，则返回最近一个连接的延迟
static void accept_enable()
{
    redsocks_instance *self = NULL;
    list_for_each_entry(self, &instances, list)
    {
        if (event_add(&self->listener, NULL) != 0)
            log_errno(LOG_ERR, "event_add");
    }
}

// 连接压力降低
static void conn_pressure_lowered()
{
    if (redsocks_conn >= redsocks_conn_max())
        return; // 降低...但不多!

    if (event_pending(&accept_backoff_ev, EV_TIMEOUT, NULL))
    {
        if (event_del(&accept_backoff_ev) != 0)
            log_errno(LOG_ERR, "event_del");
        accept_enable();
    }
}

// 接受连接退避回调
static void redsocks_accept_backoff(int fd, short what, void *_null)
{
    if (conn_pressure_ongoing())
    {
        conn_pressure(); // 重新设置超时
    }
    else
    {
        accept_enable(); // `accept_backoff_ev`现在没有挂起
    }
}

// 内部关闭函数
void redsocks_close_internal(int fd, const char *file, int line, const char *func)
{
    if (close(fd) == 0)
    {
        conn_pressure_lowered();
    }
    else
    {
        const int do_errno = 1;
        _log_write(file, line, func, do_errno, LOG_WARNING, "close");
    }
}

// 内部事件添加函数
void redsocks_event_add_internal(redsocks_client *client, struct event *ev, const char *file, int line, const char *func)
{
    if (event_add(ev, NULL) != 0)
    {
        const int do_errno = 1;
        redsocks_log_write_plain(file, line, func, do_errno, &(client)->clientaddr, &(client)->destaddr, LOG_WARNING, "event_add");
    }
}

// 内部事件删除函数
void redsocks_event_del_internal(redsocks_client *client, struct event *ev, const char *file, int line, const char *func)
{
    if (event_del(ev) != 0)
    {
        const int do_errno = 1;
        redsocks_log_write_plain(file, line, func, do_errno, &(client)->clientaddr, &(client)->destaddr, LOG_WARNING, "event_del");
    }
}

// 内部缓冲区事件丢弃文件描述符函数
void redsocks_bufferevent_dropfd_internal(redsocks_client *client, struct bufferevent *ev, const char *file, int line, const char *func)
{
    if (bufferevent_setfd(ev, -1) != 0)
    {
        const int do_errno = 1;
        redsocks_log_write_plain(file, line, func, do_errno, &(client)->clientaddr, &(client)->destaddr, LOG_WARNING, "bufferevent_setfd");
    }
}

// 释放缓冲区事件
void redsocks_bufferevent_free(struct bufferevent *buffev)
{
    int fd = bufferevent_getfd(buffev);
    if (bufferevent_setfd(buffev, -1))
    { // 避免epoll的EBADFD警告
        log_errno(LOG_WARNING, "bufferevent_setfd");
    }
    bufferevent_free(buffev);
    if (fd != -1)
        redsocks_close(fd);
}

// 添加连接到连接列表
static void redsocks_conn_list_add(redsocks_instance *self, redsocks_client *client)
{
    assert(list_empty(&client->list));
    assert(redsocks_conn < redsocks_conn_max());
    list_add(&client->list, &self->clients);
    redsocks_conn++;
    if (redsocks_conn >= redsocks_conn_max())
    {
        log_error(LOG_WARNING, "reached redsocks_conn_max limit, %d connections", redsocks_conn);
        conn_pressure();
    }
}

// 从连接列表中删除连接
static void redsocks_conn_list_del(redsocks_client *client)
{
    if (!list_empty(&client->list))
    {
        redsocks_conn--;
        list_del(&client->list);
    }
    conn_pressure_lowered();
}

// 接受客户端连接
static void redsocks_accept_client(int fd, short what, void *_arg)
{
    log_error(LOG_NOTICE, "[*] redsocks_accept_client 接受客户端连接");
    redsocks_instance *self = _arg;
    redsocks_client *client = NULL;
    struct sockaddr_in clientaddr;
    struct sockaddr_in myaddr;
    struct sockaddr_in destaddr;
    socklen_t addrlen = sizeof(clientaddr);
    int client_fd = -1;
    int error;

    assert(redsocks_conn < redsocks_conn_max());

    // 接受客户端连接
    client_fd = accept(fd, (struct sockaddr *)&clientaddr, &addrlen);
    if (client_fd == -1)
    {
        const int e = errno;
        log_errno(LOG_WARNING, "accept");
        /* 不同系统使用不同的`errno`值来表示不同的`文件描述符不足`情况 */
        if (e == ENFILE || e == EMFILE || e == ENOBUFS || e == ENOMEM)
        {
            conn_pressure();
        }
        goto fail;
    }
    accept_backoff_ms = 0;

    // 获取套接字实际绑定的地址(可能是0.0.0.0)
    addrlen = sizeof(myaddr);
    error = getsockname(client_fd, (struct sockaddr *)&myaddr, &addrlen);
    if (error)
    {
        log_errno(LOG_WARNING, "getsockname");
        goto fail;
    }

    // 获取目标地址
    error = getdestaddr(client_fd, &clientaddr, &myaddr, &destaddr);
    if (error)
    {
        goto fail;
    }

    // 设置非阻塞模式
    error = fcntl_nonblock(client_fd);
    if (error)
    {
        log_errno(LOG_ERR, "fcntl");
        goto fail;
    }

    // 设置TCP keepalive
    if (apply_tcp_keepalive(client_fd))
        goto fail;

    // 分配客户端内存
    client = calloc(1, sizeof_client(self));
    if (!client)
    {
        log_errno(LOG_ERR, "calloc");
        goto fail;
    }
    client->instance = self;
    if (client->instance->config.use_splice)
    {
        redsocks_pump *pump = red_pump(client);
        pump->request.read = -1;
        pump->request.write = -1;
        pump->reply.read = -1;
        pump->reply.write = -1;
    }
    memcpy(&client->clientaddr, &clientaddr, sizeof(clientaddr));
    memcpy(&client->destaddr, &destaddr, sizeof(destaddr));
    INIT_LIST_HEAD(&client->list);
    self->relay_ss->init(client);

    if (redsocks_gettimeofday(&client->first_event) != 0)
        goto fail;

    redsocks_touch_client(client);

    // 创建客户端缓冲区事件
    client->client = bufferevent_new(client_fd, NULL, NULL, redsocks_event_error, client);
    if (!client->client)
    {
        log_errno(LOG_ERR, "bufferevent_new");
        goto fail;
    }
    client_fd = -1;

    // 添加到连接列表
    redsocks_conn_list_add(self, client);

    // 启用读取以处理客户端的EOF
    if (bufferevent_enable(client->client, EV_READ) != 0)
    {
        redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        goto fail;
    }

    // 这里已经可以读取到客户端发送过来的 目标ip 比如： [192.168.111.128:55992->183.2.172.177:443]
    // redsocks_log_error(client, LOG_INFO, "accepted");
    char clientaddr_str[RED_INET_ADDRSTRLEN], destaddr_str[RED_INET_ADDRSTRLEN];

    log_error(LOG_NOTICE, "[*] 请求连接： %s -> %s",
              red_inet_ntop(&(client)->clientaddr, clientaddr_str, sizeof(clientaddr_str)),
              red_inet_ntop(&(client)->destaddr, destaddr_str, sizeof(destaddr_str)));

    // 连接中继
    if (self->relay_ss->connect_relay)
        self->relay_ss->connect_relay(client);
    else
        redsocks_connect_relay(client);

    return;

fail:
    if (client)
    {
        redsocks_drop_client(client);
    }
    if (client_fd != -1)
        redsocks_close(client_fd);
}

// 获取关闭事件字符串表示
static const char *redsocks_evshut_str(unsigned short evshut)
{
    return evshut == EV_READ ? "SHUT_RD" : evshut == EV_WRITE           ? "SHUT_WR"
                                       : evshut == (EV_READ | EV_WRITE) ? "SHUT_RDWR"
                                       : evshut == 0                    ? ""
                                                                        : "???";
}

// 获取事件字符串表示
static const char *redsocks_event_str(unsigned short what)
{
    return what == EV_READ ? "R/-" : what == EV_WRITE           ? "-/W"
                                 : what == (EV_READ | EV_WRITE) ? "R/W"
                                 : what == 0                    ? "-/-"
                                                                : "???";
}

// 检查是否有splice实例
bool redsocks_has_splice_instance()
{
    // 目前只初始化了i->config
    redsocks_instance *i = NULL;
    list_for_each_entry(i, &instances, list)
    {
        if (i->config.use_splice)
            return true;
    }
    return false;
}

// 完成实例
static void redsocks_fini_instance(redsocks_instance *instance);

// 初始化实例
static int redsocks_init_instance(redsocks_instance *instance)
{
    /* FIXME: 在失败情况下调用redsocks_fini_instance，此函数将从实例列表中删除实例 - 结果看起来不美观 */
    int error;
    int fd = -1;

    fd = red_socket_server(SOCK_STREAM, &instance->config.bindaddr);
    if (fd == -1)
    {
        goto fail;
    }

    error = listen(fd, instance->config.listenq);
    if (error)
    {
        log_errno(LOG_ERR, "listen");
        goto fail;
    }

    event_set(&instance->listener, fd, EV_READ | EV_PERSIST, redsocks_accept_client, instance);
    fd = -1;

    error = event_add(&instance->listener, NULL);
    if (error)
    {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    if (instance->relay_ss->instance_init)
        instance->relay_ss->instance_init(instance);

    return 0;

fail:
    redsocks_fini_instance(instance);

    if (fd != -1)
    {
        redsocks_close(fd);
    }

    return -1;
}

/* 完全删除实例，释放其内存并从实例列表中移除 */
static void redsocks_fini_instance(redsocks_instance *instance)
{
    if (!list_empty(&instance->clients))
    {
        redsocks_client *tmp, *client = NULL;

        //        log_error(LOG_WARNING, "There are connected clients during shutdown! Disconnecting them.");
        list_for_each_entry_safe(client, tmp, &instance->clients, list)
        {
            redsocks_drop_client(client);
        }
    }

    if (instance->relay_ss->instance_fini)
        instance->relay_ss->instance_fini(instance);

    if (event_initialized(&instance->listener))
    {
        if (event_del(&instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del");
        redsocks_close(event_get_fd(&instance->listener));
        memset(&instance->listener, 0, sizeof(instance->listener));
    }

    list_del(&instance->list);

    free(instance->config.type);
    free(instance->config.login);
    free(instance->config.password);

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

// 完成redsocks
static int redsocks_fini();

// 调试转储器事件
static struct event debug_dumper;

/* 调试转储单个实例 */
static uint32_t redsocks_debug_dump_instance(redsocks_instance *instance, struct timeval *now)
{
    redsocks_client *client = NULL;
    uint32_t conn = 0;
    char bindaddr_str[RED_INET_ADDRSTRLEN];

    log_error(LOG_NOTICE, "Dumping client list for %s at %s:",
              instance->config.type,
              red_inet_ntop(&instance->config.bindaddr, bindaddr_str, sizeof(bindaddr_str)));

    list_for_each_entry(client, &instance->clients, list)
    {
        conn++;
        const char *s_client_evshut = redsocks_evshut_str(client->client_evshut);
        const char *s_relay_evshut = redsocks_evshut_str(client->relay_evshut);
        struct timeval age, idle;
        timersub(now, &client->first_event, &age);
        timersub(now, &client->last_event, &idle);

        redsocks_log_error(client, LOG_NOTICE,
                           "client: %i (%s)%s%s, relay: %i (%s)%s%s, age: %ld.%06ld sec, idle: %ld.%06ld sec.",
                           client->client ? bufferevent_getfd(client->client) : -1,
                           client->client ? redsocks_event_str(client->client->enabled) : "NULL",
                           s_client_evshut[0] ? " " : "", s_client_evshut,
                           client->relay ? bufferevent_getfd(client->relay) : -1,
                           client->relay ? redsocks_event_str(client->relay->enabled) : "NULL",
                           s_relay_evshut[0] ? " " : "", s_relay_evshut,
                           age.tv_sec, age.tv_usec,
                           idle.tv_sec, idle.tv_usec);
    }
    return conn;
}

/* 调试信号处理函数 */
static void redsocks_debug_dump(int sig, short what, void *_arg)
{
    redsocks_instance *instance = NULL;
    struct timeval now;
    redsocks_gettimeofday(&now);
    uint32_t conn = 0;

    list_for_each_entry(instance, &instances, list)
        conn += redsocks_debug_dump_instance(instance, &now);
    assert(conn == redsocks_conn);
}

// 初始化redsocks
static int redsocks_init()
{
    struct sigaction sa = {}, sa_old = {};
    redsocks_instance *tmp, *instance = NULL;

    redsocks_conn = 0;

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGPIPE, &sa, &sa_old) == -1)
    {
        log_errno(LOG_ERR, "sigaction");
        return -1;
    }

    signal_set(&debug_dumper, SIGUSR1, redsocks_debug_dump, NULL);
    if (signal_add(&debug_dumper, NULL) != 0)
    {
        log_errno(LOG_ERR, "signal_add");
        goto fail;
    }

    event_set(&accept_backoff_ev, -1, 0, redsocks_accept_backoff, NULL);

    list_for_each_entry_safe(instance, tmp, &instances, list)
    {
        if (redsocks_init_instance(instance) != 0)
            goto fail;
    }

    return 0;

fail:
    // 这是第一个资源分配，它在失败时返回，而不是goto-fail
    sigaction(SIGPIPE, &sa_old, NULL);

    redsocks_fini();

    return -1;
}

// 完成redsocks
static int redsocks_fini()
{
    redsocks_instance *tmp, *instance = NULL;

    list_for_each_entry_safe(instance, tmp, &instances, list)
        redsocks_fini_instance(instance);

    assert(redsocks_conn == 0);

    if (signal_initialized(&debug_dumper))
    {
        if (signal_del(&debug_dumper) != 0)
            log_errno(LOG_WARNING, "signal_del");
        memset(&debug_dumper, 0, sizeof(debug_dumper));
    }

    return 0;
}

// redsocks子系统定义
app_subsys redsocks_subsys = {
    .init = redsocks_init,
    .fini = redsocks_fini,
    .conf_section = &redsocks_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */