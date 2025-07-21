/* redsocks2 - 透明TCP到代理的重定向器
 * 版权所有 (C) 2013-2017 Zhuofei Wang <semigodking@gmail.com>
 *
 * 此代码基于Leonid Evdokimov开发的redsocks项目。
 * 根据Apache License 2.0版本授权（"许可证"）；除非符合许可证，
 * 否则不得使用此文件。您可以在以下网址获取许可证副本：
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 除非适用法律要求或书面同意，按"原样"分发的软件，
 * 没有任何明示或暗示的担保或条件。详见许可证中特定语言规定的权限和限制。
 */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include "base.h"
#include "list.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "tcpdns.h"
#include "utils.h"
#include "debugcor.h"

// 定义日志宏
#define tcpdns_log_error(prio, msg...) \
    redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &req->client_addr, &req->instance->config.bindaddr, prio, ##msg)
#define tcpdns_log_errno(prio, msg...) \
    redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &req->client_addr, &req->instance->config.bindaddr, prio, ##msg)


/* 添加这些宏定义 */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif


// 前向声明
static void tcpdns_fini_instance(tcpdns_instance *instance);
static int tcpdns_fini();

// DNS协议相关定义
#define DNS_QR 0x80      // 查询/响应标志
#define DNS_TC 0x02      // 截断标志
#define DNS_Z 0x40       // 保留位
#define DNS_RC_MASK 0x0F // 返回码掩码

// DNS返回码
#define DNS_RC_NOERROR 0  // 无错误
#define DNS_RC_FORMERR 1  // 格式错误
#define DNS_RC_SERVFAIL 2 // 服务器失败
#define DNS_RC_NXDOMAIN 3 // 域名不存在
#define DNS_RC_NOTIMP 4   // 未实现
#define DNS_RC_REFUSED 5  // 拒绝
#define DNS_RC_YXDOMAIN 6 // 域名存在
#define DNS_RC_XRRSET 7   // RR集合存在
#define DNS_RC_NOTAUTH 8  // 未授权
#define DNS_RC_NOTZONE 9  // 不在区域

#define DEFAULT_TIMEOUT_SECONDS 4 // 默认超时时间(秒)

// 测试标志
#define FLAG_TCP_TEST 0x01
#define FLAG_UDP_TEST 0x02

#define DELAY_LOG_FORMAT "[*] DNS服务器 %s 延迟: %dms (历史: %d/%d/%d) | 请求ID: %04x | 客户端: %s:%d \n"

// TCPDNS状态枚举
typedef enum tcpdns_state_t
{
    STATE_NEW,           // 新建状态
    STATE_REQUEST_SENT,  // 请求已发送
    STATE_RESPONSE_SENT, // 响应已发送
} tcpdns_state;
/* 打印十六进制数据的辅助函数 */
static void print_hex_dump(const char *title, const void *data, size_t len)
{
    const unsigned char *buf = (const unsigned char *)data;
    size_t i, j;

    // log_error(LOG_DEBUG, "====== %s (长度: %zu) ======", title, len);
    printf("====== %s (长度: %zu) ======\n", title, len);
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

        // log_error(LOG_DEBUG, "0x%04zx: %s |%s|", i, hex, ascii);
        printf("0x%04zx: %s |%s| \n", i, hex, ascii);
    }
    printf("\n");
}

// 获取QTYPE的辅助函数
static uint16_t get_qtype(const uint8_t *packet, size_t packet_len)
{
    if (packet_len < 12 + 1)
        return 0; // 至少Header+1字节查询名

    const uint8_t *qname = packet + 12; // 跳过Header
    while (*qname && qname < packet + packet_len)
    { // 跳过查询名
        qname += *qname + 1;
    }
    qname++; // 跳过结束的0x00

    if (qname + 4 > packet + packet_len)
        return 0;                     // 确保有QTYPE+QCLASS空间
    return ntohs(*(uint16_t *)qname); // QTYPE是网络字节序
}

/***********************************************************************
 * 核心逻辑
 */

/* 释放请求资源
 * @param req 要释放的DNS请求
 */
static void tcpdns_drop_request(dns_request *req)
{
    int fd;
    LOG_DEBUG_C("释放请求 %p (状态=%d, resolver=%p) \n",
                req, req->state, req->resolver);
    if (req->resolver)
    {
        bufferevent_free(req->resolver); // 确保释放bufferevent
        req->resolver = NULL;            // 避免野指针
    }
    list_del(&req->list); // 从链表中移除
    free(req);            // 释放内存
}

/* 更新DNS服务器延迟
 * @param req 请求对象
 * @param delay 要设置的延迟值(毫秒)
 */
static inline void tcpdns_update_delay(dns_request *req, int delay)
{
    //add.................

    // 确定当前操作的 DNS代理服务器
    if (!req || !req->delay || !req->instance)
    {
        return;
    }

    tcpdns_instance *instances = req->instance;
    char dns_addr_str[INET_ADDRSTRLEN];

    char *server_name = "unkonwn";
    int *delay_ptr = req->delay;
    // 确定是哪一个代理服务器
    if (delay_ptr == &instances->tcp1_delay_ms && instances->config.tcpdns1)
    {
        server_name = "TCPDNS1";
        //red_inet_ntop(&instances->config.tcpdns1_addr, dns_addr_str, sizeof(dns_addr_str));

        struct sockaddr_in *sin = (struct sockaddr_in *)&instances->config.tcpdns1_addr;
        inet_ntop(AF_INET,&sin->sin_addr,dns_addr_str,sizeof(dns_addr_str));
    }
    else if (delay_ptr == (struct sockaddr_in*)&instances->tcp2_delay_ms && instances->config.tcpdns2)
    {
        server_name = "TCPDNS2";
        struct sockaddr_in *sin = (struct sockaddr_in *)&instances->config.tcpdns2_addr;
        inet_ntop(AF_INET,&sin->sin_addr,dns_addr_str,sizeof(dns_addr_str));
 
    }

    // 计算统计指标
    static struct
    {
        int min;
        int max;
        int total;
        int count;
    } delay_stats[2] = {{INT_MAX, 0, 0, 0}, {INT_MAX, 0, 0, 0}};

    int server_idx = (delay_ptr == &instances->tcp1_delay_ms) ? 0 : 1;
    delay_stats[server_idx].total += delay;
    delay_stats[server_idx].count++;
    delay_stats[server_idx].min = MIN(delay_stats[server_idx].min, delay);
    delay_stats[server_idx].max = MAX(delay_stats[server_idx].max, delay);
    int avg = delay_stats[server_idx].total / delay_stats[server_idx].count;

    // 获取请求信息  dns-request-id
    uint16_t req_id = ntohs(req->data.header.id);
    char client_addr[INET_ADDRSTRLEN];
    int client_port;
    if (req->client_addr.ss_family == AF_INET)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&req->client_addr;
        inet_ntop(AF_INET, &sin->sin_addr, client_addr, sizeof(client_addr));
        client_port = ntohs(sin->sin_port);
    }
    // 记录详细日志
    printf(DELAY_LOG_FORMAT,
           dns_addr_str, delay,
           delay_stats[server_idx].min,
           avg,
           delay_stats[server_idx].max,
           req_id,
           client_addr,
           client_port);

    // 更新延迟
    delay_ptr = delay;
}


/* 从上游DNS服务器读取响应的回调
 * @param from 触发事件的bufferevent
 * @param _arg 用户参数(这里是dns_request指针)
 */
static void tcpdns_readcb(struct bufferevent *from, void *_arg)
{
    dns_request *req = _arg;
    union
    {
        short len;      // TCP DNS长度字段
        char raw[4096]; // 原始数据缓冲区
    } buff;
    struct timeval tv;
    assert(from == req->resolver);
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));

    printf("响应大小: %zu \n", input_size);

    if (input_size == 0 || input_size > sizeof(buff))
        // EOF或响应过大，丢弃
        goto finish;

    // 检查状态和最小长度要求
    if (req->state == STATE_REQUEST_SENT && input_size > 2)
    {
        size_t read_size = bufferevent_read(from, &buff, sizeof(buff));
        if (read_size > (2 + sizeof(dns_header)))
        {
            dns_header *dh = (dns_header *)&buff.raw[2];

            print_hex_dump("响应DNS UDP数据包", &buff.raw[2], read_size);

            // 打印IP和域名映射关系

            // parse_dns_response(&buff.raw[2], read_size);
            // 解析DNS域名：

            switch (dh->ra_z_rcode & DNS_RC_MASK)
            {
            case DNS_RC_NOERROR:
            case DNS_RC_FORMERR:
            case DNS_RC_NXDOMAIN:
            {
                // 将响应发送回客户端(UDP)
                int fd = event_get_fd(req->instance->listener);

                if (sendto(fd, &buff.raw[2], read_size - 2, 0,
                           (struct sockaddr *)&req->client_addr,
                           sizeof(req->client_addr)) != read_size - 2)
                {
                    printf("[*] sendoto Client DNS error\n");
                    tcpdns_log_errno(LOG_ERR, "sendto失败");
                }
                req->state = STATE_RESPONSE_SENT;
                // 计算并更新DNS解析器的延迟
                gettimeofday(&tv, 0);
                timersub(&tv, &req->req_time, &tv);
                tcpdns_update_delay(req, tv.tv_sec * 1000 + tv.tv_usec / 1000);
                
                //tcpdns_drop_request(req);
            }
            break;
            default:
                // 惩罚服务器(设置高延迟)
                tcpdns_update_delay(req, (req->instance->config.timeout + 1) * 1000);
                //tcpdns_drop_request(req);
            }
        }
    }
finish:
    tcpdns_drop_request(req); // 无论成功与否都释放请求
}

/* 连接到上游DNS服务器成功的回调
 * @param buffev 已连接的bufferevent
 * @param _arg 用户参数(dns_request指针)
 */
static void tcpdns_connected(struct bufferevent *buffev, void *_arg)
{
    dns_request *req = _arg;
    if (!req || !buffev)
    {
        log_error(LOG_ERR, "无效参数: req=%p, buffev=%p", req, buffev);
        return;
    }
    // //BUG   修复纪念：未声明函数，导致编译器自动识别为int，发生类型截断
    // if (buffev != req->resolver)
    // {
    //      LOG_DEBUG_C("req->resolver=%p, buffev=%p)\n",
    //                req->resolver, buffev);
    //      //tcpdns_drop_request(req);
    //      //return;
    //     req->resolver = buffev;
    //     //buffev = req->resolver; //error
    // }

    assert(buffev == req->resolver);
    struct timeval tv, tv2;

    if (!red_is_socket_connected_ok(buffev))
    {
        tcpdns_log_error(LOG_DEBUG, "连接到目标失败");
        tcpdns_drop_request(req);
        return;
    }

    if (req->state != STATE_NEW) // 没有数据要发送
        return;

    // 构造TCP DNS请求(2字节长度+查询)
    uint16_t len = htons((uint16_t)req->data_len);
    if (bufferevent_write(buffev, &len, sizeof(uint16_t)) == -1 || bufferevent_write(buffev, &req->data.raw, req->data_len) == -1)
    {
        LOG_DEBUG_C("[*] bufferevent_write失败 \n");
        tcpdns_drop_request(req);
        return;
    }

    // 设置读取超时(剩余时间)
    gettimeofday(&tv, 0);
    timersub(&tv, &req->req_time, &tv);
    tv2.tv_sec = req->instance->config.timeout;
    tv2.tv_usec = 0;
    timersub(&tv2, &tv, &tv);
    if (tv.tv_sec > 0 || tv.tv_usec > 0)
    {
        bufferevent_set_timeouts(buffev, &tv, NULL);
        bufferevent_enable(buffev, EV_READ); // 启用读取
        req->state = STATE_REQUEST_SENT;
    }
    else
    {
        tcpdns_update_delay(req, tv2.tv_sec * 1000);
        tcpdns_drop_request(req);
    }
}

/* 错误事件处理回调
 * @param buffev 触发事件的bufferevent
 * @param what 事件标志
 * @param _arg 用户参数(dns_request指针)
 */
static void tcpdns_event_error(struct bufferevent *buffev, short what, void *_arg)
{
    dns_request *req = _arg;
    int saved_errno = errno;
    assert(buffev == req->resolver);

    tcpdns_log_errno(LOG_DEBUG, "errno(%d), 事件: " event_fmt_str,
                     saved_errno, event_fmt(what));

    if (req->state == STATE_NEW && what == (BEV_EVENT_WRITING | BEV_EVENT_TIMEOUT))
    {
        tcpdns_update_delay(req, -1); // 标记为不可用
    }
    else if (saved_errno == ECONNRESET)
    {
        // 如果连接被重置，尽量避免使用此DNS服务器
        tcpdns_update_delay(req, (req->instance->config.timeout + 1) * 1000);
    }
    tcpdns_drop_request(req);
}

/* 选择最优的上游TCP DNS服务器
 * @param instance TCPDNS实例
 * @param delay 用于返回延迟指针的指针
 * @return 选择的服务器地址
 */
static struct sockaddr_storage *choose_tcpdns(tcpdns_instance *instance, int **delay)
{
    static int n = 0;
    log_error(LOG_DEBUG, "TCP DNS解析器延迟: %d, %d", instance->tcp1_delay_ms, instance->tcp2_delay_ms);

    // 如果有两个服务器配置
    if (instance->config.tcpdns1 && instance->config.tcpdns2)
    {
        if (instance->tcp1_delay_ms <= 0 && instance->tcp2_delay_ms <= 0)
        {
            // 都不可用，轮询选择
            n += 1;
            if (n % 2)
                goto return_tcp1;
            else
                goto return_tcp2;
        }
        // 根据延迟选择最优服务器
        if (instance->tcp1_delay_ms > instance->tcp2_delay_ms)
        {
            if (instance->tcp2_delay_ms < 0)
                goto return_tcp1;
            else
                goto return_tcp2;
        }
        else
        {
            if (instance->tcp1_delay_ms < 0)
                goto return_tcp2;
            else
                goto return_tcp1;
        }
    }
    // 只有一个服务器的情况
    if (instance->config.tcpdns1)
        goto return_tcp1;
    if (instance->config.tcpdns2)
        goto return_tcp2;

    *delay = NULL;
    return NULL;

return_tcp1:
    *delay = &instance->tcp1_delay_ms;
    return &instance->config.tcpdns1_addr;

return_tcp2:
    *delay = &instance->tcp2_delay_ms;
    return &instance->config.tcpdns2_addr;
}

/* 处理来自客户端的UDP DNS数据包
 * @param fd 监听套接字
 * @param what 事件类型
 * @param _arg 用户参数(tcpdns_instance指针)
 */
static void tcpdns_pkt_from_client(int fd, short what, void *_arg)
{
    tcpdns_instance *self = _arg;
    dns_request *req = NULL;
    struct timeval tv;
    struct sockaddr_storage *destaddr;
    ssize_t pktlen;

    assert(fd == event_get_fd(self->listener));

    // 分配并初始化请求结构
    req = (dns_request *)calloc(sizeof(dns_request), 1);
    if (!req)
    {
        log_error(LOG_ERR, "内存不足");
        return;
    }
    req->resolver = NULL;
    req->instance = self;
    req->state = STATE_NEW;
    gettimeofday(&req->req_time, 0);

    // 接收UDP数据包
    pktlen = red_recv_udp_pkt(fd, req->data.raw, sizeof(req->data.raw), &req->client_addr, NULL);
    if (pktlen == -1)
    {
        free(req);
        return;
    }
    
    // 验证DNS请求
    if (pktlen <= sizeof(dns_header))
    {
        tcpdns_log_error(LOG_INFO, "不完整的DNS请求");
        free(req);
        return;
    }

    req->data_len = pktlen;

   

    uint16_t qtype = get_qtype(req->data.raw, req->data_len);
    if (qtype != 1 /* A记录 */)
    {
        log_error(LOG_DEBUG, "忽略非A记录查询（类型=%d）", qtype);
        free(req);
        return;
    }

    // printf("新请求: 客户端端口=%d, 类型=%s\n",ntohs(((struct sockaddr_in *)&req->client_addr)->sin_port),(qtype == 1) ? "A" : (qtype == 28) ? "AAAA": "其他");

    // 检查DNS头标志
    if ((req->data.header.qr_opcode_aa_tc_rd & DNS_QR) == 0 && // 是查询
        (req->data.header.ra_z_rcode & DNS_Z) == 0 &&          // Z位为0
        req->data.header.qdcount &&                            // 有问题记录
        !req->data.header.ancount && !req->data.header.nscount // 无回答和授权记录
        && qtype == 1                                          // 只处理A请求
    )
    {
        


        // 打印接收到的原始数据包(十六进制)
        print_hex_dump("请求DNS UDP数据包", req->data.raw, req->data_len);
        char buf[255];
        printf("新建请求 %p, 客户端: %s\n", req,
               red_inet_ntop(&req->client_addr, buf, sizeof(buf)));

        tv.tv_sec = self->config.timeout;
        tv.tv_usec = 0;

        // 选择上游服务器

        destaddr = choose_tcpdns(self, &req->delay);
        if (!destaddr)
        {
            tcpdns_log_error(LOG_WARNING, "未配置有效的DNS解析器");
            free(req);
            return;
        }

        // 连接到上游DNS服务器 建立TCP 连接
        req->resolver = red_connect_relay2(NULL, destaddr,
                                           tcpdns_readcb, tcpdns_connected, tcpdns_event_error, req,
                                           &tv);

        // LOG_DEBUG_C("[*] req->resolver = %p\n",req->resolver);

        if (req->resolver)
            list_add(&req->list, &self->requests); // 添加到请求列表
        else
        {
            tcpdns_log_error(LOG_INFO, "连接到DNS解析器失败");
            free(req);
        }
    }
    else
    {
        tcpdns_log_error(LOG_INFO, "格式错误的DNS请求");
        free(req);
    }
}

/***********************************************************************
 * 初始化/关闭
 */

// 配置项定义
static parser_entry tcpdns_entries[] =
    {
        {.key = "bind", .type = pt_pchar},     // 绑定地址
        {.key = "tcpdns1", .type = pt_pchar},  // 第一个TCP DNS服务器
        {.key = "tcpdns2", .type = pt_pchar},  // 第二个TCP DNS服务器
        {.key = "timeout", .type = pt_uint16}, // 超时时间(秒)
        {}};

static list_head instances = LIST_HEAD_INIT(instances); // 实例列表

/* 进入配置节时的回调
 * @param section 配置节
 * @return 成功返回0，失败返回-1
 */
static int tcpdns_onenter(parser_section *section)
{
    tcpdns_instance *instance = calloc(1, sizeof(*instance));
    if (!instance)
    {
        parser_error(section->context, "内存不足");
        return -1;
    }

    INIT_LIST_HEAD(&instance->list);
    INIT_LIST_HEAD(&instance->requests);

    // 设置默认绑定地址(本地回环:53)
    struct sockaddr_in *addr = (struct sockaddr_in *)&instance->config.bindaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr->sin_port = htons(53);

    // 设置配置项地址
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "bind") == 0) ? (void *)&instance->config.bind : (strcmp(entry->key, "tcpdns1") == 0) ? (void *)&instance->config.tcpdns1
                                                                             : (strcmp(entry->key, "tcpdns2") == 0)   ? (void *)&instance->config.tcpdns2
                                                                             : (strcmp(entry->key, "timeout") == 0)   ? (void *)&instance->config.timeout
                                                                                                                      : NULL;
    section->data = instance;
    return 0;
}

/* 退出配置节时的回调
 * @param section 配置节
 * @return 成功返回0，失败返回-1
 */
static int tcpdns_onexit(parser_section *section)
{
    const char *err = NULL;
    tcpdns_instance *instance = section->data;

    section->data = NULL;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    // 解析绑定地址
    if (instance->config.bind)
    {
        struct sockaddr *addr = (struct sockaddr *)&instance->config.bindaddr;
        int addr_size = sizeof(instance->config.bindaddr);
        if (evutil_parse_sockaddr_port(instance->config.bind, addr, &addr_size))
            err = "无效的绑定地址";
    }

    // 解析第一个TCP DNS服务器地址
    if (!err && instance->config.tcpdns1)
    {
        struct sockaddr *addr = (struct sockaddr *)&instance->config.tcpdns1_addr;
        int addr_size = sizeof(instance->config.tcpdns1_addr);
        if (evutil_parse_sockaddr_port(instance->config.tcpdns1, addr, &addr_size))
            err = "无效的tcpdns1地址";
        else if (addr->sa_family == AF_INET && ((struct sockaddr_in *)addr)->sin_port == 0)
            ((struct sockaddr_in *)addr)->sin_port = htons(53); // 默认DNS端口
        else if (addr->sa_family == AF_INET6 && ((struct sockaddr_in6 *)addr)->sin6_port == 0)
            ((struct sockaddr_in6 *)addr)->sin6_port = htons(53);
    }

    // 解析第二个TCP DNS服务器地址
    if (!err && instance->config.tcpdns2)
    {
        struct sockaddr *addr = (struct sockaddr *)&instance->config.tcpdns2_addr;
        int addr_size = sizeof(instance->config.tcpdns2_addr);
        if (evutil_parse_sockaddr_port(instance->config.tcpdns2, addr, &addr_size))
            err = "无效的tcpdns2地址";
        else if (addr->sa_family == AF_INET && ((struct sockaddr_in *)addr)->sin_port == 0)
            ((struct sockaddr_in *)addr)->sin_port = htons(53);
        else if (addr->sa_family == AF_INET6 && ((struct sockaddr_in6 *)addr)->sin6_port == 0)
            ((struct sockaddr_in6 *)addr)->sin6_port = htons(53);
    }

    // 验证至少配置了一个TCP DNS服务器
    if (instance->config.tcpdns1 == NULL && instance->config.tcpdns2 == NULL)
        err = "必须配置至少一个TCP DNS解析器";

    if (err)
        parser_error(section->context, "%s", err);
    else
        list_add(&instance->list, &instances); // 添加到实例列表

    // 设置默认超时(如果未配置或配置为0)
    if (instance->config.timeout == 0)
        instance->config.timeout = DEFAULT_TIMEOUT_SECONDS;
    return err ? -1 : 0;
}

/* 初始化TCPDNS实例
 * @param instance 要初始化的实例
 * @return 成功返回0，失败返回-1
 */
static int tcpdns_init_instance(tcpdns_instance *instance)
{
    int error;
    int fd = -1;
    int bindaddr_len = 0;
    char buf1[RED_INET_ADDRSTRLEN];

    // 创建UDP套接字
    fd = socket(instance->config.bindaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1)
    {
        log_errno(LOG_ERR, "socket创建失败");
        goto fail;
    }

    // 设置SO_REUSEPORT(如果支持)
    if (apply_reuseport(fd))
        log_error(LOG_WARNING, "继续运行，未启用SO_REUSEPORT");

// 计算绑定地址长度(不同系统处理方式不同)
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    bindaddr_len = instance->config.bindaddr.ss_len > 0 ? instance->config.bindaddr.ss_len : sizeof(instance->config.bindaddr);
#else
    bindaddr_len = sizeof(instance->config.bindaddr);
#endif

    // 绑定到指定地址
    error = bind(fd, (struct sockaddr *)&instance->config.bindaddr, bindaddr_len);
    if (error)
    {
        log_errno(LOG_ERR, "bind失败");
        goto fail;
    }

    // 设置为非阻塞模式
    error = evutil_make_socket_nonblocking(fd);
    if (error)
    {
        log_errno(LOG_ERR, "设置非阻塞失败");
        goto fail;
    }

    // 创建监听事件
    instance->listener = event_new(get_event_base(), fd, EV_READ | EV_PERSIST,
                                   tcpdns_pkt_from_client, instance);
    if (!instance->listener)
    {
        log_errno(LOG_ERR, "event_new失败");
        goto fail;
    }

    // 添加事件到事件循环
    error = event_add(instance->listener, NULL);
    if (error)
    {
        log_errno(LOG_ERR, "event_add失败");
        goto fail;
    }

    log_error(LOG_INFO, "tcpdns @ %s",
              red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)));
    return 0;

fail:
    tcpdns_fini_instance(instance);

    if (fd != -1 && close(fd) != 0)
        log_errno(LOG_WARNING, "关闭失败");

    return -1;
}

/* 完全释放实例资源
 * @param instance 要释放的实例
 */
static void tcpdns_fini_instance(tcpdns_instance *instance)
{
    if (instance->listener)
    {
        if (event_del(instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del失败");
        if (close(event_get_fd(instance->listener)) != 0)
            log_errno(LOG_WARNING, "关闭失败");
        event_free(instance->listener);
    }

    list_del(&instance->list); // 从实例列表中移除

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

/* 初始化TCPDNS模块
 * @return 成功返回0，失败返回-1
 */
static int tcpdns_init()
{
    tcpdns_instance *tmp, *instance = NULL;

    // 初始化所有配置的实例
    list_for_each_entry_safe(instance, tmp, &instances, list)
    {
        if (tcpdns_init_instance(instance) != 0)
            goto fail;
    }

    return 0;

fail:
    tcpdns_fini();
    return -1;
}

/* 关闭TCPDNS模块
 * @return 总是返回0
 */
static int tcpdns_fini()
{
    tcpdns_instance *tmp, *instance = NULL;

    // 释放所有实例
    list_for_each_entry_safe(instance, tmp, &instances, list)
        tcpdns_fini_instance(instance);

    return 0;
}

/* 转储实例信息(调试用)
 * @param instance 要转储的实例
 */
static void tcpdns_dump_instance(tcpdns_instance *instance)
{
    char buf1[RED_INET_ADDRSTRLEN];

    log_error(LOG_INFO, "转储实例数据 (tcpdns @ %s):",
              red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)));
    log_error(LOG_INFO, "TCP DNS [%s] 延迟: %dms",
              red_inet_ntop(&instance->config.tcpdns1_addr, buf1, sizeof(buf1)),
              instance->tcp1_delay_ms);
    log_error(LOG_INFO, "TCP DNS [%s] 延迟: %dms",
              red_inet_ntop(&instance->config.tcpdns2_addr, buf1, sizeof(buf1)),
              instance->tcp2_delay_ms);
    log_error(LOG_INFO, "数据转储结束");
}

/* 调试转储所有实例信息
 */
static void tcpdns_debug_dump()
{
    tcpdns_instance *instance = NULL;

    list_for_each_entry(instance, &instances, list)
        tcpdns_dump_instance(instance);
}

// 配置节定义
static parser_section tcpdns_conf_section =
    {
        .name = "tcpdns",          // 配置节名称
        .entries = tcpdns_entries, // 配置项数组
        .onenter = tcpdns_onenter, // 进入节回调
        .onexit = tcpdns_onexit    // 退出节回调
};

// 子系统定义
app_subsys tcpdns_subsys =
    {
        .init = tcpdns_init,                  // 初始化函数
        .fini = tcpdns_fini,                  // 清理函数
        .dump = tcpdns_debug_dump,            // 调试转储函数
        .conf_section = &tcpdns_conf_section, // 配置节
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */