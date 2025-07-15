/* redsocks - 透明TCP到代理的重定向器 */
/* 版权所有 (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru> */
/* 遵循Apache License 2.0版本 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <search.h>
#include <errno.h>

#include "list.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "dnsu2t.h"
#include "utils.h"

// DNS UDP转TCP模块专用的日志宏
#define dnsu2t_log_error(prio, msg...) \
    redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &clientaddr, &self->config.bindaddr, prio, ##msg)
#define dnsu2t_log_errno(prio, msg...) \
    redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &clientaddr, &self->config.bindaddr, prio, ##msg)

// DNS头部结构
struct dns_header
{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};
// DNS查询/响应结构
struct dns_question
{
    unsigned short qtype;
    unsigned short qclass;
};

// DNS资源记录结构
struct dns_rr
{
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rdlength;
    unsigned char *rdata;
};

// DNS记录类型
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1

// 函数前置声明
static void dnsu2t_fini_instance(dnsu2t_instance *instance);
static int dnsu2t_fini();
static void dnsu2t_pkt_from_client(int fd, short what, void *_arg);
static void dnsu2t_pkt_from_relay(int fd, short what, void *_arg);
static void dnsu2t_relay_writable(int fd, short what, void *_arg);
static void dnsu2t_close_relay(dnsu2t_instance *self);

// DNS解析
//  自定义的ntohs和ntohl实现
unsigned short my_ntohs(unsigned short net)
{
    return (net << 8) | (net >> 8);
}

unsigned int my_ntohl(unsigned int net)
{
    return ((net & 0xFF) << 24) |
           ((net & 0xFF00) << 8) |
           ((net & 0xFF0000) >> 8) |
           ((net & 0xFF000000) >> 24);
}

// 解析DNS域名
void parse_dns_name(unsigned char *buffer, unsigned char *name, int *offset)
{
    int pos = 0;
    int len = 0;
    int jumped = 0;
    int new_offset = *offset;

    while (1)
    {
        len = buffer[new_offset];

        if ((len & 0xC0) == 0xC0)
        { // 处理指针
            int jump_offset = ((buffer[new_offset] & 0x3F) << 8) | buffer[new_offset + 1];
            new_offset += 2;

            if (!jumped)
            {
                *offset = new_offset;
                jumped = 1;
            }

            parse_dns_name(buffer, name + pos, &jump_offset);
            name[pos + strlen((char *)(name + pos))] = 0;
            return;
        }
        else
        {
            new_offset++;

            if (len == 0)
            {
                name[pos] = 0;
                break;
            }

            memcpy(name + pos, buffer + new_offset, len);
            new_offset += len;
            pos += len;
            name[pos] = '.';
            pos++;
        }
    }

    if (!jumped)
    {
        *offset = new_offset;
    }

    if (pos > 0)
    {
        name[pos - 1] = 0; // 去掉最后的点
    }
}

// 解析DNS响应
// 解析 DNS 响应
void parse_dns_response(unsigned char *buffer, int length) {
    struct dns_header *header = (struct dns_header *)buffer;
    int offset = sizeof(struct dns_header);
    unsigned char original_name[256] = {0};
    unsigned char last_cname[256] = {0};
    
    // 转换字节序
    header->qdcount = my_ntohs(header->qdcount);
    header->ancount = my_ntohs(header->ancount);
    
    // 获取原始查询的域名（问题部分）
    if (header->qdcount > 0) {
        parse_dns_name(buffer, original_name, &offset);
        offset += sizeof(struct dns_question);
    }
    
    // 解析回答部分
    for (int i = 0; i < header->ancount; i++) {
        unsigned char name[256] = {0};
        parse_dns_name(buffer, name, &offset);
        
        struct dns_rr rr;
        memcpy(&rr, buffer + offset, 10);
        offset += 10;
        
        rr.type = my_ntohs(rr.type);
        rr.class = my_ntohs(rr.class);
        rr.ttl = my_ntohl(rr.ttl);
        rr.rdlength = my_ntohs(rr.rdlength);
        
        if (rr.type == 5) { // CNAME 记录
            unsigned char cname[256] = {0};
            int temp_offset = offset;
            parse_dns_name(buffer, cname, &temp_offset);
            offset += rr.rdlength;
            
            // 保存当前 CNAME 映射
            strcpy(last_cname, cname);
           // printf("%s is an alias for %s\n", original_name, last_cname);
        } 
        else if (rr.type == 1 && rr.rdlength == 4) { // A 记录
            unsigned char ip[4];
            memcpy(ip, buffer + offset, 4);
            offset += 4;
            
            // 如果有 CNAME 记录，显示原始域名和 CNAME
            if (strlen(last_cname) > 0) {
                printf("[*] %d DNS解析：%s (via %s) -> %d.%d.%d.%d\n", i,
                       original_name, last_cname, ip[0], ip[1], ip[2], ip[3]);
            } else {
                printf("[*] %d DNS解析：%s -> %d.%d.%d.%d\n", i,
                original_name, ip[0], ip[1], ip[2], ip[3]);
            }
        } else {
            offset += rr.rdlength;
        }
    }
}


// 用于DNS健康检查的SOA根查询包
static const uint8_t dnsq_soa_root[] = {
    0x00, 0x00, 0x01, 0x20,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x06, 0x00, 0x01};

// 用于跟踪进行中的DNS请求
typedef struct inflight_req_t
{
    uint16_t id;                   // 网络字节序的请求ID
    struct sockaddr_in clientaddr; // 客户端地址，用于返回响应
} inflight_req;

// 用于二叉搜索树比较的函数
static int inflight_cmp(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(uint16_t));
}
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

/***********************************************************************
 * DNS UDP转TCP核心逻辑
 */



// 处理来自客户端的UDP数据包
static void dnsu2t_pkt_from_client(int srvfd, short what, void *_arg)
{
    dnsu2t_instance *self = _arg;  // 获取实例指针
    struct sockaddr_in clientaddr; // 客户端地址
    ssize_t pktlen;                // 数据包长度
    dns_tcp_pkt in;                // 输入的DNS数据包

    assert(srvfd == event_get_fd(&self->listener));

    // 从客户端接收UDP数据包
    pktlen = red_recv_udp_pkt(srvfd, in.dns.raw, sizeof(in.dns.raw), &clientaddr, NULL);
    if (pktlen == -1)
        return;

    // 验证DNS数据包有效性
    if (pktlen <= sizeof(dns_header))
    {
        dnsu2t_log_error(LOG_NOTICE, "不完整的DNS请求");
        return;
    }

    
    // 检查DNS请求格式是否正确
    if (pktlen > 0xffff || (in.dns.hdr.qr_opcode_aa_tc_rd & DNS_QR) != 0 /* 不是查询请求 */
        || in.dns.hdr.qdcount == 0                                       /* 没有查询问题 */
        || in.dns.hdr.ancount || in.dns.hdr.nscount                      /* 包含回答或授权记录 */
    )
    {
        dnsu2t_log_error(LOG_NOTICE, "格式错误的DNS请求");
        return;
    }
    // 打印接收到的原始数据包(十六进制)
    print_hex_dump("请求DNS UDP数据包", in.dns.raw, pktlen);
    // 检查是否已有相同的请求在处理中
    inflight_req **preq = tfind(&in.dns.hdr.id, &self->inflight_root, inflight_cmp);
    if (preq)
    {
        // 处理重复请求(当前未实现请求重编号)
        assert((*preq)->id == in.dns.hdr.id);
        if (memcmp(&(*preq)->clientaddr, &clientaddr, sizeof(clientaddr)) != 0)
        {
            char other_addr[RED_INET_ADDRSTRLEN];
            dnsu2t_log_error(LOG_WARNING, "DNS请求 #%04x 已从 %s 开始处理，未实现请求重编号",
                             ntohs(in.dns.hdr.id),
                             red_inet_ntop(&(*preq)->clientaddr, other_addr, sizeof(other_addr)));
        }
        return;
    }

    // 准备TCP格式的DNS数据包(添加长度前缀)
    in.sz = htons((uint16_t)pktlen);
    pktlen += sizeof(in.sz);

    int fd = -1;
    inflight_req *node = calloc(1, sizeof(inflight_req));
    node->id = in.dns.hdr.id;
    node->clientaddr = clientaddr;

    int sent;
    if (!event_initialized(&self->relay_rd))
    {
        // 第一个请求 - 建立到上游DNS的TCP连接
        log_error(LOG_NOTICE, "[*] 第一个请求 - 建立到上游DNS的TCP连接");
        fd = red_socket_client(SOCK_STREAM);
        if (fd < 0)
            goto fail;

        // 设置TCP连接的事件处理器
        event_set(&self->relay_rd, fd, EV_READ | EV_PERSIST, dnsu2t_pkt_from_relay, self);
        event_set(&self->relay_wr, fd, EV_WRITE, dnsu2t_relay_writable, self);
        fd = -1;

        // 设置TCP连接超时
        const struct timeval relay_timeout = {.tv_sec = self->config.relay_timeout};
        if (event_add(&self->relay_rd, &relay_timeout) != 0)
        {
            dnsu2t_log_error(LOG_ERR, "event_add失败");
            goto fail;
        }
        if (event_add(&self->relay_wr, &relay_timeout) != 0)
        {
            dnsu2t_log_error(LOG_ERR, "event_add失败");
            goto fail;
        }

        // 使用TCP快速打开(如果可用)
        sent = sendto(event_get_fd(&self->relay_rd), &in, pktlen, MSG_FASTOPEN,
                      (struct sockaddr *)&self->config.relayaddr, sizeof(self->config.relayaddr));
        // 临时禁用监听器，因为套接字可能不能立即写入
        if (event_del(&self->listener))
            dnsu2t_log_error(LOG_ERR, "event_del失败");
    }
    else
    {
        // 已有连接 - 直接写入
        sent = write(event_get_fd(&self->relay_rd), &in, pktlen);
    }

    if (sent == pktlen || (sent == -1 && errno == EINPROGRESS))
    {
        // 成功发送或正在处理中
        self->request_count++;
        self->inflight_count++;

        // 如果进行中请求过多则进行限流
        if (self->inflight_count >= self->config.inflight_max)
        {
            if (event_del(&self->listener))
                dnsu2t_log_error(LOG_ERR, "event_del失败");
        }

        // 添加到进行中请求跟踪
        inflight_req **new = tsearch(node, &self->inflight_root, inflight_cmp);
        if (!new)
            abort(); // 内存不足
        assert(*new == node);
        node = NULL;
        dnsu2t_log_error(LOG_DEBUG, "DNS请求 #%04x", ntohs(in.dns.hdr.id));
    }
    else if (sent == -1)
    {
        dnsu2t_log_errno(LOG_DEBUG, "DNS请求 #%04x write()失败", ntohs(in.dns.hdr.id));
        goto fail;
    }
    else if (sent != pktlen)
    {
        // 处理部分写入情况
        dnsu2t_log_error(LOG_WARNING, "未处理的部分写入");
        if (shutdown(fd, SHUT_WR) != 0)
            dnsu2t_log_error(LOG_ERR, "shutdown失败");
        if (event_del(&self->listener))
            dnsu2t_log_error(LOG_ERR, "event_del失败");
        self->reqstream_broken = true;
    }

    return;

fail:
    if (fd != -1)
        redsocks_close(fd);
    if (node)
        free(node);
    dnsu2t_close_relay(self);
}

// 进行中请求的清理函数
static void free_inflight_req(void *p)
{
    inflight_req *preq = p;
    free(preq);
}

// 关闭TCP中继连接并清理
static void dnsu2t_close_relay(dnsu2t_instance *self)
{
    if (event_initialized(&self->relay_rd))
    {
        int fd = event_get_fd(&self->relay_rd);
        assert(fd == event_get_fd(&self->relay_wr));

        // 移除事件处理器
        if (event_del(&self->relay_rd) == -1)
            log_error(LOG_ERR, "event_del失败");
        if (event_del(&self->relay_wr) == -1)
            log_error(LOG_ERR, "event_del失败");

        // 关闭套接字并重置事件
        redsocks_close(fd);
        memset(&self->relay_rd, 0, sizeof(self->relay_rd));
        memset(&self->relay_wr, 0, sizeof(self->relay_wr));

        // 如果监听器被禁用则重新启用
        if (!event_pending(&self->listener, EV_READ, NULL))
        {
            if (event_add(&self->listener, NULL) != 0)
            {
                log_error(LOG_ERR, "event_add失败");
            }
        }
    }

    // 记录丢失的进行中请求
    if (self->inflight_count)
    {
        log_error(LOG_WARNING, "丢失 %d 个进行中DNS请求(已处理 %d 个)",
                  self->inflight_count, self->request_count - self->inflight_count);
    }

    // 清理进行中请求跟踪
    tdestroy(self->inflight_root, free_inflight_req);
    self->inflight_root = NULL;
    self->inflight_count = 0;
    self->request_count = 0;
    self->reqstream_broken = false;
}

// 当中继TCP连接可写时的处理函数
void dnsu2t_relay_writable(int fd, short what, void *_arg)
{
    dnsu2t_instance *self = _arg;
    assert(event_get_fd(&self->relay_wr) == fd);

    // 如果有处理能力则重新启用监听器
    if ((what & EV_WRITE) && self->inflight_count < self->config.inflight_max && !self->reqstream_broken)
    {
        if (event_add(&self->listener, NULL) != 0)
            log_errno(LOG_ERR, "event_add失败");
    }
}

// 处理来自中继的TCP数据包
void dnsu2t_pkt_from_relay(int fd, short what, void *_arg)
{
    log_error(LOG_NOTICE, "[*] dnsu2t_pkt_from_relay 处理来自中继的TCP数据包");
    dnsu2t_instance *self = _arg;
    assert(event_get_fd(&self->relay_rd) == fd);

    if (what & EV_READ)
    {
        // 从TCP连接读取数据
        char *dst = ((char *)&self->pkt) + self->pkt_size;
        if (self->pkt_size)
            log_error(LOG_DEBUG, "部分数据包, 偏移=%lu", self->pkt_size);

        const size_t bufsz = sizeof(self->pkt) - self->pkt_size;
        assert(bufsz > 0 && self->pkt_size >= 0);

        ssize_t rcvd = recv(fd, dst, bufsz, 0);
        if (rcvd > 0)
        {
            self->pkt_size += rcvd;

            // 处理完整的数据包
            while (self->pkt_size >= sizeof(self->pkt.sz))
            {
                const ssize_t pktlen = ntohs(self->pkt.sz);
                const ssize_t tcplen = pktlen + sizeof(self->pkt.sz);

                if (pktlen <= sizeof(dns_header))
                {
                    log_error(LOG_NOTICE, "格式错误的DNS响应");
                    dnsu2t_close_relay(self);
                    break;
                }
                else if (self->pkt_size >= tcplen)
                {
                    // 查找匹配的进行中请求
                    inflight_req **preq = tfind(&self->pkt.dns.hdr.id, &self->inflight_root, inflight_cmp);
                    if (preq)
                    {
                        inflight_req *req = *preq;
                        assert(self->pkt.dns.hdr.id == req->id);
                        log_error(LOG_DEBUG, "DNS响应 #%04x", ntohs(self->pkt.dns.hdr.id));
                        // 打印接收到的原始数据包(十六进制)
                        print_hex_dump("响应UDP数据包", &self->pkt.dns, pktlen);

                        // 打印IP和域名映射关系
                        parse_dns_response(&self->pkt.dns, pktlen);
                        // 将响应发送回原始客户端
                        int sent = sendto(event_get_fd(&self->listener),
                                          &self->pkt.dns, pktlen, 0,
                                          (struct sockaddr *)&req->clientaddr, sizeof(req->clientaddr));
                        if (sent == -1)
                        {
                            log_errno(LOG_WARNING, "sendto失败");
                        }
                        else if (sent != pktlen)
                        {
                            log_errno(LOG_WARNING, "部分sendto");
                        }

                        // 更新进行中计数
                        self->inflight_count--;
                        if (self->inflight_count < self->config.inflight_max && !self->reqstream_broken)
                        {
                            if (event_add(&self->listener, NULL))
                                log_error(LOG_ERR, "event_add失败");
                        }

                        // 从跟踪中移除
                        inflight_req *parent = tdelete(req, &self->inflight_root, inflight_cmp);
                        assert(parent);
                        free(req);
                    }
                    else
                    {
                        log_error(LOG_NOTICE, "意外的DNS响应 #%04x",
                                  ntohs(self->pkt.dns.hdr.id));
                    }

                    // 处理缓冲区中的剩余数据
                    if (self->pkt_size == tcplen)
                    {
                        self->pkt_size = 0;
                    }
                    else
                    {
                        char *src = ((char *)&self->pkt) + tcplen;
                        self->pkt_size -= tcplen;
                        memmove(&self->pkt, src, self->pkt_size);
                    }
                }
                else
                {
                    break; // 需要更多数据组成完整包
                }
            }
        }
        else if (rcvd == 0)
        {
            // 服务器关闭连接
            log_error(LOG_DEBUG, "DNS服务器关闭连接");
            dnsu2t_close_relay(self);
        }
        else
        {
            // 接收错误
            log_errno(LOG_DEBUG, "recv失败");
            dnsu2t_close_relay(self);
        }
    }
    if (what & EV_TIMEOUT)
    {
        // 连接超时
        log_error(LOG_DEBUG, "DNS服务器响应超时");
        dnsu2t_close_relay(self);
    }
}

/***********************************************************************
 * 初始化和关闭
 */

// 配置解析条目
static parser_entry dnsu2t_entries[] =
    {
        {.key = "local_ip", .type = pt_in_addr},      // 本地绑定IP
        {.key = "local_port", .type = pt_uint16},     // 本地绑定端口
        {.key = "remote_ip", .type = pt_in_addr},     // 上游DNS服务器IP
        {.key = "remote_port", .type = pt_uint16},    // 上游DNS服务器端口
        {.key = "remote_timeout", .type = pt_uint16}, // TCP连接超时时间(秒)
        {.key = "inflight_max", .type = pt_uint16},   // 最大进行中请求数
        {}                                            // 结束标记
};

// 活动实例列表
static list_head instances = LIST_HEAD_INIT(instances);

// 进入dnsu2t配置段时调用
static int dnsu2t_onenter(parser_section *section)
{
    // 分配新实例
    dnsu2t_instance *instance = calloc(1, sizeof(*instance));
    if (!instance)
    {
        parser_error(section->context, "内存不足");
        return -1;
    }

    // 初始化实例
    INIT_LIST_HEAD(&instance->list);
    instance->config.bindaddr.sin_family = AF_INET;
    instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.bindaddr.sin_port = htons(53);
    ;
    instance->config.relayaddr.sin_family = AF_INET;
    instance->config.relayaddr.sin_port = htons(53);
    instance->config.relay_timeout = 30; // 默认30秒超时
    instance->config.inflight_max = 16;  // 默认最大16个进行中请求

    // 设置配置解析映射
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "local_ip") == 0) ? (void *)&instance->config.bindaddr.sin_addr : (strcmp(entry->key, "local_port") == 0)   ? (void *)&instance->config.bindaddr.sin_port
                                                                                              : (strcmp(entry->key, "remote_ip") == 0)      ? (void *)&instance->config.relayaddr.sin_addr
                                                                                              : (strcmp(entry->key, "remote_port") == 0)    ? (void *)&instance->config.relayaddr.sin_port
                                                                                              : (strcmp(entry->key, "remote_timeout") == 0) ? (void *)&instance->config.relay_timeout
                                                                                              : (strcmp(entry->key, "inflight_max") == 0)   ? (void *)&instance->config.inflight_max
                                                                                                                                            : NULL;
    section->data = instance;
    return 0;
}

// 退出dnsu2t配置段时调用
static int dnsu2t_onexit(parser_section *section)
{
    dnsu2t_instance *instance = section->data;

    section->data = NULL;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    // 转换端口号为网络字节序
    instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
    instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);

    // 添加到实例列表
    list_add(&instance->list, &instances);

    return 0;
}

// 初始化单个dnsu2t实例
static int dnsu2t_init_instance(dnsu2t_instance *instance)
{
    int error;
    // 创建UDP服务器套接字
    int fd = red_socket_server(SOCK_DGRAM, &instance->config.bindaddr);

    if (fd == -1)
    {
        goto fail;
    }

    // 设置监听器事件
    event_set(&instance->listener, fd, EV_READ | EV_PERSIST, dnsu2t_pkt_from_client, instance);
    error = event_add(&instance->listener, NULL);
    if (error)
    {
        log_errno(LOG_ERR, "event_add失败");
        goto fail;
    }

    return 0;

fail:
    dnsu2t_fini_instance(instance);

    if (fd != -1)
    {
        if (close(fd) != 0)
            log_errno(LOG_WARNING, "close失败");
    }

    return -1;
}

/* 完全销毁实例，释放内存并从实例列表中移除 */
static void dnsu2t_fini_instance(dnsu2t_instance *instance)
{
    // 关闭中继连接
    dnsu2t_close_relay(instance);

    // 清理监听器
    if (event_initialized(&instance->listener))
    {
        if (event_del(&instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del失败");
        if (close(event_get_fd(&instance->listener)) != 0)
            log_errno(LOG_WARNING, "close失败");
        memset(&instance->listener, 0, sizeof(instance->listener));
    }

    // 从列表移除
    list_del(&instance->list);

    // 清理内存
    memset(instance, 0, sizeof(*instance));
    free(instance);
}

// 初始化所有dnsu2t实例
static int dnsu2t_init()
{
    dnsu2t_instance *tmp, *instance = NULL;

    // 遍历所有实例并初始化
    list_for_each_entry_safe(instance, tmp, &instances, list)
    {
        if (dnsu2t_init_instance(instance) != 0)
            goto fail;
    }

    return 0;

fail:
    dnsu2t_fini();
    return -1;
}

// 关闭所有dnsu2t实例
static int dnsu2t_fini()
{
    dnsu2t_instance *tmp, *instance = NULL;

    // 遍历所有实例并销毁
    list_for_each_entry_safe(instance, tmp, &instances, list)
        dnsu2t_fini_instance(instance);

    return 0;
}

// dnsu2t配置段定义
static parser_section dnsu2t_conf_section =
    {
        .name = "dnsu2t",          // 配置段名称
        .entries = dnsu2t_entries, // 配置条目
        .onenter = dnsu2t_onenter, // 进入配置段回调
        .onexit = dnsu2t_onexit    // 退出配置段回调
};

// dnsu2t子系统定义
app_subsys dnsu2t_subsys =
    {
        .init = dnsu2t_init,                  // 初始化函数
        .fini = dnsu2t_fini,                  // 关闭函数
        .conf_section = &dnsu2t_conf_section, // 配置段
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */