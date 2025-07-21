#ifndef TCPDNS_H
#define TCPDNS_H

/* TCPDNS配置结构体 */
typedef struct tcpdns_config_t {
    struct sockaddr_storage bindaddr;    // 本地绑定地址信息
    struct sockaddr_storage tcpdns1_addr; // 第一个TCP DNS服务器地址
    struct sockaddr_storage tcpdns2_addr; // 第二个TCP DNS服务器地址
    char *bind;         // 本地绑定地址字符串表示（如"0.0.0.0:53"）
    char *tcpdns1;      // 第一个TCP DNS服务器地址字符串
    char *tcpdns2;      // 第二个TCP DNS服务器地址字符串
    uint16_t timeout;   // DNS响应超时时间（秒）
} tcpdns_config;

/* TCPDNS实例结构体 */
typedef struct tcpdns_instance_t {
    list_head       list;       // 链表节点，用于将实例链接到全局列表
    tcpdns_config   config;     // 实例配置信息
    struct event *  listener;   // libevent监听事件对象
    list_head       requests;   // 当前处理的请求链表
    
    /* DNS解析器状态跟踪数据 */
    int             udp1_delay_ms;  // UDP DNS服务器1的延迟（毫秒）
    int             udp2_delay_ms;  // UDP DNS服务器2的延迟（毫秒） 
    int             tcp1_delay_ms;  // TCP DNS服务器1的延迟（毫秒）
    int             tcp2_delay_ms;  // TCP DNS服务器2的延迟（毫秒）
} tcpdns_instance;

/* DNS协议头部结构体（按网络字节序）*/
typedef struct dns_header_t {
    uint16_t id;                // 事务ID（用于匹配请求/响应）
    
    /* 标志位字段（高位到低位）*/
    uint8_t qr_opcode_aa_tc_rd; // 包含：
                                // QR(1): 0=查询,1=响应
                                // OPCODE(4): 操作码
                                // AA(1): 授权回答
                                // TC(1): 截断标志
                                // RD(1): 递归期望
    
    uint8_t ra_z_rcode;         // 包含：
                                // RA(1): 递归可用
                                // Z(3): 保留位
                                // RCODE(4): 响应码
    
    uint16_t qdcount;           // 问题部分记录数
    uint16_t ancount;           // 回答部分记录数
    uint16_t nscount;           // 授权部分记录数
    uint16_t arcount;           // 附加部分记录数
} PACKED dns_header;  // PACKED确保编译器不进行内存对齐优化

/* DNS请求结构体 */
typedef struct dns_request_t {
    list_head           list;           // 链表节点，用于链接到实例的请求列表
    tcpdns_instance *   instance;       // 所属TCPDNS实例指针
    short               state;          // 请求状态（STATE_NEW/REQUEST_SENT等）
    int                 flags;          // 标志位（FLAG_TCP_TEST等）
    struct bufferevent* resolver;       // 与上游DNS服务器的连接bufferevent
    struct sockaddr_storage client_addr; // 客户端原始地址信息
    
    struct timeval      req_time;       // 请求开始时间（用于计算延迟）
    int *               delay;          // 指向当前使用的DNS服务器延迟变量
    size_t              data_len;       // DNS请求数据长度
    
    /* DNS请求数据联合体 */
    union {
        char            raw[513];      // 原始数据缓冲区（DNS超过512字节需用TCP）
        dns_header      header;         // 解析为DNS头部的视图
    } data;
} dns_request;

#endif /* TCPDNS_H */