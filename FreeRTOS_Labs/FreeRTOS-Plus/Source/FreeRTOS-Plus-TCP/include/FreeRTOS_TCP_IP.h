
#ifndef FREERTOS_TCP_IP_H
#define FREERTOS_TCP_IP_H

#ifdef __cplusplus
extern "C" {
#endif

BaseType_t xProcessReceivedTCPPacket( NetworkBufferDescriptor_t *pxNetworkBuffer );

typedef enum eTCP_STATE {
    /* Comments about the TCP states are borrowed from the very useful
     * Wiki page:
     * http://en.wikipedia.org/wiki/Transmission_Control_Protocol */
    eCLOSED = 0u,   /* 0 (server + client) 没有连接状态 */
    eTCP_LISTEN,    /* 1 (server) 等待连接请求 */
    eCONNECT_SYN,   /* 2 (client) 内部状态: 套接字想发送连接 */
    eSYN_FIRST,     /* 3 (server) 刚刚创建, 必须应答SYN请求 */
    eSYN_RECEIVED,  /* 4 (server) 需要连接请求的应答在已经接收到并发送连接请求之后 */
    eESTABLISHED,   /* 5 (server + client) 已连接，数据可以传输，数据传输阶段的正常状态 */
    eFIN_WAIT_1,    /* 6 (server+client)等待远程TCP发送结束请求或者已经确认了远程TCP的结束请求*/
    eFIN_WAIT_2,    /* 7 (server + client) 等待远程TCP发送结束请求 */
    eCLOSE_WAIT,    /* 8 (server + client) 等待本地用户的结束请求 */
    eCLOSING,       /*   (server + client) 等待远程对结束请求的确认 */
    eLAST_ACK,      /* 9 (server + client) 等待远程的结束请求确认(也包括了对他们连接请求的确认). */
    eTIME_WAIT,     /* 10 (either server or client) 等待足够长时间以确保远程的到了结束请求  */
} eIPTCPState_t;


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* FREERTOS_TCP_IP_H */













