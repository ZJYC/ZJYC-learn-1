
#ifndef FREERTOS_SOCKETS_H
#define FREERTOS_SOCKETS_H

#ifdef __cplusplus
extern "C" {
#endif

/* 标准头文件 */
#include <string.h>

/* 用户层配置 */
#include "FreeRTOSIPConfig.h"

#ifndef FREERTOS_IP_CONFIG_H
    #error FreeRTOSIPConfig.h has not been included yet
#endif

/* 事件位被选择函数需要 */
#include "event_groups.h"

#ifndef INC_FREERTOS_H
    #error FreeRTOS.h must be included before FreeRTOS_Sockets.h.
#endif

#ifndef INC_TASK_H
    #ifndef TASK_H /* 与老版本FREERTOS兼容 */
        #error The FreeRTOS header file task.h must be included before FreeRTOS_Sockets.h.
    #endif
#endif

/* 套接字无效时被赋的值，有可能因为他不能被创建 */
#define FREERTOS_INVALID_SOCKET ( ( void * ) ~0U )

/* API function error values.  As errno is supported, the FreeRTOS sockets
functions return error codes rather than just a pass or fail indication. */
/* HT: Extended the number of error codes, gave them positive values and if possible
the corresponding found in errno.h
In case of an error, API's will still return negative numbers, e.g.
  return -pdFREERTOS_ERRNO_EWOULDBLOCK;
in case an operation would block */

/* The following defines are obsolete, please use -pdFREERTOS_ERRNO_Exxx */
/* API 函数错误值。FreeRTOS传回错误代码而不是仅仅一个fail，在errno.h中可以找到一些
在错误的情况下， */
#define FREERTOS_SOCKET_ERROR   ( -1 )
#define FREERTOS_EWOULDBLOCK    ( - pdFREERTOS_ERRNO_EWOULDBLOCK )
#define FREERTOS_EINVAL         ( - pdFREERTOS_ERRNO_EINVAL )
#define FREERTOS_EADDRNOTAVAIL  ( - pdFREERTOS_ERRNO_EADDRNOTAVAIL )
#define FREERTOS_EADDRINUSE     ( - pdFREERTOS_ERRNO_EADDRINUSE )
#define FREERTOS_ENOBUFS        ( - pdFREERTOS_ERRNO_ENOBUFS )
#define FREERTOS_ENOPROTOOPT    ( - pdFREERTOS_ERRNO_ENOPROTOOPT )
#define FREERTOS_ECLOSED        ( - pdFREERTOS_ERRNO_ENOTCONN )

/* FreeRTOS_socket() 的参数值 与 伯里克标准一致 更多信息请查看 FreeRTOS_socket()的文档*/
#define FREERTOS_AF_INET        ( 2 )
#define FREERTOS_AF_INET6       ( 10 )
#define FREERTOS_SOCK_DGRAM     ( 2 )
#define FREERTOS_IPPROTO_UDP    ( 17 )

#define FREERTOS_SOCK_STREAM    ( 1 )
#define FREERTOS_IPPROTO_TCP    ( 6 )
/* IP packet of type "Any local network"
 * can be used in stead of TCP for testing with sockets in raw mode
 */
#define FREERTOS_IPPROTO_USR_LAN  ( 63 )

/* 传递给 FreeRTOS_sendto() 的标志位，表明使用零复制，更多信息查看 FreeRTOS_sockets() 文档*/
#define FREERTOS_ZERO_COPY      ( 1 )

/* 传递给 FreeRTOS_setsockopt() 的选项值  */
#define FREERTOS_SO_RCVTIMEO            ( 0 )       /* 设置接收超时 */
#define FREERTOS_SO_SNDTIMEO            ( 1 )       /* 设置发送超时 */
#define FREERTOS_SO_UDPCKSUM_OUT        ( 2 )       /* 用于打开或关闭一个socket的UDP校验和使用。这也可以作为一个8位位套接字选项部分。 */
#if( ipconfigSOCKET_HAS_USER_SEMAPHORE == 1 )
    #define FREERTOS_SO_SET_SEMAPHORE   ( 3 )       /* 设置用户信号量 */
#endif
#define FREERTOS_SO_SNDBUF              ( 4 )       /* 设置发送缓存大小 (TCP only) */
#define FREERTOS_SO_RCVBUF              ( 5 )       /* 设置接受缓存大小 (TCP only) */

#if ipconfigUSE_CALLBACKS == 1
#define FREERTOS_SO_TCP_CONN_HANDLER    ( 6 )       /* 安装(断开)连接事件回调函数 提供到F_TCP_UDP_Handler_t的指针 */
#define FREERTOS_SO_TCP_RECV_HANDLER    ( 7 )       /* 安装接收TCP数据事件回调函数 提供到F_TCP_UDP_Handler_t的指针 */
#define FREERTOS_SO_TCP_SENT_HANDLER    ( 8 )       /* 安装发送TCP数据事件回调函数 提供到F_TCP_UDP_Handler_t的指针 */
#define FREERTOS_SO_UDP_RECV_HANDLER    ( 9 )       /* 安装接收UDP数据事件回调函数 提供到F_TCP_UDP_Handler_t的指针 */
#define FREERTOS_SO_UDP_SENT_HANDLER    ( 10 )      /* 安装发送UDP数据事件回调函数 提供到F_TCP_UDP_Handler_t的指针 */
#endif /* ipconfigUSE_CALLBACKS */

#define FREERTOS_SO_REUSE_LISTEN_SOCKET ( 11 )      /* 正在监听的套接字得到连接，不创建而是重复利用此套接字 */
#define FREERTOS_SO_CLOSE_AFTER_SEND    ( 12 )      /* 一旦最后的数据传输完成，关闭连接 */
#define FREERTOS_SO_WIN_PROPERTIES      ( 13 )      /* 在一个调用中设置所有缓冲和窗口的属性，参数指向WinProperties_t */
#define FREERTOS_SO_SET_FULL_SIZE       ( 14 )      /* 拒绝发送小于MSS的包 */

#define FREERTOS_SO_STOP_RX             ( 15 )      /* 简单的挂起接收，用于流媒体客户端 */

#if( ipconfigUDP_MAX_RX_PACKETS > 0 )
    #define FREERTOS_SO_UDP_MAX_RX_PACKETS  ( 16 )      /* 此选项帮助与限制UDP套接字的将会缓存的最大包个数 */
#endif

#define FREERTOS_NOT_LAST_IN_FRAGMENTED_PACKET  ( 0x80 )  /* 仅供内部使用，但也有一部分是8位值。 */
#define FREERTOS_FRAGMENTED_PACKET              ( 0x40 )  /* 仅供内部使用，但也有一部分是8位值。 */

/* Values for flag for FreeRTOS_shutdown(). */
#define FREERTOS_SHUT_RD                ( 0 )       /* Not really at this moment, 只是为了接口的兼容性 */
#define FREERTOS_SHUT_WR                ( 1 )
#define FREERTOS_SHUT_RDWR              ( 2 )

/* Values for flag for FreeRTOS_recv(). */
#define FREERTOS_MSG_OOB                ( 2 )       /* 处理带外数据 */
#define FREERTOS_MSG_PEEK               ( 4 )       /* 偷看进来的信息 */
#define FREERTOS_MSG_DONTROUTE          ( 8 )       /* 不使用路由表发送 */
#define FREERTOS_MSG_DONTWAIT           ( 16 )      /* 可以被 recvfrom(), sendto(), recv(), and send().使用 */

typedef struct xWIN_PROPS {
    /* Tx Buffer 和 windows 的属性 */
    int32_t lTxBufSize; /* 单位：字节 */
    int32_t lTxWinSize; /* 单位：MSS */

    /* Rx Buffer 和 windows 的属性 */
    int32_t lRxBufSize; /* 单位：字节 */
    int32_t lRxWinSize; /* 单位：MSS */
} WinProperties_t;

/* 为了与预期伯克利套接字命名兼容 */
#define socklen_t uint32_t

/* 对于这个有限的实现, 在伯力克风格的套接字结构中只有两个成员是必须的 */
struct freertos_sockaddr
{
    /* 在32位和64位架构上，添加的两个uint8_t区域不会使得结构体变大，由于对其的原因，这区域为IPv6为准备 */
    /* sin_len 和 sin_family 只在IPv4中使用 */
    uint8_t sin_len;        /* 结构体长度 */
    uint8_t sin_family;     /* FREERTOS_AF_INET. */
    uint16_t sin_port;
    uint32_t sin_addr;
};

#if ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN

    #define FreeRTOS_inet_addr_quick( ucOctet0, ucOctet1, ucOctet2, ucOctet3 )              \
                                        ( ( ( ( uint32_t ) ( ucOctet3 ) ) << 24UL ) |       \
                                        ( ( ( uint32_t ) ( ucOctet2 ) ) << 16UL ) |         \
                                        ( ( ( uint32_t ) ( ucOctet1 ) ) <<  8UL ) |         \
                                        ( ( uint32_t ) ( ucOctet0 ) ) )

    #define FreeRTOS_inet_ntoa( ulIPAddress, pucBuffer )                                    \
                                sprintf( ( char * ) ( pucBuffer ), "%u.%u.%u.%u",           \
                                    ( ( unsigned ) ( ( ulIPAddress ) & 0xffUL ) ),          \
                                    ( ( unsigned ) ( ( ( ulIPAddress ) >> 8 ) & 0xffUL ) ), \
                                    ( ( unsigned ) ( ( ( ulIPAddress ) >> 16 ) & 0xffUL ) ),\
                                    ( ( unsigned ) ( ( ulIPAddress ) >> 24 ) ) )

#else /* ipconfigBYTE_ORDER */

    #define FreeRTOS_inet_addr_quick( ucOctet0, ucOctet1, ucOctet2, ucOctet3 )              \
                                        ( ( ( ( uint32_t ) ( ucOctet0 ) ) << 24UL ) |       \
                                        ( ( ( uint32_t ) ( ucOctet1 ) ) << 16UL ) |         \
                                        ( ( ( uint32_t ) ( ucOctet2 ) ) <<  8UL ) |         \
                                        ( ( uint32_t ) ( ucOctet3 ) ) )

    #define FreeRTOS_inet_ntoa( ulIPAddress, pucBuffer )                                    \
                                sprintf( ( char * ) ( pucBuffer ), "%u.%u.%u.%u",           \
                                    ( ( unsigned ) ( ( ulIPAddress ) >> 24 ) ),             \
                                    ( ( unsigned ) ( ( ( ulIPAddress ) >> 16 ) & 0xffUL ) ),\
                                    ( ( unsigned ) ( ( ( ulIPAddress ) >> 8 ) & 0xffUL ) ), \
                                    ( ( unsigned ) ( ( ulIPAddress ) & 0xffUL ) ) )

#endif /* ipconfigBYTE_ORDER */

/* 套接字类型. */
typedef void *Socket_t;

/* 套接字集合 */
typedef void *SocketSet_t;

/* 完整的 最新的和**的参考文档在如下的URL中有效：http://www.FreeRTOS.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/FreeRTOS_TCP_API_Functions.html */
Socket_t FreeRTOS_socket( BaseType_t xDomain, BaseType_t xType, BaseType_t xProtocol );
int32_t FreeRTOS_recvfrom( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags, struct freertos_sockaddr *pxSourceAddress, socklen_t *pxSourceAddressLength );
int32_t FreeRTOS_sendto( Socket_t xSocket, const void *pvBuffer, size_t xTotalDataLength, BaseType_t xFlags, const struct freertos_sockaddr *pxDestinationAddress, socklen_t xDestinationAddressLength );
BaseType_t FreeRTOS_bind( Socket_t xSocket, struct freertos_sockaddr *pxAddress, socklen_t xAddressLength );

/* 获取本地地址和端口的函数 */
size_t FreeRTOS_GetLocalAddress( Socket_t xSocket, struct freertos_sockaddr *pxAddress );

/* 当ipconfigETHERNET_DRIVER_FILTERS_PACKETS为1时有效 */
BaseType_t xPortHasUDPSocket( uint16_t usPortNr );

#if ipconfigUSE_TCP == 1

BaseType_t FreeRTOS_connect( Socket_t xClientSocket, struct freertos_sockaddr *pxAddress, socklen_t xAddressLength );
BaseType_t FreeRTOS_listen( Socket_t xSocket, BaseType_t xBacklog );
BaseType_t FreeRTOS_recv( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags );
BaseType_t FreeRTOS_send( Socket_t xSocket, const void *pvBuffer, size_t uxDataLength, BaseType_t xFlags );
Socket_t FreeRTOS_accept( Socket_t xServerSocket, struct freertos_sockaddr *pxAddress, socklen_t *pxAddressLength );
BaseType_t FreeRTOS_shutdown (Socket_t xSocket, BaseType_t xHow);

#if( ipconfigSUPPORT_SIGNALS != 0 )
    /* 给等待给定套接字的任务一个信号 */
    BaseType_t FreeRTOS_SignalSocket( Socket_t xSocket );
    /* 给从这个套接字读取数据的 任务 一个信号（FromISR 版本） */
    BaseType_t FreeRTOS_SignalSocketFromISR( Socket_t xSocket, BaseType_t *pxHigherPriorityTaskWoken );
#endif /* ipconfigSUPPORT_SIGNALS */
/* 返回远程的地址和端口号 */
BaseType_t FreeRTOS_GetRemoteAddress( Socket_t xSocket, struct freertos_sockaddr *pxAddress );
/* 如果TCP套接字连接，返回 pdTRUE*/
BaseType_t FreeRTOS_issocketconnected( Socket_t xSocket );
/* 返回被使用的实际的MSS值 */
BaseType_t FreeRTOS_mss( Socket_t xSocket );
/* 只是内部使用，返回连接状态 */
BaseType_t FreeRTOS_connstatus( Socket_t xSocket );
/* 返回可以加入到txStream的字节数 */
BaseType_t FreeRTOS_maywrite( Socket_t xSocket );
/* 两个辅助函数主要是用于测试 rx_size返回Rx缓冲区中可利用的字节数，
tx_space 返回 Tx 缓冲中的空闲大小*/
BaseType_t FreeRTOS_rx_size( Socket_t xSocket );
BaseType_t FreeRTOS_tx_space( Socket_t xSocket );
BaseType_t FreeRTOS_tx_size( Socket_t xSocket );
/* 返回txStream等待 确认的字节数 */
/* 函数 FreeRTOS_outstanding() 用 FreeRTOS_tx_size()实现*/
#define FreeRTOS_outstanding( xSocket ) FreeRTOS_tx_size( xSocket )
/* 返回 rxStream 中的字节数，函数 FreeRTOS_recvcount() 用 FreeRTOS_rx_size()实现 */
#define FreeRTOS_recvcount( xSocket )   FreeRTOS_rx_size( xSocket )
/* 为高级用户使用：
获取指向环形缓冲器的指针 *pxLength 会指明可写的字节数 */
uint8_t *FreeRTOS_get_tx_head( Socket_t xSocket, BaseType_t *pxLength );

#endif /* ipconfigUSE_TCP */

/*
 * Connect / disconnect handler for a TCP socket
 * For example:
 *      static void vMyConnectHandler (Socket_t xSocket, BaseType_t ulConnected)
 *      {
 *      }
 *      F_TCP_UDP_Handler_t xHnd = { vMyConnectHandler };
 *      FreeRTOS_setsockopt( sock, 0, FREERTOS_SO_TCP_CONN_HANDLER, ( void * ) &xHnd, sizeof( xHnd ) );
 */
/* TCP 套接字的 连接/断开 句柄 */
typedef void (* FOnConnected_t )( Socket_t /* xSocket */, BaseType_t /* ulConnected */ );

/*
 * Reception handler for a TCP socket
 * A user-proved function will be called on reception of a message
 * If the handler returns a positive number, the messages will not be stored
 * For example:
 *      static BaseType_t xOnTCPReceive( Socket_t xSocket, void * pData, size_t xLength )
 *      {
 *          // handle the message
 *          return 1;
 *      }
 *      F_TCP_UDP_Handler_t xHand = { xOnTCPReceive };
 *      FreeRTOS_setsockopt( sock, 0, FREERTOS_SO_TCP_RECV_HANDLER, ( void * ) &xHand, sizeof( xHand ) );
 */
/* TCP 套接字的 接收句柄 */
typedef BaseType_t (* FOnTCPReceive_t )( Socket_t /* xSocket */, void * /* pData */, size_t /* xLength */ );
typedef void (* FOnTCPSent_t )( Socket_t /* xSocket */, size_t /* xLength */ );

/*
 * Reception handler for a UDP socket
 * A user-proved function will be called on reception of a message
 * If the handler returns a positive number, the messages will not be stored
 */
/* UDP 套接字的 接收句柄 */
typedef BaseType_t (* FOnUDPReceive_t ) (Socket_t /* xSocket */, void * /* pData */, size_t /* xLength */,
    const struct freertos_sockaddr * /* pxFrom */, const struct freertos_sockaddr * /* pxDest */ );
typedef void (* FOnUDPSent_t )( Socket_t /* xSocket */, size_t /* xLength */ );


typedef union xTCP_UDP_HANDLER
{
    FOnConnected_t  pxOnTCPConnected;   /* FREERTOS_SO_TCP_CONN_HANDLER */
    FOnTCPReceive_t pxOnTCPReceive;     /* FREERTOS_SO_TCP_RECV_HANDLER */
    FOnTCPSent_t    pxOnTCPSent;        /* FREERTOS_SO_TCP_SENT_HANDLER */
    FOnUDPReceive_t pxOnUDPReceive;     /* FREERTOS_SO_UDP_RECV_HANDLER */
    FOnUDPSent_t    pxOnUDPSent;        /* FREERTOS_SO_UDP_SENT_HANDLER */
} F_TCP_UDP_Handler_t;

BaseType_t FreeRTOS_setsockopt( Socket_t xSocket, int32_t lLevel, int32_t lOptionName, const void *pvOptionValue, size_t xOptionLength );
BaseType_t FreeRTOS_closesocket( Socket_t xSocket );
uint32_t FreeRTOS_gethostbyname( const char *pcHostName );
uint32_t FreeRTOS_inet_addr( const char * pcIPAddress );
/* 对于网络服务器，借环形缓冲来检查，HTML驱动想看一看是否序列13/10/13/10可用 */
const struct xSTREAM_BUFFER *FreeRTOS_get_rx_buf( Socket_t xSocket );

void FreeRTOS_netstat( void );

#if ipconfigSUPPORT_SELECT_FUNCTION == 1
    /* 对于 FD_SET 和 FD_CLR 如下的结合可以被使用*/
    typedef enum eSELECT_EVENT {
        eSELECT_READ    = 0x0001,
        eSELECT_WRITE   = 0x0002,
        eSELECT_EXCEPT  = 0x0004,
        eSELECT_INTR    = 0x0008,
        eSELECT_ALL     = 0x000F,
        /* 保留为内部使用 */
        eSELECT_CALL_IP = 0x0010,
        /* end */
    } eSelectEvent_t;

    SocketSet_t FreeRTOS_CreateSocketSet( void );
    void FreeRTOS_DeleteSocketSet( SocketSet_t xSocketSet );
    void FreeRTOS_FD_SET( Socket_t xSocket, SocketSet_t xSocketSet, EventBits_t xBitsToSet );
    void FreeRTOS_FD_CLR( Socket_t xSocket, SocketSet_t xSocketSet, EventBits_t xBitsToClear );
    EventBits_t FreeRTOS_FD_ISSET( Socket_t xSocket, SocketSet_t xSocketSet );
    BaseType_t FreeRTOS_select( SocketSet_t xSocketSet, TickType_t xBlockTimeTicks );

#endif /* ipconfigSUPPORT_SELECT_FUNCTION */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* FREERTOS_SOCKETS_H */













