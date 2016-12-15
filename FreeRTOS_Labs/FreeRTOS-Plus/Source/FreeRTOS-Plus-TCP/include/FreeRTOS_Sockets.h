
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
    #define FREERTOS_SO_UDP_MAX_RX_PACKETS  ( 16 )      /* This option helps to limit the maximum number of packets a UDP socket will buffer */
#endif

#define FREERTOS_NOT_LAST_IN_FRAGMENTED_PACKET  ( 0x80 )  /* For internal use only, but also part of an 8-bit bitwise value. */
#define FREERTOS_FRAGMENTED_PACKET              ( 0x40 )  /* For internal use only, but also part of an 8-bit bitwise value. */

/* Values for flag for FreeRTOS_shutdown(). */
#define FREERTOS_SHUT_RD                ( 0 )       /* Not really at this moment, just for compatibility of the interface */
#define FREERTOS_SHUT_WR                ( 1 )
#define FREERTOS_SHUT_RDWR              ( 2 )

/* Values for flag for FreeRTOS_recv(). */
#define FREERTOS_MSG_OOB                ( 2 )       /* process out-of-band data */
#define FREERTOS_MSG_PEEK               ( 4 )       /* peek at incoming message */
#define FREERTOS_MSG_DONTROUTE          ( 8 )       /* send without using routing tables */
#define FREERTOS_MSG_DONTWAIT           ( 16 )      /* Can be used with recvfrom(), sendto(), recv(), and send(). */

typedef struct xWIN_PROPS {
    /* Properties of the Tx buffer and Tx window */
    int32_t lTxBufSize; /* Unit: bytes */
    int32_t lTxWinSize; /* Unit: MSS */

    /* Properties of the Rx buffer and Rx window */
    int32_t lRxBufSize; /* Unit: bytes */
    int32_t lRxWinSize; /* Unit: MSS */
} WinProperties_t;

/* For compatibility with the expected Berkeley sockets naming. */
#define socklen_t uint32_t

/* For this limited implementation, only two members are required in the
Berkeley style sockaddr structure. */
struct freertos_sockaddr
{
    /* _HT_ On 32- and 64-bit architectures, the addition of the two uint8_t
    fields doesn't make the structure bigger, due to alignment.
    The fields are inserted as a preparation for IPv6. */

    /* sin_len and sin_family not used in the IPv4-only release. */
    uint8_t sin_len;        /* length of this structure. */
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

/* The socket type itself. */
typedef void *Socket_t;

/* The SocketSet_t type is the equivalent to the fd_set type used by the
Berkeley API. */
typedef void *SocketSet_t;

/**
 * FULL, UP-TO-DATE AND MAINTAINED REFERENCE DOCUMENTATION FOR ALL THESE
 * FUNCTIONS IS AVAILABLE ON THE FOLLOWING URL:
 * http://www.FreeRTOS.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/FreeRTOS_TCP_API_Functions.html
 */
Socket_t FreeRTOS_socket( BaseType_t xDomain, BaseType_t xType, BaseType_t xProtocol );
int32_t FreeRTOS_recvfrom( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags, struct freertos_sockaddr *pxSourceAddress, socklen_t *pxSourceAddressLength );
int32_t FreeRTOS_sendto( Socket_t xSocket, const void *pvBuffer, size_t xTotalDataLength, BaseType_t xFlags, const struct freertos_sockaddr *pxDestinationAddress, socklen_t xDestinationAddressLength );
BaseType_t FreeRTOS_bind( Socket_t xSocket, struct freertos_sockaddr *pxAddress, socklen_t xAddressLength );

/* function to get the local address and IP port */
size_t FreeRTOS_GetLocalAddress( Socket_t xSocket, struct freertos_sockaddr *pxAddress );

/* Made available when ipconfigETHERNET_DRIVER_FILTERS_PACKETS is set to 1. */
BaseType_t xPortHasUDPSocket( uint16_t usPortNr );

#if ipconfigUSE_TCP == 1

BaseType_t FreeRTOS_connect( Socket_t xClientSocket, struct freertos_sockaddr *pxAddress, socklen_t xAddressLength );
BaseType_t FreeRTOS_listen( Socket_t xSocket, BaseType_t xBacklog );
BaseType_t FreeRTOS_recv( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags );
BaseType_t FreeRTOS_send( Socket_t xSocket, const void *pvBuffer, size_t uxDataLength, BaseType_t xFlags );
Socket_t FreeRTOS_accept( Socket_t xServerSocket, struct freertos_sockaddr *pxAddress, socklen_t *pxAddressLength );
BaseType_t FreeRTOS_shutdown (Socket_t xSocket, BaseType_t xHow);

#if( ipconfigSUPPORT_SIGNALS != 0 )
    /* Send a signal to the task which is waiting for a given socket. */
    BaseType_t FreeRTOS_SignalSocket( Socket_t xSocket );

    /* Send a signal to the task which reads from this socket (FromISR
    version). */
    BaseType_t FreeRTOS_SignalSocketFromISR( Socket_t xSocket, BaseType_t *pxHigherPriorityTaskWoken );
#endif /* ipconfigSUPPORT_SIGNALS */

/* Return the remote address and IP port. */
BaseType_t FreeRTOS_GetRemoteAddress( Socket_t xSocket, struct freertos_sockaddr *pxAddress );

/* returns pdTRUE if TCP socket is connected */
BaseType_t FreeRTOS_issocketconnected( Socket_t xSocket );

/* returns the actual size of MSS being used */
BaseType_t FreeRTOS_mss( Socket_t xSocket );

/* for internal use only: return the connection status */
BaseType_t FreeRTOS_connstatus( Socket_t xSocket );

/* Returns the number of bytes that may be added to txStream */
BaseType_t FreeRTOS_maywrite( Socket_t xSocket );

/*
 * Two helper functions, mostly for testing
 * rx_size returns the number of bytes available in the Rx buffer
 * tx_space returns the free space in the Tx buffer
 */
BaseType_t FreeRTOS_rx_size( Socket_t xSocket );
BaseType_t FreeRTOS_tx_space( Socket_t xSocket );
BaseType_t FreeRTOS_tx_size( Socket_t xSocket );

/* Returns the number of outstanding bytes in txStream. */
/* The function FreeRTOS_outstanding() was already implemented
FreeRTOS_tx_size(). */
#define FreeRTOS_outstanding( xSocket ) FreeRTOS_tx_size( xSocket )

/* Returns the number of bytes in the socket's rxStream. */
/* The function FreeRTOS_recvcount() was already implemented
FreeRTOS_rx_size(). */
#define FreeRTOS_recvcount( xSocket )   FreeRTOS_rx_size( xSocket )

/*
 * For advanced applications only:
 * Get a direct pointer to the circular transmit buffer.
 * '*pxLength' will contain the number of bytes that may be written.
 */
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
typedef BaseType_t (* FOnTCPReceive_t )( Socket_t /* xSocket */, void * /* pData */, size_t /* xLength */ );
typedef void (* FOnTCPSent_t )( Socket_t /* xSocket */, size_t /* xLength */ );

/*
 * Reception handler for a UDP socket
 * A user-proved function will be called on reception of a message
 * If the handler returns a positive number, the messages will not be stored
 */
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

/*
 * For the web server: borrow the circular Rx buffer for inspection
 * HTML driver wants to see if a sequence of 13/10/13/10 is available
 */
const struct xSTREAM_BUFFER *FreeRTOS_get_rx_buf( Socket_t xSocket );

void FreeRTOS_netstat( void );

#if ipconfigSUPPORT_SELECT_FUNCTION == 1

    /* For FD_SET and FD_CLR, a combination of the following bits can be used: */

    typedef enum eSELECT_EVENT {
        eSELECT_READ    = 0x0001,
        eSELECT_WRITE   = 0x0002,
        eSELECT_EXCEPT  = 0x0004,
        eSELECT_INTR    = 0x0008,
        eSELECT_ALL     = 0x000F,
        /* Reserved for internal use: */
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













