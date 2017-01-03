
#ifndef FREERTOS_SOCKETS_H
#define FREERTOS_SOCKETS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ��׼ͷ�ļ� */
#include <string.h>

/* �û������� */
#include "FreeRTOSIPConfig.h"

#ifndef FREERTOS_IP_CONFIG_H
    #error FreeRTOSIPConfig.h has not been included yet
#endif

/* �¼�λ��ѡ������Ҫ */
#include "event_groups.h"

#ifndef INC_FREERTOS_H
    #error FreeRTOS.h must be included before FreeRTOS_Sockets.h.
#endif

#ifndef INC_TASK_H
    #ifndef TASK_H /* ���ϰ汾FREERTOS���� */
        #error The FreeRTOS header file task.h must be included before FreeRTOS_Sockets.h.
    #endif
#endif

/* �׽�����Чʱ������ֵ���п�����Ϊ�����ܱ����� */
#define FREERTOS_INVALID_SOCKET ( ( void * ) ~0U )

/* API function error values.  As errno is supported, the FreeRTOS sockets
functions return error codes rather than just a pass or fail indication. */
/* HT: Extended the number of error codes, gave them positive values and if possible
the corresponding found in errno.h
In case of an error, API's will still return negative numbers, e.g.
  return -pdFREERTOS_ERRNO_EWOULDBLOCK;
in case an operation would block */

/* The following defines are obsolete, please use -pdFREERTOS_ERRNO_Exxx */
/* API ��������ֵ��FreeRTOS���ش����������ǽ���һ��fail����errno.h�п����ҵ�һЩ
�ڴ��������£� */
#define FREERTOS_SOCKET_ERROR   ( -1 )
#define FREERTOS_EWOULDBLOCK    ( - pdFREERTOS_ERRNO_EWOULDBLOCK )
#define FREERTOS_EINVAL         ( - pdFREERTOS_ERRNO_EINVAL )
#define FREERTOS_EADDRNOTAVAIL  ( - pdFREERTOS_ERRNO_EADDRNOTAVAIL )
#define FREERTOS_EADDRINUSE     ( - pdFREERTOS_ERRNO_EADDRINUSE )
#define FREERTOS_ENOBUFS        ( - pdFREERTOS_ERRNO_ENOBUFS )
#define FREERTOS_ENOPROTOOPT    ( - pdFREERTOS_ERRNO_ENOPROTOOPT )
#define FREERTOS_ECLOSED        ( - pdFREERTOS_ERRNO_ENOTCONN )

/* FreeRTOS_socket() �Ĳ���ֵ �� ����˱�׼һ�� ������Ϣ��鿴 FreeRTOS_socket()���ĵ�*/
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

/* ���ݸ� FreeRTOS_sendto() �ı�־λ������ʹ���㸴�ƣ�������Ϣ�鿴 FreeRTOS_sockets() �ĵ�*/
#define FREERTOS_ZERO_COPY      ( 1 )

/* ���ݸ� FreeRTOS_setsockopt() ��ѡ��ֵ  */
#define FREERTOS_SO_RCVTIMEO            ( 0 )       /* ���ý��ճ�ʱ */
#define FREERTOS_SO_SNDTIMEO            ( 1 )       /* ���÷��ͳ�ʱ */
#define FREERTOS_SO_UDPCKSUM_OUT        ( 2 )       /* ���ڴ򿪻�ر�һ��socket��UDPУ���ʹ�á���Ҳ������Ϊһ��8λλ�׽���ѡ��֡� */
#if( ipconfigSOCKET_HAS_USER_SEMAPHORE == 1 )
    #define FREERTOS_SO_SET_SEMAPHORE   ( 3 )       /* �����û��ź��� */
#endif
#define FREERTOS_SO_SNDBUF              ( 4 )       /* ���÷��ͻ����С (TCP only) */
#define FREERTOS_SO_RCVBUF              ( 5 )       /* ���ý��ܻ����С (TCP only) */

#if ipconfigUSE_CALLBACKS == 1
#define FREERTOS_SO_TCP_CONN_HANDLER    ( 6 )       /* ��װ(�Ͽ�)�����¼��ص����� �ṩ��F_TCP_UDP_Handler_t��ָ�� */
#define FREERTOS_SO_TCP_RECV_HANDLER    ( 7 )       /* ��װ����TCP�����¼��ص����� �ṩ��F_TCP_UDP_Handler_t��ָ�� */
#define FREERTOS_SO_TCP_SENT_HANDLER    ( 8 )       /* ��װ����TCP�����¼��ص����� �ṩ��F_TCP_UDP_Handler_t��ָ�� */
#define FREERTOS_SO_UDP_RECV_HANDLER    ( 9 )       /* ��װ����UDP�����¼��ص����� �ṩ��F_TCP_UDP_Handler_t��ָ�� */
#define FREERTOS_SO_UDP_SENT_HANDLER    ( 10 )      /* ��װ����UDP�����¼��ص����� �ṩ��F_TCP_UDP_Handler_t��ָ�� */
#endif /* ipconfigUSE_CALLBACKS */

#define FREERTOS_SO_REUSE_LISTEN_SOCKET ( 11 )      /* ���ڼ������׽��ֵõ����ӣ������������ظ����ô��׽��� */
#define FREERTOS_SO_CLOSE_AFTER_SEND    ( 12 )      /* һ���������ݴ�����ɣ��ر����� */
#define FREERTOS_SO_WIN_PROPERTIES      ( 13 )      /* ��һ���������������л���ʹ��ڵ����ԣ�����ָ��WinProperties_t */
#define FREERTOS_SO_SET_FULL_SIZE       ( 14 )      /* �ܾ�����С��MSS�İ� */

#define FREERTOS_SO_STOP_RX             ( 15 )      /* �򵥵Ĺ�����գ�������ý��ͻ��� */

#if( ipconfigUDP_MAX_RX_PACKETS > 0 )
    #define FREERTOS_SO_UDP_MAX_RX_PACKETS  ( 16 )      /* ��ѡ�����������UDP�׽��ֵĽ��Ỻ����������� */
#endif

#define FREERTOS_NOT_LAST_IN_FRAGMENTED_PACKET  ( 0x80 )  /* �����ڲ�ʹ�ã���Ҳ��һ������8λֵ�� */
#define FREERTOS_FRAGMENTED_PACKET              ( 0x40 )  /* �����ڲ�ʹ�ã���Ҳ��һ������8λֵ�� */

/* Values for flag for FreeRTOS_shutdown(). */
#define FREERTOS_SHUT_RD                ( 0 )       /* Not really at this moment, ֻ��Ϊ�˽ӿڵļ����� */
#define FREERTOS_SHUT_WR                ( 1 )
#define FREERTOS_SHUT_RDWR              ( 2 )

/* Values for flag for FreeRTOS_recv(). */
#define FREERTOS_MSG_OOB                ( 2 )       /* ����������� */
#define FREERTOS_MSG_PEEK               ( 4 )       /* ͵����������Ϣ */
#define FREERTOS_MSG_DONTROUTE          ( 8 )       /* ��ʹ��·�ɱ��� */
#define FREERTOS_MSG_DONTWAIT           ( 16 )      /* ���Ա� recvfrom(), sendto(), recv(), and send().ʹ�� */

typedef struct xWIN_PROPS {
    /* Tx Buffer �� windows ������ */
    int32_t lTxBufSize; /* ��λ���ֽ� */
    int32_t lTxWinSize; /* ��λ��MSS */

    /* Rx Buffer �� windows ������ */
    int32_t lRxBufSize; /* ��λ���ֽ� */
    int32_t lRxWinSize; /* ��λ��MSS */
} WinProperties_t;

/* Ϊ����Ԥ�ڲ������׽����������� */
#define socklen_t uint32_t

/* ����������޵�ʵ��, �ڲ����˷����׽��ֽṹ��ֻ��������Ա�Ǳ���� */
struct freertos_sockaddr
{
    /* ��32λ��64λ�ܹ��ϣ���ӵ�����uint8_t���򲻻�ʹ�ýṹ�������ڶ����ԭ��������ΪIPv6Ϊ׼�� */
    /* sin_len �� sin_family ֻ��IPv4��ʹ�� */
    uint8_t sin_len;        /* �ṹ�峤�� */
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

/* �׽�������. */
typedef void *Socket_t;

/* �׽��ּ��� */
typedef void *SocketSet_t;

/* ������ ���µĺ�**�Ĳο��ĵ������µ�URL����Ч��http://www.FreeRTOS.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/FreeRTOS_TCP_API_Functions.html */
Socket_t FreeRTOS_socket( BaseType_t xDomain, BaseType_t xType, BaseType_t xProtocol );
int32_t FreeRTOS_recvfrom( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags, struct freertos_sockaddr *pxSourceAddress, socklen_t *pxSourceAddressLength );
int32_t FreeRTOS_sendto( Socket_t xSocket, const void *pvBuffer, size_t xTotalDataLength, BaseType_t xFlags, const struct freertos_sockaddr *pxDestinationAddress, socklen_t xDestinationAddressLength );
BaseType_t FreeRTOS_bind( Socket_t xSocket, struct freertos_sockaddr *pxAddress, socklen_t xAddressLength );

/* ��ȡ���ص�ַ�Ͷ˿ڵĺ��� */
size_t FreeRTOS_GetLocalAddress( Socket_t xSocket, struct freertos_sockaddr *pxAddress );

/* ��ipconfigETHERNET_DRIVER_FILTERS_PACKETSΪ1ʱ��Ч */
BaseType_t xPortHasUDPSocket( uint16_t usPortNr );

#if ipconfigUSE_TCP == 1

BaseType_t FreeRTOS_connect( Socket_t xClientSocket, struct freertos_sockaddr *pxAddress, socklen_t xAddressLength );
BaseType_t FreeRTOS_listen( Socket_t xSocket, BaseType_t xBacklog );
BaseType_t FreeRTOS_recv( Socket_t xSocket, void *pvBuffer, size_t xBufferLength, BaseType_t xFlags );
BaseType_t FreeRTOS_send( Socket_t xSocket, const void *pvBuffer, size_t uxDataLength, BaseType_t xFlags );
Socket_t FreeRTOS_accept( Socket_t xServerSocket, struct freertos_sockaddr *pxAddress, socklen_t *pxAddressLength );
BaseType_t FreeRTOS_shutdown (Socket_t xSocket, BaseType_t xHow);

#if( ipconfigSUPPORT_SIGNALS != 0 )
    /* ���ȴ������׽��ֵ�����һ���ź� */
    BaseType_t FreeRTOS_SignalSocket( Socket_t xSocket );
    /* ��������׽��ֶ�ȡ���ݵ� ���� һ���źţ�FromISR �汾�� */
    BaseType_t FreeRTOS_SignalSocketFromISR( Socket_t xSocket, BaseType_t *pxHigherPriorityTaskWoken );
#endif /* ipconfigSUPPORT_SIGNALS */
/* ����Զ�̵ĵ�ַ�Ͷ˿ں� */
BaseType_t FreeRTOS_GetRemoteAddress( Socket_t xSocket, struct freertos_sockaddr *pxAddress );
/* ���TCP�׽������ӣ����� pdTRUE*/
BaseType_t FreeRTOS_issocketconnected( Socket_t xSocket );
/* ���ر�ʹ�õ�ʵ�ʵ�MSSֵ */
BaseType_t FreeRTOS_mss( Socket_t xSocket );
/* ֻ���ڲ�ʹ�ã���������״̬ */
BaseType_t FreeRTOS_connstatus( Socket_t xSocket );
/* ���ؿ��Լ��뵽txStream���ֽ��� */
BaseType_t FreeRTOS_maywrite( Socket_t xSocket );
/* ��������������Ҫ�����ڲ��� rx_size����Rx�������п����õ��ֽ�����
tx_space ���� Tx �����еĿ��д�С*/
BaseType_t FreeRTOS_rx_size( Socket_t xSocket );
BaseType_t FreeRTOS_tx_space( Socket_t xSocket );
BaseType_t FreeRTOS_tx_size( Socket_t xSocket );
/* ����txStream�ȴ� ȷ�ϵ��ֽ��� */
/* ���� FreeRTOS_outstanding() �� FreeRTOS_tx_size()ʵ��*/
#define FreeRTOS_outstanding( xSocket ) FreeRTOS_tx_size( xSocket )
/* ���� rxStream �е��ֽ��������� FreeRTOS_recvcount() �� FreeRTOS_rx_size()ʵ�� */
#define FreeRTOS_recvcount( xSocket )   FreeRTOS_rx_size( xSocket )
/* Ϊ�߼��û�ʹ�ã�
��ȡָ���λ�������ָ�� *pxLength ��ָ����д���ֽ��� */
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
/* TCP �׽��ֵ� ����/�Ͽ� ��� */
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
/* TCP �׽��ֵ� ���վ�� */
typedef BaseType_t (* FOnTCPReceive_t )( Socket_t /* xSocket */, void * /* pData */, size_t /* xLength */ );
typedef void (* FOnTCPSent_t )( Socket_t /* xSocket */, size_t /* xLength */ );

/*
 * Reception handler for a UDP socket
 * A user-proved function will be called on reception of a message
 * If the handler returns a positive number, the messages will not be stored
 */
/* UDP �׽��ֵ� ���վ�� */
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
/* ����������������軷�λ�������飬HTML�����뿴һ���Ƿ�����13/10/13/10���� */
const struct xSTREAM_BUFFER *FreeRTOS_get_rx_buf( Socket_t xSocket );

void FreeRTOS_netstat( void );

#if ipconfigSUPPORT_SELECT_FUNCTION == 1
    /* ���� FD_SET �� FD_CLR ���µĽ�Ͽ��Ա�ʹ��*/
    typedef enum eSELECT_EVENT {
        eSELECT_READ    = 0x0001,
        eSELECT_WRITE   = 0x0002,
        eSELECT_EXCEPT  = 0x0004,
        eSELECT_INTR    = 0x0008,
        eSELECT_ALL     = 0x000F,
        /* ����Ϊ�ڲ�ʹ�� */
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













