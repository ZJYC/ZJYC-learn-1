/* TCP协议是TCP/IP协议的重中之重，保证数据连接的可靠性，加入端口号使得不同的进程可以共享网卡 */
/* Standard includes. */
#include <stdint.h>
#include <stdio.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_TCP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_TCP_WIN.h"


/* 好大的一个宏定义！ */
#if ipconfigUSE_TCP == 1

/* 数据大小的判别 */

#if ( ( ipconfigTCP_MSS + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER ) > ipconfigNETWORK_MTU )
    #error The ipconfigTCP_MSS setting in FreeRTOSIPConfig.h is too large.
#endif

/*
 * TCP标志
 */
#define ipTCP_FLAG_FIN          0x0001u /* No more data from sender */
#define ipTCP_FLAG_SYN          0x0002u /* Synchronize sequence numbers */
#define ipTCP_FLAG_RST          0x0004u /* Reset the connection */
#define ipTCP_FLAG_PSH          0x0008u /* Push function: please push buffered data to the recv application */
#define ipTCP_FLAG_ACK          0x0010u /* Acknowledgment field is significant */
#define ipTCP_FLAG_URG          0x0020u /* Urgent pointer field is significant */
#define ipTCP_FLAG_ECN          0x0040u /* ECN-Echo */
#define ipTCP_FLAG_CWR          0x0080u /* Congestion Window Reduced */
#define ipTCP_FLAG_NS           0x0100u /* ECN-nonce concealment protection */
#define ipTCP_FLAG_RSV          0x0E00u /* Reserved, keep 0 */

/* 屏蔽掉协议位的掩码 */
#define ipTCP_FLAG_CTRL         0x001Fu

/*
 * TCP选项
 */
#define TCP_OPT_END             0u   /* End of TCP options list */
#define TCP_OPT_NOOP            1u   /* "No-operation" TCP option */
#define TCP_OPT_MSS             2u   /* Maximum segment size TCP option */
#define TCP_OPT_WSOPT           3u   /* TCP Window Scale Option (3-byte long) */
#define TCP_OPT_SACK_P          4u   /* Advertize that SACK is permitted */
#define TCP_OPT_SACK_A          5u   /* SACK option with first/last */
#define TCP_OPT_TIMESTAMP       8u   /* Time-stamp option */

#define TCP_OPT_MSS_LEN         4u   /* Length of TCP MSS option. */
#define TCP_OPT_WSOPT_LEN       3u   /* Length of TCP WSOPT option. */

#define TCP_OPT_TIMESTAMP_LEN   10  /* fixed length of the time-stamp option */

#ifndef ipconfigTCP_ACK_EARLIER_PACKET
    #define ipconfigTCP_ACK_EARLIER_PACKET      1
#endif

/*
 * The macro NOW_CONNECTED() is use to determine if the connection makes a
 * transition from connected to non-connected and vice versa.
 * NOW_CONNECTED() returns true when the status has one of these values:
 * eESTABLISHED, eFIN_WAIT_1, eFIN_WAIT_2, eCLOSING, eLAST_ACK, eTIME_WAIT
 * Technically the connection status is closed earlier, but the library wants
 * to prevent that the socket will be deleted before the last ACK has been
 * and thus causing a 'RST' packet on either side.
 */
#define NOW_CONNECTED( status )\
    ( ( status >= eESTABLISHED ) && ( status != eCLOSE_WAIT ) )

/* 高四位表示TCP报文头大小 */
#define VALID_BITS_IN_TCP_OFFSET_BYTE       ( 0xF0u )

/* 对于TCP数据的确认需要延迟一段时间，通常是200ms，20ms是为了提供较高的表现 */
#define DELAYED_ACK_SHORT_DELAY_MS          ( 2 )
#define DELAYED_ACK_LONGER_DELAY_MS         ( 20 )

/* 1460并不能通过网络，仍会减少到1400 */
#define REDUCED_MSS_THROUGH_INTERNET        ( 1400 )

/* 每次建立TCP连接就会使用一个初始的序列号，序列号最好以0x102的大小自增 */
#define INITIAL_SEQUENCE_NUMBER_INCREMENT       ( 0x102UL )

/*
 * When there are no TCP options, the TCP offset equals 20 bytes, which is stored as
 * the number 5 (words) in the higher niblle of the TCP-offset byte.
 */
/* 如果不使用TCP选项，TCP头的大小为20字节，表示为5个字 */
#define TCP_OFFSET_LENGTH_BITS          ( 0xf0u )
#define TCP_OFFSET_STANDARD_LENGTH      ( 0x50u )

/* 应当定期检查每一个套接字，以确保其能否发送数据。通常这样的检查的包的最大数量会被限制为8，如果设置窗口则会进一步限制此数值 */
#if( !defined( SEND_REPEATED_COUNT ) )
    #define SEND_REPEATED_COUNT     ( 8 )
#endif /* !defined( SEND_REPEATED_COUNT ) */

/* 不同状态时的名称 */
#if( ( ipconfigHAS_DEBUG_PRINTF != 0 ) || ( ipconfigHAS_PRINTF != 0 ) )
    static const char *pcStateNames[] = {
        "eCLOSED",
        "eTCP_LISTEN",
        "eCONNECT_SYN",
        "eSYN_FIRST",
        "eSYN_RECEIVED",
        "eESTABLISHED",
        "eFIN_WAIT_1",
        "eFIN_WAIT_2",
        "eCLOSE_WAIT",
        "eCLOSING",
        "eLAST_ACK",
        "eTIME_WAIT",
        "eUNKNOWN",
};
#endif /* ( ipconfigHAS_DEBUG_PRINTF != 0 ) || ( ipconfigHAS_PRINTF != 0 ) */

/*
 * Returns true if the socket must be checked.  Non-active sockets are waiting
 * for user action, either connect() or close().
 */
static BaseType_t prvTCPSocketIsActive( UBaseType_t uxStatus );

/*
 * Either sends a SYN or calls prvTCPSendRepeated (for regular messages).
 */
static int32_t prvTCPSendPacket( FreeRTOS_Socket_t *pxSocket );

/*
 * Try to send a series of messages.
 */
static int32_t prvTCPSendRepeated( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer );

/*
 * Return or send a packet to the other party.
 */
static void prvTCPReturnPacket( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer,
    uint32_t ulLen, BaseType_t xReleaseAfterSend );

/*
 * Initialise the data structures which keep track of the TCP windowing system.
 */
static void prvTCPCreateWindow( FreeRTOS_Socket_t *pxSocket );

/*
 * Let ARP look-up the MAC-address of the peer and initialise the first SYN
 * packet.
 */
static BaseType_t prvTCPPrepareConnect( FreeRTOS_Socket_t *pxSocket );

#if( ipconfigHAS_DEBUG_PRINTF != 0 )
    /*
     * For logging and debugging: make a string showing the TCP flags.
     */
    static const char *prvTCPFlagMeaning( UBaseType_t xFlags);
#endif /* ipconfigHAS_DEBUG_PRINTF != 0 */

/* 检查TCP选项 */
static void prvCheckOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/*
 * Set the initial properties in the options fields, like the preferred
 * value of MSS and whether SACK allowed.  Will be transmitted in the state
 * 'eCONNECT_SYN'.
 */
static UBaseType_t prvSetSynAckOptions( FreeRTOS_Socket_t *pxSocket, TCPPacket_t * pxTCPPacket );

/*
 * For anti-hang protection and TCP keep-alive messages.  Called in two places:
 * after receiving a packet and after a state change.  The socket's alive timer
 * may be reset.
 */
static void prvTCPTouchSocket( FreeRTOS_Socket_t *pxSocket );

/*
 * Prepare an outgoing message, if anything has to be sent.
 */
static int32_t prvTCPPrepareSend( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer, UBaseType_t uxOptionsLength );

/*
 * Calculate when this socket needs to be checked to do (re-)transmissions.
 */
static TickType_t prvTCPNextTimeout( FreeRTOS_Socket_t *pxSocket );

/*
 * The API FreeRTOS_send() adds data to the TX stream.  Add
 * this data to the windowing system to it can be transmitted.
 */
static void prvTCPAddTxData( FreeRTOS_Socket_t *pxSocket );

/*
 *  Called to handle the closure of a TCP connection.
 */
static BaseType_t prvTCPHandleFin( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

#if(    ipconfigUSE_TCP_TIMESTAMPS == 1 )
    static UBaseType_t prvTCPSetTimeStamp( BaseType_t lOffset, FreeRTOS_Socket_t *pxSocket, TCPHeader_t *pxTCPHeader );
#endif

/*
 * Called from prvTCPHandleState().  Find the TCP payload data and check and
 * return its length.
 */
static BaseType_t prvCheckRxData( NetworkBufferDescriptor_t *pxNetworkBuffer, uint8_t **ppucRecvData );

/*
 * Called from prvTCPHandleState().  Check if the payload data may be accepted.
 * If so, it will be added to the socket's reception queue.
 */
static BaseType_t prvStoreRxData( FreeRTOS_Socket_t *pxSocket, uint8_t *pucRecvData,
    NetworkBufferDescriptor_t *pxNetworkBuffer, uint32_t ulReceiveLength );

/*
 * Set the TCP options (if any) for the outgoing packet.
 */
static UBaseType_t prvSetOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/*
 * Called from prvTCPHandleState() as long as the TCP status is eSYN_RECEIVED to
 * eCONNECT_SYN.
 */
static BaseType_t prvHandleSynReceived( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength );

/*
 * Called from prvTCPHandleState() as long as the TCP status is eESTABLISHED.
 */
static BaseType_t prvHandleEstablished( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength );

/*
 * Called from prvTCPHandleState().  There is data to be sent.
 * If ipconfigUSE_TCP_WIN is defined, and if only an ACK must be sent, it will
 * be checked if it would better be postponed for efficiency.
 */
static BaseType_t prvSendData( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, BaseType_t xSendLength );

/*
 * The heart of all: check incoming packet for valid data and acks and do what
 * is necessary in each state.
 */
static BaseType_t prvTCPHandleState( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer );

/*
 * Reply to a peer with the RST flag on, in case a packet can not be handled.
 */
static BaseType_t prvTCPSendReset( NetworkBufferDescriptor_t *pxNetworkBuffer );

/*
 * Set the initial value for MSS (Maximum Segment Size) to be used.
 */
static void prvSocketSetMSS( FreeRTOS_Socket_t *pxSocket );

/*
 * Return either a newly created socket, or the current socket in a connected
 * state (depends on the 'bReuseSocket' flag).
 */
static FreeRTOS_Socket_t *prvHandleListen( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/*
 * After a listening socket receives a new connection, it may duplicate itself.
 * The copying takes place in prvTCPSocketCopy.
 */
static BaseType_t prvTCPSocketCopy( FreeRTOS_Socket_t *pxNewSocket, FreeRTOS_Socket_t *pxSocket );

/*
 * prvTCPStatusAgeCheck() will see if the socket has been in a non-connected
 * state for too long.  If so, the socket will be closed, and -1 will be
 * returned.
 */
/* 本函数将会检查套接字是否非连接状态太久了，如果是，这个套接字会被关闭并返回-1 */
#if( ipconfigTCP_HANG_PROTECTION == 1 )
    static BaseType_t prvTCPStatusAgeCheck( FreeRTOS_Socket_t *pxSocket );
#endif

static NetworkBufferDescriptor_t *prvTCPBufferResize( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer,
    int32_t lDataLen, UBaseType_t uxOptionsLength );

#if( ( ipconfigHAS_DEBUG_PRINTF != 0 ) || ( ipconfigHAS_PRINTF != 0 ) )
    const char *FreeRTOS_GetTCPStateName( UBaseType_t ulState );
#endif

#if( ipconfigUSE_TCP_WIN != 0 )
    static uint8_t prvWinScaleFactor( FreeRTOS_Socket_t *pxSocket );
#endif

/*-----------------------------------------------------------*/

/* 初始化序列号，此数值应当随机以防止洪水攻击 */
uint32_t ulNextInitialSequenceNumber = 0ul;

/*-----------------------------------------------------------*/

/* prvTCPSocketIsActive() returns true if the socket must be checked.
 * Non-active sockets are waiting for user action, either connect()
 * or close(). */
static BaseType_t prvTCPSocketIsActive( UBaseType_t uxStatus )
{
    switch( uxStatus )
    {
    case eCLOSED:
    case eCLOSE_WAIT:
    case eFIN_WAIT_2:
    case eCLOSING:
    case eTIME_WAIT:
        return pdFALSE;
    default:
        return pdTRUE;
    }
}
/*-----------------------------------------------------------*/

#if( ipconfigTCP_HANG_PROTECTION == 1 )

    static BaseType_t prvTCPStatusAgeCheck( FreeRTOS_Socket_t *pxSocket )
    {
    BaseType_t xResult;
        switch( pxSocket->u.xTCP.ucTCPState )
        {
        case eESTABLISHED:
            /* If the 'ipconfigTCP_KEEP_ALIVE' option is enabled, sockets in
            state ESTABLISHED can be protected using keep-alive messages. */
            xResult = pdFALSE;
            break;
        case eCLOSED:
        case eTCP_LISTEN:
        case eCLOSE_WAIT:
            /* These 3 states may last for ever, up to the owner. */
            xResult = pdFALSE;
            break;
        default:
            /* All other (non-connected) states will get anti-hanging
            protection. */
            xResult = pdTRUE;
            break;
        }
        if( xResult != pdFALSE )
        {
            /* 计算时长 */
            TickType_t xAge = xTaskGetTickCount( ) - pxSocket->u.xTCP.xLastActTime;

            /* ipconfigTCP_HANG_PROTECTION_TIME is in units of seconds. */
            if( xAge > ( ipconfigTCP_HANG_PROTECTION_TIME * configTICK_RATE_HZ ) )
            {
                #if( ipconfigHAS_DEBUG_PRINTF == 1 )
                {
                    FreeRTOS_debug_printf( ( "Inactive socket closed: port %u rem %lxip:%u status %s\n",
                        pxSocket->usLocalPort,
                        pxSocket->u.xTCP.ulRemoteIP,
                        pxSocket->u.xTCP.usRemotePort,
                        FreeRTOS_GetTCPStateName( ( UBaseType_t ) pxSocket->u.xTCP.ucTCPState ) ) );
                }
                #endif /* ipconfigHAS_DEBUG_PRINTF */

                /* 转向eCLOSE_WAIT状态 */
                vTCPStateChange( pxSocket, eCLOSE_WAIT );

                /* 当bPassQueued为true，在连接之前，套接字为孤儿 */
                if( pxSocket->u.xTCP.bits.bPassQueued != pdFALSE_UNSIGNED )
                {
                    if( pxSocket->u.xTCP.bits.bReuseSocket == pdFALSE_UNSIGNED )
                    {
                        /* 由于没有连接并且用户再也不接收，这将会删除。 */
                        vSocketClose( pxSocket );
                    }
                    /* 返回一否定数据，通知xTCPTimerCheck()：套接字已关闭并且不再能访问 */
                    xResult = -1;
                }
            }
        }
        return xResult;
    }
    /*-----------------------------------------------------------*/

#endif

/*
 * 当TCP套接字的定时器到期，本函数会被xTCPTimerCheck调用
 * 他可以发送延迟应答或者是新的数据
 * 通常的调用序列如下 :
 * IP-Task:
 *      xTCPTimerCheck()                // Check all sockets ( declared in FreeRTOS_Sockets.c )
 *      xTCPSocketCheck()               // Either send a delayed ACK or call prvTCPSendPacket()
 *      prvTCPSendPacket()              // Either send a SYN or call prvTCPSendRepeated ( regular messages )
 *      prvTCPSendRepeated()            // Send at most 8 messages on a row
 *          prvTCPReturnPacket()        // Prepare for returning
 *          xNetworkInterfaceOutput()   // Sends data to the NIC ( declared in portable/NetworkInterface/xxx )
 */
BaseType_t xTCPSocketCheck( FreeRTOS_Socket_t *pxSocket )
{
BaseType_t xResult = 0;
BaseType_t xReady = pdFALSE;

    if( ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) && ( pxSocket->u.xTCP.txStream != NULL ) )
    {
        /* The API FreeRTOS_send() might have added data to the TX stream.  Add
        this data to the windowing system to it can be transmitted. */
        prvTCPAddTxData( pxSocket );
    }

    #if ipconfigUSE_TCP_WIN == 1
    {
        if( pxSocket->u.xTCP.pxAckMessage != NULL )
        {
            /* 该套接字检查的第一个任务便是发送延迟应答 */
            if( pxSocket->u.xTCP.bits.bUserShutdown == pdFALSE_UNSIGNED )
            {
                /* 早先的数据被接收但还没有应答，本函数在定时器到期时调用，现在将会发送应答 */
                if( pxSocket->u.xTCP.ucTCPState != eCLOSED )
                {
                    if( xTCPWindowLoggingLevel > 1 && ipconfigTCP_MAY_LOG_PORT( pxSocket->usLocalPort ) )
                    {
                        FreeRTOS_debug_printf( ( "Send[%u->%u] del ACK %lu SEQ %lu (len %u)\n",
                            pxSocket->usLocalPort,
                            pxSocket->u.xTCP.usRemotePort,
                            pxSocket->u.xTCP.xTCPWindow.rx.ulCurrentSequenceNumber - pxSocket->u.xTCP.xTCPWindow.rx.ulFirstSequenceNumber,
                            pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber   - pxSocket->u.xTCP.xTCPWindow.tx.ulFirstSequenceNumber,
                            ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER ) );
                    }
                    /* 这是啥？？？？？？？？？？？？？？？？？？？？ */
                    prvTCPReturnPacket( pxSocket, pxSocket->u.xTCP.pxAckMessage, ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER, ipconfigZERO_COPY_TX_DRIVER );

                    #if( ipconfigZERO_COPY_TX_DRIVER != 0 )
                    {
                        /* The ownership has been passed to the SEND routine,
                        clear the pointer to it. */
                        /* 所有权已经被传递给发送程序，现在清除指针 */
                        pxSocket->u.xTCP.pxAckMessage = NULL;
                    }
                    #endif /* ipconfigZERO_COPY_TX_DRIVER */
                }
                if( prvTCPNextTimeout( pxSocket ) > 1 )
                {
                    /* 告诉下面的代码，这个函数已经准备好了 */
                    xReady = pdTRUE;
                }
            }
            else
            {
                /* The user wants to perform an active shutdown(), skip sending
                the delayed ACK.  The function prvTCPSendPacket() will send the
                FIN along with the ACK's. */
                /* 用户希望主动关闭，略过延迟应答，函数prvTCPSendPacket将会发送FIN顺带ACK */
            }

            if( pxSocket->u.xTCP.pxAckMessage != NULL )
            {
                vReleaseNetworkBufferAndDescriptor( pxSocket->u.xTCP.pxAckMessage );
                pxSocket->u.xTCP.pxAckMessage = NULL;
            }
        }
    }
    #endif /* ipconfigUSE_TCP_WIN */

    if( xReady == pdFALSE )
    {
        /* 该套接字检查项的第二个任务便是发送数据 */
        if( ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) ||
            ( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN ) )
        {
            prvTCPSendPacket( pxSocket );
        }
        /* 设置该套接字 到下一次唤醒的超时时长 */
        prvTCPNextTimeout( pxSocket );

        #if( ipconfigTCP_HANG_PROTECTION == 1 )
        {
            /* In all (non-connected) states in which keep-alive messages can not be sent
            the anti-hang protocol will close sockets that are 'hanging'. */
            xResult = prvTCPStatusAgeCheck( pxSocket );
        }
        #endif
    }

    return xResult;
}
/* 本函数在套接字定时到期时调用，只能被函数xTCPSocketCheck()调用 */
static int32_t prvTCPSendPacket( FreeRTOS_Socket_t *pxSocket )
{
int32_t lResult = 0;
UBaseType_t uxOptionsLength;
TCPPacket_t *pxTCPPacket;
NetworkBufferDescriptor_t *pxNetworkBuffer;

    if( pxSocket->u.xTCP.ucTCPState != eCONNECT_SYN )
    {
        /* 连接不在SYN状态 */
        pxNetworkBuffer = NULL;
        /* prvTCPSendRepeated()将只会创建一网络缓冲区，即：当数据必须发送给对方的时候 */
        lResult = prvTCPSendRepeated( pxSocket, &pxNetworkBuffer );
        if( pxNetworkBuffer != NULL )
        {
            vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
        }
    }
    else
    {
        if( pxSocket->u.xTCP.ucRepCount >= 3u )
        {
            /* 连接处于SYN状态，包会重复最多三次，没有回复时，套接字进入状态eCLOSE_WAIT */
            FreeRTOS_debug_printf( ( "Connect: giving up %lxip:%u\n",
                pxSocket->u.xTCP.ulRemoteIP,        /* IP address of remote machine. */
                pxSocket->u.xTCP.usRemotePort ) );  /* Port on remote machine. */
                /* 更改状态 */
            vTCPStateChange( pxSocket, eCLOSE_WAIT );
        }
        else if( ( pxSocket->u.xTCP.bits.bConnPrepared != pdFALSE_UNSIGNED ) || ( prvTCPPrepareConnect( pxSocket ) == pdTRUE ) )
        {
            /* 
            或者是，如果连接准备就绪，或可准备就绪，发送带有SYN标志的包，prvTCPPrepareConnect()
            准备xPacket，如果局域网地址或者网关被发现返回真
            */
            pxTCPPacket = ( TCPPacket_t * )pxSocket->u.xTCP.xPacket.u.ucLastPacket;
            #if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
            {
                /* 如果时间戳使能，只有在同伴为局域网外时才可使用，通常是在internet上。 */
                if( ( ( pxSocket->u.xTCP.ulRemoteIP ^ FreeRTOS_ntohl( *ipLOCAL_IP_ADDRESS_POINTER ) ) & xNetworkAddressing.ulNetMask ) != 0ul )
                {
                    pxSocket->u.xTCP.xTCPWindow.u.bits.bTimeStamps = pdTRUE_UNSIGNED;
                }
            }
            #endif
            /* 发送一个SYN包。调用prvSetSynAckOptions() 去设置合适的选项：MSS大小和是否允许SACK */
            uxOptionsLength = prvSetSynAckOptions( pxSocket, pxTCPPacket );

            /* 返回需要发送的字节数 */
            lResult = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
            /* 
            设置数据大小，ipSIZE_OF_TCP_HEADER等于20，uxOptionsLength总是4的倍数，完整的公式是：
            ucTCPOffset = ( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) / 4 ) << 4
            */
            pxTCPPacket->xTCPHeader.ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
            /* 重试次数用于套接字的连接，用于限制尝试的次数 */
            pxSocket->u.xTCP.ucRepCount++;
            /* 发送SYN消息开始连接，信息保存在xPacket中，在其被发送之前，会被包裹进伪网络缓冲区 */
            prvTCPReturnPacket( pxSocket, NULL, ( uint32_t ) lResult, pdFALSE );
        }
    }

    /* Return the total number of bytes sent. */
    return lResult;
}
/*-----------------------------------------------------------*/
/* 只要存在需要发送的数据，只要发送窗口不满，prvTCPSendRepeated就会尝试发送一系列信息 */
static int32_t prvTCPSendRepeated( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer )
{
UBaseType_t uxIndex;
int32_t lResult = 0;
UBaseType_t uxOptionsLength = 0u;
int32_t xSendLength;

    for( uxIndex = 0u; uxIndex < ( UBaseType_t ) SEND_REPEATED_COUNT; uxIndex++ )
    {
        /* 如果有数据需要发送，prvTCPPrepareSend()会申请一网络缓冲区 */
        xSendLength = prvTCPPrepareSend( pxSocket, ppxNetworkBuffer, uxOptionsLength );
        if( xSendLength <= 0 )
        {
            break;
        }
        /* 返回包给对等体 */
        prvTCPReturnPacket( pxSocket, *ppxNetworkBuffer, ( uint32_t ) xSendLength, ipconfigZERO_COPY_TX_DRIVER );
        #if( ipconfigZERO_COPY_TX_DRIVER != 0 )
        {
            *ppxNetworkBuffer = NULL;
        }
        #endif /* ipconfigZERO_COPY_TX_DRIVER */
        lResult += xSendLength;
    }
    /* 返回总共发送的字节数 */
    return lResult;
}
/*-----------------------------------------------------------*/
/* 
返回（或者发送）包到peer，数据存储在pxBuffer中，pxBuffer或者指向真正的网络缓冲区或者
指向TCP套接字的xTCP.xPacket成员，临时的xNetworkBuffer将会被用于传递数据到NIC
*/
static void prvTCPReturnPacket( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer, uint32_t ulLen, BaseType_t xReleaseAfterSend )
{
TCPPacket_t * pxTCPPacket;
IPHeader_t *pxIPHeader;
EthernetHeader_t *pxEthernetHeader;
uint32_t ulFrontSpace, ulSpace, ulSourceAddress, ulWinSize;
TCPWindow_t *pxTCPWindow;
NetworkBufferDescriptor_t xTempBuffer;
/* 为了发送，一个伪网络缓冲区将被使用，正如前面所述 */
    if( pxNetworkBuffer == NULL )
    {
        pxNetworkBuffer = &xTempBuffer;

        #if( ipconfigUSE_LINKED_RX_MESSAGES != 0 )
        {
            xTempBuffer.pxNextBuffer = NULL;
        }
        #endif
        xTempBuffer.pucEthernetBuffer = pxSocket->u.xTCP.xPacket.u.ucLastPacket;
        xTempBuffer.xDataLength = sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket );
        xReleaseAfterSend = pdFALSE;
    }

    #if( ipconfigZERO_COPY_TX_DRIVER != 0 )
    {
        if( xReleaseAfterSend == pdFALSE )
        {
            pxNetworkBuffer = pxDuplicateNetworkBufferWithDescriptor( pxNetworkBuffer, ( BaseType_t ) pxNetworkBuffer->xDataLength );
            if( pxNetworkBuffer == NULL )
            {
                FreeRTOS_debug_printf( ( "prvTCPReturnPacket: duplicate failed\n" ) );
            }
            xReleaseAfterSend = pdTRUE;
        }
    }
    #endif /* ipconfigZERO_COPY_TX_DRIVER */

    if( pxNetworkBuffer != NULL )
    {
        pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
        pxIPHeader = &pxTCPPacket->xIPHeader;
        pxEthernetHeader = &pxTCPPacket->xEthernetHeader;
        /* 填充包，使用hton转义 */
        if( pxSocket != NULL )
        {
            /* 计算接受缓冲的空间以公布套接字的接收窗口大小 */
            pxTCPWindow = &( pxSocket->u.xTCP.xTCPWindow );

            if( pxSocket->u.xTCP.rxStream != NULL )
            {
                /* 缓冲早已经创建，直接看有多少空闲空间就好了 */
                ulFrontSpace = ( uint32_t ) uxStreamBufferFrontSpace( pxSocket->u.xTCP.rxStream );
            }
            else
            {
                /* 缓冲未被创建，全部可用 */
                ulFrontSpace = ( uint32_t ) pxSocket->u.xTCP.uxRxStreamSize;
            }
            /* 获取缓冲区空间和窗口之间的最小值 */
            ulSpace = FreeRTOS_min_uint32( pxSocket->u.xTCP.ulRxCurWinSize, pxTCPWindow->xSize.ulRxWindowLength );
            if( ( pxSocket->u.xTCP.bits.bLowWater != pdFALSE_UNSIGNED ) || ( pxSocket->u.xTCP.bits.bRxStopped != pdFALSE_UNSIGNED ) )
            {
                /* 已经达到了吃水线，说明可利用空间很少了，套接字会等待用户取走或丢弃到来的数据，同时会公布0窗口 */
                ulSpace = 0u;
            }
            /* 如果可能，公布至少为1的接收窗口，否则，对方会启动零窗口探测，即：发送小数据包1、2、4、8字节 */
            if( ( ulSpace < pxSocket->u.xTCP.usCurMSS ) && ( ulFrontSpace >= pxSocket->u.xTCP.usCurMSS ) )
            {
                ulSpace = pxSocket->u.xTCP.usCurMSS;
            }
            /* 避免16位窗口溢出 */
            ulWinSize = ( ulSpace >> pxSocket->u.xTCP.ucMyWinScaleFactor );
            if( ulWinSize > 0xfffcUL )
            {
                ulWinSize = 0xfffcUL;
            }
            /* 进行字节转换 */
            pxTCPPacket->xTCPHeader.usWindow = FreeRTOS_htons( ( uint16_t ) ulWinSize );
            /*  */
            #if( ipconfigHAS_DEBUG_PRINTF != 0 )
            {
                if( ipconfigTCP_MAY_LOG_PORT( pxSocket->usLocalPort ) != pdFALSE )
                {
                    if( ( xTCPWindowLoggingLevel != 0 ) && ( pxSocket->u.xTCP.bits.bWinChange != pdFALSE_UNSIGNED ) )
                    {
                    size_t uxFrontSpace;

                        if(pxSocket->u.xTCP.rxStream != NULL)
                        {
                            uxFrontSpace =  uxStreamBufferFrontSpace( pxSocket->u.xTCP.rxStream ) ;
                        }
                        else
                        {
                            uxFrontSpace = 0u;
                        }

                        FreeRTOS_debug_printf( ( "%s: %lxip:%u: [%lu < %lu] winSize %ld\n",
                        pxSocket->u.xTCP.bits.bLowWater ? "STOP" : "GO ",
                            pxSocket->u.xTCP.ulRemoteIP,
                            pxSocket->u.xTCP.usRemotePort,
                            pxSocket->u.xTCP.bits.bLowWater ? pxSocket->u.xTCP.uxLittleSpace : uxFrontSpace, pxSocket->u.xTCP.uxEnoughSpace,
                            (int32_t) ( pxTCPWindow->rx.ulHighestSequenceNumber - pxTCPWindow->rx.ulCurrentSequenceNumber ) ) );
                    }
                }
            }
            #endif /* ipconfigHAS_DEBUG_PRINTF != 0 */
            /* 新的窗口已经被公布，关闭标志 */
            pxSocket->u.xTCP.bits.bWinChange = pdFALSE_UNSIGNED;
            /* 后来，当决定延迟一个应答，空闲接收大小需要一个精确地评估，在这时，ulHighestRxAllowed将会是套接字能接收到的最高序列号减一*/
            pxSocket->u.xTCP.ulHighestRxAllowed = pxTCPWindow->rx.ulCurrentSequenceNumber + ulSpace;
            #if( ipconfigTCP_KEEP_ALIVE == 1 )
                if( pxSocket->u.xTCP.bits.bSendKeepAlive != pdFALSE_UNSIGNED )
                {
                    /* Sending a keep-alive packet, send the current sequence number
                    minus 1, which will be recognised as a keep-alive packet an
                    responded to by acknowledging the last byte. */
                    /* 发送保活包，发送当前的序列号减一，这将会被识别为一个保活包 */
                    pxSocket->u.xTCP.bits.bSendKeepAlive = pdFALSE_UNSIGNED;
                    pxSocket->u.xTCP.bits.bWaitKeepAlive = pdTRUE_UNSIGNED;
                    pxTCPPacket->xTCPHeader.ulSequenceNumber = pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber - 1UL;
                    pxTCPPacket->xTCPHeader.ulSequenceNumber = FreeRTOS_htonl( pxTCPPacket->xTCPHeader.ulSequenceNumber );
                }
                else
            #endif
            {
                pxTCPPacket->xTCPHeader.ulSequenceNumber = FreeRTOS_htonl( pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber );
                if( ( pxTCPPacket->xTCPHeader.ucTCPFlags & ( uint8_t ) ipTCP_FLAG_FIN ) != 0u )
                {
                    /* 去掉FIN标志以防包中带有早先重传的数据 */
                    uint32_t ulDataLen = ( uint32_t ) ( ulLen - ( ipSIZE_OF_TCP_HEADER + ipSIZE_OF_IPv4_HEADER ) );
                    if( ( pxTCPWindow->ulOurSequenceNumber + ulDataLen ) != pxTCPWindow->tx.ulFINSequenceNumber )
                    {
                        pxTCPPacket->xTCPHeader.ucTCPFlags &= ( ( uint8_t ) ~ipTCP_FLAG_FIN );
                        FreeRTOS_debug_printf( ( "Suppress FIN for %lu + %lu < %lu\n",
                            pxTCPWindow->ulOurSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber,
                            ulDataLen,
                            pxTCPWindow->tx.ulFINSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber ) );
                    }
                }
            }
            /* 告诉我们下一个需要接收的序列号是多少 */
            pxTCPPacket->xTCPHeader.ulAckNr = FreeRTOS_htonl( pxTCPWindow->rx.ulCurrentSequenceNumber );
        }
        else
        {
            /* 发送数据而不是用套接字，或许回复一只是包含着两个序列号的RST */
            vFlip_32( pxTCPPacket->xTCPHeader.ulSequenceNumber, pxTCPPacket->xTCPHeader.ulAckNr );
        }
        pxIPHeader->ucTimeToLive           = ( uint8_t ) ipconfigTCP_TIME_TO_LIVE;
        pxIPHeader->usLength               = FreeRTOS_htons( ulLen );
        if( ( pxSocket == NULL ) || ( *ipLOCAL_IP_ADDRESS_POINTER == 0ul ) )
        {
            /* When pxSocket is NULL, this function is called by prvTCPSendReset()
            and the IP-addresses must be swapped.
            Also swap the IP-addresses in case the IP-tack doesn't have an
            IP-address yet, i.e. when ( *ipLOCAL_IP_ADDRESS_POINTER == 0ul ). */
            ulSourceAddress = pxIPHeader->ulDestinationIPAddress;
        }
        else
        {
            ulSourceAddress = *ipLOCAL_IP_ADDRESS_POINTER;
        }
        pxIPHeader->ulDestinationIPAddress = pxIPHeader->ulSourceIPAddress;
        pxIPHeader->ulSourceIPAddress = ulSourceAddress;
        vFlip_16( pxTCPPacket->xTCPHeader.usSourcePort, pxTCPPacket->xTCPHeader.usDestinationPort );
        /* Just an increasing number. */
        pxIPHeader->usIdentification = FreeRTOS_htons( usPacketIdentifier );
        usPacketIdentifier++;
        pxIPHeader->usFragmentOffset = 0u;
        #if( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
        {
            /* 计算IP头校验和，以防驱动不作此项 */
            pxIPHeader->usHeaderChecksum = 0x00u;
            pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0UL, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
            pxIPHeader->usHeaderChecksum = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
            /* 对于即将发出的包，计算TCP的校验和 */
            usGenerateProtocolChecksum( (uint8_t*)pxTCPPacket, pdTRUE );
            /* 计算的校验和为0必须颠倒，因为0意味着校验失能 */
            if( pxTCPPacket->xTCPHeader.usChecksum == 0x00u )
            {
                pxTCPPacket->xTCPHeader.usChecksum = 0xffffU;
            }
        }
        #endif
    #if( ipconfigUSE_LINKED_RX_MESSAGES != 0 )
        pxNetworkBuffer->pxNextBuffer = NULL;
    #endif
        /* 告诉NIC驱动，有多少个字节要发送 */
        pxNetworkBuffer->xDataLength = ulLen + ipSIZE_OF_ETH_HEADER;
        /* 填充目的MAC地址 */
        memcpy( ( void * ) &( pxEthernetHeader->xDestinationAddress ), ( void * ) &( pxEthernetHeader->xSourceAddress ),
            sizeof( pxEthernetHeader->xDestinationAddress ) );
        /* 填充本地MAC地址 */
        memcpy( ( void * ) &( pxEthernetHeader->xSourceAddress) , ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
        /* 数据的填充 */
        #if defined( ipconfigETHERNET_MINIMUM_PACKET_BYTES )
        {
            if( pxNetworkBuffer->xDataLength < ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES )
            {
            BaseType_t xIndex;

                FreeRTOS_printf( ( "prvTCPReturnPacket: length %lu\n", pxNetworkBuffer->xDataLength ) );
                for( xIndex = ( BaseType_t ) pxNetworkBuffer->xDataLength; xIndex < ( BaseType_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES; xIndex++ )
                {
                    pxNetworkBuffer->pucEthernetBuffer[ xIndex ] = 0u;
                }
                pxNetworkBuffer->xDataLength = ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES;
            }
        }
        #endif
        /* 发送数据！ */
        xNetworkInterfaceOutput( pxNetworkBuffer, xReleaseAfterSend );
        if( xReleaseAfterSend == pdFALSE )
        {
            /* Swap-back some fields, as pxBuffer probably points to a socket field
            containing the packet header. */
            vFlip_16( pxTCPPacket->xTCPHeader.usSourcePort, pxTCPPacket->xTCPHeader.usDestinationPort);
            pxTCPPacket->xIPHeader.ulSourceIPAddress = pxTCPPacket->xIPHeader.ulDestinationIPAddress;
            memcpy( pxEthernetHeader->xSourceAddress.ucBytes, pxEthernetHeader->xDestinationAddress.ucBytes, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
        }
        else
        {
            /* Nothing to do: the buffer has been passed to DMA and will be released after use */
        }
    } /* if( pxNetworkBuffer != NULL ) */
}
/*-----------------------------------------------------------*/

/*
 * The SYN event is very important: the sequence numbers, which have a kind of
 * random starting value, are being synchronised.  The sliding window manager
 * (in FreeRTOS_TCP_WIN.c) needs to know them, along with the Maximum Segment
 * Size (MSS) in use.
 */
/* SYN时间非常重要：这序列号，开始于随机数值，在过程中被同步。滑动窗口管理需要知道这些 */
static void prvTCPCreateWindow( FreeRTOS_Socket_t *pxSocket )
{
    if( xTCPWindowLoggingLevel )
        FreeRTOS_debug_printf( ( "Limits (using): TCP Win size %lu Water %lu <= %lu <= %lu\n",
            pxSocket->u.xTCP.uxRxWinSize * ipconfigTCP_MSS,
            pxSocket->u.xTCP.uxLittleSpace ,
            pxSocket->u.xTCP.uxEnoughSpace,
            pxSocket->u.xTCP.uxRxStreamSize ) );
    vTCPWindowCreate(
        &pxSocket->u.xTCP.xTCPWindow,
        ipconfigTCP_MSS * pxSocket->u.xTCP.uxRxWinSize,
        ipconfigTCP_MSS * pxSocket->u.xTCP.uxTxWinSize,
        pxSocket->u.xTCP.xTCPWindow.rx.ulCurrentSequenceNumber,
        pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber,
        ( uint32_t ) pxSocket->u.xTCP.usInitMSS );
}
/*-----------------------------------------------------------*/
/* 
连接套接字有一特殊的状态：eCONNECT_SYN，在这个阶段下，目标的MAC地址可能已经通过ARP获取，
为防止目标IP不在局域网中，网关的地址需要用到。
 */
static BaseType_t prvTCPPrepareConnect( FreeRTOS_Socket_t *pxSocket )
{
TCPPacket_t *pxTCPPacket;
IPHeader_t *pxIPHeader;
eARPLookupResult_t eReturned;
uint32_t ulRemoteIP;
MACAddress_t xEthAddress;
BaseType_t xReturn = pdTRUE;

    #if( ipconfigHAS_PRINTF != 0 )
    {
        /* Only necessary for nicer logging. */
        memset( xEthAddress.ucBytes, '\0', sizeof( xEthAddress.ucBytes ) );
    }
    #endif /* ipconfigHAS_PRINTF != 0 */
    ulRemoteIP = FreeRTOS_htonl( pxSocket->u.xTCP.ulRemoteIP );
    /* 获取ARP对于目标IP地址的反应 */
    eReturned = eARPGetCacheEntry( &( ulRemoteIP ), &( xEthAddress ) );
    switch( eReturned )
    {
    case eARPCacheHit:      /* An ARP table lookup found a valid entry. */
        break;              /* We can now prepare the SYN packet. */
    case eARPCacheMiss:     /* An ARP table lookup did not find a valid entry. */
    case eCantSendPacket:   /* There is no IP address, or an ARP is still in progress. */
    default:
        /* 记录ARP找不到记录的次数 */
        pxSocket->u.xTCP.ucRepCount++;
        FreeRTOS_debug_printf( ( "ARP for %lxip (using %lxip): rc=%d %02X:%02X:%02X %02X:%02X:%02X\n",
            pxSocket->u.xTCP.ulRemoteIP,
            FreeRTOS_htonl( ulRemoteIP ),
            eReturned,
            xEthAddress.ucBytes[ 0 ],
            xEthAddress.ucBytes[ 1 ],
            xEthAddress.ucBytes[ 2 ],
            xEthAddress.ucBytes[ 3 ],
            xEthAddress.ucBytes[ 4 ],
            xEthAddress.ucBytes[ 5 ] ) );
        /* 同时发送一ARP请求 */
        FreeRTOS_OutputARPRequest( ulRemoteIP );
        xReturn = pdFALSE;
    }

    if( xReturn != pdFALSE )
    {
        /* 对方的MAC或者是网关的MAC已经被获取，现在准备初始的TCP包 */
        pxTCPPacket = ( TCPPacket_t * )pxSocket->u.xTCP.xPacket.u.ucLastPacket;
        pxIPHeader = &pxTCPPacket->xIPHeader;
        /* 复位重试次数到0 */
        pxSocket->u.xTCP.ucRepCount = 0u;
        /* 并且记住：连接/SYN数据已经准备好了 */
        pxSocket->u.xTCP.bits.bConnPrepared = pdTRUE_UNSIGNED;
        /* 现在以太网地址已经知道了，初始的包可以准备 */
        memset( pxSocket->u.xTCP.xPacket.u.ucLastPacket, '\0', sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket ) );
        /* 将目标地址写入源地址，因为他会被prvTCPReturnPacket交换 */
        memcpy( &pxTCPPacket->xEthernetHeader.xSourceAddress, &xEthAddress, sizeof( xEthAddress ) );
        /* 'ipIPv4_FRAME_TYPE' is already in network-byte-order. */
        pxTCPPacket->xEthernetHeader.usFrameType = ipIPv4_FRAME_TYPE;
        pxIPHeader->ucVersionHeaderLength = 0x45u;
        pxIPHeader->usLength = FreeRTOS_htons( sizeof( TCPPacket_t ) - sizeof( pxTCPPacket->xEthernetHeader ) );
        pxIPHeader->ucTimeToLive = ( uint8_t ) ipconfigTCP_TIME_TO_LIVE;
        pxIPHeader->ucProtocol = ( uint8_t ) ipPROTOCOL_TCP;
        /* IP地址和端口号会被交换，因为prvTCPReturnPacket会把他们交换回来 */
        pxIPHeader->ulDestinationIPAddress = *ipLOCAL_IP_ADDRESS_POINTER;
        pxIPHeader->ulSourceIPAddress = FreeRTOS_htonl( pxSocket->u.xTCP.ulRemoteIP );
        pxTCPPacket->xTCPHeader.usSourcePort = FreeRTOS_htons( pxSocket->u.xTCP.usRemotePort );
        pxTCPPacket->xTCPHeader.usDestinationPort = FreeRTOS_htons( pxSocket->usLocalPort );
        /* 我们主动发起连接，所以对方的序列号不知道 */
        pxSocket->u.xTCP.xTCPWindow.rx.ulCurrentSequenceNumber = 0ul;
        /* 出事序列号 */
        pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber = ulNextInitialSequenceNumber;
        /* 推荐的序列号增量是258 */
        ulNextInitialSequenceNumber += 0x102UL;
        /* TCP头部大小为20B，除以4得5，此数值将会被放到offset的高位 */
        pxTCPPacket->xTCPHeader.ucTCPOffset = 0x50u;
        /* 只设置SYN标志 */
        pxTCPPacket->xTCPHeader.ucTCPFlags = ipTCP_FLAG_SYN;
        /* 设置套接字的MSS：usInitMSS / usCurMSS */
        prvSocketSetMSS( pxSocket );
        /* 此时，同样是推荐的窗口大小 */
        pxSocket->u.xTCP.ulRxCurWinSize = pxSocket->u.xTCP.usInitMSS;
        /* 在我们这一边的出事序列号已经知道了，后面调用vTCPWindowInit()来填充对方的序列号，但是首先等待SYN+ACK回复 */
        prvTCPCreateWindow( pxSocket );
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

/* For logging and debugging: make a string showing the TCP flags
*/
#if( ipconfigHAS_DEBUG_PRINTF != 0 )

    static const char *prvTCPFlagMeaning( UBaseType_t xFlags)
    {
        static char retString[10];
        snprintf(retString, sizeof( retString ), "%c%c%c%c%c%c%c%c%c",
            ( xFlags & ipTCP_FLAG_FIN )  ? 'F' : '.',   /* 0x0001: No more data from sender */
            ( xFlags & ipTCP_FLAG_SYN )  ? 'S' : '.',   /* 0x0002: Synchronize sequence numbers */
            ( xFlags & ipTCP_FLAG_RST )  ? 'R' : '.',   /* 0x0004: Reset the connection */
            ( xFlags & ipTCP_FLAG_PSH )  ? 'P' : '.',   /* 0x0008: Push function: please push buffered data to the recv application */
            ( xFlags & ipTCP_FLAG_ACK )  ? 'A' : '.',   /* 0x0010: Acknowledgment field is significant */
            ( xFlags & ipTCP_FLAG_URG )  ? 'U' : '.',   /* 0x0020: Urgent pointer field is significant */
            ( xFlags & ipTCP_FLAG_ECN )  ? 'E' : '.',   /* 0x0040: ECN-Echo */
            ( xFlags & ipTCP_FLAG_CWR )  ? 'C' : '.',   /* 0x0080: Congestion Window Reduced */
            ( xFlags & ipTCP_FLAG_NS )   ? 'N' : '.');  /* 0x0100: ECN-nonce concealment protection */
        return retString;
    }
    /*-----------------------------------------------------------*/

#endif /* ipconfigHAS_DEBUG_PRINTF */

/*
 * Parse the TCP option(s) received, if present.  It has already been verified
 * that: ((pxTCPHeader->ucTCPOffset & 0xf0) > 0x50), meaning that the TP header
 * is longer than the usual 20 (5 x 4) bytes.
 */
/* 检查收到的选项，如果存在：((pxTCPHeader->ucTCPOffset & 0xf0) > 0x50) TCP包头大于5*4=20 */
static void prvCheckOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer )
{
TCPPacket_t * pxTCPPacket;
TCPHeader_t * pxTCPHeader;
const unsigned char *pucPtr;
const unsigned char *pucLast;
TCPWindow_t *pxTCPWindow;
UBaseType_t uxNewMSS;

    pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
    pxTCPHeader = &pxTCPPacket->xTCPHeader;
    /* 一个字符指针遍历选项数据 */
    pucPtr = pxTCPHeader->ucOptdata;
    pucLast = pucPtr + (((pxTCPHeader->ucTCPOffset >> 4) - 5) << 2);
    pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
    /* 只有当选项数据损坏的情况下才会比较pucLast，我们不喜欢走入无效内存。。然后崩溃 */
        /*
            Kind(1B)+Length(1B)+Info(nB)
            
        */
    while( pucPtr < pucLast )
    {
        if( pucPtr[ 0 ] == TCP_OPT_END )
        {
            /* End of options. */
            return;
        }
        if( pucPtr[ 0 ] == TCP_OPT_NOOP)
        {
            pucPtr++;

            /* NOP option, inserted to make the length a multiple of 4. */
        }
#if( ipconfigUSE_TCP_WIN != 0 )
        else if( ( pucPtr[ 0 ] == TCP_OPT_WSOPT ) && ( pucPtr[ 1 ] == TCP_OPT_WSOPT_LEN ) )
        {
            /* 窗口放大因子 */
            pxSocket->u.xTCP.ucPeerWinScaleFactor = pucPtr[ 2 ];
            pxSocket->u.xTCP.bits.bWinScaling = pdTRUE_UNSIGNED;
            pucPtr += TCP_OPT_WSOPT_LEN;
        }
#endif  /* ipconfigUSE_TCP_WIN */
        else if( ( pucPtr[ 0 ] == TCP_OPT_MSS ) && ( pucPtr[ 1 ] == TCP_OPT_MSS_LEN ) )
        {
            /* 设置MSS数值 */
            uxNewMSS = usChar2u16( pucPtr + 2 );
            if( pxSocket->u.xTCP.usInitMSS != uxNewMSS )
            {
                FreeRTOS_debug_printf( ( "MSS change %u -> %lu\n", pxSocket->u.xTCP.usInitMSS, uxNewMSS ) );
            }
            if( pxSocket->u.xTCP.usInitMSS > uxNewMSS )
            {
                /* 我们的MSS大于另一方的MSS，调整一下 */
                pxSocket->u.xTCP.bits.bMssChange = pdTRUE_UNSIGNED;
                if( ( pxTCPWindow != NULL ) && ( pxSocket->u.xTCP.usCurMSS > uxNewMSS ) )
                {
                    /* 对方公布了一个比我们更小的MSS，就用他的那个 */
                    FreeRTOS_debug_printf( ( "Change mss %d => %lu\n", pxSocket->u.xTCP.usCurMSS, uxNewMSS ) );
                    pxSocket->u.xTCP.usCurMSS = ( uint16_t ) uxNewMSS;
                }
                pxTCPWindow->xSize.ulRxWindowLength = ( ( uint32_t ) uxNewMSS ) * ( pxTCPWindow->xSize.ulRxWindowLength / ( ( uint32_t ) uxNewMSS ) );
                pxTCPWindow->usMSSInit = ( uint16_t ) uxNewMSS;
                pxTCPWindow->usMSS = ( uint16_t ) uxNewMSS;
                pxSocket->u.xTCP.usInitMSS = ( uint16_t ) uxNewMSS;
                pxSocket->u.xTCP.usCurMSS = ( uint16_t ) uxNewMSS;
            }

            #if( ipconfigUSE_TCP_WIN != 1 )
                /* Without scaled windows, MSS is the only interesting option. */
                break;
            #else
                /* Or else we continue to check another option: selective ACK. */
                pucPtr += TCP_OPT_MSS_LEN;
            #endif  /* ipconfigUSE_TCP_WIN != 1 */
        }
        else
        {
            /* 所有其他的选项有一个长度成员，所以我们能比较容易的跳过他们 */
            int len = ( int )pucPtr[ 1 ];
            if( len == 0 )
            {
                /* 如果长度成员为0，这个选项是个畸形，我们不会处理它 */
                break;
            }

            #if( ipconfigUSE_TCP_WIN == 1 )
            {
                /* 
                    选择性回复：对方已经收到包，但是丢失了之前的包。至少这一次的数据包不需要
                    重传了，ulTCPWindowTxSack()负责处理这一块
                */
                if( pucPtr[0] == TCP_OPT_SACK_A )
                {
                    len -= 2;
                    pucPtr += 2;

                    while( len >= 8 )
                    {
                    uint32_t ulFirst = ulChar2u32( pucPtr );
                    uint32_t ulLast  = ulChar2u32( pucPtr + 4 );
                    uint32_t ulCount = ulTCPWindowTxSack( &pxSocket->u.xTCP.xTCPWindow, ulFirst, ulLast );
                        /* ulTCPWindowTxSack返回从头部开始已经被应答的字节数 */
                        if( ( pxSocket->u.xTCP.txStream  != NULL ) && ( ulCount > 0 ) )
                        {
                            /* Just advancing the tail index, 'ulCount' bytes have been confirmed. */
                            uxStreamBufferGet( pxSocket->u.xTCP.txStream, 0, NULL, ( size_t ) ulCount, pdFALSE );
                            pxSocket->xEventBits |= eSOCKET_SEND;
                            #if ipconfigSUPPORT_SELECT_FUNCTION == 1
                            {
                                if( pxSocket->xSelectBits & eSELECT_WRITE )
                                {
                                    /* The field 'xEventBits' is used to store regular socket events (at most 8),
                                    as well as 'select events', which will be left-shifted */
                                    pxSocket->xEventBits |= ( eSELECT_WRITE << SOCKET_EVENT_BIT_COUNT );
                                }
                            }
                            #endif
                            #if( ipconfigUSE_CALLBACKS == 1 )
                            {
                                if( ipconfigIS_VALID_PROG_ADDRESS( pxSocket->u.xTCP.pxHandleSent ) )
                                {
                                    pxSocket->u.xTCP.pxHandleSent( (Socket_t *)pxSocket, ulCount );
                                }
                            }
                            #endif /* ipconfigUSE_CALLBACKS == 1  */
                        }
                        pucPtr += 8;
                        len -= 8;
                    }
                    /* len should be 0 by now. */
                }
                #if ipconfigUSE_TCP_TIMESTAMPS == 1
                    else if( pucPtr[0] == TCP_OPT_TIMESTAMP )
                    {
                        len -= 2;   /* Skip option and length byte. */
                        pucPtr += 2;
                        pxSocket->u.xTCP.xTCPWindow.u.bits.bTimeStamps = pdTRUE_UNSIGNED;
                        pxSocket->u.xTCP.xTCPWindow.rx.ulTimeStamp = ulChar2u32( pucPtr );
                        pxSocket->u.xTCP.xTCPWindow.tx.ulTimeStamp = ulChar2u32( pucPtr + 4 );
                    }
                #endif  /* ipconfigUSE_TCP_TIMESTAMPS == 1 */
            }
            #endif  /* ipconfigUSE_TCP_WIN == 1 */
            pucPtr += len;
        }
    }
}
/*-----------------------------------------------------------*/
/*2016--12--05--14--44--49(ZJYC): 设置窗口放大因子   */ 
#if( ipconfigUSE_TCP_WIN != 0 )

    static uint8_t prvWinScaleFactor( FreeRTOS_Socket_t *pxSocket )
    {
    size_t uxWinSize;
    uint8_t ucFactor;
        /* xTCP.uxRxWinSize是接收窗口的大小，以MSS为单位 */
        uxWinSize = pxSocket->u.xTCP.uxRxWinSize * ( size_t ) pxSocket->u.xTCP.usInitMSS;
        ucFactor = 0u;
        while( uxWinSize > 0xfffful )
        {
            /* 超过16位，除2，同时放大因子加1 */
            uxWinSize >>= 1;
            ucFactor++;
        }
        FreeRTOS_debug_printf( ( "prvWinScaleFactor: uxRxWinSize %lu MSS %lu Factor %u\n",
            pxSocket->u.xTCP.uxRxWinSize,
            pxSocket->u.xTCP.usInitMSS,
            ucFactor ) );
        return ucFactor;
    }

#endif
/*-----------------------------------------------------------*/
/* 当打开一TCP连接，当SYN被发送，对方可能会通知他需要什么样的MSS，MSS是负荷的净尺寸，总是小于MTU */
static UBaseType_t prvSetSynAckOptions( FreeRTOS_Socket_t *pxSocket, TCPPacket_t * pxTCPPacket )
{
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
uint16_t usMSS = pxSocket->u.xTCP.usInitMSS;
#if ipconfigUSE_TCP_WIN == 1
    UBaseType_t uxOptionsLength;
#endif
    /* 我们发出MSS选项和我们的SYN[+ACK] */
    pxTCPHeader->ucOptdata[ 0 ] = ( uint8_t ) TCP_OPT_MSS;
    pxTCPHeader->ucOptdata[ 1 ] = ( uint8_t ) TCP_OPT_MSS_LEN;
    pxTCPHeader->ucOptdata[ 2 ] = ( uint8_t ) ( usMSS >> 8 );
    pxTCPHeader->ucOptdata[ 3 ] = ( uint8_t ) ( usMSS & 0xffu );

    #if( ipconfigUSE_TCP_WIN != 0 )
    {
        /* 添加窗口放大因子 */
        pxSocket->u.xTCP.ucMyWinScaleFactor = prvWinScaleFactor( pxSocket );
        pxTCPHeader->ucOptdata[ 4 ] = TCP_OPT_NOOP;
        pxTCPHeader->ucOptdata[ 5 ] = ( uint8_t ) ( TCP_OPT_WSOPT );
        pxTCPHeader->ucOptdata[ 6 ] = ( uint8_t ) ( TCP_OPT_WSOPT_LEN );
        pxTCPHeader->ucOptdata[ 7 ] = ( uint8_t ) pxSocket->u.xTCP.ucMyWinScaleFactor;
        uxOptionsLength = 8u;
    }
    #else
    {
        uxOptionsLength = 4u;
    }
    #endif


    #if( ipconfigUSE_TCP_WIN == 0 )
    {
        return uxOptionsLength;
    }
    #else
    {
        #if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
            if( pxSocket->u.xTCP.xTCPWindow.u.bits.bTimeStamps )
            {
                /* 添加时间戳 */
                uxOptionsLength += prvTCPSetTimeStamp( uxOptionsLength, pxSocket, &pxTCPPacket->xTCPHeader );
                pxTCPHeader->ucOptdata[ uxOptionsLength + 0 ] = TCP_OPT_SACK_P; /* 4: Sack-Permitted Option. */
                pxTCPHeader->ucOptdata[ uxOptionsLength + 1 ] = 2u;
                uxOptionsLength += 2u;
            }
            else
        #endif
        {
            /* 空白操作 */
            pxTCPHeader->ucOptdata[ uxOptionsLength + 0 ] = TCP_OPT_NOOP;
            pxTCPHeader->ucOptdata[ uxOptionsLength + 1 ] = TCP_OPT_NOOP;
            pxTCPHeader->ucOptdata[ uxOptionsLength + 2 ] = TCP_OPT_SACK_P; /* 4: Sack-Permitted Option. */
            pxTCPHeader->ucOptdata[ uxOptionsLength + 3 ] = 2;  /* 2: length of this option. */
            uxOptionsLength += 4u;
        }
        return uxOptionsLength; /* bytes, not words. */
    }
    #endif  /* ipconfigUSE_TCP_WIN == 0 */
}
/* 对于防挂保护和TCP保活包，会在两个地方调用：收到数据包之后和状态改变之后，套接字的保活定时器可能会复位 */
static void prvTCPTouchSocket( FreeRTOS_Socket_t *pxSocket )
{
    #if( ipconfigTCP_HANG_PROTECTION == 1 )
    {
        pxSocket->u.xTCP.xLastActTime = xTaskGetTickCount( );
    }
    #endif
    #if( ipconfigTCP_KEEP_ALIVE == 1 )
    {
        pxSocket->u.xTCP.bits.bWaitKeepAlive = pdFALSE_UNSIGNED;
        pxSocket->u.xTCP.bits.bSendKeepAlive = pdFALSE_UNSIGNED;
        pxSocket->u.xTCP.ucKeepRepCount = 0u;
        pxSocket->u.xTCP.xLastAliveTime = xTaskGetTickCount( );
    }
    #endif
    ( void ) pxSocket;
}
/*-----------------------------------------------------------*/
/* 
改变到一新的状态。集中在此处做一些特殊的动作，比如：重设保活定时器，
调用用户的连接句柄来修改套接字的链接和非连接属性，设置为来解锁对FreeRTOS_select 的调用
 */
void vTCPStateChange( FreeRTOS_Socket_t *pxSocket, enum eTCP_STATE eTCPState )
{
FreeRTOS_Socket_t *xParent = NULL;
BaseType_t bBefore = ( BaseType_t ) NOW_CONNECTED( pxSocket->u.xTCP.ucTCPState );   /* Was it connected ? */
BaseType_t bAfter  = ( BaseType_t ) NOW_CONNECTED( eTCPState );                     /* Is it connected now ? */
#if( ipconfigHAS_DEBUG_PRINTF != 0 )
    BaseType_t xPreviousState = ( BaseType_t ) pxSocket->u.xTCP.ucTCPState;
#endif
#if( ipconfigUSE_CALLBACKS == 1 )
    FreeRTOS_Socket_t *xConnected = NULL;
#endif

    /* 状态是否发生改变？ */
    if( bBefore != bAfter )
    {
        /* 套接字现在还连接吗 */
        if( bAfter != pdFALSE )
        {
            /* 如果bPassQueued为真，直到连接之前，本套接字是个孤儿 */
            if( pxSocket->u.xTCP.bits.bPassQueued != pdFALSE_UNSIGNED )
            {
                /* 现在他已连接，找到他的父亲 */
                if( pxSocket->u.xTCP.bits.bReuseSocket != pdFALSE_UNSIGNED )
                {
                    xParent = pxSocket;
                }
                else
                {
                    xParent = pxSocket->u.xTCP.pxPeerSocket;
                    configASSERT( xParent != NULL );
                }
                if( xParent != NULL )
                {
                    if( xParent->u.xTCP.pxPeerSocket == NULL )
                    {
                        xParent->u.xTCP.pxPeerSocket = pxSocket;
                    }
                    xParent->xEventBits |= eSOCKET_ACCEPT;
                    #if( ipconfigSUPPORT_SELECT_FUNCTION == 1 )
                    {
                        /* 库支持FreeRTOS_select()，收到一个新的连接会被翻译为一个读请求 */
                        if( ( xParent->xSelectBits & eSELECT_READ ) != 0 )
                        {
                            xParent->xEventBits |= ( eSELECT_READ << SOCKET_EVENT_BIT_COUNT );
                        }
                    }
                    #endif
                    #if( ipconfigUSE_CALLBACKS == 1 )
                    {
                        if( ( ipconfigIS_VALID_PROG_ADDRESS( xParent->u.xTCP.pxHandleConnected ) != pdFALSE ) &&
                            ( xParent->u.xTCP.bits.bReuseSocket == pdFALSE_UNSIGNED ) )
                        {
                            /* The listening socket does not become connected itself, in stead
                            a child socket is created.
                            Postpone a call the OnConnect event until the end of this function. */
                            /* 监听套接字不会自己连接，相反，一个子套接字被建立。 */
                            xConnected = xParent;
                        }
                    }
                    #endif
                }
                /* 不再需要父套接字，所以引用pxPeerSocket可以被清除掉 */
                pxSocket->u.xTCP.pxPeerSocket = NULL;
                pxSocket->u.xTCP.bits.bPassQueued = pdFALSE_UNSIGNED;
                /* When true, this socket may be returned in a call to accept(). */
                /* 当为真，套接字可能被返回。。。。。 */
                pxSocket->u.xTCP.bits.bPassAccept = pdTRUE_UNSIGNED;
            }
            else
            {
                pxSocket->xEventBits |= eSOCKET_CONNECT;
                #if( ipconfigSUPPORT_SELECT_FUNCTION == 1 )
                {
                    if( pxSocket->xSelectBits & eSELECT_WRITE )
                    {
                        pxSocket->xEventBits |= ( eSELECT_WRITE << SOCKET_EVENT_BIT_COUNT );
                    }
                }
                #endif
            }
        }
        else  /* bAfter == pdFALSE, connection is closed. */
        {
            /* 通过信号量 通知/唤醒套接字的拥有者 */
            pxSocket->xEventBits |= eSOCKET_CLOSED;
            #if( ipconfigSUPPORT_SELECT_FUNCTION == 1 )
            {
                if( ( pxSocket->xSelectBits & eSELECT_EXCEPT ) != 0 )
                {
                    pxSocket->xEventBits |= ( eSELECT_EXCEPT << SOCKET_EVENT_BIT_COUNT );
                }
            }
            #endif
        }
        #if( ipconfigUSE_CALLBACKS == 1 )
        {
            if( ( ipconfigIS_VALID_PROG_ADDRESS( pxSocket->u.xTCP.pxHandleConnected ) != pdFALSE ) && ( xConnected == NULL ) )
            {
                /* 连接的状态已经被更改，调用用户处理程序 */
                xConnected = pxSocket;
            }
        }
        #endif /* ipconfigUSE_CALLBACKS */

        if( prvTCPSocketIsActive( ( UBaseType_t ) pxSocket->u.xTCP.ucTCPState ) == pdFALSE )
        {
            /* 现在，套接字处于非激活状态所以不再需要获得IP-task的关心，设置超时为0是的此套接字不会被定期检查 */
            pxSocket->u.xTCP.usTimeout = 0u;
        }
    }
    else
    {
        if( eTCPState == eCLOSED )
        {
            /* 当套接字因为RST而转变状态为eCLOSED，并且谁也不引用他，直接删除 */
            if( ( pxSocket->u.xTCP.bits.bPassQueued != pdFALSE_UNSIGNED ) ||
                ( pxSocket->u.xTCP.bits.bPassAccept != pdFALSE_UNSIGNED ) )
            {
                FreeRTOS_debug_printf( ( "vTCPStateChange: Closing socket\n" ) );
                if( pxSocket->u.xTCP.bits.bReuseSocket == pdFALSE_UNSIGNED )
                {
                    FreeRTOS_closesocket( pxSocket );
                }
            }
        }
    }
    /* 填写新的状态 */
    pxSocket->u.xTCP.ucTCPState = ( uint8_t ) eTCPState;
    /* touch the alive timers because moving to another state. */
    prvTCPTouchSocket( pxSocket );
    #if( ipconfigHAS_DEBUG_PRINTF == 1 )
    {
    if( ( xTCPWindowLoggingLevel >= 0 ) && ( ipconfigTCP_MAY_LOG_PORT( pxSocket->usLocalPort ) != pdFALSE ) )
        FreeRTOS_debug_printf( ( "Socket %d -> %lxip:%u State %s->%s\n",
            pxSocket->usLocalPort,
            pxSocket->u.xTCP.ulRemoteIP,
            pxSocket->u.xTCP.usRemotePort,
            FreeRTOS_GetTCPStateName( ( UBaseType_t ) xPreviousState ),
            FreeRTOS_GetTCPStateName( ( UBaseType_t ) eTCPState ) ) );
    }
    #endif /* ipconfigHAS_DEBUG_PRINTF */

    #if( ipconfigUSE_CALLBACKS == 1 )
    {
        if( xConnected != NULL )
        {
            /* 连接的状态已经被改变了，调用其父的OnConnect handler */
            xConnected->u.xTCP.pxHandleConnected( ( Socket_t * ) xConnected, bAfter );
        }
    }
    #endif
    if( xParent != NULL )
    {
        vSocketWakeUpUser( xParent );
    }
}
/*-----------------------------------------------------------*/

static NetworkBufferDescriptor_t *prvTCPBufferResize( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer,
    int32_t lDataLen, UBaseType_t uxOptionsLength )
{
NetworkBufferDescriptor_t *pxReturn;
int32_t lNeeded;
BaseType_t xResize;

    if( xBufferAllocFixedSize != pdFALSE )
    {
        /* 网络缓冲通过固定的大小创建，可以容下最大的MTU */
        lNeeded = ( int32_t ) ipTOTAL_ETHERNET_FRAME_SIZE;
        /* 所以缓存不能太小，只能申请一个新的缓存以防没有提供 */
        xResize = ( pxNetworkBuffer == NULL );
    }
    else
    {
        /* 网络缓存通过可变大小被创建，看看他是否需要增长 */
        lNeeded = FreeRTOS_max_int32( ( int32_t ) sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket ),
            ( int32_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength ) + lDataLen );
        /* 以防我们被TCP定时器时间调用，缓冲必须被建立，否则，测试所提供的缓冲的大小 */
        xResize = ( pxNetworkBuffer == NULL ) || ( pxNetworkBuffer->xDataLength < (size_t)lNeeded );
    }

    if( xResize != pdFALSE )
    {
        /* 调用者没有提供缓存或者是提供的缓存太小，由于我们必须发送数据，所以在这里我们会创建缓存 */
        pxReturn = pxGetNetworkBufferWithDescriptor( ( uint32_t ) lNeeded, 0u );

        if( pxReturn != NULL )
        {
            /* 复制现存数据到新的缓存 */
            if( pxNetworkBuffer )
            {
                /* 从之前的缓存中复制 */
                memcpy( pxReturn->pucEthernetBuffer, pxNetworkBuffer->pucEthernetBuffer, pxNetworkBuffer->xDataLength );

                /* 释放之前的那个 */
                vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
            }
            else
            {
                /* 或者从套接字的xTCP.xPacket区域 */
                memcpy( pxReturn->pucEthernetBuffer, pxSocket->u.xTCP.xPacket.u.ucLastPacket, sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket ) );
            }
        }
    }
    else
    {
        /* 网络缓存足够大 */
        pxReturn = pxNetworkBuffer;
        /* Thanks to Andrey Ivanov from swissEmbedded for reporting that the
        xDataLength member must get the correct length too! */
        pxNetworkBuffer->xDataLength = ( size_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength ) + ( size_t ) lDataLen;
    }

    return pxReturn;
}
/*-----------------------------------------------------------*/
/* 准备一向外发的数据包，以防有数据要发送 */
static int32_t prvTCPPrepareSend( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer, UBaseType_t uxOptionsLength )
{
int32_t lDataLen;
uint8_t *pucEthernetBuffer, *pucSendData;
TCPPacket_t *pxTCPPacket;
size_t uxOffset;
uint32_t ulDataGot, ulDistance;
TCPWindow_t *pxTCPWindow;
NetworkBufferDescriptor_t *pxNewBuffer;
int32_t lStreamPos;

    if( ( *ppxNetworkBuffer ) != NULL )
    {
        /* 网络缓冲描述符早已经创建了 */
        pucEthernetBuffer = ( *ppxNetworkBuffer )->pucEthernetBuffer;
    }
    else
    {
        /* 现在，让他指向上一个包的头 */
        pucEthernetBuffer = pxSocket->u.xTCP.xPacket.u.ucLastPacket;
    }
    pxTCPPacket = ( TCPPacket_t * ) ( pucEthernetBuffer );
    pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
    lDataLen = 0;
    lStreamPos = 0;
    pxTCPPacket->xTCPHeader.ucTCPFlags |= ipTCP_FLAG_ACK;
    if( pxSocket->u.xTCP.txStream != NULL )
    {
        /* ulTCPWindowTxGet将会返回被发送数据的大小和在发送流中的位置，为什么检查MSS大于1？因为一些TCP协议栈用此来进行流控 */
        if( pxSocket->u.xTCP.usCurMSS > 1u )
        {
            lDataLen = ( int32_t ) ulTCPWindowTxGet( pxTCPWindow, pxSocket->u.xTCP.ulWindowSize, &lStreamPos );
        }
        if( lDataLen > 0 )
        {
            /* 检查当前的缓存是否足够大，如果不，重新设定它 */
            pxNewBuffer = prvTCPBufferResize( pxSocket, *ppxNetworkBuffer, lDataLen, uxOptionsLength );
            if( pxNewBuffer != NULL )
            {
                *ppxNetworkBuffer = pxNewBuffer;
                pucEthernetBuffer = pxNewBuffer->pucEthernetBuffer;
                pxTCPPacket = ( TCPPacket_t * ) ( pucEthernetBuffer );

                pucSendData = pucEthernetBuffer + ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength;

                /* Translate the position in txStream to an offset from the tail
                marker. */
                uxOffset = uxStreamBufferDistance( pxSocket->u.xTCP.txStream, pxSocket->u.xTCP.txStream->uxTail, ( size_t ) lStreamPos );

                /* Here data is copied from the txStream in 'peek' mode.  Only
                when the packets are acked, the tail marker will be updated. */
                ulDataGot = ( uint32_t ) uxStreamBufferGet( pxSocket->u.xTCP.txStream, uxOffset, pucSendData, ( size_t ) lDataLen, pdTRUE );

                #if( ipconfigHAS_DEBUG_PRINTF != 0 )
                {
                    if( ulDataGot != ( uint32_t ) lDataLen )
                    {
                        FreeRTOS_debug_printf( ( "uxStreamBufferGet: pos %lu offs %lu only %lu != %lu\n",
                            lStreamPos, uxOffset, ulDataGot, lDataLen ) );
                    }
                }
                #endif
                /* 如果用户需要关闭，添加FIN标志 */
                if( ( pxSocket->u.xTCP.bits.bCloseRequested != pdFALSE_UNSIGNED ) && ( pxSocket->u.xTCP.bits.bFinSent == pdFALSE_UNSIGNED ) )
                {
                    ulDistance = ( uint32_t ) uxStreamBufferDistance( pxSocket->u.xTCP.txStream, ( size_t ) lStreamPos, pxSocket->u.xTCP.txStream->uxHead );

                    if( ulDistance == ulDataGot )
                    {
                        #if (ipconfigHAS_DEBUG_PRINTF == 1)
                        {
                        /* the order of volatile accesses is undefined
                            so such workaround */
                            size_t uxHead = pxSocket->u.xTCP.txStream->uxHead;
                            size_t uxMid = pxSocket->u.xTCP.txStream->uxMid;
                            size_t uxTail = pxSocket->u.xTCP.txStream->uxTail;

                            FreeRTOS_debug_printf( ( "CheckClose %lu <= %lu (%lu <= %lu <= %lu)\n", ulDataGot, ulDistance,
                                uxTail, uxMid, uxHead ) );
                        }
                        #endif
                        /* 虽然套接字发送了一个FIN，但是他会一直停留在ESTABLISHED状态直到数据被发送会被接收 */
                        pxTCPPacket->xTCPHeader.ucTCPFlags |= ipTCP_FLAG_FIN;
                        pxTCPWindow->tx.ulFINSequenceNumber = pxTCPWindow->ulOurSequenceNumber + ( uint32_t ) lDataLen;
                        pxSocket->u.xTCP.bits.bFinSent = pdTRUE_UNSIGNED;
                    }
                }
            }
            else
            {
                lDataLen = -1;
            }
        }
    }

    if( ( lDataLen >= 0 ) && ( pxSocket->u.xTCP.ucTCPState == eESTABLISHED ) )
    {
        /* 看看用户是否要关闭该连接 */
        if( ( pxSocket->u.xTCP.bits.bUserShutdown != pdFALSE_UNSIGNED ) &&
            ( xTCPWindowTxDone( pxTCPWindow ) != pdFALSE ) )
        {
            pxSocket->u.xTCP.bits.bUserShutdown = pdFALSE_UNSIGNED;
            pxTCPPacket->xTCPHeader.ucTCPFlags |= ipTCP_FLAG_FIN;
            pxSocket->u.xTCP.bits.bFinSent = pdTRUE_UNSIGNED;
            pxSocket->u.xTCP.bits.bWinChange = pdTRUE_UNSIGNED;
            pxTCPWindow->tx.ulFINSequenceNumber = pxTCPWindow->tx.ulCurrentSequenceNumber;
            vTCPStateChange( pxSocket, eFIN_WAIT_1 );
        }

        #if( ipconfigTCP_KEEP_ALIVE != 0 )
        {
            if( pxSocket->u.xTCP.ucKeepRepCount > 3u )
            {
                FreeRTOS_debug_printf( ( "keep-alive: giving up %lxip:%u\n",
                    pxSocket->u.xTCP.ulRemoteIP,            /* IP address of remote machine. */
                    pxSocket->u.xTCP.usRemotePort ) );  /* Port on remote machine. */
                vTCPStateChange( pxSocket, eCLOSE_WAIT );
                lDataLen = -1;
            }
            if( ( lDataLen == 0 ) && ( pxSocket->u.xTCP.bits.bWinChange == pdFALSE_UNSIGNED ) )
            {
                /* 如果没有数据要发送，并且没有窗口更新信息，我们可能想发送保活信息 */
                TickType_t xAge = xTaskGetTickCount( ) - pxSocket->u.xTCP.xLastAliveTime;
                TickType_t xMax;
                xMax = ( ( TickType_t ) ipconfigTCP_KEEP_ALIVE_INTERVAL * configTICK_RATE_HZ );
                if( pxSocket->u.xTCP.ucKeepRepCount )
                {
                    xMax = ( 3u * configTICK_RATE_HZ );
                }
                if( xAge > xMax )
                {
                    pxSocket->u.xTCP.xLastAliveTime = xTaskGetTickCount( );
                    if( xTCPWindowLoggingLevel )
                        FreeRTOS_debug_printf( ( "keep-alive: %lxip:%u count %u\n",
                            pxSocket->u.xTCP.ulRemoteIP,
                            pxSocket->u.xTCP.usRemotePort,
                            pxSocket->u.xTCP.ucKeepRepCount ) );
                    pxSocket->u.xTCP.bits.bSendKeepAlive = pdTRUE_UNSIGNED;
                    pxSocket->u.xTCP.usTimeout = ( ( uint16_t ) pdMS_TO_TICKS( 2500 ) );
                    pxSocket->u.xTCP.ucKeepRepCount++;
                }
            }
        }
        #endif /* ipconfigTCP_KEEP_ALIVE */
    }
    /* 任何数据的发送，窗口大小的广播，或者是发送一个保活信号？ */
    if( ( lDataLen > 0 ) ||
        ( pxSocket->u.xTCP.bits.bWinChange != pdFALSE_UNSIGNED ) ||
        ( pxSocket->u.xTCP.bits.bSendKeepAlive != pdFALSE_UNSIGNED ) )
    {
        pxTCPPacket->xTCPHeader.ucTCPFlags &= ( ( uint8_t ) ~ipTCP_FLAG_PSH );
        pxTCPPacket->xTCPHeader.ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );

        pxTCPPacket->xTCPHeader.ucTCPFlags |= ( uint8_t ) ipTCP_FLAG_ACK;

        if( lDataLen != 0l )
        {
            pxTCPPacket->xTCPHeader.ucTCPFlags |= ( uint8_t ) ipTCP_FLAG_PSH;
        }

        #if ipconfigUSE_TCP_TIMESTAMPS == 1
        {
            if( xOptionsLength == 0 )
            {
                if( pxSocket->u.xTCP.xTCPWindow.u.bits.bTimeStamps )
                {
                    TCPPacket_t * pxTCPPacket = ( TCPPacket_t * ) ( pucEthernetBuffer );
                    xOptionsLength = prvTCPSetTimeStamp( 0, pxSocket, &pxTCPPacket->xTCPHeader );
                }
            }
        }
        #endif

        lDataLen += ( int32_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
    }

    return lDataLen;
}
/* 计算该套接字再次检查需要多长时间 */
static TickType_t prvTCPNextTimeout ( FreeRTOS_Socket_t *pxSocket )
{
TickType_t ulDelayMs = ( TickType_t ) 20000;
    if( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN )
    {
        /* 套接字主动连接到对方 */
        if( pxSocket->u.xTCP.bits.bConnPrepared )
        {
            /* 以太网地址已经被发现，对此连接激活连接超时 */
            if( pxSocket->u.xTCP.ucRepCount < 3u )
            {
                ulDelayMs = ( 3000UL << ( pxSocket->u.xTCP.ucRepCount - 1u ) );
            }
            else
            {
                ulDelayMs = 11000UL;
            }
        }
        else
        {
            /* Still in the ARP phase: check every half second. */
            /* 依然在ARP阶段，每半秒检查 */
            ulDelayMs = 500UL;
        }
        FreeRTOS_debug_printf( ( "Connect[%lxip:%u]: next timeout %u: %lu ms\n",
            pxSocket->u.xTCP.ulRemoteIP, pxSocket->u.xTCP.usRemotePort,
            pxSocket->u.xTCP.ucRepCount, ulDelayMs ) );
        pxSocket->u.xTCP.usTimeout = ( uint16_t )pdMS_TO_MIN_TICKS( ulDelayMs );
    }
    else if( pxSocket->u.xTCP.usTimeout == 0u )
    {
        /* 让滑动窗口机制决定多少超时是合适的 */
        BaseType_t xResult = xTCPWindowTxHasData( &pxSocket->u.xTCP.xTCPWindow, pxSocket->u.xTCP.ulWindowSize, &ulDelayMs );
        if( ulDelayMs == 0u )
        {
            ulDelayMs = xResult ? 1UL : 20000UL;
        }
        else
        {
            /* ulDelayMs包含了重传所需的时间 */
        }
        pxSocket->u.xTCP.usTimeout = ( uint16_t )pdMS_TO_MIN_TICKS( ulDelayMs );
    }
    else
    {
        /* field '.usTimeout' has already been set (by the
        keep-alive/delayed-ACK mechanism). */
    }

    /* Return the number of clock ticks before the timer expires. */
    return ( TickType_t ) pxSocket->u.xTCP.usTimeout;
}
/*-----------------------------------------------------------*/

static void prvTCPAddTxData( FreeRTOS_Socket_t *pxSocket )
{
int32_t lCount, lLength;

    /* 发送流已经创建，看看滑动窗口是否有新的数据 
    uxStreamBufferMidSpace()返回rxHead和rxMid的距离，它包括新的没有被传递给滑动窗口的数据。老的没被确认的数据在rxTail
    */
    lLength = ( int32_t ) uxStreamBufferMidSpace( pxSocket->u.xTCP.txStream );

    if( lLength > 0 )
    {
        /* 
        介于txMid和rxHead之间的数据会被传送到滑动窗口，然后可以开始传递。
        交出新的数据到滑动窗口的句柄，他将会分成1460的段（取决于ipconfigTCP_MSS）
        */
        lCount = lTCPWindowTxAdd(   &pxSocket->u.xTCP.xTCPWindow,
                                ( uint32_t ) lLength,
                                ( int32_t ) pxSocket->u.xTCP.txStream->uxMid,
                                ( int32_t ) pxSocket->u.xTCP.txStream->LENGTH );
        /* 移动rxMid向前到达rxHead */
        if( lCount > 0 )
        {
            vStreamBufferMoveMid( pxSocket->u.xTCP.txStream, ( size_t ) lCount );
        }
    }
}
/* prvTCPHandleFin()用来掌管套接字的关闭，关闭开始于FIN的接收或者是FIN的发送，在被调用之前，接收和发送的检查已经完成 */
static BaseType_t prvTCPHandleFin( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
uint8_t ucTCPFlags = pxTCPHeader->ucTCPFlags;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
BaseType_t xSendLength = 0;
uint32_t ulAckNr = FreeRTOS_ntohl( pxTCPHeader->ulAckNr );

    if( ( ucTCPFlags & ipTCP_FLAG_FIN ) != 0u )
    {
        pxTCPWindow->rx.ulCurrentSequenceNumber = pxTCPWindow->rx.ulFINSequenceNumber + 1u;
    }
    if( pxSocket->u.xTCP.bits.bFinSent == pdFALSE_UNSIGNED )
    {
        /* 我们还没有回复FIN，现在就做 */
        pxTCPWindow->tx.ulFINSequenceNumber = pxTCPWindow->tx.ulCurrentSequenceNumber;
        pxSocket->u.xTCP.bits.bFinSent = pdTRUE_UNSIGNED;
    }
    else
    {
        /* 我们确实是发送了FIN，看看是否收到应答 */
        if( ulAckNr == pxTCPWindow->tx.ulFINSequenceNumber + 1u )
        {
            pxSocket->u.xTCP.bits.bFinAcked = pdTRUE_UNSIGNED;
        }
    }

    if( pxSocket->u.xTCP.bits.bFinAcked == pdFALSE_UNSIGNED )
    {
        pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->tx.ulFINSequenceNumber;
        pxTCPHeader->ucTCPFlags = ipTCP_FLAG_ACK | ipTCP_FLAG_FIN;
        /* 等待最后的应答 */
        vTCPStateChange( pxSocket, eLAST_ACK );
    }
    else
    {
        /* Our FIN has been ACK'd, the outgoing sequence number is now fixed. */
        /* 我们的FIN已经被应答了， */
        pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->tx.ulFINSequenceNumber + 1u;
        if( pxSocket->u.xTCP.bits.bFinRecv == pdFALSE_UNSIGNED )
        {
            /* 我们已经发送了FIN，但是对方并没有回复一个FIN，现在什么也不做 */
            pxTCPHeader->ucTCPFlags = 0u;
        }
        else
        {
            if( pxSocket->u.xTCP.bits.bFinLast == pdFALSE_UNSIGNED )
            {
                /* 这是三步握手的第三步：最后的应答 */
                pxTCPHeader->ucTCPFlags = ipTCP_FLAG_ACK;
            }
            else
            {
                /* 对方开始关闭，所以我们只是等待最后的ACK */
                pxTCPHeader->ucTCPFlags = 0u;
            }
            /* 等待用户关闭本套接字 */
            vTCPStateChange( pxSocket, eCLOSE_WAIT );
        }
    }

    pxTCPWindow->ulOurSequenceNumber = pxTCPWindow->tx.ulCurrentSequenceNumber;

    if( pxTCPHeader->ucTCPFlags != 0u )
    {
        xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + pxTCPWindow->ucOptionLength );
    }

    pxTCPHeader->ucTCPOffset = ( uint8_t ) ( ( ipSIZE_OF_TCP_HEADER + pxTCPWindow->ucOptionLength ) << 2 );

    if( xTCPWindowLoggingLevel != 0 )
    {
        FreeRTOS_debug_printf( ( "TCP: send FIN+ACK (ack %lu, cur/nxt %lu/%lu) ourSeqNr %lu | Rx %lu\n",
            ulAckNr - pxTCPWindow->tx.ulFirstSequenceNumber,
            pxTCPWindow->tx.ulCurrentSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber,
            pxTCPWindow->ulNextTxSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber,
            pxTCPWindow->ulOurSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber,
            pxTCPWindow->rx.ulCurrentSequenceNumber - pxTCPWindow->rx.ulFirstSequenceNumber ) );
    }

    return xSendLength;
}
/*-----------------------------------------------------------*/
/* 设置时间戳 */
#if ipconfigUSE_TCP_TIMESTAMPS == 1

    static UBaseType_t prvTCPSetTimeStamp( BaseType_t lOffset, FreeRTOS_Socket_t *pxSocket, TCPHeader_t *pxTCPHeader )
    {
    uint32_t ulTimes[2];
    uint8_t *ucOptdata = &( pxTCPHeader->ucOptdata[ lOffset ] );

        ulTimes[0]   = ( xTaskGetTickCount ( ) * 1000u ) / configTICK_RATE_HZ;
        ulTimes[0]   = FreeRTOS_htonl( ulTimes[0] );
        ulTimes[1]   = FreeRTOS_htonl( pxSocket->u.xTCP.xTCPWindow.rx.ulTimeStamp );
        ucOptdata[0] = ( uint8_t ) TCP_OPT_TIMESTAMP;
        ucOptdata[1] = ( uint8_t ) TCP_OPT_TIMESTAMP_LEN;
        memcpy( &(ucOptdata[2] ), ulTimes, 8u );
        ucOptdata[10] = ( uint8_t ) TCP_OPT_NOOP;
        ucOptdata[11] = ( uint8_t ) TCP_OPT_NOOP;
        /* Do not return the same timestamps 2 times. */
        pxSocket->u.xTCP.xTCPWindow.rx.ulTimeStamp = 0ul;
        return 12u;
    }

#endif
/*-----------------------------------------------------------*/
/* prvCheckRxData()在prvTCPHandleState()中被调用，第一件要做的事是找到TCP负荷数据并检查数据长度 */
static BaseType_t prvCheckRxData( NetworkBufferDescriptor_t *pxNetworkBuffer, uint8_t **ppucRecvData )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &( pxTCPPacket->xTCPHeader );
int32_t lLength, lTCPHeaderLength, lReceiveLength, lUrgentLength;
    /* 决定被发送到此节点上的数据的长度和偏移，TCP数据头是需要乘以4的， */
    lTCPHeaderLength = ( BaseType_t ) ( ( pxTCPHeader->ucTCPOffset & VALID_BITS_IN_TCP_OFFSET_BYTE ) >> 2 );
    /* 使得pucRecvData指向接收到的第一个字节 */
    *ppucRecvData = pxNetworkBuffer->pucEthernetBuffer + ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + lTCPHeaderLength;
    /* 计算接收到的数据长度-等同于包长度减去 ( LinkLayer length (14) + IP header length (20) + size of TCP header(20 +) )*/
    lReceiveLength = ( ( int32_t ) pxNetworkBuffer->xDataLength ) - ( int32_t ) ipSIZE_OF_ETH_HEADER;
    lLength =  ( int32_t )FreeRTOS_htons( pxTCPPacket->xIPHeader.usLength );
    if( lReceiveLength > lLength )
    {
        /* 数据超出太多一般是因为填充字节 */
        lReceiveLength = lLength;
    }
    /* 减去TCP和IP的头的长度就会得到真实的数据长度 */
    if( lReceiveLength > ( lTCPHeaderLength + ( int32_t ) ipSIZE_OF_IPv4_HEADER ) )
    {
        lReceiveLength -= ( lTCPHeaderLength + ( int32_t ) ipSIZE_OF_IPv4_HEADER );
    }
    else
    {
        lReceiveLength = 0;
    }

    /* Urgent Pointer:
    This field communicates the current value of the urgent pointer as a
    positive offset from the sequence number in this segment.  The urgent
    pointer points to the sequence number of the octet following the urgent
    data.  This field is only be interpreted in segments with the URG control
    bit set. */
    /* 紧急指针：
        
    */
    if( ( pxTCPHeader->ucTCPFlags & ipTCP_FLAG_URG ) != 0u )
    {
        /* 虽然我们忽略紧急数据，我们不得不跳过他 */
        lUrgentLength = ( int32_t ) FreeRTOS_htons( pxTCPHeader->usUrgent );
        *ppucRecvData += lUrgentLength;
        lReceiveLength -= FreeRTOS_min_int32( lReceiveLength, lUrgentLength );
    }
    return ( BaseType_t ) lReceiveLength;
}
/*2016--11--20--19--53--58(ZJYC): prvStoreRxData()被函数prvTCPHandleState()调用，第二件要做的事情便是检查数据负载
是否可接受，如果是的话，他们将被添加到接受序列   */ 
/* prvStoreRxData()被prvTCPHandleState()调用，第二件要做的事情便是检查负载是否被接收，如果是的话，他们将被加入到接受队列 */
static BaseType_t prvStoreRxData( FreeRTOS_Socket_t *pxSocket, uint8_t *pucRecvData,
    NetworkBufferDescriptor_t *pxNetworkBuffer, uint32_t ulReceiveLength )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
uint32_t ulSequenceNumber, ulSpace;
int32_t lOffset, lStored;
BaseType_t xResult = 0;
    ulSequenceNumber = FreeRTOS_ntohl( pxTCPHeader->ulSequenceNumber );
    if( ( ulReceiveLength > 0u ) && ( pxSocket->u.xTCP.ucTCPState >= eSYN_RECEIVED ) )
    {
		/*2016--11--20--19--57--26(ZJYC):看看我们是否接收数据并将其推送到套接字拥有者    */ 
		/*2016--11--20--19--59--54(ZJYC): 如果不可被接受，他需要被存储并发送可选择的ACK或SACK
		来确认，在这种情况下，xTCPWindowRxStore() 会被调用来存储非顺序的数据包
		*/ 
        /* 看我们是否收到数据内容，并将它传递给套接字的拥有者 */
        /* 如果他不能被接收，他可能已经被存储，发送一个可选的ack (SACK)选项头应答之，
            在这种情况下，xTCPWindowRxStore()后期会被调用来存储那些非顺序的数据
        */
        if ( pxSocket->u.xTCP.rxStream )
        {
            ulSpace = ( uint32_t )uxStreamBufferGetSpace ( pxSocket->u.xTCP.rxStream );
        }
        else
        {
            ulSpace = ( uint32_t )pxSocket->u.xTCP.uxRxStreamSize;
        }
        lOffset = lTCPWindowRxCheck( pxTCPWindow, ulSequenceNumber, ulReceiveLength, ulSpace );
        if( lOffset >= 0 )
        {
			/*2016--11--20--20--01--53(ZJYC):新数据已经到达并且可以被用户使用。看看是否头部标志
			
			*/ 
            /* New data has arrived and may be made available to the user.  See
            if the head marker in rxStream may be advanced, only if lOffset == 0.
            In case the low-water mark is reached, bLowWater will be set
            "low-water" here stands for "little space". */
            /* 新数据已经到达，可以被用户使用，看看是否 */
            lStored = lTCPAddRxdata( pxSocket, ( uint32_t ) lOffset, pucRecvData, ulReceiveLength );

            if( lStored != ( int32_t ) ulReceiveLength )
            {
                FreeRTOS_debug_printf( ( "lTCPAddRxdata: stored %ld / %lu bytes??\n", lStored, ulReceiveLength ) );
				/*2016--11--20--20--04--39(ZJYC):接收到的数据不能被存储。套接字的bMallocError标志被置位
				套接字现在eCLOSE_WAIT的状态为并且将发出RST包
				*/ 
                /* 接收到的数据不能被存储，套接字的标志位bMallocError被置位，套接字现在的状态为eCLOSE_WAIT并且带有RST的数据包将会被返回 */
                prvTCPSendReset( pxNetworkBuffer );
                xResult = -1;
            }
        }
		/*2016--11--20--20--06--04(ZJYC):收到一个丢失的包之后，更高的数据包会被传递给用户    */ 
			/*2016--11--20--20--07--12(ZJYC):现在lTCPAddRxdata()将会向前移动rxHead指针，
			所以对用户而言，数据很快变得可用起来，置位bLowWater以防止到达低位线，*/ 
        /* 当接收到丢失的数据包之后，较高的数据包可能传递给用户 */
        #if( ipconfigUSE_TCP_WIN == 1 )
        {
            /* Now lTCPAddRxdata() will move the rxHead pointer forward
            so data becomes available to the user immediately
            In case the low-water mark is reached, bLowWater will be set. */
            /* 现在lTCPAddRxdata()，将会向前移动rxHead指针，所以数据立即变得对用户可用，为防止到达低水位标志，bLowWater会被置位 */
            if( ( xResult == 0 ) && ( pxTCPWindow->ulUserDataLength > 0 ) )
            {
                lTCPAddRxdata( pxSocket, 0ul, NULL, pxTCPWindow->ulUserDataLength );
                pxTCPWindow->ulUserDataLength = 0;
            }
        }
        #endif /* ipconfigUSE_TCP_WIN */
    }
    else
    {
        pxTCPWindow->ucOptionLength = 0u;
    }
    return xResult;
}
/*2016--11--20--20--09--51(ZJYC): 为即将发出的数据包设置选项（如果有的话）   */ 
static UBaseType_t prvSetOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
UBaseType_t uxOptionsLength = pxTCPWindow->ucOptionLength;

    #if(    ipconfigUSE_TCP_WIN == 1 )
        if( uxOptionsLength != 0u )
        {
			/*2016--11--20--20--10--46(ZJYC):TCP选项必须被发送，因为接受到了非顺序数据包    */ 
            if( xTCPWindowLoggingLevel >= 0 )
                FreeRTOS_debug_printf( ( "SACK[%d,%d]: optlen %lu sending %lu - %lu\n",
                    pxSocket->usLocalPort,
                    pxSocket->u.xTCP.usRemotePort,
                    uxOptionsLength,
                    FreeRTOS_ntohl( pxTCPWindow->ulOptionsData[ 1 ] ) - pxSocket->u.xTCP.xTCPWindow.rx.ulFirstSequenceNumber,
                    FreeRTOS_ntohl( pxTCPWindow->ulOptionsData[ 2 ] ) - pxSocket->u.xTCP.xTCPWindow.rx.ulFirstSequenceNumber ) );
            memcpy( pxTCPHeader->ucOptdata, pxTCPWindow->ulOptionsData, ( size_t ) uxOptionsLength );
			/*2016--11--20--20--11--42(ZJYC): 除以4并放在高位，等同于左移2   */ 
            pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
        }
        else
    #endif  /* ipconfigUSE_TCP_WIN */
    if( ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) && ( pxSocket->u.xTCP.bits.bMssChange != pdFALSE_UNSIGNED ) )
    {
		/*2016--11--20--20--12--48(ZJYC):TCP选项必须被发送，因为MSS已改变    */ 
        pxSocket->u.xTCP.bits.bMssChange = pdFALSE_UNSIGNED;
        if( xTCPWindowLoggingLevel >= 0 )
        {
            FreeRTOS_debug_printf( ( "MSS: sending %d\n", pxSocket->u.xTCP.usCurMSS ) );
        }

        pxTCPHeader->ucOptdata[ 0 ] = TCP_OPT_MSS;
        pxTCPHeader->ucOptdata[ 1 ] = TCP_OPT_MSS_LEN;
        pxTCPHeader->ucOptdata[ 2 ] = ( uint8_t ) ( ( pxSocket->u.xTCP.usCurMSS ) >> 8 );
        pxTCPHeader->ucOptdata[ 3 ] = ( uint8_t ) ( ( pxSocket->u.xTCP.usCurMSS ) & 0xffu );
        uxOptionsLength = 4u;
        pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
    }

    #if(    ipconfigUSE_TCP_TIMESTAMPS == 1 )
    {
        if( pxSocket->u.xTCP.xTCPWindow.u.bits.bTimeStamps )
        {
            uxOptionsLength += prvTCPSetTimeStamp( xOptionsLength, pxSocket, pxTCPHeader );
        }
    }
    #endif  /* ipconfigUSE_TCP_TIMESTAMPS == 1 */

    return uxOptionsLength;
}
/*2016--11--20--20--13--24(ZJYC): prvHandleSynReceived()被函数 prvTCPHandleState()调用，在
eSYN_RECEIVED and eCONNECT_SYN状态下调用，如果收到的标志是正确的，套接字会变为eESTABLISHED  */ 
static BaseType_t prvHandleSynReceived( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( (*ppxNetworkBuffer)->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
uint8_t ucTCPFlags = pxTCPHeader->ucTCPFlags;
uint32_t ulSequenceNumber = FreeRTOS_ntohl( pxTCPHeader->ulSequenceNumber );
BaseType_t xSendLength = 0;

	/*2016--11--20--20--40--34(ZJYC): 期望ACK或者是SYN+ACK*/ 
    uint16_t usExpect = ( uint16_t ) ipTCP_FLAG_ACK;
    if( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN )
    {
        usExpect |= ( uint16_t ) ipTCP_FLAG_SYN;
    }

    if( ( ucTCPFlags & 0x17u ) != usExpect )
    {
        /* eSYN_RECEIVED: flags 0010 expected, not 0002. */
        /* eSYN_RECEIVED: flags ACK  expected, not SYN. */
        FreeRTOS_debug_printf( ( "%s: flags %04X expected, not %04X\n",
            pxSocket->u.xTCP.ucTCPState == eSYN_RECEIVED ? "eSYN_RECEIVED" : "eCONNECT_SYN",
            usExpect, ucTCPFlags ) );
        vTCPStateChange( pxSocket, eCLOSE_WAIT );
        pxTCPHeader->ucTCPFlags |= ipTCP_FLAG_RST;
        xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
        pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
    }
    else
    {
        pxTCPWindow->usPeerPortNumber = pxSocket->u.xTCP.usRemotePort;
        pxTCPWindow->usOurPortNumber = pxSocket->usLocalPort;

        if( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN )
        {
            TCPPacket_t *pxLastTCPPacket = ( TCPPacket_t * ) ( pxSocket->u.xTCP.xPacket.u.ucLastPacket );

            /* Clear the SYN flag in lastPacket. */
            pxLastTCPPacket->xTCPHeader.ucTCPFlags = ipTCP_FLAG_ACK;

            /* This socket was the one connecting actively so now perofmr the
            synchronisation. */
            vTCPWindowInit( &pxSocket->u.xTCP.xTCPWindow,
                ulSequenceNumber, pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber, ( uint32_t ) pxSocket->u.xTCP.usCurMSS );
            pxTCPWindow->rx.ulCurrentSequenceNumber = pxTCPWindow->rx.ulHighestSequenceNumber = ulSequenceNumber + 1u;
            pxTCPWindow->tx.ulCurrentSequenceNumber++; /* because we send a TCP_SYN [ | TCP_ACK ]; */
            pxTCPWindow->ulNextTxSequenceNumber++;
        }
        else if( ulReceiveLength == 0u )
        {
            pxTCPWindow->rx.ulCurrentSequenceNumber = ulSequenceNumber;
        }

        /* The SYN+ACK has been confirmed, increase the next sequence number by
        1. */
        pxTCPWindow->ulOurSequenceNumber = pxTCPWindow->tx.ulFirstSequenceNumber + 1u;

        #if( ipconfigUSE_TCP_WIN == 1 )
        {
            FreeRTOS_debug_printf( ( "TCP: %s %d => %lxip:%d set ESTAB (scaling %u)\n",
                pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN ? "active" : "passive",
                pxSocket->usLocalPort,
                pxSocket->u.xTCP.ulRemoteIP,
                pxSocket->u.xTCP.usRemotePort,
                ( unsigned ) pxSocket->u.xTCP.bits.bWinScaling ) );
        }
        #endif /* ipconfigUSE_TCP_WIN */

        if( ( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN ) || ( ulReceiveLength != 0u ) )
        {
            pxTCPHeader->ucTCPFlags = ipTCP_FLAG_ACK;
            xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
            pxTCPHeader->ucTCPOffset = ( uint8_t ) ( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
        }

        if( pxSocket->u.xTCP.bits.bWinScaling == pdFALSE_UNSIGNED )
        {
            /* The other party did not send a scaling factor.
            A shifting factor in this side must be canceled. */
            pxSocket->u.xTCP.ucMyWinScaleFactor = 0;
            pxSocket->u.xTCP.ucPeerWinScaleFactor = 0;
        }
        /* This was the third step of connecting: SYN, SYN+ACK, ACK so now the
        connection is established. */
        vTCPStateChange( pxSocket, eESTABLISHED );
    }

    return xSendLength;
}
/*2016--11--20--20--42--03(ZJYC):prvHandleEstablished()被prvTCPHandleState()调用，如果状态为建立则调用此函数
数据接收早些时候已经被掌管，这里的对方发过来的ACK会被检查，如果收到FIN，代码会检查是否收到他，即：如果所有的数据
被完全接收    */ 
static BaseType_t prvHandleEstablished( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( (*ppxNetworkBuffer)->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
uint8_t ucTCPFlags = pxTCPHeader->ucTCPFlags;
uint32_t ulSequenceNumber = FreeRTOS_ntohl( pxTCPHeader->ulSequenceNumber ), ulCount;
BaseType_t xSendLength = 0, xMayClose = pdFALSE, bRxComplete, bTxDone;
int32_t lDistance, lSendResult;

    /*2016--11--20--20--49--36(ZJYC):记住对方公布的窗口大小    */ 
    pxSocket->u.xTCP.ulWindowSize = FreeRTOS_ntohs( pxTCPHeader->usWindow );
    pxSocket->u.xTCP.ulWindowSize =
        ( pxSocket->u.xTCP.ulWindowSize << pxSocket->u.xTCP.ucPeerWinScaleFactor );

    if( ( ucTCPFlags & ( uint8_t ) ipTCP_FLAG_ACK ) != 0u )
    {
        ulCount = ulTCPWindowTxAck( pxTCPWindow, FreeRTOS_ntohl( pxTCPPacket->xTCPHeader.ulAckNr ) );
        /*2016--11--20--20--50--38(ZJYC):ulTCPWindowTxAck返回已经被被应答的字节数，从tx.ulCurrentSequenceNumber开始    */ 
        /* ulTCPWindowTxAck() returns the number of bytes which have been acked,
        starting at 'tx.ulCurrentSequenceNumber'.  Advance the tail pointer in
        txStream. */
        if( ( pxSocket->u.xTCP.txStream != NULL ) && ( ulCount > 0u ) )
        {
            /* Just advancing the tail index, 'ulCount' bytes have been
            confirmed, and because there is new space in the txStream, the
            user/owner should be woken up. */
            /* _HT_ : only in case the socket's waiting? */
            if( uxStreamBufferGet( pxSocket->u.xTCP.txStream, 0u, NULL, ( size_t ) ulCount, pdFALSE ) != 0u )
            {
                pxSocket->xEventBits |= eSOCKET_SEND;

                #if ipconfigSUPPORT_SELECT_FUNCTION == 1
                {
                    if( ( pxSocket->xSelectBits & eSELECT_WRITE ) != 0 )
                    {
                        pxSocket->xEventBits |= ( eSELECT_WRITE << SOCKET_EVENT_BIT_COUNT );
                    }
                }
                #endif
                /* In case the socket owner has installed an OnSent handler,
                call it now. */
                #if( ipconfigUSE_CALLBACKS == 1 )
                {
                    if( ipconfigIS_VALID_PROG_ADDRESS( pxSocket->u.xTCP.pxHandleSent ) )
                    {
                        pxSocket->u.xTCP.pxHandleSent( (Socket_t *)pxSocket, ulCount );
                    }
                }
                #endif /* ipconfigUSE_CALLBACKS == 1  */
            }
        }
    }

    /* If this socket has a stream for transmission, add the data to the
    outgoing segment(s). */
    if( pxSocket->u.xTCP.txStream != NULL )
    {
        prvTCPAddTxData( pxSocket );
    }

    pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber = pxTCPWindow->tx.ulCurrentSequenceNumber;

    if( ( pxSocket->u.xTCP.bits.bFinAccepted != pdFALSE_UNSIGNED ) || ( ( ucTCPFlags & ( uint8_t ) ipTCP_FLAG_FIN ) != 0u ) )
    {
        /* Peer is requesting to stop, see if we're really finished. */
        xMayClose = pdTRUE;

        /* Checks are only necessary if we haven't sent a FIN yet. */
        if( pxSocket->u.xTCP.bits.bFinSent == pdFALSE_UNSIGNED )
        {
            /* xTCPWindowTxDone returns true when all Tx queues are empty. */
            bRxComplete = xTCPWindowRxEmpty( pxTCPWindow );
            bTxDone     = xTCPWindowTxDone( pxTCPWindow );

            if( ( bRxComplete == 0 ) || ( bTxDone == 0 ) )
            {
                /* Refusing FIN: Rx incomp 1 optlen 4 tx done 1. */
                FreeRTOS_debug_printf( ( "Refusing FIN[%u,%u]: RxCompl %lu tx done %ld\n",
                    pxSocket->usLocalPort,
                    pxSocket->u.xTCP.usRemotePort,
                    bRxComplete, bTxDone ) );
                xMayClose = pdFALSE;
            }
            else
            {
                lDistance = ( int32_t ) ( ulSequenceNumber + ulReceiveLength - pxTCPWindow->rx.ulCurrentSequenceNumber );

                if( lDistance > 1 )
                {
                    FreeRTOS_debug_printf( ( "Refusing FIN: Rx not complete %ld (cur %lu high %lu)\n",
                        lDistance, pxTCPWindow->rx.ulCurrentSequenceNumber - pxTCPWindow->rx.ulFirstSequenceNumber,
                        pxTCPWindow->rx.ulHighestSequenceNumber - pxTCPWindow->rx.ulFirstSequenceNumber ) );

                    xMayClose = pdFALSE;
                }
            }
        }

        if( xTCPWindowLoggingLevel > 0 )
        {
            FreeRTOS_debug_printf( ( "TCP: FIN received, mayClose = %ld (Rx %lu Len %ld, Tx %lu)\n",
                xMayClose, ulSequenceNumber - pxSocket->u.xTCP.xTCPWindow.rx.ulFirstSequenceNumber, ulReceiveLength,
                pxTCPWindow->tx.ulCurrentSequenceNumber - pxSocket->u.xTCP.xTCPWindow.tx.ulFirstSequenceNumber ) );
        }

        if( xMayClose != pdFALSE )
        {
            pxSocket->u.xTCP.bits.bFinAccepted = pdTRUE_UNSIGNED;
            xSendLength = prvTCPHandleFin( pxSocket, *ppxNetworkBuffer );
        }
    }

    if( xMayClose == pdFALSE )
    {
        pxTCPHeader->ucTCPFlags = ipTCP_FLAG_ACK;

        if( ulReceiveLength != 0u )
        {
            xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
            /* TCP-offsett equals '( ( length / 4 ) << 4 )', resulting in a shift-left 2 */
            pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );

            if( pxSocket->u.xTCP.bits.bFinSent != pdFALSE_UNSIGNED )
            {
                pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->tx.ulFINSequenceNumber;
            }
        }

        /* Now get data to be transmitted. */
        /* _HT_ patch: since the MTU has be fixed at 1500 in stead of 1526, TCP
        can not send-out both TCP options and also a full packet. Sending
        options (SACK) is always more urgent than sending data, which can be
        sent later. */
        if( uxOptionsLength == 0u )
        {
            /* prvTCPPrepareSend might allocate a bigger network buffer, if
            necessary. */
            lSendResult = prvTCPPrepareSend( pxSocket, ppxNetworkBuffer, uxOptionsLength );
            if( lSendResult > 0 )
            {
                xSendLength = ( BaseType_t ) lSendResult;
            }
        }
    }

    return xSendLength;
}
/*2016--12--05--14--38--25(ZJYC): 有数据要发送，如果ipconfigUSE_TCP_WIN被定义 并且只有一个ACK被发送
最好是延迟一段时间再发送（再延迟的过程中有数据的话就跟随者发出去，这样更加高效）   */ 
static BaseType_t prvSendData( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, BaseType_t xSendLength )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( (*ppxNetworkBuffer)->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
/* Find out what window size we may advertised. */
uint32_t ulFrontSpace;
int32_t lRxSpace;
#if( ipconfigUSE_TCP_WIN == 1 )
    #if( ipconfigTCP_ACK_EARLIER_PACKET == 0 )
        const int32_t lMinLength = 0;
    #else
        int32_t lMinLength;
    #endif
#endif
    pxSocket->u.xTCP.ulRxCurWinSize = pxTCPWindow->xSize.ulRxWindowLength -
                                     ( pxTCPWindow->rx.ulHighestSequenceNumber - pxTCPWindow->rx.ulCurrentSequenceNumber );

    /* Free space in rxStream. */
    if( pxSocket->u.xTCP.rxStream != NULL )
    {
        ulFrontSpace = ( uint32_t ) uxStreamBufferFrontSpace( pxSocket->u.xTCP.rxStream );
    }
    else
    {
        ulFrontSpace = ( uint32_t ) pxSocket->u.xTCP.uxRxStreamSize;
    }

    pxSocket->u.xTCP.ulRxCurWinSize = FreeRTOS_min_uint32( ulFrontSpace, pxSocket->u.xTCP.ulRxCurWinSize );

    /* Set the time-out field, so that we'll be called by the IP-task in case no
    next message will be received. */
    lRxSpace = (int32_t)( pxSocket->u.xTCP.ulHighestRxAllowed - pxTCPWindow->rx.ulCurrentSequenceNumber );
    #if ipconfigUSE_TCP_WIN == 1
    {

        #if( ipconfigTCP_ACK_EARLIER_PACKET != 0 )
        {
            lMinLength = ( ( int32_t ) 2 ) * ( ( int32_t ) pxSocket->u.xTCP.usCurMSS );
        }
        #endif /* ipconfigTCP_ACK_EARLIER_PACKET */

        /* In case we're receiving data continuously, we might postpone sending
        an ACK to gain performance. */
        if( ( ulReceiveLength > 0 ) &&                          /* Data was sent to this socket. */
            ( lRxSpace >= lMinLength ) &&                       /* There is Rx space for more data. */
            ( pxSocket->u.xTCP.bits.bFinSent == pdFALSE_UNSIGNED ) &&   /* Not in a closure phase. */
            ( xSendLength == ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER ) ) && /* No Tx data or options to be sent. */
            ( pxSocket->u.xTCP.ucTCPState == eESTABLISHED ) &&  /* Connection established. */
            ( pxTCPHeader->ucTCPFlags == ipTCP_FLAG_ACK ) )     /* There are no other flags than an ACK. */
        {
            if( pxSocket->u.xTCP.pxAckMessage != *ppxNetworkBuffer )
            {
                /* There was still a delayed in queue, delete it. */
                if( pxSocket->u.xTCP.pxAckMessage != 0 )
                {
                    vReleaseNetworkBufferAndDescriptor( pxSocket->u.xTCP.pxAckMessage );
                }

                pxSocket->u.xTCP.pxAckMessage = *ppxNetworkBuffer;
            }
            if( ( ulReceiveLength < ( uint32_t ) pxSocket->u.xTCP.usCurMSS ) || /* Received a small message. */
                ( lRxSpace < ( int32_t ) ( 2U * pxSocket->u.xTCP.usCurMSS ) ) ) /* There are less than 2 x MSS space in the Rx buffer. */
            {
                pxSocket->u.xTCP.usTimeout = ( uint16_t ) pdMS_TO_MIN_TICKS( DELAYED_ACK_SHORT_DELAY_MS );
            }
            else
            {
                /* Normally a delayed ACK should wait 200 ms for a next incoming
                packet.  Only wait 20 ms here to gain performance.  A slow ACK
                for full-size message. */
                pxSocket->u.xTCP.usTimeout = ( uint16_t ) pdMS_TO_MIN_TICKS( DELAYED_ACK_LONGER_DELAY_MS );
            }

            if( ( xTCPWindowLoggingLevel > 1 ) && ( ipconfigTCP_MAY_LOG_PORT( pxSocket->usLocalPort ) != pdFALSE ) )
            {
                FreeRTOS_debug_printf( ( "Send[%u->%u] del ACK %lu SEQ %lu (len %lu) tmout %u d %lu\n",
                    pxSocket->usLocalPort,
                    pxSocket->u.xTCP.usRemotePort,
                    pxTCPWindow->rx.ulCurrentSequenceNumber - pxTCPWindow->rx.ulFirstSequenceNumber,
                    pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber,
                    xSendLength,
                    pxSocket->u.xTCP.usTimeout, lRxSpace ) );
            }

            *ppxNetworkBuffer = NULL;
            xSendLength = 0;
        }
        else if( pxSocket->u.xTCP.pxAckMessage != NULL )
        {
            /* As an ACK is not being delayed, remove any earlier delayed ACK
            message. */
            if( pxSocket->u.xTCP.pxAckMessage != *ppxNetworkBuffer )
            {
                vReleaseNetworkBufferAndDescriptor( pxSocket->u.xTCP.pxAckMessage );
            }

            pxSocket->u.xTCP.pxAckMessage = NULL;
        }
    }
    #else
    {
        /* Remove compiler warnings. */
        ( void ) ulReceiveLength;
        ( void ) pxTCPHeader;
        ( void ) lRxSpace;
    }
    #endif /* ipconfigUSE_TCP_WIN */

    if( xSendLength != 0 )
    {
        if( ( xTCPWindowLoggingLevel > 1 ) && ( ipconfigTCP_MAY_LOG_PORT( pxSocket->usLocalPort ) != pdFALSE ) )
        {
            FreeRTOS_debug_printf( ( "Send[%u->%u] imm ACK %lu SEQ %lu (len %lu)\n",
                pxSocket->usLocalPort,
                pxSocket->u.xTCP.usRemotePort,
                pxTCPWindow->rx.ulCurrentSequenceNumber - pxTCPWindow->rx.ulFirstSequenceNumber,
                pxTCPWindow->ulOurSequenceNumber - pxTCPWindow->tx.ulFirstSequenceNumber,
                xSendLength ) );
        }

        /* Set the parameter 'xReleaseAfterSend' to the value of
        ipconfigZERO_COPY_TX_DRIVER. */
        prvTCPReturnPacket( pxSocket, *ppxNetworkBuffer, ( uint32_t ) xSendLength, ipconfigZERO_COPY_TX_DRIVER );
        #if( ipconfigZERO_COPY_TX_DRIVER != 0 )
        {
            /* The driver has taken ownership of the Network Buffer. */
            *ppxNetworkBuffer = NULL;
        }
        #endif
    }

    return xSendLength;
}
/*
 * prvTCPHandleState()
 * is the most important function of this TCP stack
 * We've tried to keep it (relatively short) by putting a lot of code in
 * the static functions above:
 *
 *      prvCheckRxData()
 *      prvStoreRxData()
 *      prvSetOptions()
 *      prvHandleSynReceived()
 *      prvHandleEstablished()
 *      prvSendData()
 *
 * As these functions are declared static, and they're called from one location
 * only, most compilers will inline them, thus avoiding a call and return.
 */
/*2016--12--05--14--37--32(ZJYC): 状态机主体   */ 
static BaseType_t prvTCPHandleState( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( (*ppxNetworkBuffer)->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &( pxTCPPacket->xTCPHeader );
BaseType_t xSendLength = 0;
uint32_t ulReceiveLength;   /*2016--12--04--21--26--45(ZJYC): 接收数据的长度   */ 
uint8_t *pucRecvData;
uint32_t ulSequenceNumber = FreeRTOS_ntohl (pxTCPHeader->ulSequenceNumber);

    /* xOptionsLength: the size of the options to be sent (always a multiple of
    4 bytes)
    1. in the SYN phase, we shall communicate the MSS
    2. in case of a SACK, Selective ACK, ack a segment which comes in
    out-of-order. */
UBaseType_t uxOptionsLength = 0u;
uint8_t ucTCPFlags = pxTCPHeader->ucTCPFlags;
TCPWindow_t *pxTCPWindow = &( pxSocket->u.xTCP.xTCPWindow );
    /*2016--12--04--21--22--15(ZJYC): 第一步获取接收到的数据的长度和位置
    pucRecvData将会指向TCP数据的第一个字节*/ 
    ulReceiveLength = ( uint32_t ) prvCheckRxData( *ppxNetworkBuffer, &pucRecvData );
    /*2016--12--04--21--30--11(ZJYC): 以下判断他是不是一个包活信号   */ 
    if( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED )
    {
        /*2016--12--04--21--23--08(ZJYC): 目前已经处于连接建立的状态   */ 
        if ( pxTCPWindow->rx.ulCurrentSequenceNumber == ulSequenceNumber + 1u )
        {
            /*2016--12--04--21--25--45(ZJYC): 难道不应该是ACK number？？
            我发现在数据结构中根本就不存在ACK Num这一回事，估计是，被在RX
            中的SEQ就是ACK NUM
            */ 
            /*2016--12--04--21--23--33(ZJYC): 判断其确认号为当前seq+1，判断此为包活信号
            这里置位bWinChange并不会改变窗口大小，而是使得立即发送一个ACK*/ 
            pxSocket->u.xTCP.bits.bWinChange = pdTRUE_UNSIGNED;
        }
    }

    /* Keep track of the highest sequence number that might be expected within
    this connection. */
    /*2016--12--04--21--30--57(ZJYC): 用来跟踪最高序列号，这个序列号在后期大有用处，比如在
    回复时需要回复最高序列号（SACK除外）   */ 
    if( ( ( int32_t ) ( ulSequenceNumber + ulReceiveLength - pxTCPWindow->rx.ulHighestSequenceNumber ) ) > 0 )
    {
        pxTCPWindow->rx.ulHighestSequenceNumber = ulSequenceNumber + ulReceiveLength;
    }

    /* Storing data may result in a fatal error if malloc() fails. */
    if( prvStoreRxData( pxSocket, pucRecvData, *ppxNetworkBuffer, ulReceiveLength ) < 0 )
    {
        xSendLength = -1;
    }
    else
    {
        uxOptionsLength = prvSetOptions( pxSocket, *ppxNetworkBuffer );
        /*2016--12--04--21--44--22(ZJYC): 下面这个判断是什么意思？？？   */ 
        if( ( pxSocket->u.xTCP.ucTCPState == eSYN_RECEIVED ) && ( ( ucTCPFlags & ipTCP_FLAG_CTRL ) == ipTCP_FLAG_SYN ) )
        {
            FreeRTOS_debug_printf( ( "eSYN_RECEIVED: ACK expected, not SYN: peer missed our SYN+ACK\n" ) );
            /*2016--12--04--21--40--02(ZJYC): eSYN_RECEIVED表明我们期望收到ACK，但是并没有   */ 
            vTCPStateChange( pxSocket, eSYN_FIRST );
        }
        /*2016--12--04--21--45--35(ZJYC): 对方要停止 && 还没有收到过FIN   */ 
        if( ( ( ucTCPFlags & ipTCP_FLAG_FIN ) != 0u ) && ( pxSocket->u.xTCP.bits.bFinRecv == pdFALSE_UNSIGNED ) )
        {
            /*2016--12--04--21--46--21(ZJYC): 收到了第一个FIN，记住他的序列号   */ 
            pxTCPWindow->rx.ulFINSequenceNumber = ulSequenceNumber + ulReceiveLength;
            pxSocket->u.xTCP.bits.bFinRecv = pdTRUE_UNSIGNED;
            /*2016--12--04--21--47--03(ZJYC): 判断是否是对方先发送的FIN，如果是，我们就得发送
            LAST-ACK，否则就不用发了   */ 
            if( pxSocket->u.xTCP.bits.bFinSent == pdFALSE_UNSIGNED )
            {
                pxSocket->u.xTCP.bits.bFinLast = pdTRUE_UNSIGNED;
            }
        }

        switch (pxSocket->u.xTCP.ucTCPState)
        {
        case eCLOSED:/*2016--12--04--21--48--16(ZJYC): （CS）不存在任何连接，我们什么也不做，
        等待用户动作*/ 
            break;

        case eTCP_LISTEN:/*2016--12--04--21--48--59(ZJYC): （S）等待任何远程连接，监听状态由
        xProcessReceivedTCPPacket()控制，这里不再叙述*/ 
            break;

        case eSYN_FIRST:    /*2016--12--04--21--04--41(ZJYC): 服务器刚刚收到一SYN请求   */ 
            {
                /*2016--12--04--21--03--38(ZJYC): 一个新的套接字已经被创建，回复SYN+ACK
                确认号为seq+1*/ 
                uxOptionsLength = prvSetSynAckOptions( pxSocket, pxTCPPacket );
                pxTCPHeader->ucTCPFlags = ipTCP_FLAG_SYN | ipTCP_FLAG_ACK;
                xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
                /*2016--12--04--21--05--12(ZJYC): 设置TCP偏移字段，ipSIZE_OF_TCP_HEADER等于20
                 xOptionsLength是4的倍数，完全的表达式为ucTCPOffset = ( ( ipSIZE_OF_TCP_HEADER + xOptionsLength ) / 4 ) << 4*/ 
                pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
                vTCPStateChange( pxSocket, eSYN_RECEIVED );
                pxTCPWindow->rx.ulCurrentSequenceNumber = pxTCPWindow->rx.ulHighestSequenceNumber = ulSequenceNumber + 1u;
                pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->ulNextTxSequenceNumber = pxTCPWindow->tx.ulFirstSequenceNumber + 1u; /* because we send a TCP_SYN. */
            }
            break;

        case eCONNECT_SYN: /*2016--12--04--21--07--49(ZJYC): 客户发送SYN，我们期望收到SYN+ACK。   */ 
            /* Fall through */
        case eSYN_RECEIVED: /*2016--12--04--21--09--06(ZJYC): 收到SYN并回复了SYN+ACK，期望收到ACK   */ 
            xSendLength = prvHandleSynReceived( pxSocket, ppxNetworkBuffer, ulReceiveLength, uxOptionsLength );
            break;

        case eESTABLISHED:  /* (server + client) an open connection, data
                            received can be delivered to the user. The normal
                            state for the data transfer phase of the connection
                            The closing states are also handled here with the
                            use of some flags. */
            xSendLength = prvHandleEstablished( pxSocket, ppxNetworkBuffer, ulReceiveLength, uxOptionsLength );
            break;

        case eLAST_ACK:     /* (server + client) waiting for an acknowledgement
                            of the connection termination request previously
                            sent to the remote TCP (which includes an
                            acknowledgement of its connection termination
                            request). */
            /* Fall through */
        case eFIN_WAIT_1:   /* (server + client) waiting for a connection termination request from the remote TCP,
                             * or an acknowledgement of the connection termination request previously sent. */
            /* Fall through */
        case eFIN_WAIT_2:   /* (server + client) waiting for a connection termination request from the remote TCP. */
            xSendLength = prvTCPHandleFin( pxSocket, *ppxNetworkBuffer );
            break;

        case eCLOSE_WAIT:   /* (server + client) waiting for a connection
                            termination request from the local user.  Nothing to
                            do, connection is closed, wait for owner to close
                            this socket. */
            break;

        case eCLOSING:      /* (server + client) waiting for a connection
                            termination request acknowledgement from the remote
                            TCP. */
            break;

        case eTIME_WAIT:    /* (either server or client) waiting for enough time
                            to pass to be sure the remote TCP received the
                            acknowledgement of its connection termination
                            request. [According to RFC 793 a connection can stay
                            in TIME-WAIT for a maximum of four minutes known as
                            a MSL (maximum segment lifetime).]  These states are
                            implemented implicitly by settings flags like
                            'bFinSent', 'bFinRecv', and 'bFinAcked'. */
            break;
        default:
            break;
        }
    }

    if( xSendLength > 0 )
    {
        xSendLength = prvSendData( pxSocket, ppxNetworkBuffer, ulReceiveLength, xSendLength );
    }

    return xSendLength;
}
/*-----------------------------------------------------------*/
/*2016--12--05--14--36--51(ZJYC): 发送复位标志   */ 
static BaseType_t prvTCPSendReset( NetworkBufferDescriptor_t *pxNetworkBuffer )
{
    #if( ipconfigIGNORE_UNKNOWN_PACKETS == 0 )
    {
    TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
    const BaseType_t xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + 0u );    /* Plus 0 options. */

        pxTCPPacket->xTCPHeader.ucTCPFlags = ipTCP_FLAG_ACK | ipTCP_FLAG_RST;
        pxTCPPacket->xTCPHeader.ucTCPOffset = ( ipSIZE_OF_TCP_HEADER + 0u ) << 2;
        prvTCPReturnPacket( NULL, pxNetworkBuffer, ( uint32_t ) xSendLength, pdFALSE );
    }
    #endif /* !ipconfigIGNORE_UNKNOWN_PACKETS */
    /* Remove compiler warnings if ipconfigIGNORE_UNKNOWN_PACKETS == 1. */
    ( void ) pxNetworkBuffer;
    /* The packet was not consumed. */
    return pdFAIL;
}
/*2016--12--05--14--34--01(ZJYC): 通过简单判断并设置套接字的MSS值，   */ 
static void prvSocketSetMSS( FreeRTOS_Socket_t *pxSocket )
{
uint32_t ulMSS = ipconfigTCP_MSS;

    if( ( ( FreeRTOS_ntohl( pxSocket->u.xTCP.ulRemoteIP ) ^ *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) != 0ul )
    {
        /*2016--12--05--14--34--32(ZJYC): 判断而得出 到达对方的数据有可能经过路由器甚至是因特网  我们应把MSS限制在1400或更少   */ 
        ulMSS = FreeRTOS_min_uint32( ( uint32_t ) REDUCED_MSS_THROUGH_INTERNET, ulMSS );
    }
    FreeRTOS_debug_printf( ( "prvSocketSetMSS: %lu bytes for %lxip:%u\n", ulMSS, pxSocket->u.xTCP.ulRemoteIP, pxSocket->u.xTCP.usRemotePort ) );
    pxSocket->u.xTCP.usInitMSS = pxSocket->u.xTCP.usCurMSS = ( uint16_t ) ulMSS;
}
/*
 *  FreeRTOS_TCP_IP has only 2 public functions, this is the second one:
 *  xProcessReceivedTCPPacket()
 *      prvTCPHandleState()
 *          prvTCPPrepareSend()
 *              prvTCPReturnPacket()
 *              xNetworkInterfaceOutput()   // Sends data to the NIC
 *      prvTCPSendRepeated()
 *          prvTCPReturnPacket()        // Prepare for returning
 *          xNetworkInterfaceOutput()   // Sends data to the NIC
*/
/*2016--12--05--14--32--55(ZJYC): 号称第二大TCP_IP公开函数，灰常重要   */ 
BaseType_t xProcessReceivedTCPPacket( NetworkBufferDescriptor_t *pxNetworkBuffer )
{
FreeRTOS_Socket_t *pxSocket;
TCPPacket_t * pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
uint16_t ucTCPFlags = pxTCPPacket->xTCPHeader.ucTCPFlags;
uint32_t ulLocalIP = FreeRTOS_htonl( pxTCPPacket->xIPHeader.ulDestinationIPAddress );
uint16_t xLocalPort = FreeRTOS_htons( pxTCPPacket->xTCPHeader.usDestinationPort );
uint32_t ulRemoteIP = FreeRTOS_htonl( pxTCPPacket->xIPHeader.ulSourceIPAddress );
uint16_t xRemotePort = FreeRTOS_htons( pxTCPPacket->xTCPHeader.usSourcePort );
BaseType_t xResult = pdPASS;
    /*2016--12--04--21--51--13(ZJYC): 寻找目标套接字，如果没有，返回一个监听
    目标端口的套接字？？？（为什么返回一个监听的套接字？？？？）   */ 
    pxSocket = ( FreeRTOS_Socket_t * ) pxTCPSocketLookup( ulLocalIP, xLocalPort, ulRemoteIP, xRemotePort );
    if( ( pxSocket == NULL ) || ( prvTCPSocketIsActive( ( UBaseType_t ) pxSocket->u.xTCP.ucTCPState ) == pdFALSE ) )
    {
        /*2016--12--04--21--52--44(ZJYC): 收到了TCP消息，但是或者没有套接字对应
        或者套接字处于eCLOSED, eCLOSE_WAIT, eFIN_WAIT_2, eCLOSING, or eTIME_WAIT*/ 
        FreeRTOS_debug_printf( ( "TCP: No active socket on port %d (%lxip:%d)\n", xLocalPort, ulRemoteIP, xRemotePort ) );
        /* Send a RST to all packets that can not be handled.  As a result
        the other party will get a ECONN error.  There are two exceptions:
        1) A packet that already has the RST flag set.
        2) A packet that only has the ACK flag set.
        A packet with only the ACK flag set might be the last ACK in
        a three-way hand-shake that closes a connection. */
        if( ( ( ucTCPFlags & ipTCP_FLAG_CTRL ) != ipTCP_FLAG_ACK ) &&
            ( ( ucTCPFlags & ipTCP_FLAG_RST ) == 0u ) )
        {
            prvTCPSendReset( pxNetworkBuffer );
        }
        /* The packet can't be handled. */
        xResult = pdFAIL;
    }
    else
    {
        pxSocket->u.xTCP.ucRepCount = 0u;
        if( pxSocket->u.xTCP.ucTCPState == eTCP_LISTEN )
        {
            /*2016--12--04--21--56--20(ZJYC): 匹配的套接字有SYN标志，看看对方是不是有SYN   */ 
            if( ( ucTCPFlags & ipTCP_FLAG_CTRL ) != ipTCP_FLAG_SYN )
            {
                /*2016--12--04--21--57--05(ZJYC): 我们在同步状态，但是对方没发送SYN，给他个FST   */ 
                #if( ipconfigHAS_DEBUG_PRINTF == 1 )
                {
                FreeRTOS_debug_printf( ( "TCP: Server can't handle flags: %s from %lxip:%u to port %u\n",
                    prvTCPFlagMeaning( ( UBaseType_t ) ucTCPFlags ), ulRemoteIP, xRemotePort, xLocalPort ) );
                }
                #endif /* ipconfigHAS_DEBUG_PRINTF */
                if( ( ucTCPFlags & ipTCP_FLAG_RST ) == 0u )
                {
                    prvTCPSendReset( pxNetworkBuffer );
                }
                xResult = pdFAIL;
            }
            else
            {
                /*2016--12--04--21--59--09(ZJYC): 啥意思：if bReuseSocket is false？？？？   */ 
                /*2016--12--04--21--57--57(ZJYC): prvHandleListen()将会返回一个新的套接字
                （if bReuseSocket is false），要不然，返回当前套接字，后期会被连接   */ 
                pxSocket = prvHandleListen( pxSocket, pxNetworkBuffer );
                if( pxSocket == NULL )
                {
                    xResult = pdFAIL;
                }
            }
        }   /* if( pxSocket->u.xTCP.ucTCPState == eTCP_LISTEN ). */
        else
        {
            /*2016--12--04--22--00--18(ZJYC): 本套接字并不处于监听模式，检查RST   */ 
            if( ( ucTCPFlags & ipTCP_FLAG_RST ) != 0u )
            {
                /*2016--12--04--22--01--26(ZJYC): 本套接字不在监听模式，而又收到了RST
                说明本套接字想关闭*/ 
                FreeRTOS_debug_printf( ( "TCP: RST received from %lxip:%u for %u\n", ulRemoteIP, xRemotePort, xLocalPort ) );
                vTCPStateChange( pxSocket, eCLOSED );
                /* The packet cannot be handled. */
                xResult = pdFAIL;
            }
            else if( ( ( ucTCPFlags & ipTCP_FLAG_CTRL ) == ipTCP_FLAG_SYN ) && ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) )
            {
                /*2016--12--04--22--02--47(ZJYC): 对方发送SYN && 我们早就建立连接了==矛盾了   */ 
                FreeRTOS_debug_printf( ( "TCP: SYN unexpected from %lxip:%u\n", ulRemoteIP, xRemotePort ) );
                /* The packet cannot be handled. */
                xResult = pdFAIL;
            }
            else
            {
                /* Update the copy of the TCP header only (skipping eth and IP
                headers).  It might be used later on, whenever data must be sent
                to the peer. */
                /*2016--12--04--22--04--47(ZJYC): 保存报文头？？？？？？？   */ 
                /*2016--12--04--22--05--58(ZJYC): 这里才是正常的流程？？？   */ 
                const BaseType_t lOffset = ( BaseType_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER );
                memcpy( pxSocket->u.xTCP.xPacket.u.ucLastPacket + lOffset, pxNetworkBuffer->pucEthernetBuffer + lOffset, ipSIZE_OF_TCP_HEADER );
            }
        }
    }
    if( xResult != pdFAIL )
    {
        /*2016--12--04--22--06--30(ZJYC): 更新计时   */ 
        prvTCPTouchSocket( pxSocket );
        /*2016--12--04--22--07--07(ZJYC): 解析TCP选项，如果我们处于SYN阶段，但是对方没有发送MSS
        我们默认为536，以为了后续的兼容性*/ 
        /*2016--12--04--22--08--13(ZJYC): 如果不存在TCP选项，offset为5表示20字节，   */ 
        if( ( pxTCPPacket->xTCPHeader.ucTCPOffset & TCP_OFFSET_LENGTH_BITS ) > TCP_OFFSET_STANDARD_LENGTH )
        {
            /*2016--12--04--22--09--00(ZJYC): 我们需要检查选项   */ 
            prvCheckOptions( pxSocket, pxNetworkBuffer );
        }
        #if( ipconfigUSE_TCP_WIN == 1 )
        {
            /*2016--12--04--22--09--54(ZJYC): 此处设置窗口大小=窗口*放大因子   */ 
            pxSocket->u.xTCP.ulWindowSize = FreeRTOS_ntohs( pxTCPPacket->xTCPHeader.usWindow );
            pxSocket->u.xTCP.ulWindowSize =
                ( pxSocket->u.xTCP.ulWindowSize << pxSocket->u.xTCP.ucPeerWinScaleFactor );
        }
        #endif
        /*2016--12--05--14--18--12(ZJYC): 根据状态机来处理这些数据   */ 
        if( prvTCPHandleState( pxSocket, &pxNetworkBuffer ) > 0 )
        {
            /* prvTCPHandleState() has sent a message, see if there are more to
            be transmitted. */
            #if( ipconfigUSE_TCP_WIN == 1 )
            {
                prvTCPSendRepeated( pxSocket, &pxNetworkBuffer );
            }
            #endif /* ipconfigUSE_TCP_WIN */
        }
        if( pxNetworkBuffer != NULL )
        {
            /*2016--12--04--22--14--48(ZJYC): 把缓存释放吧，没用了   */ 
            vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
            pxNetworkBuffer = NULL;
        }
        /*2016--12--04--22--13--48(ZJYC): 最后计算下次被唤醒的时间   */ 
        prvTCPNextTimeout ( pxSocket );
        /*2016--12--04--22--14--11(ZJYC): 告诉调用者，缓存已被消耗   */ 
        xResult = pdPASS;
    }
    /* pdPASS being returned means the buffer has been consumed. */
    return xResult;
}
/*-----------------------------------------------------------*/
/*2016--12--05--14--27--22(ZJYC): 在监听状态下我们收到了连接请求，我们在这里想办法搞出一
套接字，并填充该套接字   */ 
static FreeRTOS_Socket_t *prvHandleListen( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer )
{
TCPPacket_t * pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
FreeRTOS_Socket_t *pxReturn;
    /*2016--12--04--22--17--56(ZJYC): 收到一个单纯的SYN，创建一个套接字来对付他   */ 
    if( pxSocket->u.xTCP.bits.bReuseSocket != pdFALSE_UNSIGNED )
    {
        /*2016--12--04--22--18--29(ZJYC): 这个套接字确实实在等待此端口，我们直接用这个
        套接字而不用在建立了*/ 
        pxReturn = pxSocket;
        pxSocket->u.xTCP.bits.bPassQueued = pdTRUE_UNSIGNED;
        pxSocket->u.xTCP.pxPeerSocket = pxSocket;
    }
    else
    {
        /*2016--12--04--22--19--39(ZJYC): 直接创建个新的套接字   */ 
        pxReturn = NULL;
        if( pxSocket->u.xTCP.usChildCount >= pxSocket->u.xTCP.usBacklog )
        {
            FreeRTOS_printf( ( "Check: Socket %u already has %u / %u child%s\n",
                pxSocket->usLocalPort,
                pxSocket->u.xTCP.usChildCount,
                pxSocket->u.xTCP.usBacklog,
                pxSocket->u.xTCP.usChildCount == 1 ? "" : "ren" ) );
            prvTCPSendReset( pxNetworkBuffer );
        }
        else
        {
            FreeRTOS_Socket_t *pxNewSocket = (FreeRTOS_Socket_t *)
                FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP );
            if( ( pxNewSocket == NULL ) || ( pxNewSocket == FREERTOS_INVALID_SOCKET ) )
            {
                FreeRTOS_debug_printf( ( "TCP: Listen: new socket failed\n" ) );
                prvTCPSendReset( pxNetworkBuffer );
            }
            else if( prvTCPSocketCopy( pxNewSocket, pxSocket ) != pdFALSE )
            {
                /*2016--12--04--22--22--47(ZJYC): 套接字后期马上就会连接，也没有时间见去配置，
                我们直接使用本套接字的设置就可以啦*/ 
                pxReturn = pxNewSocket;
            }
        }
    }

    if( pxReturn != NULL )
    {
        /*2016--12--05--14--30--35(ZJYC): 套接字已经建立，如下填充该套接字   */ 
        pxReturn->u.xTCP.usRemotePort = FreeRTOS_htons( pxTCPPacket->xTCPHeader.usSourcePort );
        pxReturn->u.xTCP.ulRemoteIP = FreeRTOS_htonl( pxTCPPacket->xIPHeader.ulSourceIPAddress );
        pxReturn->u.xTCP.xTCPWindow.ulOurSequenceNumber = ulNextInitialSequenceNumber;
        pxReturn->u.xTCP.xTCPWindow.rx.ulCurrentSequenceNumber = FreeRTOS_ntohl( pxTCPPacket->xTCPHeader.ulSequenceNumber );
        prvSocketSetMSS( pxReturn );
        prvTCPCreateWindow( pxReturn );
        ulNextInitialSequenceNumber += INITIAL_SEQUENCE_NUMBER_INCREMENT;
        vTCPStateChange( pxReturn, eSYN_FIRST );
        memcpy( pxReturn->u.xTCP.xPacket.u.ucLastPacket, pxNetworkBuffer->pucEthernetBuffer, sizeof( pxReturn->u.xTCP.xPacket.u.ucLastPacket ) );
    }
    return pxReturn;
}
/*2016--12--05--14--21--22(ZJYC): 监听状态的套接字收到连接之后会复制别人的套接字设置 因为 
监听状态下的套接字没有时间配置套接字  */ 
static BaseType_t prvTCPSocketCopy( FreeRTOS_Socket_t *pxNewSocket, FreeRTOS_Socket_t *pxSocket )
{
struct freertos_sockaddr xAddress;

    pxNewSocket->xReceiveBlockTime = pxSocket->xReceiveBlockTime;
    pxNewSocket->xSendBlockTime = pxSocket->xSendBlockTime;
    pxNewSocket->ucSocketOptions = pxSocket->ucSocketOptions;
    pxNewSocket->u.xTCP.uxRxStreamSize = pxSocket->u.xTCP.uxRxStreamSize;
    pxNewSocket->u.xTCP.uxTxStreamSize = pxSocket->u.xTCP.uxTxStreamSize;
    pxNewSocket->u.xTCP.uxLittleSpace = pxSocket->u.xTCP.uxLittleSpace;
    pxNewSocket->u.xTCP.uxEnoughSpace = pxSocket->u.xTCP.uxEnoughSpace;
    pxNewSocket->u.xTCP.uxRxWinSize  = pxSocket->u.xTCP.uxRxWinSize;
    pxNewSocket->u.xTCP.uxTxWinSize  = pxSocket->u.xTCP.uxTxWinSize;

    #if( ipconfigSOCKET_HAS_USER_SEMAPHORE == 1 )
    {
        pxNewSocket->pxUserSemaphore = pxSocket->pxUserSemaphore;
    }
    #endif /* ipconfigSOCKET_HAS_USER_SEMAPHORE */

    #if( ipconfigUSE_CALLBACKS == 1 )
    {
        /* In case call-backs are used, copy them from parent to child. */
        pxNewSocket->u.xTCP.pxHandleConnected = pxSocket->u.xTCP.pxHandleConnected;
        pxNewSocket->u.xTCP.pxHandleReceive = pxSocket->u.xTCP.pxHandleReceive;
        pxNewSocket->u.xTCP.pxHandleSent = pxSocket->u.xTCP.pxHandleSent;
    }
    #endif /* ipconfigUSE_CALLBACKS */

    #if( ipconfigSUPPORT_SELECT_FUNCTION == 1 )
    {
        /* Child socket of listening sockets will inherit the Socket Set
        Otherwise the owner has no chance of including it into the set. */
        if( pxSocket->pxSocketSet )
        {
            pxNewSocket->pxSocketSet = pxSocket->pxSocketSet;
            pxNewSocket->xSelectBits = pxSocket->xSelectBits | eSELECT_READ | eSELECT_EXCEPT;
        }
    }
    #endif /* ipconfigSUPPORT_SELECT_FUNCTION */

    /* And bind it to the same local port as its parent. */
    xAddress.sin_addr = *ipLOCAL_IP_ADDRESS_POINTER;
    xAddress.sin_port = FreeRTOS_htons( pxSocket->usLocalPort );

    #if( ipconfigTCP_HANG_PROTECTION == 1 )
    {
        /* Only when there is anti-hanging protection, a socket may become an
        orphan temporarily.  Once this socket is really connected, the owner of
        the server socket will be notified. */

        /* When bPassQueued is true, the socket is an orphan until it gets
        connected. */
        pxNewSocket->u.xTCP.bits.bPassQueued = pdTRUE_UNSIGNED;
        pxNewSocket->u.xTCP.pxPeerSocket = pxSocket;
    }
    #else
    {
        /* A reference to the new socket may be stored and the socket is marked
        as 'passable'. */

        /* When bPassAccept is pdTRUE_UNSIGNED this socket may be returned in a call to
        accept(). */
        pxNewSocket->u.xTCP.bits.bPassAccept = pdTRUE_UNSIGNED;
        if(pxSocket->u.xTCP.pxPeerSocket == NULL )
        {
            pxSocket->u.xTCP.pxPeerSocket = pxNewSocket;
        }
    }
    #endif

    pxSocket->u.xTCP.usChildCount++;

    FreeRTOS_debug_printf( ( "Gain: Socket %u now has %u / %u child%s\n",
        pxSocket->usLocalPort,
        pxSocket->u.xTCP.usChildCount,
        pxSocket->u.xTCP.usBacklog,
        pxSocket->u.xTCP.usChildCount == 1u ? "" : "ren" ) );

    /* Now bind the child socket to the same port as the listening socket. */
    if( vSocketBind ( pxNewSocket, &xAddress, sizeof( xAddress ), pdTRUE ) != 0 )
    {
        FreeRTOS_debug_printf( ( "TCP: Listen: new socket bind error\n" ) );
        vSocketClose( pxNewSocket );
        return pdFALSE;
    }

    return pdTRUE;
}
/*2016--12--05--14--23--25(ZJYC): 获取TCP状态的名称，常用于调试打印   */ 
#if( ( ipconfigHAS_DEBUG_PRINTF != 0 ) || ( ipconfigHAS_PRINTF != 0 ) )

    const char *FreeRTOS_GetTCPStateName( UBaseType_t ulState )
    {
        if( ulState >= ( UBaseType_t ) ARRAY_SIZE( pcStateNames ) )
        {
            ulState = ( UBaseType_t ) ARRAY_SIZE( pcStateNames ) - 1u;
        }
        return pcStateNames[ ulState ];
    }

#endif /* ( ( ipconfigHAS_DEBUG_PRINTF != 0 ) || ( ipconfigHAS_PRINTF != 0 ) ) */
/*2016--12--05--14--24--28(ZJYC): API accept()，用户会问是否存在一个新的客户（连接）
由于API不能直接遍历xBoundTCPSocketsList  IP主任务会这样做   */ 
BaseType_t xTCPCheckNewClient( FreeRTOS_Socket_t *pxSocket )
{
TickType_t xLocalPort = FreeRTOS_htons( pxSocket->usLocalPort );
ListItem_t *pxIterator;
FreeRTOS_Socket_t *pxFound;
BaseType_t xResult = pdFALSE;
    for( pxIterator = ( ListItem_t * ) listGET_HEAD_ENTRY( &xBoundTCPSocketsList );
        pxIterator != ( ListItem_t * ) listGET_END_MARKER( &xBoundTCPSocketsList );
        pxIterator = ( ListItem_t * ) listGET_NEXT( pxIterator ) )
    {
        if( listGET_LIST_ITEM_VALUE( pxIterator ) == xLocalPort )
        {
            pxFound = ( FreeRTOS_Socket_t * ) listGET_LIST_ITEM_OWNER( pxIterator );
            if( ( pxFound->ucProtocol == FREERTOS_IPPROTO_TCP ) && ( pxFound->u.xTCP.bits.bPassAccept != pdFALSE_UNSIGNED ) )
            {
                pxSocket->u.xTCP.pxPeerSocket = pxFound;
                FreeRTOS_debug_printf( ( "xTCPCheckNewClient[0]: client on port %u\n", pxSocket->usLocalPort ) );
                xResult = pdTRUE;
                break;
            }
        }
    }
    return xResult;
}
/*-----------------------------------------------------------*/

#endif /* ipconfigUSE_TCP == 1 */

