/* TCPЭ����TCP/IPЭ�������֮�أ���֤�������ӵĿɿ��ԣ�����˿ں�ʹ�ò�ͬ�Ľ��̿��Թ������� */
/*                      API���               
    prvTCPSocketIsActive
        ����׽����Ƿ񼤻�������Ƿ����
    prvTCPStatusAgeCheck
        �������������׽����Ƿ������״̬̫���ˣ�����ǣ�����׽��ֻᱻ�رղ�����-1
    xTCPSocketCheck
        ���Է����ӳ�Ӧ��������µ�����
    prvTCPSendRepeated
        ֻҪ������Ҫ���͵����ݣ�ֻҪ���ʹ��ڲ������������ͻ᳢�Է���һϵ����Ϣ
    prvTCPReturnPacket
        ������̫������
    prvTCPCreateWindow
        ��������
    prvTCPPrepareConnect
        ׼�����ӣ�����ARP�����TCP����������
    prvCheckOptions
        ���TCPѡ��
    prvWinScaleFactor
        ���ô��ڷŴ�����
    prvSetSynAckOptions
        ����ѡ������SYN+ACK����
    prvTCPTouchSocket
        �����׽��ּ�����
    
 */
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


/* �ô��һ���궨�壡 */
#if ipconfigUSE_TCP == 1

/* ���ݴ�С���б� */

#if ( ( ipconfigTCP_MSS + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER ) > ipconfigNETWORK_MTU )
    #error The ipconfigTCP_MSS setting in FreeRTOSIPConfig.h is too large.
#endif

/*
 * TCP��־
 */

/*                  ����˵��                
    ipTCP_FLAG_ECN��
    һ����������ǰ������м价�ڣ�·�ɵȣ������ں��ӿ�����ֻ��ͨ���������ж��Ƿ���ӵ����
    ���ڲ���Ӧ�ã�������Ƶ����ӵ�������У��򵥵Ķ����ش����������Ϳ����ش�ʹ���û������
    ���������֧��ECN���ܣ��������IP���������ECTָʾ�����м�·������RED�㷨��⵽��
    ���ܿ���֮��Ὣ�����ݰ����ΪCE�����ն��յ����ݰ�֮�󣬷���CE��־��Ч����������ACK
    ���ĵ�TCPͶ������ECN-Echo��ָʾӵ���ķ��������Ͷ��յ�֮�������Ӧ���������ڱ�С�ˣ���
    ��������TCP����������CWRλ�����ն��յ���CWR��־����֪�����Ͷ����˽���ӵ�����������
    ���ACK�㲻������ECN-Echo��IPͷ����һECN����
    00��֧��ECT
    01ECT(1)
    10ECT(0)
    11CE

*/

#define ipTCP_FLAG_FIN          0x0001u /* ������־�������߲����������� */
#define ipTCP_FLAG_SYN          0x0002u /* ͬ���� */
#define ipTCP_FLAG_RST          0x0004u /* ��λ���� */
#define ipTCP_FLAG_PSH          0x0008u /* �����ݣ�������ݴ��ݸ��û����� */
#define ipTCP_FLAG_ACK          0x0010u /* Ӧ��������Ч*/
#define ipTCP_FLAG_URG          0x0020u /* ����ָ����Ч */
#define ipTCP_FLAG_ECN          0x0040u /* ������������ڷ���ӵ������ʽӵ��ͨ�棩 */
#define ipTCP_FLAG_CWR          0x0080u /* ӵ�����ڼ��� */
#define ipTCP_FLAG_NS           0x0100u /* ECN-nonce concealment protection */
#define ipTCP_FLAG_RSV          0x0E00u /* Reserved, keep 0 */

/* ���ε�Э��λ������ */
#define ipTCP_FLAG_CTRL         0x001Fu

/*
 * TCPѡ��
 */
/*                      ����˵��                
    SACK
    ��TCP���ݶ�ʧ֮�󣬴�ͳ���������ش��������ݣ�������TCP�����ʣ�ʹ��SACK
    ��ѡ�����ش���֮����ֻ�����´�����Щ��ʧ�İ���
 */
#define TCP_OPT_END             0u   /* TCPѡ����� */
#define TCP_OPT_NOOP            1u   /* TCPѡ��ղ����� */
#define TCP_OPT_MSS             2u   /* TCPѡ��MSS */
#define TCP_OPT_WSOPT           3u   /* TCP���ڷŴ����� */
#define TCP_OPT_SACK_P          4u   /* ����SACK */
#define TCP_OPT_SACK_A          5u   /* ѡ����ȷ������ */
#define TCP_OPT_TIMESTAMP       8u   /* ʱ��� */
#define TCP_OPT_MSS_LEN         4u   /* TCP MSSѡ��ĳ��� */
#define TCP_OPT_WSOPT_LEN       3u   /* ���ڷŴ�ϵ���ĳ��� */
#define TCP_OPT_TIMESTAMP_LEN   10   /* ʱ������� */

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
/* �궨��NOW_CONNECTED()�����ж��Ƿ񣬼����Ͻ�������״̬��ͱ��ر��ˣ�����
�������׽�������Է�����ACK֮ǰ���رմӶ���ɡ�RST�������� */
/* ���״̬�������¼��֣�eESTABLISHED, eFIN_WAIT_1, eFIN_WAIT_2, eCLOSING, eLAST_ACK, eTIME_WAIT
��궨��NOW_CONNECTED()�����棬 */
#define NOW_CONNECTED( status )\
    ( ( status >= eESTABLISHED ) && ( status != eCLOSE_WAIT ) )

/* ����λ��ʾTCP����ͷ��С */
#define VALID_BITS_IN_TCP_OFFSET_BYTE       ( 0xF0u )

/* ����TCP���ݵ�ȷ����Ҫ�ӳ�һ��ʱ�䣬ͨ����200ms��20ms��Ϊ���ṩ�ϸߵı��� */
#define DELAYED_ACK_SHORT_DELAY_MS          ( 2 )
#define DELAYED_ACK_LONGER_DELAY_MS         ( 20 )

/* 1460������ͨ�����磬�Ի���ٵ�1400 */
#define REDUCED_MSS_THROUGH_INTERNET        ( 1400 )

/* ÿ�ν���TCP���Ӿͻ�ʹ��һ����ʼ�����кţ����к������0x102�Ĵ�С���� */
#define INITIAL_SEQUENCE_NUMBER_INCREMENT       ( 0x102UL )

/* �����ʹ��TCPѡ�TCPͷ�Ĵ�СΪ20�ֽڣ���ʾΪ5���֣��洢�ڸ�λ */
#define TCP_OFFSET_LENGTH_BITS          ( 0xf0u )
#define TCP_OFFSET_STANDARD_LENGTH      ( 0x50u )

/* Ӧ�����ڼ��ÿһ���׽��֣���ȷ�����ܷ������ݡ�ͨ�������ļ��İ�����������ᱻ����Ϊ8��������ô�������һ�����ƴ���ֵ */
#if( !defined( SEND_REPEATED_COUNT ) )
    #define SEND_REPEATED_COUNT     ( 8 )
#endif /* !defined( SEND_REPEATED_COUNT ) */

/* ��ͬ״̬ʱ������ */
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

/* ����׽��ֱ����飬�򷵻��棬δ������׽����ڵȴ��û����������ӻ����ǹر� */
static BaseType_t prvTCPSocketIsActive( UBaseType_t uxStatus );

/* ���ڷ������ݰ� */
static int32_t prvTCPSendPacket( FreeRTOS_Socket_t *pxSocket );

/* ���Է���һϵ������ */
static int32_t prvTCPSendRepeated( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer );

/* ���ػ����Ƿ������ݸ���һ�� */
static void prvTCPReturnPacket( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer,
    uint32_t ulLen, BaseType_t xReleaseAfterSend );

/* ��ʼ�����ָ���TCP����ϵͳ�����ݽṹ */
static void prvTCPCreateWindow( FreeRTOS_Socket_t *pxSocket );

/* ��ARP���ҶԷ�MAC����ʼ����һ��SYN�� */
static BaseType_t prvTCPPrepareConnect( FreeRTOS_Socket_t *pxSocket );

#if( ipconfigHAS_DEBUG_PRINTF != 0 )
    /* ���ڼ�¼�͵��� */
    static const char *prvTCPFlagMeaning( UBaseType_t xFlags);
#endif /* ipconfigHAS_DEBUG_PRINTF != 0 */

/* ���TCPѡ�� */
static void prvCheckOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/* ����ѡ������ĳ������ԣ�����MSS���Ƿ�����SACK��������״̬��eCONNECT_SYN������ */
static UBaseType_t prvSetSynAckOptions( FreeRTOS_Socket_t *pxSocket, TCPPacket_t * pxTCPPacket );

/* ���ڷ����𱣻���TCP�����źţ��������ط����ã��յ�һ�����ݰ���״̬�ı䡣
�׽��ֵĻʱ���ᱻ��λ */
static void prvTCPTouchSocket( FreeRTOS_Socket_t *pxSocket );

/* ����ж���Ҫ���ͣ�׼��һ��������������Ϣ */
static int32_t prvTCPPrepareSend( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer, UBaseType_t uxOptionsLength );

/* ����ʲôʱ���׽�����Ҫ�����ȥ�ش� */
static TickType_t prvTCPNextTimeout( FreeRTOS_Socket_t *pxSocket );

/* API FreeRTOS_send()��TX��������ݣ���������ӵ�����ϵͳ���������� */
static void prvTCPAddTxData( FreeRTOS_Socket_t *pxSocket );

/* ��������TCP���ӵĹر� */
static BaseType_t prvTCPHandleFin( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/* ����TCPʱ��� */
#if(    ipconfigUSE_TCP_TIMESTAMPS == 1 )
    static UBaseType_t prvTCPSetTimeStamp( BaseType_t lOffset, FreeRTOS_Socket_t *pxSocket, TCPHeader_t *pxTCPHeader );
#endif

/* ��prvTCPHandleState()���ã��ҵ�TCP���ݲ���鷵���䳤�� */
static BaseType_t prvCheckRxData( NetworkBufferDescriptor_t *pxNetworkBuffer, uint8_t **ppucRecvData );

/* ��prvTCPHandleState()���ã�����Ƿ����ݿ��Ա����ܣ�����ǣ���������ӵ��׽��ֵĽ��ܶ��� */
static BaseType_t prvStoreRxData( FreeRTOS_Socket_t *pxSocket, uint8_t *pucRecvData,
    NetworkBufferDescriptor_t *pxNetworkBuffer, uint32_t ulReceiveLength );

/* ����TCPѡ�� */
static UBaseType_t prvSetOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/*
 * Called from prvTCPHandleState() as long as the TCP status is eSYN_RECEIVED to
 * eCONNECT_SYN.
 */
/* ��prvTCPHandleState()���ã� */
static BaseType_t prvHandleSynReceived( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength );

/* ��prvTCPHandleState()���ã�TCP״̬ΪeESTABLISHED */
static BaseType_t prvHandleEstablished( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength );

/* ��prvTCPHandleState()���������ݱ����ͣ����������ipconfigUSE_TCP_WIN������ֻ��һ��ACKҪ����ʱ
���ǻ���һ���ǲ����Ƴ�һ��ʱ���ٷ��͸��ø���Ч�� */
static BaseType_t prvSendData( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, BaseType_t xSendLength );

/* ���еĺ��ģ���鵽�������ݻ���Ӧ�𣬸��ݵ�ǰ״̬����Ҫ��ʲô */
static BaseType_t prvTCPHandleState( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer );

/* ��RST�ظ��Է��������ݴ����������ʱ��ʹ�� */
static BaseType_t prvTCPSendReset( NetworkBufferDescriptor_t *pxNetworkBuffer );

/* ����MSS��ʼֵ�� */
static void prvSocketSetMSS( FreeRTOS_Socket_t *pxSocket );

/* ����һ���´������׽��֣������ǵ�ǰ���ӵ��׽��֣�ȡ���ڱ�־��bReuseSocket���� */
static FreeRTOS_Socket_t *prvHandleListen( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer );

/* �ڼ����׽����յ�һ���µ�����֮�����Ḵ���Լ����ô˺�����ɸ��� */
static BaseType_t prvTCPSocketCopy( FreeRTOS_Socket_t *pxNewSocket, FreeRTOS_Socket_t *pxSocket );

/* �������������׽����Ƿ������״̬̫���ˣ�����ǣ�����׽��ֻᱻ�رղ�����-1 */
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

/* ��ʼ�����кţ�����ֵӦ������Է�ֹ��ˮ���� */
uint32_t ulNextInitialSequenceNumber = 0ul;

/* ����׽��ֱ����飬�򷵻��棬δ������׽����ڵȴ��û����������ӻ����ǹر� */

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
/* �������������׽����Ƿ������״̬̫���ˣ�����ǣ�����׽��ֻᱻ�رղ�����-1 */
#if( ipconfigTCP_HANG_PROTECTION == 1 )
    static BaseType_t prvTCPStatusAgeCheck( FreeRTOS_Socket_t *pxSocket )
    {
    BaseType_t xResult;
        switch( pxSocket->u.xTCP.ucTCPState )
        {
        case eESTABLISHED:
            /* ���ipconfigTCP_KEEP_ALIVEѡ�ʹ�ܣ�����ESTABLISHED���׽���
            ��ͨ�������źű���*/
            xResult = pdFALSE;
            break;
        case eCLOSED:
        case eTCP_LISTEN:
        case eCLOSE_WAIT:
            /* ������״̬����������ã��Ϳ��û���  */
            xResult = pdFALSE;
            break;
        default:
            /* ���������������ӣ�״̬����õ������𱣻� */
            xResult = pdTRUE;
            break;
        }
        if( xResult != pdFALSE )
        {
            /* ����ʱ�� */
            TickType_t xAge = xTaskGetTickCount( ) - pxSocket->u.xTCP.xLastActTime;
            /* ipconfigTCP_HANG_PROTECTION_TIME����Ϊ��λ */
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
                /* ת��eCLOSE_WAIT״̬ */
                vTCPStateChange( pxSocket, eCLOSE_WAIT );
                /* ��bPassQueuedΪtrue��������֮ǰ���׽���Ϊ�¶� */
                if( pxSocket->u.xTCP.bits.bPassQueued != pdFALSE_UNSIGNED )
                {
                    if( pxSocket->u.xTCP.bits.bReuseSocket == pdFALSE_UNSIGNED )
                    {
                        /* ����û�����Ӳ����û���Ҳ�����գ��⽫��ɾ���� */
                        vSocketClose( pxSocket );
                    }
                    /* ����һ�����ݣ�֪ͨxTCPTimerCheck()���׽����ѹرղ��Ҳ����ܷ��� */
                    xResult = -1;
                }
            }
        }
        return xResult;
    }
#endif

/*
 * ��TCP�׽��ֵĶ�ʱ�����ڣ��������ᱻxTCPTimerCheck����
 * �����Է����ӳ�Ӧ��������µ�����
 * ͨ���ĵ����������� :
 * IP-Task:
 *      xTCPTimerCheck()                // ������е��׽���
 *      xTCPSocketCheck()               // Ҫô�����ӳ�Ӧ��Ҫô����prvTCPSendPacket()
 *      prvTCPSendPacket()              // Ҫô�����ӳ�Ӧ��Ҫô����prvTCPSendRepeated
 *      prvTCPSendRepeated()            // ��һ�з�������8����Ϣ
 *          prvTCPReturnPacket()        // ׼������
 *          xNetworkInterfaceOutput()   // ������ӿڷ������� ( ��portable/NetworkInterface/xxx���� )
 */
BaseType_t xTCPSocketCheck( FreeRTOS_Socket_t *pxSocket )
{
BaseType_t xResult = 0;
BaseType_t xReady = pdFALSE;

    if( ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) && ( pxSocket->u.xTCP.txStream != NULL ) )
    {
        /* API FreeRTOS_send()��TX��������ݣ���������ӵ�����ϵͳ���������� */
        prvTCPAddTxData( pxSocket );
    }
    #if ipconfigUSE_TCP_WIN == 1
    {
        if( pxSocket->u.xTCP.pxAckMessage != NULL )
        {
            /* ���׽��ּ��ĵ�һ��������Ƿ����ӳ�Ӧ�� */
            if( pxSocket->u.xTCP.bits.bUserShutdown == pdFALSE_UNSIGNED )
            {
                /* ���ȵ����ݱ����յ���û��Ӧ�𣬱������ڶ�ʱ������ʱ���ã����ڽ��ᷢ��Ӧ�� */
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
                    /* ����ɶ���������������������������������������� */
                    prvTCPReturnPacket( pxSocket, pxSocket->u.xTCP.pxAckMessage, ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER, ipconfigZERO_COPY_TX_DRIVER );
                    #if( ipconfigZERO_COPY_TX_DRIVER != 0 )
                    {
                        /* The ownership has been passed to the SEND routine,
                        clear the pointer to it. */
                        /* ����Ȩ�Ѿ������ݸ����ͳ����������ָ�� */
                        pxSocket->u.xTCP.pxAckMessage = NULL;
                    }
                    #endif /* ipconfigZERO_COPY_TX_DRIVER */
                }
                if( prvTCPNextTimeout( pxSocket ) > 1 )
                {
                    /* ��������Ĵ��룬��������Ѿ�׼������ */
                    xReady = pdTRUE;
                }
            }
            else
            {
                /* �û�ϣ�������رգ��Թ��ӳ�Ӧ�𣬺���prvTCPSendPacket���ᷢ��FIN˳��ACK */
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
        /* ���׽��ּ����ĵڶ���������Ƿ������� */
        if( ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) ||
            ( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN ) )
        {
            prvTCPSendPacket( pxSocket );
        }
        /* ���ø��׽��� ����һ�λ��ѵĳ�ʱʱ�� */
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
/* ���������׽��ֶ�ʱ����ʱ���ã�ֻ�ܱ�����xTCPSocketCheck()���� */
static int32_t prvTCPSendPacket( FreeRTOS_Socket_t *pxSocket )
{
int32_t lResult = 0;
UBaseType_t uxOptionsLength;
TCPPacket_t *pxTCPPacket;
NetworkBufferDescriptor_t *pxNetworkBuffer;

    if( pxSocket->u.xTCP.ucTCPState != eCONNECT_SYN )
    {
        /* ���Ӳ���SYN״̬ */
        pxNetworkBuffer = NULL;
        /* prvTCPSendRepeated()��ֻ�ᴴ��һ���绺���������������ݱ��뷢�͸��Է���ʱ�� */
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
            /* ���Ӵ���SYN״̬�������ظ�������Σ�û�лظ�ʱ���׽��ֽ���״̬eCLOSE_WAIT */
            FreeRTOS_debug_printf( ( "Connect: giving up %lxip:%u\n",
                pxSocket->u.xTCP.ulRemoteIP,        /* IP address of remote machine. */
                pxSocket->u.xTCP.usRemotePort ) );  /* Port on remote machine. */
                /* ����״̬ */
            vTCPStateChange( pxSocket, eCLOSE_WAIT );
        }
        else if( ( pxSocket->u.xTCP.bits.bConnPrepared != pdFALSE_UNSIGNED ) || ( prvTCPPrepareConnect( pxSocket ) == pdTRUE ) )
        {
            /* 
            �����ǣ��������׼�����������׼�����������ʹ���SYN��־�İ���prvTCPPrepareConnect()
            ׼��xPacket�������������ַ�������ر����ַ�����
            */
            pxTCPPacket = ( TCPPacket_t * )pxSocket->u.xTCP.xPacket.u.ucLastPacket;
            #if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
            {
                /* ���ʱ���ʹ�ܣ�ֻ����ͬ��Ϊ��������ʱ�ſ�ʹ�ã�ͨ������internet�ϡ� */
                if( ( ( pxSocket->u.xTCP.ulRemoteIP ^ FreeRTOS_ntohl( *ipLOCAL_IP_ADDRESS_POINTER ) ) & xNetworkAddressing.ulNetMask ) != 0ul )
                {
                    pxSocket->u.xTCP.xTCPWindow.u.bits.bTimeStamps = pdTRUE_UNSIGNED;
                }
            }
            #endif
            /* ����һ��SYN��������prvSetSynAckOptions() ȥ���ú��ʵ�ѡ�MSS��С���Ƿ�����SACK */
            uxOptionsLength = prvSetSynAckOptions( pxSocket, pxTCPPacket );

            /* ������Ҫ���͵��ֽ��� */
            lResult = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
            /* 
            �������ݴ�С��ipSIZE_OF_TCP_HEADER����20��uxOptionsLength����4�ı����������Ĺ�ʽ�ǣ�
            ucTCPOffset = ( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) / 4 ) << 4
            */
            pxTCPPacket->xTCPHeader.ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
            /* ���Դ��������׽��ֵ����ӣ��������Ƴ��ԵĴ��� */
            pxSocket->u.xTCP.ucRepCount++;
            /* ����SYN��Ϣ��ʼ���ӣ���Ϣ������xPacket�У����䱻����֮ǰ���ᱻ������α���绺���� */
            prvTCPReturnPacket( pxSocket, NULL, ( uint32_t ) lResult, pdFALSE );
        }
    }

    /* Return the total number of bytes sent. */
    return lResult;
}
/*-----------------------------------------------------------*/
/* ֻҪ������Ҫ���͵����ݣ�ֻҪ���ʹ��ڲ������������ͻ᳢�Է���һϵ����Ϣ */
static int32_t prvTCPSendRepeated( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer )
{
UBaseType_t uxIndex;
int32_t lResult = 0;
UBaseType_t uxOptionsLength = 0u;
int32_t xSendLength;

    for( uxIndex = 0u; uxIndex < ( UBaseType_t ) SEND_REPEATED_COUNT; uxIndex++ )
    {
        /* �����������Ҫ���ͣ�prvTCPPrepareSend()������һ���绺���� */
        xSendLength = prvTCPPrepareSend( pxSocket, ppxNetworkBuffer, uxOptionsLength );
        if( xSendLength <= 0 )
        {
            break;
        }
        /* ���ذ����Ե��� */
        prvTCPReturnPacket( pxSocket, *ppxNetworkBuffer, ( uint32_t ) xSendLength, ipconfigZERO_COPY_TX_DRIVER );
        #if( ipconfigZERO_COPY_TX_DRIVER != 0 )
        {
            *ppxNetworkBuffer = NULL;
        }
        #endif /* ipconfigZERO_COPY_TX_DRIVER */
        lResult += xSendLength;
    }
    /* �����ܹ����͵��ֽ��� */
    return lResult;
}
/*-----------------------------------------------------------*/
/* 
���أ����߷��ͣ�����peer�����ݴ洢��pxBuffer�У�pxBuffer����ָ�����������绺��������
ָ��TCP�׽��ֵ�xTCP.xPacket��Ա����ʱ��xNetworkBuffer���ᱻ���ڴ������ݵ�NIC
*/
/*
****************************************************
*  ������         : prvTCPReturnPacket
*  ��������       : 
*  ����           : 
                    pxSocket���׽���
                    pxNetworkBuffer�����绺��
                    ulLen�����������ݳ���
                    xReleaseAfterSend������֮���Ƿ��ͷŵ�
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static void prvTCPReturnPacket( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer, uint32_t ulLen, BaseType_t xReleaseAfterSend )
{
TCPPacket_t * pxTCPPacket;
IPHeader_t *pxIPHeader;
EthernetHeader_t *pxEthernetHeader;
uint32_t ulFrontSpace, ulSpace, ulSourceAddress, ulWinSize;
TCPWindow_t *pxTCPWindow;
NetworkBufferDescriptor_t xTempBuffer;
/* Ϊ�˷��ͣ�һ��α���绺��������ʹ�ã�����ǰ������ */
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
        /* ������ʹ��htonת�� */
        if( pxSocket != NULL )
        {
            /* ������ܻ���Ŀռ��Թ����׽��ֵĽ��մ��ڴ�С */
            pxTCPWindow = &( pxSocket->u.xTCP.xTCPWindow );
            if( pxSocket->u.xTCP.rxStream != NULL )
            {
                /* �������Ѿ�������ֱ�ӿ��ж��ٿ��пռ�ͺ��� */
                ulFrontSpace = ( uint32_t ) uxStreamBufferFrontSpace( pxSocket->u.xTCP.rxStream );
            }
            else
            {
                /* ����δ��������ȫ������ */
                ulFrontSpace = ( uint32_t ) pxSocket->u.xTCP.uxRxStreamSize;
            }
            /* ��ȡ�������ռ�ʹ���֮�����Сֵ */
            ulSpace = FreeRTOS_min_uint32( pxSocket->u.xTCP.ulRxCurWinSize, pxTCPWindow->xSize.ulRxWindowLength );
            if( ( pxSocket->u.xTCP.bits.bLowWater != pdFALSE_UNSIGNED ) || ( pxSocket->u.xTCP.bits.bRxStopped != pdFALSE_UNSIGNED ) )
            {
                /* �Ѿ��ﵽ�˳�ˮ�ߣ�˵�������ÿռ�����ˣ��׽��ֻ�ȴ��û�ȡ�߻������������ݣ�ͬʱ�ṫ��0���� */
                ulSpace = 0u;
            }
            /* ������ܣ���������Ϊ1�Ľ��մ��ڣ����򣬶Է��������㴰��̽�⣬��������С���ݰ�1��2��4��8�ֽ� */
            if( ( ulSpace < pxSocket->u.xTCP.usCurMSS ) && ( ulFrontSpace >= pxSocket->u.xTCP.usCurMSS ) )
            {
                ulSpace = pxSocket->u.xTCP.usCurMSS;
            }
            /* ����16λ������� */
            ulWinSize = ( ulSpace >> pxSocket->u.xTCP.ucMyWinScaleFactor );
            if( ulWinSize > 0xfffcUL )
            {
                ulWinSize = 0xfffcUL;
            }
            /* �����ֽ�ת�� */
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
            /* �µĴ����Ѿ����������رձ�־ */
            pxSocket->u.xTCP.bits.bWinChange = pdFALSE_UNSIGNED;
            /* �������������ӳ�һ��Ӧ�𣬿��н��մ�С��Ҫһ����ȷ������������ʱ��ulHighestRxAllowed�������׽����ܽ��յ���������кż�һ*/
            pxSocket->u.xTCP.ulHighestRxAllowed = pxTCPWindow->rx.ulCurrentSequenceNumber + ulSpace;
            #if( ipconfigTCP_KEEP_ALIVE == 1 )
                if( pxSocket->u.xTCP.bits.bSendKeepAlive != pdFALSE_UNSIGNED )
                {
                    /* Sending a keep-alive packet, send the current sequence number
                    minus 1, which will be recognised as a keep-alive packet an
                    responded to by acknowledging the last byte. */
                    /* ���ͱ���������͵�ǰ�����кż�һ���⽫�ᱻʶ��Ϊһ������� */
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
                    /* ȥ��FIN��־�Է����д��������ش������� */
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
            /* ����������һ����Ҫ���յ����к��Ƕ��� */
            pxTCPPacket->xTCPHeader.ulAckNr = FreeRTOS_htonl( pxTCPWindow->rx.ulCurrentSequenceNumber );
        }
        else
        {
            /* �������ݶ��������׽��֣�����ظ�һֻ�ǰ������������кŵ�RST */
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
            /* ����IPͷУ��ͣ��Է������������� */
            pxIPHeader->usHeaderChecksum = 0x00u;
            pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0UL, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
            pxIPHeader->usHeaderChecksum = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
            /* ���ڼ��������İ�������TCP��У��� */
            usGenerateProtocolChecksum( (uint8_t*)pxTCPPacket, pdTRUE );
            /* �����У���Ϊ0����ߵ�����Ϊ0��ζ��У��ʧ�� */
            if( pxTCPPacket->xTCPHeader.usChecksum == 0x00u )
            {
                pxTCPPacket->xTCPHeader.usChecksum = 0xffffU;
            }
        }
        #endif
    #if( ipconfigUSE_LINKED_RX_MESSAGES != 0 )
        pxNetworkBuffer->pxNextBuffer = NULL;
    #endif
        /* ����NIC�������ж��ٸ��ֽ�Ҫ���� */
        pxNetworkBuffer->xDataLength = ulLen + ipSIZE_OF_ETH_HEADER;
        /* ���Ŀ��MAC��ַ */
        memcpy( ( void * ) &( pxEthernetHeader->xDestinationAddress ), ( void * ) &( pxEthernetHeader->xSourceAddress ),
            sizeof( pxEthernetHeader->xDestinationAddress ) );
        /* ��䱾��MAC��ַ */
        memcpy( ( void * ) &( pxEthernetHeader->xSourceAddress) , ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
        /* ���ݵ���� */
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
        /* �������ݣ� */
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
/* SYNʱ��ǳ���Ҫ�������кţ���ʼ�������ֵ���ڹ����б�ͬ�����������ڹ�����Ҫ֪����Щ */
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
�����׽�����һ�����״̬��eCONNECT_SYN��������׶��£�Ŀ���MAC��ַ�����Ѿ�ͨ��ARP��ȡ��
Ϊ��ֹĿ��IP���ھ������У����صĵ�ַ��Ҫ�õ���
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
    /* ��ȡARP����Ŀ��IP��ַ�ķ�Ӧ */
    eReturned = eARPGetCacheEntry( &( ulRemoteIP ), &( xEthAddress ) );
    switch( eReturned )
    {
    case eARPCacheHit:      /* An ARP table lookup found a valid entry. */
        break;              /* We can now prepare the SYN packet. */
    case eARPCacheMiss:     /* An ARP table lookup did not find a valid entry. */
    case eCantSendPacket:   /* There is no IP address, or an ARP is still in progress. */
    default:
        /* ��¼ARP�Ҳ�����¼�Ĵ��� */
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
        /* ͬʱ����һARP���� */
        FreeRTOS_OutputARPRequest( ulRemoteIP );
        xReturn = pdFALSE;
    }

    if( xReturn != pdFALSE )
    {
        /* �Է���MAC���������ص�MAC�Ѿ�����ȡ������׼����ʼ��TCP�� */
        pxTCPPacket = ( TCPPacket_t * )pxSocket->u.xTCP.xPacket.u.ucLastPacket;
        pxIPHeader = &pxTCPPacket->xIPHeader;
        /* ��λ���Դ�����0 */
        pxSocket->u.xTCP.ucRepCount = 0u;
        /* ���Ҽ�ס������/SYN�����Ѿ�׼������ */
        pxSocket->u.xTCP.bits.bConnPrepared = pdTRUE_UNSIGNED;
        /* ������̫����ַ�Ѿ�֪���ˣ���ʼ�İ�����׼�� */
        memset( pxSocket->u.xTCP.xPacket.u.ucLastPacket, '\0', sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket ) );
        /* ��Ŀ���ַд��Դ��ַ����Ϊ���ᱻprvTCPReturnPacket���� */
        memcpy( &pxTCPPacket->xEthernetHeader.xSourceAddress, &xEthAddress, sizeof( xEthAddress ) );
        /* 'ipIPv4_FRAME_TYPE' is already in network-byte-order. */
        pxTCPPacket->xEthernetHeader.usFrameType = ipIPv4_FRAME_TYPE;
        pxIPHeader->ucVersionHeaderLength = 0x45u;
        pxIPHeader->usLength = FreeRTOS_htons( sizeof( TCPPacket_t ) - sizeof( pxTCPPacket->xEthernetHeader ) );
        pxIPHeader->ucTimeToLive = ( uint8_t ) ipconfigTCP_TIME_TO_LIVE;
        pxIPHeader->ucProtocol = ( uint8_t ) ipPROTOCOL_TCP;
        /* IP��ַ�Ͷ˿ںŻᱻ��������ΪprvTCPReturnPacket������ǽ������� */
        pxIPHeader->ulDestinationIPAddress = *ipLOCAL_IP_ADDRESS_POINTER;
        pxIPHeader->ulSourceIPAddress = FreeRTOS_htonl( pxSocket->u.xTCP.ulRemoteIP );
        pxTCPPacket->xTCPHeader.usSourcePort = FreeRTOS_htons( pxSocket->u.xTCP.usRemotePort );
        pxTCPPacket->xTCPHeader.usDestinationPort = FreeRTOS_htons( pxSocket->usLocalPort );
        /* ���������������ӣ����ԶԷ������кŲ�֪�� */
        pxSocket->u.xTCP.xTCPWindow.rx.ulCurrentSequenceNumber = 0ul;
        /* �������к� */
        pxSocket->u.xTCP.xTCPWindow.ulOurSequenceNumber = ulNextInitialSequenceNumber;
        /* �Ƽ������к�������258 */
        ulNextInitialSequenceNumber += 0x102UL;
        /* TCPͷ����СΪ20B������4��5������ֵ���ᱻ�ŵ�offset�ĸ�λ */
        pxTCPPacket->xTCPHeader.ucTCPOffset = 0x50u;
        /* ֻ����SYN��־ */
        pxTCPPacket->xTCPHeader.ucTCPFlags = ipTCP_FLAG_SYN;
        /* �����׽��ֵ�MSS��usInitMSS / usCurMSS */
        prvSocketSetMSS( pxSocket );
        /* ��ʱ��ͬ�����Ƽ��Ĵ��ڴ�С */
        pxSocket->u.xTCP.ulRxCurWinSize = pxSocket->u.xTCP.usInitMSS;
        /* ��������һ�ߵĳ������к��Ѿ�֪���ˣ��������vTCPWindowInit()�����Է������кţ��������ȵȴ�SYN+ACK�ظ� */
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

/* ����յ���ѡ�������ڣ�((pxTCPHeader->ucTCPOffset & 0xf0) > 0x50) TCP��ͷ����5*4=20 */
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
    /* һ���ַ�ָ�����ѡ������ */
    pucPtr = pxTCPHeader->ucOptdata;
    pucLast = pucPtr + (((pxTCPHeader->ucTCPOffset >> 4) - 5) << 2);
    pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
    /* ֻ�е�ѡ�������𻵵�����²Ż�Ƚ�pucLast�����ǲ�ϲ��������Ч�ڴ档��Ȼ����� */
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
            /* ���ڷŴ����� */
            pxSocket->u.xTCP.ucPeerWinScaleFactor = pucPtr[ 2 ];
            pxSocket->u.xTCP.bits.bWinScaling = pdTRUE_UNSIGNED;
            pucPtr += TCP_OPT_WSOPT_LEN;
        }
#endif  /* ipconfigUSE_TCP_WIN */
        else if( ( pucPtr[ 0 ] == TCP_OPT_MSS ) && ( pucPtr[ 1 ] == TCP_OPT_MSS_LEN ) )
        {
            /* ����MSS��ֵ */
            uxNewMSS = usChar2u16( pucPtr + 2 );
            if( pxSocket->u.xTCP.usInitMSS != uxNewMSS )
            {
                FreeRTOS_debug_printf( ( "MSS change %u -> %lu\n", pxSocket->u.xTCP.usInitMSS, uxNewMSS ) );
            }
            if( pxSocket->u.xTCP.usInitMSS > uxNewMSS )
            {
                /* ���ǵ�MSS������һ����MSS������һ�� */
                pxSocket->u.xTCP.bits.bMssChange = pdTRUE_UNSIGNED;
                if( ( pxTCPWindow != NULL ) && ( pxSocket->u.xTCP.usCurMSS > uxNewMSS ) )
                {
                    /* �Է�������һ�������Ǹ�С��MSS�����������Ǹ� */
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
            /* ����������ѡ����һ�����ȳ�Ա�����������ܱȽ����׵��������� */
            int len = ( int )pucPtr[ 1 ];
            if( len == 0 )
            {
                /* ������ȳ�ԱΪ0�����ѡ���Ǹ����Σ����ǲ��ᴦ���� */
                break;
            }

            #if( ipconfigUSE_TCP_WIN == 1 )
            {
                /* 
                    ѡ���Իظ����Է��Ѿ��յ��������Ƕ�ʧ��֮ǰ�İ���������һ�ε����ݰ�����Ҫ
                    �ش��ˣ�ulTCPWindowTxSack()��������һ��
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
                        /* ulTCPWindowTxSack���ش�ͷ����ʼ�Ѿ���Ӧ����ֽ��� */
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
/*2016--12--05--14--44--49(ZJYC): ���ô��ڷŴ�����   */ 
#if( ipconfigUSE_TCP_WIN != 0 )

    static uint8_t prvWinScaleFactor( FreeRTOS_Socket_t *pxSocket )
    {
    size_t uxWinSize;
    uint8_t ucFactor;
        /* xTCP.uxRxWinSize�ǽ��մ��ڵĴ�С����MSSΪ��λ */
        uxWinSize = pxSocket->u.xTCP.uxRxWinSize * ( size_t ) pxSocket->u.xTCP.usInitMSS;
        ucFactor = 0u;
        while( uxWinSize > 0xfffful )
        {
            /* ����16λ����2��ͬʱ�Ŵ����Ӽ�1 */
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
/* ����һTCP���ӣ���SYN�����ͣ��Է����ܻ�֪ͨ����Ҫʲô����MSS��MSS�Ǹ��ɵľ��ߴ磬����С��MTU */
static UBaseType_t prvSetSynAckOptions( FreeRTOS_Socket_t *pxSocket, TCPPacket_t * pxTCPPacket )
{
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
uint16_t usMSS = pxSocket->u.xTCP.usInitMSS;
#if ipconfigUSE_TCP_WIN == 1
    UBaseType_t uxOptionsLength;
#endif
    /* ���Ƿ���MSSѡ������ǵ�SYN[+ACK] */
    pxTCPHeader->ucOptdata[ 0 ] = ( uint8_t ) TCP_OPT_MSS;
    pxTCPHeader->ucOptdata[ 1 ] = ( uint8_t ) TCP_OPT_MSS_LEN;
    pxTCPHeader->ucOptdata[ 2 ] = ( uint8_t ) ( usMSS >> 8 );
    pxTCPHeader->ucOptdata[ 3 ] = ( uint8_t ) ( usMSS & 0xffu );

    #if( ipconfigUSE_TCP_WIN != 0 )
    {
        /* ��Ӵ��ڷŴ����� */
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
                /* ���ʱ��� */
                uxOptionsLength += prvTCPSetTimeStamp( uxOptionsLength, pxSocket, &pxTCPPacket->xTCPHeader );
                pxTCPHeader->ucOptdata[ uxOptionsLength + 0 ] = TCP_OPT_SACK_P; /* 4: Sack-Permitted Option. */
                pxTCPHeader->ucOptdata[ uxOptionsLength + 1 ] = 2u;
                uxOptionsLength += 2u;
            }
            else
        #endif
        {
            /* �հײ��� */
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
/* ���ڷ��ұ�����TCP����������������ط����ã��յ����ݰ�֮���״̬�ı�֮���׽��ֵı��ʱ�����ܻḴλ */
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
�ı䵽һ�µ�״̬�������ڴ˴���һЩ����Ķ��������磺���豣�ʱ����
�����û������Ӿ�����޸��׽��ֵ����Ӻͷ��������ԣ�����Ϊ��������FreeRTOS_select �ĵ���
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

    /* ״̬�����ı� */
    if( bBefore != bAfter )
    {
        /* �׽����������� */
        if( bAfter != pdFALSE )
        {
            /* ���׽����Ǹ��¶� */
            if( pxSocket->u.xTCP.bits.bPassQueued != pdFALSE_UNSIGNED )
            {
                /* �����������ӣ��ҵ����ĸ��� */
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
                        /* ��֧��FreeRTOS_select()���յ�һ���µ����ӻᱻ����Ϊһ�������� */
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
                            /* �����׽��ֲ����Լ����ӣ��෴��һ�����׽��ֱ������� */
                            xConnected = xParent;
                        }
                    }
                    #endif
                }
                /* ������Ҫ���׽��֣���������pxPeerSocket���Ա������ */
                pxSocket->u.xTCP.pxPeerSocket = NULL;
                pxSocket->u.xTCP.bits.bPassQueued = pdFALSE_UNSIGNED;
                /* ��Ϊ�棬�׽��ֿ��ܱ����ء��������� */
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
        else  /* ���ӱ��ر� */
        {
            /* ͨ���ź��� ֪ͨ/�����׽��ֵ�ӵ���� */
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
                /* ���ӵ�״̬�Ѿ������ģ������û�������� */
                xConnected = pxSocket;
            }
        }
        #endif /* ipconfigUSE_CALLBACKS */

        if( prvTCPSocketIsActive( ( UBaseType_t ) pxSocket->u.xTCP.ucTCPState ) == pdFALSE )
        {
            /* ���ڣ��׽��ִ��ڷǼ���״̬���Բ�����Ҫ���IP-task�Ĺ��ģ����ó�ʱΪ0�ǵĴ��׽��ֲ��ᱻ���ڼ�� */
            pxSocket->u.xTCP.usTimeout = 0u;
        }
    }
    else
    {
        if( eTCPState == eCLOSED )
        {
            /* ���׽�����ΪRST��ת��״̬ΪeCLOSED������˭Ҳ����������ֱ��ɾ�� */
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
    /* ��д�µ�״̬ */
    pxSocket->u.xTCP.ucTCPState = ( uint8_t ) eTCPState;
    /* �����䶨ʱ������ */
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
            /* ���ӵ�״̬�Ѿ����ı��ˣ������丸��OnConnect handler */
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

    if( xBufferAllocFixedSize != pdFALSE )/* �������������С */
    {
        /* ���绺��ͨ���̶��Ĵ�С������������������MTU */
        lNeeded = ( int32_t ) ipTOTAL_ETHERNET_FRAME_SIZE;
        /* ���Ի��治��̫С��ֻ������һ���µĻ����Է�û���ṩ */
        xResize = ( pxNetworkBuffer == NULL );
        /* 
            if(pxNetworkBuffer == NULL)xResize = pdTRUE;
            else xResize = pdFALSE;
        */
    }
    else
    {
        /* ���绺��ͨ���ɱ��С���������������Ƿ���Ҫ���� */
        lNeeded = FreeRTOS_max_int32( ( int32_t ) sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket ),
            ( int32_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength ) + lDataLen );
        /* �Է����Ǳ�TCP��ʱ��ʱ����ã�������뱻���������򣬲������ṩ�Ļ���Ĵ�С */
        xResize = ( pxNetworkBuffer == NULL ) || ( pxNetworkBuffer->xDataLength < (size_t)lNeeded );
    }

    if( xResize != pdFALSE )
    {
        /* ������û���ṩ����������ṩ�Ļ���̫С���������Ǳ��뷢�����ݣ��������������ǻᴴ������ */
        pxReturn = pxGetNetworkBufferWithDescriptor( ( uint32_t ) lNeeded, 0u );

        if( pxReturn != NULL )
        {
            /* �����ִ����ݵ��µĻ��� */
            if( pxNetworkBuffer )
            {
                /* ��֮ǰ�Ļ����и��� */
                memcpy( pxReturn->pucEthernetBuffer, pxNetworkBuffer->pucEthernetBuffer, pxNetworkBuffer->xDataLength );

                /* �ͷ�֮ǰ���Ǹ� */
                vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
            }
            else
            {
                /* ���ߴ��׽��ֵ�xTCP.xPacket���� */
                memcpy( pxReturn->pucEthernetBuffer, pxSocket->u.xTCP.xPacket.u.ucLastPacket, sizeof( pxSocket->u.xTCP.xPacket.u.ucLastPacket ) );
            }
        }
    }
    else
    {
        /* ���绺���㹻�� */
        pxReturn = pxNetworkBuffer;
        /* Thanks to Andrey Ivanov from swissEmbedded for reporting that the
        xDataLength member must get the correct length too! */
        pxNetworkBuffer->xDataLength = ( size_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength ) + ( size_t ) lDataLen;
    }

    return pxReturn;
}
/*-----------------------------------------------------------*/
/* ׼��һ���ⷢ�����ݰ����Է�������Ҫ���� */
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
        /* ���绺�����������Ѿ������� */
        pucEthernetBuffer = ( *ppxNetworkBuffer )->pucEthernetBuffer;
    }
    else
    {
        /* ���ڣ�����ָ����һ������ͷ */
        /*2016--12--11--20--42--03(ZJYC): ΪʲôҪ����һ�����л�ȡ��̫�����壿��*/ 
        pucEthernetBuffer = pxSocket->u.xTCP.xPacket.u.ucLastPacket;
    }
    pxTCPPacket = ( TCPPacket_t * ) ( pucEthernetBuffer );
    pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
    lDataLen = 0;
    lStreamPos = 0;
    pxTCPPacket->xTCPHeader.ucTCPFlags |= ipTCP_FLAG_ACK;
    if( pxSocket->u.xTCP.txStream != NULL )
    {
        /* ulTCPWindowTxGet ���᷵�ر��������ݵĴ�С���ڷ������е�λ�ã�Ϊʲô���MSS����1����ΪһЩTCPЭ��ջ�ô����������� */
        if( pxSocket->u.xTCP.usCurMSS > 1u )
        {
            lDataLen = ( int32_t ) ulTCPWindowTxGet( pxTCPWindow, pxSocket->u.xTCP.ulWindowSize, &lStreamPos );
        }
        if( lDataLen > 0 )
        {
            /* ��鵱ǰ�Ļ����Ƿ��㹻��������������趨�� */
            pxNewBuffer = prvTCPBufferResize( pxSocket, *ppxNetworkBuffer, lDataLen, uxOptionsLength );
            if( pxNewBuffer != NULL )
            {
                *ppxNetworkBuffer = pxNewBuffer;
                pucEthernetBuffer = pxNewBuffer->pucEthernetBuffer;
                pxTCPPacket = ( TCPPacket_t * ) ( pucEthernetBuffer );
                pucSendData = pucEthernetBuffer + ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength;
                /* Translate the position in txStream to an offset from the tail marker. */
                uxOffset = uxStreamBufferDistance( pxSocket->u.xTCP.txStream, pxSocket->u.xTCP.txStream->uxTail, ( size_t ) lStreamPos );
                /* Here data is copied from the txStream in 'peek' mode.  Only when the packets are acked, the tail marker will be updated. */
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
                /* ����û���Ҫ�رգ����FIN��־ */
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
                        /* ��Ȼ�׽��ַ�����һ��FIN����������һֱͣ����ESTABLISHED״ֱ̬�����ݱ����ͻᱻ���� */
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
        /* �����û��Ƿ�Ҫ�رո����� */
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
                /* ���û������Ҫ���ͣ�����û�д��ڸ�����Ϣ�����ǿ����뷢�ͱ�����Ϣ */
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
    /* �κ����ݵķ��ͣ����ڴ�С�Ĺ㲥�������Ƿ���һ�������źţ� */
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
/* ������׽����ٴμ����Ҫ�೤ʱ�� */
static TickType_t prvTCPNextTimeout ( FreeRTOS_Socket_t *pxSocket )
{
TickType_t ulDelayMs = ( TickType_t ) 20000;
    if( pxSocket->u.xTCP.ucTCPState == eCONNECT_SYN )
    {
        /* �׽����������ӵ��Է� */
        if( pxSocket->u.xTCP.bits.bConnPrepared )
        {
            /* ��̫����ַ�Ѿ������֣��Դ����Ӽ������ӳ�ʱ */
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
            /* ��Ȼ��ARP�׶Σ�ÿ������ */
            ulDelayMs = 500UL;
        }
        FreeRTOS_debug_printf( ( "Connect[%lxip:%u]: next timeout %u: %lu ms\n",
            pxSocket->u.xTCP.ulRemoteIP, pxSocket->u.xTCP.usRemotePort,
            pxSocket->u.xTCP.ucRepCount, ulDelayMs ) );
        pxSocket->u.xTCP.usTimeout = ( uint16_t )pdMS_TO_MIN_TICKS( ulDelayMs );
    }
    else if( pxSocket->u.xTCP.usTimeout == 0u )
    {
        /* �û������ڻ��ƾ������ٳ�ʱ�Ǻ��ʵ� */
        BaseType_t xResult = xTCPWindowTxHasData( &pxSocket->u.xTCP.xTCPWindow, pxSocket->u.xTCP.ulWindowSize, &ulDelayMs );
        if( ulDelayMs == 0u )
        {
            ulDelayMs = xResult ? 1UL : 20000UL;
        }
        else
        {
            /* ulDelayMs�������ش������ʱ�� */
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

    /* �������Ѿ��������������������Ƿ����µ����� 
    uxStreamBufferMidSpace()����rxHead��rxMid�ľ��룬�������µ�û�б����ݸ��������ڵ����ݡ��ϵ�û��ȷ�ϵ�������rxTail
    */
    lLength = ( int32_t ) uxStreamBufferMidSpace( pxSocket->u.xTCP.txStream );

    if( lLength > 0 )
    {
        /* 
        ����txMid��rxHead֮������ݻᱻ���͵��������ڣ�Ȼ����Կ�ʼ���ݡ�
        �����µ����ݵ��������ڵľ����������ֳ�1460�ĶΣ�ȡ����ipconfigTCP_MSS��
        */
        lCount = lTCPWindowTxAdd(   &pxSocket->u.xTCP.xTCPWindow,
                                ( uint32_t ) lLength,
                                ( int32_t ) pxSocket->u.xTCP.txStream->uxMid,
                                ( int32_t ) pxSocket->u.xTCP.txStream->LENGTH );
        /* �ƶ�rxMid��ǰ����rxHead */
        if( lCount > 0 )
        {
            vStreamBufferMoveMid( pxSocket->u.xTCP.txStream, ( size_t ) lCount );
        }
    }
}
/* prvTCPHandleFin()�����ƹ��׽��ֵĹرգ��رտ�ʼ��FIN�Ľ��ջ�����FIN�ķ��ͣ��ڱ�����֮ǰ�����պͷ��͵ļ���Ѿ���� */
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
        /* ���ǻ�û�лظ�FIN�����ھ��� */
        pxTCPWindow->tx.ulFINSequenceNumber = pxTCPWindow->tx.ulCurrentSequenceNumber;
        pxSocket->u.xTCP.bits.bFinSent = pdTRUE_UNSIGNED;
    }
    else
    {
        /* ����ȷʵ�Ƿ�����FIN�������Ƿ��յ�Ӧ�� */
        if( ulAckNr == pxTCPWindow->tx.ulFINSequenceNumber + 1u )
        {
            pxSocket->u.xTCP.bits.bFinAcked = pdTRUE_UNSIGNED;
        }
    }

    if( pxSocket->u.xTCP.bits.bFinAcked == pdFALSE_UNSIGNED )
    {
        pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->tx.ulFINSequenceNumber;
        pxTCPHeader->ucTCPFlags = ipTCP_FLAG_ACK | ipTCP_FLAG_FIN;
        /* �ȴ�����Ӧ�� */
        vTCPStateChange( pxSocket, eLAST_ACK );
    }
    else
    {
        /* Our FIN has been ACK'd, the outgoing sequence number is now fixed. */
        /* ���ǵ�FIN�Ѿ���Ӧ���ˣ� */
        pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->tx.ulFINSequenceNumber + 1u;
        if( pxSocket->u.xTCP.bits.bFinRecv == pdFALSE_UNSIGNED )
        {
            /* �����Ѿ�������FIN�����ǶԷ���û�лظ�һ��FIN������ʲôҲ���� */
            pxTCPHeader->ucTCPFlags = 0u;
        }
        else
        {
            if( pxSocket->u.xTCP.bits.bFinLast == pdFALSE_UNSIGNED )
            {
                /* �����������ֵĵ�����������Ӧ�� */
                pxTCPHeader->ucTCPFlags = ipTCP_FLAG_ACK;
            }
            else
            {
                /* �Է���ʼ�رգ���������ֻ�ǵȴ�����ACK */
                pxTCPHeader->ucTCPFlags = 0u;
            }
            /* �ȴ��û��رձ��׽��� */
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
/* ����ʱ��� */
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
/* prvCheckRxData()��prvTCPHandleState()�б����ã���һ��Ҫ���������ҵ�TCP�������ݲ�������ݳ��� */
/*
****************************************************
*  ������         : prvCheckRxData
*  ��������       : 
*  ����           : 
                    pxNetworkBuffer�����绺��
                    ppucRecvData��Ҫ�洢�������׵�ַ
*  ����ֵ         : 
                    ���յ������ݵĳ���
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static BaseType_t prvCheckRxData( NetworkBufferDescriptor_t *pxNetworkBuffer, uint8_t **ppucRecvData )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &( pxTCPPacket->xTCPHeader );
int32_t lLength, lTCPHeaderLength, lReceiveLength, lUrgentLength;
    /* ���������͵��˽ڵ��ϵ����ݵĳ��Ⱥ�ƫ�ƣ�TCP����ͷ����Ҫ����4�ģ� */
    lTCPHeaderLength = ( BaseType_t ) ( ( pxTCPHeader->ucTCPOffset & VALID_BITS_IN_TCP_OFFSET_BYTE ) >> 2 );
    /* ʹ��pucRecvDataָ����յ��ĵ�һ���ֽ� */
    *ppucRecvData = pxNetworkBuffer->pucEthernetBuffer + ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + lTCPHeaderLength;
    /* ������յ������ݳ���-��ͬ�ڰ����ȼ�ȥ ( LinkLayer length (14) + IP header length (20) + size of TCP header(20 +) )*/
    lReceiveLength = ( ( int32_t ) pxNetworkBuffer->xDataLength ) - ( int32_t ) ipSIZE_OF_ETH_HEADER;
    lLength =  ( int32_t )FreeRTOS_htons( pxTCPPacket->xIPHeader.usLength );
    if( lReceiveLength > lLength )
    {
        /* ���ݳ���̫��һ������Ϊ����ֽ� */
        lReceiveLength = lLength;
    }
    /* ��ȥTCP��IP��ͷ�ĳ��Ⱦͻ�õ���ʵ�����ݳ��� */
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
    /* ����ָ�룺
        
    */
    if( ( pxTCPHeader->ucTCPFlags & ipTCP_FLAG_URG ) != 0u )
    {
        /* ��Ȼ���Ǻ��Խ������ݣ����ǲ��ò������� */
        lUrgentLength = ( int32_t ) FreeRTOS_htons( pxTCPHeader->usUrgent );
        *ppucRecvData += lUrgentLength;
        lReceiveLength -= FreeRTOS_min_int32( lReceiveLength, lUrgentLength );
    }
    return ( BaseType_t ) lReceiveLength;
}
/*2016--11--20--19--53--58(ZJYC): prvStoreRxData()������prvTCPHandleState()���ã��ڶ���Ҫ����������Ǽ�����ݸ���
�Ƿ�ɽ��ܣ�����ǵĻ������ǽ�����ӵ���������   */ 
/* prvStoreRxData()��prvTCPHandleState()���ã��ڶ���Ҫ����������Ǽ�鸺���Ƿ񱻽��գ�����ǵĻ������ǽ������뵽���ܶ��� */
/*
****************************************************
*  ������         : prvStoreRxData
*  ��������       : 
*  ����           : 
                    pxSocket:�׽���
                    pucRecvData:���յ������ݵ��׵�ַ
                    pxNetworkBuffer:���绺��
                    ulReceiveLength:�������ݳ���
*  ����ֵ         : 
                    0���洢�ɹ�
                    -1���洢ʧ��
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
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
        /*2016--11--20--19--57--26(ZJYC):���������Ƿ�������ݲ��������͵��׽���ӵ����    */ 
        /*2016--11--20--19--59--54(ZJYC): ������ɱ����ܣ�����Ҫ���洢�����Ϳ�ѡ���ACK��SACK
        ��ȷ�ϣ�����������£�xTCPWindowRxStore() �ᱻ�������洢��˳������ݰ�
        */ 
        /* �������Ƿ��յ��������ݣ����������ݸ��׽��ֵ�ӵ���� */
        /* ��������ܱ����գ��������Ѿ����洢������һ����ѡ��ack (SACK)ѡ��ͷӦ��֮��
            ����������£�xTCPWindowRxStore()���ڻᱻ�������洢��Щ��˳�������
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
            /*2016--11--20--20--01--53(ZJYC):�������Ѿ����ﲢ�ҿ��Ա��û�ʹ�á������Ƿ�ͷ����־
            
            */ 
            /* New data has arrived and may be made available to the user.  See
            if the head marker in rxStream may be advanced, only if lOffset == 0.
            In case the low-water mark is reached, bLowWater will be set
            "low-water" here stands for "little space". */
            /* �������Ѿ�������Ա��û�ʹ�ã������Ƿ� */
            lStored = lTCPAddRxdata( pxSocket, ( uint32_t ) lOffset, pucRecvData, ulReceiveLength );

            if( lStored != ( int32_t ) ulReceiveLength )
            {
                FreeRTOS_debug_printf( ( "lTCPAddRxdata: stored %ld / %lu bytes??\n", lStored, ulReceiveLength ) );
                /*2016--11--20--20--04--39(ZJYC):���յ������ݲ��ܱ��洢���׽��ֵ�bMallocError��־����λ
                �׽�������eCLOSE_WAIT��״̬Ϊ���ҽ�����RST��
                */ 
                /* ���յ������ݲ��ܱ��洢���׽��ֵı�־λbMallocError����λ���׽������ڵ�״̬ΪeCLOSE_WAIT���Ҵ���RST�����ݰ����ᱻ���� */
                prvTCPSendReset( pxNetworkBuffer );
                xResult = -1;
            }
        }
        /*2016--11--20--20--06--04(ZJYC):�յ�һ����ʧ�İ�֮�󣬸��ߵ����ݰ��ᱻ���ݸ��û�    */ 
            /*2016--11--20--20--07--12(ZJYC):����lTCPAddRxdata()������ǰ�ƶ�rxHeadָ�룬
            ���Զ��û����ԣ����ݺܿ��ÿ�����������λbLowWater�Է�ֹ�����λ�ߣ�*/ 
        /* �����յ���ʧ�����ݰ�֮�󣬽ϸߵ����ݰ����ܴ��ݸ��û� */
        #if( ipconfigUSE_TCP_WIN == 1 )
        {
            /* Now lTCPAddRxdata() will move the rxHead pointer forward
            so data becomes available to the user immediately
            In case the low-water mark is reached, bLowWater will be set. */
            /* ����lTCPAddRxdata()��������ǰ�ƶ�rxHeadָ�룬��������������ö��û����ã�Ϊ��ֹ�����ˮλ��־��bLowWater�ᱻ��λ */
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
/*2016--11--20--20--09--51(ZJYC): Ϊ�������������ݰ�����ѡ�����еĻ���   */ 
static UBaseType_t prvSetOptions( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
UBaseType_t uxOptionsLength = pxTCPWindow->ucOptionLength;

    #if(    ipconfigUSE_TCP_WIN == 1 )
        if( uxOptionsLength != 0u )
        {
            /*2016--11--20--20--10--46(ZJYC):TCPѡ����뱻���ͣ���Ϊ���ܵ��˷�˳�����ݰ�    */ 
            if( xTCPWindowLoggingLevel >= 0 )
                FreeRTOS_debug_printf( ( "SACK[%d,%d]: optlen %lu sending %lu - %lu\n",
                    pxSocket->usLocalPort,
                    pxSocket->u.xTCP.usRemotePort,
                    uxOptionsLength,
                    FreeRTOS_ntohl( pxTCPWindow->ulOptionsData[ 1 ] ) - pxSocket->u.xTCP.xTCPWindow.rx.ulFirstSequenceNumber,
                    FreeRTOS_ntohl( pxTCPWindow->ulOptionsData[ 2 ] ) - pxSocket->u.xTCP.xTCPWindow.rx.ulFirstSequenceNumber ) );
            memcpy( pxTCPHeader->ucOptdata, pxTCPWindow->ulOptionsData, ( size_t ) uxOptionsLength );
            /*2016--11--20--20--11--42(ZJYC): ����4�����ڸ�λ����ͬ������2   */ 
            pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
        }
        else
    #endif  /* ipconfigUSE_TCP_WIN */
    if( ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) && ( pxSocket->u.xTCP.bits.bMssChange != pdFALSE_UNSIGNED ) )
    {
        /*2016--11--20--20--12--48(ZJYC):TCPѡ����뱻���ͣ���ΪMSS�Ѹı�    */ 
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
/*2016--11--20--20--13--24(ZJYC): prvHandleSynReceived()������ prvTCPHandleState()���ã���
eSYN_RECEIVED and eCONNECT_SYN״̬�µ��ã�����յ��ı�־����ȷ�ģ��׽��ֻ��ΪeESTABLISHED  */ 
static BaseType_t prvHandleSynReceived( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer,
    uint32_t ulReceiveLength, UBaseType_t uxOptionsLength )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( (*ppxNetworkBuffer)->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &pxTCPPacket->xTCPHeader;
TCPWindow_t *pxTCPWindow = &pxSocket->u.xTCP.xTCPWindow;
uint8_t ucTCPFlags = pxTCPHeader->ucTCPFlags;
uint32_t ulSequenceNumber = FreeRTOS_ntohl( pxTCPHeader->ulSequenceNumber );
BaseType_t xSendLength = 0;

    /*2016--11--20--20--40--34(ZJYC): ����ACK������SYN+ACK*/ 
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
/*2016--11--20--20--42--03(ZJYC):prvHandleEstablished()��prvTCPHandleState()���ã����״̬Ϊ��������ô˺���
���ݽ�����Щʱ���Ѿ����ƹܣ�����ĶԷ���������ACK�ᱻ��飬����յ�FIN����������Ƿ��յ���������������е�����
����ȫ����    */ 
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

    /*2016--11--20--20--49--36(ZJYC):��ס�Է������Ĵ��ڴ�С    */ 
    pxSocket->u.xTCP.ulWindowSize = FreeRTOS_ntohs( pxTCPHeader->usWindow );
    pxSocket->u.xTCP.ulWindowSize =
        ( pxSocket->u.xTCP.ulWindowSize << pxSocket->u.xTCP.ucPeerWinScaleFactor );

    if( ( ucTCPFlags & ( uint8_t ) ipTCP_FLAG_ACK ) != 0u )
    {
        ulCount = ulTCPWindowTxAck( pxTCPWindow, FreeRTOS_ntohl( pxTCPPacket->xTCPHeader.ulAckNr ) );
        /*2016--11--20--20--50--38(ZJYC):ulTCPWindowTxAck�����Ѿ�����Ӧ����ֽ�������tx.ulCurrentSequenceNumber��ʼ    */ 
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
/*2016--12--05--14--38--25(ZJYC): ������Ҫ���ͣ����ipconfigUSE_TCP_WIN������ ����ֻ��һ��ACK������
������ӳ�һ��ʱ���ٷ��ͣ����ӳٵĹ����������ݵĻ��͸����߷���ȥ���������Ӹ�Ч��   */ 
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
    /*2017--01--01--15--27--59(ZJYC): ���Ի�ȡ���ǵĴ��ڵĴ�С   */ 
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
/*2016--12--05--14--37--32(ZJYC): ״̬������   */ 
static BaseType_t prvTCPHandleState( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t **ppxNetworkBuffer )
{
TCPPacket_t *pxTCPPacket = ( TCPPacket_t * ) ( (*ppxNetworkBuffer)->pucEthernetBuffer );
TCPHeader_t *pxTCPHeader = &( pxTCPPacket->xTCPHeader );
BaseType_t xSendLength = 0;
uint32_t ulReceiveLength;   /*2016--12--04--21--26--45(ZJYC): �������ݵĳ���   */ 
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
    /*2016--12--04--21--22--15(ZJYC): ��һ����ȡ���յ������ݵĳ��Ⱥ�λ��
    pucRecvData����ָ��TCP���ݵĵ�һ���ֽ�*/ 
    ulReceiveLength = ( uint32_t ) prvCheckRxData( *ppxNetworkBuffer, &pucRecvData );
    /*2016--12--04--21--30--11(ZJYC): �����ж����ǲ���һ�������ź�   */ 
    if( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED )
    {
        /*2016--12--04--21--23--08(ZJYC): Ŀǰ�Ѿ��������ӽ�����״̬   */ 
        if ( pxTCPWindow->rx.ulCurrentSequenceNumber == ulSequenceNumber + 1u )
        {
            /*2016--12--04--21--25--45(ZJYC): �ѵ���Ӧ����ACK number����
            �ҷ��������ݽṹ�и����Ͳ�����ACK Num��һ���£������ǣ�����RX
            �е�SEQ����ACK NUM
            */ 
            /*2016--12--04--21--23--33(ZJYC): �ж���ȷ�Ϻ�Ϊ��ǰseq+1���жϴ�Ϊ�����ź�
            ������λbWinChange������ı䴰�ڴ�С������ʹ����������һ��ACK*/ 
            pxSocket->u.xTCP.bits.bWinChange = pdTRUE_UNSIGNED;
        }
    }

    /* Keep track of the highest sequence number that might be expected within
    this connection. */
    /*2016--12--04--21--30--57(ZJYC): ��������������кţ�������к��ں��ڴ����ô���������
    �ظ�ʱ��Ҫ�ظ�������кţ�SACK���⣩   */ 
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
        /*2016--12--04--21--44--22(ZJYC): ��������ж���ʲô��˼������   */ 
        if( ( pxSocket->u.xTCP.ucTCPState == eSYN_RECEIVED ) && ( ( ucTCPFlags & ipTCP_FLAG_CTRL ) == ipTCP_FLAG_SYN ) )
        {
            FreeRTOS_debug_printf( ( "eSYN_RECEIVED: ACK expected, not SYN: peer missed our SYN+ACK\n" ) );
            /*2016--12--04--21--40--02(ZJYC): eSYN_RECEIVED�������������յ�ACK�����ǲ�û��   */ 
            vTCPStateChange( pxSocket, eSYN_FIRST );
        }
        /*2016--12--04--21--45--35(ZJYC): �Է�Ҫֹͣ && ��û���յ���FIN   */ 
        if( ( ( ucTCPFlags & ipTCP_FLAG_FIN ) != 0u ) && ( pxSocket->u.xTCP.bits.bFinRecv == pdFALSE_UNSIGNED ) )
        {
            /*2016--12--04--21--46--21(ZJYC): �յ��˵�һ��FIN����ס�������к�   */ 
            pxTCPWindow->rx.ulFINSequenceNumber = ulSequenceNumber + ulReceiveLength;
            pxSocket->u.xTCP.bits.bFinRecv = pdTRUE_UNSIGNED;
            /*2016--12--04--21--47--03(ZJYC): �ж��Ƿ��ǶԷ��ȷ��͵�FIN������ǣ����Ǿ͵÷���
            LAST-ACK������Ͳ��÷���   */ 
            if( pxSocket->u.xTCP.bits.bFinSent == pdFALSE_UNSIGNED )
            {
                pxSocket->u.xTCP.bits.bFinLast = pdTRUE_UNSIGNED;
            }
        }

        switch (pxSocket->u.xTCP.ucTCPState)
        {
        case eCLOSED:/*2016--12--04--21--48--16(ZJYC): ��CS���������κ����ӣ�����ʲôҲ������
        �ȴ��û�����*/ 
            break;

        case eTCP_LISTEN:/*2016--12--04--21--48--59(ZJYC): ��S���ȴ��κ�Զ�����ӣ�����״̬��
        xProcessReceivedTCPPacket()���ƣ����ﲻ������*/ 
            break;

        case eSYN_FIRST:    /*2016--12--04--21--04--41(ZJYC): �������ո��յ�һSYN����   */ 
            {
                /*2016--12--04--21--03--38(ZJYC): һ���µ��׽����Ѿ����������ظ�SYN+ACK
                ȷ�Ϻ�Ϊseq+1*/ 
                uxOptionsLength = prvSetSynAckOptions( pxSocket, pxTCPPacket );
                pxTCPHeader->ucTCPFlags = ipTCP_FLAG_SYN | ipTCP_FLAG_ACK;
                xSendLength = ( BaseType_t ) ( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_TCP_HEADER + uxOptionsLength );
                /*2016--12--04--21--05--12(ZJYC): ����TCPƫ���ֶΣ�ipSIZE_OF_TCP_HEADER����20
                 xOptionsLength��4�ı�������ȫ�ı��ʽΪucTCPOffset = ( ( ipSIZE_OF_TCP_HEADER + xOptionsLength ) / 4 ) << 4*/ 
                pxTCPHeader->ucTCPOffset = ( uint8_t )( ( ipSIZE_OF_TCP_HEADER + uxOptionsLength ) << 2 );
                vTCPStateChange( pxSocket, eSYN_RECEIVED );
                pxTCPWindow->rx.ulCurrentSequenceNumber = pxTCPWindow->rx.ulHighestSequenceNumber = ulSequenceNumber + 1u;
                pxTCPWindow->tx.ulCurrentSequenceNumber = pxTCPWindow->ulNextTxSequenceNumber = pxTCPWindow->tx.ulFirstSequenceNumber + 1u; /* because we send a TCP_SYN. */
            }
            break;

        case eCONNECT_SYN: /*2016--12--04--21--07--49(ZJYC): �ͻ�����SYN�����������յ�SYN+ACK��   */ 
            /* Fall through */
        case eSYN_RECEIVED: /*2016--12--04--21--09--06(ZJYC): �յ�SYN���ظ���SYN+ACK�������յ�ACK   */ 
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
/*2016--12--05--14--36--51(ZJYC): ���͸�λ��־   */ 
/*
****************************************************
*  ������         : prvTCPSendReset
*  ��������       : 
*  ����           : pxNetworkBuffer�����绺��
*  ����ֵ         : ����pdFAIL
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
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
/*2016--12--05--14--34--01(ZJYC): ͨ�����жϲ������׽��ֵ�MSSֵ��   */ 
static void prvSocketSetMSS( FreeRTOS_Socket_t *pxSocket )
{
uint32_t ulMSS = ipconfigTCP_MSS;

    if( ( ( FreeRTOS_ntohl( pxSocket->u.xTCP.ulRemoteIP ) ^ *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) != 0ul )
    {
        /*2016--12--05--14--34--32(ZJYC): �ж϶��ó� ����Է��������п��ܾ���·����������������  ����Ӧ��MSS������1400�����   */ 
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
/*2016--12--05--14--32--55(ZJYC): �ųƵڶ���TCP_IP�����������ҳ���Ҫ   */ 
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
    /*2016--12--04--21--51--13(ZJYC): Ѱ��Ŀ���׽��֣����û�У�����һ������
    Ŀ��˿ڵ��׽��֣�������Ϊʲô����һ���������׽��֣���������   */ 
    pxSocket = ( FreeRTOS_Socket_t * ) pxTCPSocketLookup( ulLocalIP, xLocalPort, ulRemoteIP, xRemotePort );
    if( ( pxSocket == NULL ) || ( prvTCPSocketIsActive( ( UBaseType_t ) pxSocket->u.xTCP.ucTCPState ) == pdFALSE ) )
    {
        /*2016--12--04--21--52--44(ZJYC): �յ���TCP��Ϣ�����ǻ���û���׽��ֶ�Ӧ
        �����׽��ִ���eCLOSED, eCLOSE_WAIT, eFIN_WAIT_2, eCLOSING, or eTIME_WAIT*/ 
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
            /*2016--12--04--21--56--20(ZJYC): ƥ����׽�����SYN��־�������Է��ǲ�����SYN   */ 
            if( ( ucTCPFlags & ipTCP_FLAG_CTRL ) != ipTCP_FLAG_SYN )
            {
                /*2016--12--04--21--57--05(ZJYC): ������ͬ��״̬�����ǶԷ�û����SYN��������FST   */ 
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
                /*2016--12--04--21--59--09(ZJYC): ɶ��˼��if bReuseSocket is false��������   */ 
                /*2016--12--04--21--57--57(ZJYC): prvHandleListen()���᷵��һ���µ��׽���
                ��if bReuseSocket is false����Ҫ��Ȼ�����ص�ǰ�׽��֣����ڻᱻ����   */ 
                pxSocket = prvHandleListen( pxSocket, pxNetworkBuffer );
                if( pxSocket == NULL )
                {
                    xResult = pdFAIL;
                }
            }
        }   /* if( pxSocket->u.xTCP.ucTCPState == eTCP_LISTEN ). */
        else
        {
            /*2016--12--04--22--00--18(ZJYC): ���׽��ֲ������ڼ���ģʽ�����RST   */ 
            if( ( ucTCPFlags & ipTCP_FLAG_RST ) != 0u )
            {
                /*2016--12--04--22--01--26(ZJYC): ���׽��ֲ��ڼ���ģʽ�������յ���RST
                ˵�����׽�����ر�*/ 
                FreeRTOS_debug_printf( ( "TCP: RST received from %lxip:%u for %u\n", ulRemoteIP, xRemotePort, xLocalPort ) );
                vTCPStateChange( pxSocket, eCLOSED );
                /* The packet cannot be handled. */
                xResult = pdFAIL;
            }
            else if( ( ( ucTCPFlags & ipTCP_FLAG_CTRL ) == ipTCP_FLAG_SYN ) && ( pxSocket->u.xTCP.ucTCPState >= eESTABLISHED ) )
            {
                /*2016--12--04--22--02--47(ZJYC): �Է�����SYN && ������ͽ���������==ì����   */ 
                FreeRTOS_debug_printf( ( "TCP: SYN unexpected from %lxip:%u\n", ulRemoteIP, xRemotePort ) );
                /* The packet cannot be handled. */
                xResult = pdFAIL;
            }
            else
            {
                /* Update the copy of the TCP header only (skipping eth and IP
                headers).  It might be used later on, whenever data must be sent
                to the peer. */
                /*2016--12--04--22--04--47(ZJYC): ���汨��ͷ��������������   */ 
                /*2016--12--04--22--05--58(ZJYC): ����������������̣�����   */ 
                const BaseType_t lOffset = ( BaseType_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER );
                memcpy( pxSocket->u.xTCP.xPacket.u.ucLastPacket + lOffset, pxNetworkBuffer->pucEthernetBuffer + lOffset, ipSIZE_OF_TCP_HEADER );
            }
        }
    }
    if( xResult != pdFAIL )
    {
        /*2016--12--04--22--06--30(ZJYC): ���¼�ʱ   */ 
        prvTCPTouchSocket( pxSocket );
        /*2016--12--04--22--07--07(ZJYC): ����TCPѡ�������Ǵ���SYN�׶Σ����ǶԷ�û�з���MSS
        ����Ĭ��Ϊ536����Ϊ�˺����ļ�����*/ 
        /*2016--12--04--22--08--13(ZJYC): ���������TCPѡ�offsetΪ5��ʾ20�ֽڣ�   */ 
        if( ( pxTCPPacket->xTCPHeader.ucTCPOffset & TCP_OFFSET_LENGTH_BITS ) > TCP_OFFSET_STANDARD_LENGTH )
        {
            /*2016--12--04--22--09--00(ZJYC): ������Ҫ���ѡ��   */ 
            prvCheckOptions( pxSocket, pxNetworkBuffer );
        }
        #if( ipconfigUSE_TCP_WIN == 1 )
        {
            /*2016--12--04--22--09--54(ZJYC): �˴����ô��ڴ�С=����*�Ŵ�����   */ 
            pxSocket->u.xTCP.ulWindowSize = FreeRTOS_ntohs( pxTCPPacket->xTCPHeader.usWindow );
            pxSocket->u.xTCP.ulWindowSize =
                ( pxSocket->u.xTCP.ulWindowSize << pxSocket->u.xTCP.ucPeerWinScaleFactor );
        }
        #endif
        /*2016--12--05--14--18--12(ZJYC): ����״̬����������Щ����   */ 
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
            /*2016--12--04--22--14--48(ZJYC): �ѻ����ͷŰɣ�û����   */ 
            vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
            pxNetworkBuffer = NULL;
        }
        /*2016--12--04--22--13--48(ZJYC): �������´α����ѵ�ʱ��   */ 
        prvTCPNextTimeout ( pxSocket );
        /*2016--12--04--22--14--11(ZJYC): ���ߵ����ߣ������ѱ�����   */ 
        xResult = pdPASS;
    }
    /* pdPASS being returned means the buffer has been consumed. */
    return xResult;
}
/*-----------------------------------------------------------*/
/*2016--12--05--14--27--22(ZJYC): �ڼ���״̬�������յ�����������������������취���һ
�׽��֣��������׽���   */ 
static FreeRTOS_Socket_t *prvHandleListen( FreeRTOS_Socket_t *pxSocket, NetworkBufferDescriptor_t *pxNetworkBuffer )
{
TCPPacket_t * pxTCPPacket = ( TCPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
FreeRTOS_Socket_t *pxReturn;
    /*2016--12--04--22--17--56(ZJYC): �յ�һ��������SYN������һ���׽������Ը���   */ 
    if( pxSocket->u.xTCP.bits.bReuseSocket != pdFALSE_UNSIGNED )
    {
        /*2016--12--04--22--18--29(ZJYC): ����׽���ȷʵʵ�ڵȴ��˶˿ڣ�����ֱ�������
        �׽��ֶ������ڽ�����*/ 
        pxReturn = pxSocket;
        pxSocket->u.xTCP.bits.bPassQueued = pdTRUE_UNSIGNED;
        pxSocket->u.xTCP.pxPeerSocket = pxSocket;
    }
    else
    {
        /*2016--12--04--22--19--39(ZJYC): ֱ�Ӵ������µ��׽���   */ 
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
                /*2016--12--04--22--22--47(ZJYC): �׽��ֺ������Ͼͻ����ӣ�Ҳû��ʱ���ȥ���ã�
                ����ֱ��ʹ�ñ��׽��ֵ����þͿ�����*/ 
                pxReturn = pxNewSocket;
            }
        }
    }

    if( pxReturn != NULL )
    {
        /*2016--12--05--14--30--35(ZJYC): �׽����Ѿ����������������׽���   */ 
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
/*2016--12--05--14--21--22(ZJYC): ����״̬���׽����յ�����֮��Ḵ�Ʊ��˵��׽������� ��Ϊ 
����״̬�µ��׽���û��ʱ�������׽���  */ 
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
/*2016--12--05--14--23--25(ZJYC): ��ȡTCP״̬�����ƣ������ڵ��Դ�ӡ   */ 
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
/*2016--12--05--14--24--28(ZJYC): API accept()���û������Ƿ����һ���µĿͻ������ӣ�
����API����ֱ�ӱ���xBoundTCPSocketsList  IP�������������   */ 
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

