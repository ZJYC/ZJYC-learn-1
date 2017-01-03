
/* Standard includes. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_TCP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_DNS.h"

/*2016--11--25--10--25--05(ZJYC): ����ȷ���ṹ������������Ч����volatile���ڷ�ֹ������������ڳ����볣���ĶԱ�   */ 
#define ipEXPECTED_EthernetHeader_t_SIZE    ( ( size_t ) 14 )
#define ipEXPECTED_ARPHeader_t_SIZE         ( ( size_t ) 28 )
#define ipEXPECTED_IPHeader_t_SIZE          ( ( size_t ) 20 )
#define ipEXPECTED_IGMPHeader__SIZE         ( ( size_t ) 8 )
#define ipEXPECTED_ICMPHeader_t_SIZE        ( ( size_t ) 8 )
#define ipEXPECTED_UDPHeader_t_SIZE         ( ( size_t ) 8 )
#define ipEXPECTED_TCPHeader_t_SIZE         ( ( size_t ) 20 )


/*2016--11--25--10--26--48(ZJYC): ICMPЭ�鶨��   */ 
#define ipICMP_ECHO_REQUEST             ( ( uint8_t ) 8 )
#define ipICMP_ECHO_REPLY               ( ( uint8_t ) 0 )

/*2016--11--25--10--27--02(ZJYC):���Գ�ʼ���ײ�Ӳ��֮���ʱ����ʱ    */ 
#define ipINITIALISATION_RETRY_DELAY    ( pdMS_TO_TICKS( 3000 ) )
/*2016--11--25--10--28--21(ZJYC):����ARP��ʱ��ִ�е�Ƶ�Σ���ʱ����windows������Ҫ��һЩ����Ϊwindows����������ʱ��    */ 
#ifndef ipARP_TIMER_PERIOD_MS
    #ifdef _WINDOWS_
        #define ipARP_TIMER_PERIOD_MS   ( 500 ) /* For windows simulator builds. */
    #else
        #define ipARP_TIMER_PERIOD_MS   ( 10000 )
    #endif
#endif

#ifndef iptraceIP_TASK_STARTING
    #define iptraceIP_TASK_STARTING()   do {} while( 0 )
#endif

#if( ( ipconfigUSE_TCP == 1 ) && !defined( ipTCP_TIMER_PERIOD_MS ) )
    /*2016--11--25--13--29--48(ZJYC):��ʼ����ʱ�������Ǹ���һ����ʼ��1S    */ 
    #define ipTCP_TIMER_PERIOD_MS   ( 1000 )
#endif
/*2016--11--25--13--30--43(ZJYC):���ipconfigETHERNET_DRIVER_FILTERS_FRAME_TYPESΪ1��
��̫���������˵��������ݰ���ֻͨ����ЩЭ��ջ��Ϊ��Ҫ����İ�������������£�
ipCONSIDER_FRAME_FOR_PROCESSING()���Ա����⴦�á��������ipconfigETHERNET_DRIVER_FILTERS_FRAME_TYPES
Ϊ0������̫��������ͨ�����е����ݰ���Э��ջ��Ҫ�Լ����й��ˣ���ʱ��ipCONSIDER_FRAME_FOR_PROCESSING
��Ҫ����eConsiderFrameForProcessing    */
#if ipconfigETHERNET_DRIVER_FILTERS_FRAME_TYPES == 0
    #define ipCONSIDER_FRAME_FOR_PROCESSING( pucEthernetBuffer ) eConsiderFrameForProcessing( ( pucEthernetBuffer ) )
#else
    #define ipCONSIDER_FRAME_FOR_PROCESSING( pucEthernetBuffer ) eProcessBuffer
#endif
/*2016--11--25--13--35--21(ZJYC):�������ICMP������ַ������Ҳ�ǻ�Ӧ���ĵ������ַ�    */ 
#define ipECHO_DATA_FILL_BYTE                       'x'

#if( ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN )
    /*2016--11--25--13--36--26(ZJYC):������������   */ 
    /* The bits in the two byte IP header field that make up the fragment offset value. */
    #define ipFRAGMENT_OFFSET_BIT_MASK              ( ( uint16_t ) 0xff0f )
#else
    /*2016--11--25--13--37--07(ZJYC):������������    */ 
    /* The bits in the two byte IP header field that make up the fragment offset value. */
    #define ipFRAGMENT_OFFSET_BIT_MASK              ( ( uint16_t ) 0x0fff )
#endif /* ipconfigBYTE_ORDER */

/*2016--11--25--13--46--28(ZJYC):IPЭ��ջ��������״̬�������ʱ��    */ 
#ifndef ipconfigMAX_IP_TASK_SLEEP_TIME
    #define ipconfigMAX_IP_TASK_SLEEP_TIME ( pdMS_TO_TICKS( 10000UL ) )
#endif
/*2016--11--25--13--47--39(ZJYC):������һ���µ�TCP���ӣ�ulNextInitialSequenceNumber���ᱻ����
��ʼ���кţ���ʼ��ʱ��ulNextInitialSequenceNumber����һ������������Ƿǳ���Ҫ�ģ���������ֵ
���뼰ʱ���ӣ�Ϊ�˱���������³����кţ�����ÿ4us����1��ÿһ��256��ʱ��    */ 
#define ipINITIAL_SEQUENCE_NUMBER_FACTOR    256UL

/*2016--11--25--13--54--05(ZJYC):��У��ʧ��ʱ���ص���ֵ������ֵӦ�������ڵ���ʱ����    */ 
#define ipUNHANDLED_PROTOCOL        0x4321u
/*2016--11--25--14--25--31(ZJYC):����˵������ʧ�ܣ�����У�鲻��Ҫ����    */ 
#define ipCORRECT_CRC               0xffffu
/*2016--11--25--14--26--44(ZJYC):��������У��ʧ�ܵ����ݵĳ��Ȳ���ʱ    */
#define ipINVALID_LENGTH            0x1234u

/*-----------------------------------------------------------*/

typedef struct xIP_TIMER
{
    uint32_t
        bActive : 1,    /* This timer is running and must be processed. */
        bExpired : 1;   /* Timer has expired and a task must be processed. */
    TimeOut_t xTimeOut;
    TickType_t ulRemainingTime;
    TickType_t ulReloadTime;
} IPTimer_t;
/*2016--11--25--14--27--50(ZJYC):У��ͼ���    */ 
typedef union _xUnion32
{
    uint32_t u32;
    uint16_t u16[ 2 ];
    uint8_t u8[ 4 ];
} xUnion32;
/*2016--11--25--14--28--08(ZJYC):����У���    */ 
typedef union _xUnionPtr
{
    uint32_t *u32ptr;
    uint16_t *u16ptr;
    uint8_t *u8ptr;
} xUnionPtr;

/*2016--11--25--14--28--25(ZJYC):TCP/IPЭ��ջ�����������������յײ�Ӳ�����׽��ֵ�����/�¼�
��ͬ���ƹ���һ�ѵĶ�ʱ����    */
static void prvIPTask( void *pvParameters );
/*2016--11--25--14--30--23(ZJYC):����������ӿڵ������ݿ���ʱ���ô˺���    */ 
static void prvProcessEthernetPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer );
/*2016--11--25--14--31--33(ZJYC):��������IP��    */ 
static eFrameProcessingResult_t prvProcessIPPacket( const IPPacket_t * const pxIPPacket, NetworkBufferDescriptor_t * const pxNetworkBuffer );

#if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )
     /*2016--11--25--14--32--26(ZJYC):��������ICMP��    */ 
    static eFrameProcessingResult_t prvProcessICMPPacket( ICMPPacket_t * const pxICMPPacket );
#endif /* ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 ) */
/*2016--11--25--14--33--03(ZJYC):ת�䵽����ping����������ת����ping�ظ�    */ 
#if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 )
    static eFrameProcessingResult_t prvProcessICMPEchoRequest( ICMPPacket_t * const pxICMPPacket );
#endif /* ipconfigREPLY_TO_INCOMING_PINGS */
/*2016--11--25--14--33--44(ZJYC):��������ping�ظ�������ᴫ�ݸ��û��ص�����vApplicationPingReplyHook()    */ 
#if ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )
    static void prvProcessICMPEchoReply( ICMPPacket_t * const pxICMPPacket );
#endif /* ipconfigSUPPORT_OUTGOING_PINGS */
/*2016--11--25--14--34--31(ZJYC):��Э��ջ����ʱ�������������Ӷ�ʧʱ��������ȥ����һ����������    */ 
static void prvProcessNetworkDownEvent( void );
/*2016--11--25--14--35--45(ZJYC):�쳵ARP��DHCP��TCP��ʱ���������Ƿ��е�����Ҫ�����    */
static void prvCheckNetworkTimers( void );
/*2016--11--25--14--36--41(ZJYC):������IP�������˯�೤ʱ�䣬��ȡ���ھ�����һ��������ִ�еĲ�����Ҫ����ʱ��    */ 
static TickType_t prvCalculateSleepTime( void );
/*2016--11--25--14--37--59(ZJYC):�����Ѿ����ܵ��˰���    */ 
/*
 * The network card driver has received a packet.  In the case that it is part
 * of a linked packet chain, walk through it to handle every message.
 */
static void prvHandleEthernetPacket( NetworkBufferDescriptor_t *pxBuffer );
/*2016--11--25--14--39--26(ZJYC):������IP��ʱ������غ���    */
static void prvIPTimerStart( IPTimer_t *pxTimer, TickType_t xTime );
static BaseType_t prvIPTimerCheck( IPTimer_t *pxTimer );
static void prvIPTimerReload( IPTimer_t *pxTimer, TickType_t xTime );

static eFrameProcessingResult_t prvAllowIPPacket( const IPPacket_t * const pxIPPacket,
    NetworkBufferDescriptor_t * const pxNetworkBuffer, UBaseType_t uxHeaderLength );

/*-----------------------------------------------------------*/
/*2016--11--25--14--40--41(ZJYC):���ڴ����¼���IP-task�Ķ���    */ 
QueueHandle_t xNetworkEventQueue = NULL;

/*_RB_ Requires comment. */
uint16_t usPacketIdentifier = 0U;
/*2016--11--25--14--41--22(ZJYC):Ϊ�˷��㣬ȫFF��MAC��ַ������Ϊ�������ڿ��ٱȽ�    */ 
const MACAddress_t xBroadcastMACAddress = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
/*2016--11--25--14--42--09(ZJYC):���ڴ洢���롢���ص�ַ��DNS��������ַ�Ľṹ��    */ 
NetworkAddressingParameters_t xNetworkAddressing = { 0, 0, 0, 0, 0 };
/*2016--11--25--14--43--19(ZJYC):���Ͻṹ��Ĭ�ϵ���ֵ���Է�ֹDHCP������û��ȷ��    */ 
NetworkAddressingParameters_t xDefaultAddressing = { 0, 0, 0, 0, 0 };
/*2016--11--25--14--44--18(ZJYC):����ȷ�����ڶ��г�������ɵĵ����¼��Ķ�ʧ   */ 
static BaseType_t xNetworkDownEventPending = pdFALSE;
/*2016--11--25--16--21--25(ZJYC):�洢�ƹ�����Э��ջ������ľ������������ڣ���ӣ�
һЩ�������жϺ��������Ǳ�����������ã������ǾͿ����������ˣ����Ǳ�Э��ջ������õ�
����Ͳ��������ˣ�    */ 
static TaskHandle_t xIPTaskHandle = NULL;

#if( ipconfigUSE_TCP != 0 )
    /*2016--11--25--16--27--05(ZJYC):���һ������TCP ��Ϣ�����һ�ֱ�ִ�У����ڷ���ֵ    */ 
    static BaseType_t xProcessedTCPMessage;
#endif
/*2016--11--25--16--28--21(ZJYC):ȡ������������ӺͶϿ����򵥵�����pdTRUE��pdFALSE    */ 
static BaseType_t xNetworkUp = pdFALSE;
/*2016--11--25--16--29--22(ZJYC):һ����ʱ���������ÿһ�����̣�ÿһ������Ҫ���¹��ɵĹ�ע
1 ARP����黺���������
2 DHCP���������󣬲�ˢ�´洢
3 TCP������Ƿ�ʱ���ش�
4 DNS����������ʱ������Ƿ�ʱ��    */ 
static IPTimer_t xARPTimer;
#if( ipconfigUSE_DHCP != 0 )
    static IPTimer_t xDHCPTimer;
#endif
#if( ipconfigUSE_TCP != 0 )
    static IPTimer_t xTCPTimer;
#endif
#if( ipconfigDNS_USE_CALLBACKS != 0 )
    static IPTimer_t xDNSTimer;
#endif
/*2016--11--25--16--32--44(ZJYC):��IP ����׼����ȥ�������ݰ�����1    */ 
static BaseType_t xIPTaskInitialised = pdFALSE;

#if( ipconfigCHECK_IP_QUEUE_SPACE != 0 )
    /*2016--11--25--16--33--56(ZJYC):���ָ���xNetworkEventQueue����Ϳռ�����    */ 
    static UBaseType_t uxQueueMinimumSpace = ipconfigEVENT_QUEUE_LENGTH;
#endif

/*-----------------------------------------------------------*/

static void prvIPTask( void *pvParameters )
{
IPStackEvent_t xReceivedEvent;
TickType_t xNextIPSleep;
FreeRTOS_Socket_t *pxSocket;
struct freertos_sockaddr xAddress;
/*2016--11--25--16--35--14(ZJYC):ֻ�Ƿ�ֹ����������    */ 
    ( void ) pvParameters;
/*2016--11--25--16--35--36(ZJYC):�п����ͳ�һЩ������Ϣ    */ 
    iptraceIP_TASK_STARTING();
/*2016--11--25--16--36--06(ZJYC):����һ������Ϣȥ˵���������Ѿ��Ͽ��ˣ�
�����������ʼ������ӿڣ�����֮����������֮ǰ�ĶϿ������Ӿ�����
��ײ�����������    */ 
    FreeRTOS_NetworkDown();

    #if( ipconfigUSE_TCP == 1 )
    {
        /*2016--11--25--16--38--49(ZJYC):��ʼ��TCP��ʱ��    */ 
        prvIPTimerReload( &xTCPTimer, pdMS_TO_TICKS( ipTCP_TIMER_PERIOD_MS ) );
    }
    #endif
/*2016--11--25--16--39--06(ZJYC):��ʼ����ɣ������¼����Ա�ִ����    */ 
    xIPTaskInitialised = pdTRUE;

    FreeRTOS_debug_printf( ( "prvIPTask started\n" ) );
/*2016--11--25--16--39--49(ZJYC):ѭ��������IP �¼�    */ 
    for( ;; )
    {
        ipconfigWATCHDOG_TIMER();
        /*2016--11--25--16--43--11(ZJYC):���ARP��DHCP��TCP��ʱ�����������Ƿ�����Ҫִ�е�    */ 
        prvCheckNetworkTimers();
        /*2016--11--25--16--43--55(ZJYC):����ɽ��ܵ����˯��ʱ��    */ 
        xNextIPSleep = prvCalculateSleepTime();
        /*2016--11--25--16--44--23(ZJYC):�ȴ�ֱ�����¿������¼���������ʼ��Ϊ��û���¼���
        �Է�ֹ���еĵ�����ʱ�˳������ǽ��յ���Ϣ*/ 
        xReceivedEvent.eEventType = eNoEvent;
        xQueueReceive( xNetworkEventQueue, ( void * ) &xReceivedEvent, xNextIPSleep );

        #if( ipconfigCHECK_IP_QUEUE_SPACE != 0 )
        {
            if( xReceivedEvent.eEventType != eNoEvent )
            {
            UBaseType_t uxCount;

                uxCount = uxQueueSpacesAvailable( xNetworkEventQueue );
                if( uxQueueMinimumSpace > uxCount )
                {
                    uxQueueMinimumSpace = uxCount;
                }
            }
        }
        #endif /* ipconfigCHECK_IP_QUEUE_SPACE */

        iptraceNETWORK_EVENT_RECEIVED( xReceivedEvent.eEventType );

        switch( xReceivedEvent.eEventType )
        {
            case eNetworkDownEvent :
                /*2016--11--25--16--47--16(ZJYC):���Խ���һ������    */ 
                prvProcessNetworkDownEvent();
                break;

            case eNetworkRxEvent:
                /*2016--11--25--16--48--19(ZJYC):����ײ������Ѿ����յ��µ�
                ���ݰ���pvDataָ�����������ݵ�ָ��*/ 
                prvHandleEthernetPacket( ( NetworkBufferDescriptor_t * ) ( xReceivedEvent.pvData ) );
                break;

            case eARPTimerEvent :
                /*2016--11--25--16--50--02(ZJYC):ARP��ʱ�����ڣ�ִ�С�����    */ 
                vARPAgeCache();
                break;

            case eSocketBindEvent:
                /*2016--11--25--16--50--31(ZJYC):FreeRTOS_bind���û�API��ҪIP-Task
                ȥ��һ���˿ڣ��ö˿ں����׽��ֵ�usLocalPort����vSocketBind
                ����ʵ�ʵİ��׽��֣����ң����׽��ֻᱻ������ֱ��eSOCKET_BOUND
                �¼�������*/ 
                pxSocket = ( FreeRTOS_Socket_t * ) ( xReceivedEvent.pvData );
                xAddress.sin_addr = 0u; /* For the moment. */
                xAddress.sin_port = FreeRTOS_ntohs( pxSocket->usLocalPort );
                pxSocket->usLocalPort = 0u;
                vSocketBind( pxSocket, &xAddress, sizeof( xAddress ), pdFALSE );
                /*2016--11--25--17--35--57(ZJYC):eSocketBindEvent������֮ǰ��
                ( xEventGroup != NULL )�ѱ����ԣ����������Ա����ڻ����û�*/ 
                pxSocket->xEventBits |= eSOCKET_BOUND;
                vSocketWakeUpUser( pxSocket );
                break;
            case eSocketCloseEvent :
                /*2016--11--25--17--39--54(ZJYC):�û�API-FreeRTOS_closesocket
                    �Ѿ���������Ϣ��IP-Taskȥ�ر�һ���׽��֣�����vSocketClose()
                    ʵ�֣����׽��ֹر��Ժ�û�ж������������API������API����
                    �ȴ����*/ 
                vSocketClose( ( FreeRTOS_Socket_t * ) ( xReceivedEvent.pvData ) );
                break;

            case eStackTxEvent :
                /*2016--11--25--17--43--07(ZJYC):Э��ջ�Ѿ�������Ҫ�����͵İ�
                ʱ��ṹ���е�pvData�洢�ò�����ָ��*/ 
                vProcessGeneratedUDPPacket( ( NetworkBufferDescriptor_t * ) ( xReceivedEvent.pvData ) );
                break;

            case eDHCPEvent:
                /*2016--11--26--10--24--50(ZJYC):DHCP״̬����Ҫִ��    */ 
                #if( ipconfigUSE_DHCP == 1 )
                {
                    vDHCPProcess( pdFALSE );
                }
                #endif /* ipconfigUSE_DHCP */
                break;

            case eSocketSelectEvent :
                /*2016--11--26--10--25--20(ZJYC):FreeRTOS_select()�Ѿ�ͨ���׽����¼�
                �����ˣ�vSocketSelect()������һ���׽������¼������¸��׽��ֵ�
                xSocketBits����*/ 
                #if( ipconfigSUPPORT_SELECT_FUNCTION == 1 )
                {
                    vSocketSelect( ( SocketSelect_t * ) ( xReceivedEvent.pvData ) );
                }
                #endif /* ipconfigSUPPORT_SELECT_FUNCTION == 1 */
                break;

            case eSocketSignalEvent :
                #if( ipconfigSUPPORT_SIGNALS != 0 )
                {
                    /*2016--11--26--10--27--24(ZJYC):ĳЩ������֪ͨ����׽��ֵ��û�
                    �����ж�*/ 
                    /* Some task wants to signal the user of this socket in
                    order to interrupt a call to recv() or a call to select(). */
                    FreeRTOS_SignalSocket( ( Socket_t ) xReceivedEvent.pvData );
                }
                #endif /* ipconfigSUPPORT_SIGNALS */
                break;

            case eTCPTimerEvent :
                #if( ipconfigUSE_TCP == 1 )
                {
                    /*2016--11--26--10--29--23(ZJYC):�򵥵İ�����TCP��ʱ��
                    ʹ�ö�ʱ����������һ�ε���prvCheckNetworkTimers()ʱ��������*/ 
                    xTCPTimer.bExpired = pdTRUE_UNSIGNED;
                }
                #endif /* ipconfigUSE_TCP */
                break;

            case eTCPAcceptEvent:
                /*2016--11--26--10--30--58(ZJYC):API FreeRTOS_accept()�����ã�IP-Task��
                �������׽����Ƿ�����յ����µ�����*/ 
				#if( ipconfigUSE_TCP == 1 )
                {
                    pxSocket = ( FreeRTOS_Socket_t * ) ( xReceivedEvent.pvData );

                    if( xTCPCheckNewClient( pxSocket ) != pdFALSE )
                    {
                        pxSocket->xEventBits |= eSOCKET_ACCEPT;
                        vSocketWakeUpUser( pxSocket );
                    }
                }
                #endif /* ipconfigUSE_TCP */
                break;

            case eTCPNetStat:
                /*2016--11--26--12--25--10(ZJYC):FreeRTOS_netstat()����������ӡȫ���׽���
                �Լ������ӵ���Ϣ*/ 
                #if( ( ipconfigUSE_TCP == 1 ) && ( ipconfigHAS_PRINTF == 1 ) )
                {
                    vTCPNetStat();
                }
                #endif /* ipconfigUSE_TCP */
                break;

            default :
                /*2016--11--26--12--26--06(ZJYC):��Ӧ��ִ�е�����    */ 
                break;
        }

        if( xNetworkDownEventPending != pdFALSE )
        {
            /*2016--11--26--12--26--28(ZJYC):�����¼�������������ܱ����͵�
            �¼����У��������ٴγ���    */ 
            FreeRTOS_NetworkDown();
        }
    }
}
/*-----------------------------------------------------------*/

BaseType_t xIsCallingFromIPTask( void )
{
BaseType_t xReturn;

    if( xTaskGetCurrentTaskHandle() == xIPTaskHandle )
    {
        xReturn = pdTRUE;
    }
    else
    {
        xReturn = pdFALSE;
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

static void prvHandleEthernetPacket( NetworkBufferDescriptor_t *pxBuffer )
{
    #if( ipconfigUSE_LINKED_RX_MESSAGES == 0 )
    {
        /*2016--11--26--12--27--56(ZJYC):i���pconfigUSE_LINKED_RX_MESSAGES��Ϊ0��
        ��һ��ֻ�ܷ���һ�����壬����TCP��MAC��Э��ջ�������ݵ�Ĭ�Ϸ�ʽ*/ 
        prvProcessEthernetPacket( pxBuffer );
    }
    #else /* ipconfigUSE_LINKED_RX_MESSAGES */
    {
    NetworkBufferDescriptor_t *pxNextBuffer;

        /*2016--11--26--12--29--37(ZJYC):������ӵ��ʱ���Ż��㷨�����õģ�����
        ÿ�ζ��������ݰ���IP-Task������ӿڿ��Խ���һϵ�����ݰ����Դ˽��䴫�ݸ�
        IP-Task������ʹ��pxNextBuffer�ĳ�Ա������ס�����µĴ������ÿһ�����ݰ�
        ������֮*/ 
        do
        {
            /*2016--11--26--12--33--26(ZJYC):�洢һָ��û����ָ���Ա����ʹ��    */ 
            pxNextBuffer = pxBuffer->pxNextBuffer;
            /*2016--11--26--12--34--46(ZJYC):��λ0�Է�����ʹ��    */ 
            pxBuffer->pxNextBuffer = NULL;
            prvProcessEthernetPacket( pxBuffer );
            pxBuffer = pxNextBuffer;
            /*2016--11--26--12--35--25(ZJYC):ѭ�����*/ 
        } while( pxBuffer != NULL );
    }
    #endif /* ipconfigUSE_LINKED_RX_MESSAGES */
}
/*-----------------------------------------------------------*/

static TickType_t prvCalculateSleepTime( void )
{
TickType_t xMaximumSleepTime;
    /*2016--11--26--12--36--04(ZJYC):�����˯��ʱ�俪ʼ��Ȼ��һ�ζԱ���������Ķ�ʱ��    */ 
    xMaximumSleepTime = ipconfigMAX_IP_TASK_SLEEP_TIME;
    if( xARPTimer.bActive != pdFALSE_UNSIGNED )
    {
        if( xARPTimer.ulRemainingTime < xMaximumSleepTime )
        {
            xMaximumSleepTime = xARPTimer.ulReloadTime;
        }
    }
    #if( ipconfigUSE_DHCP == 1 )
    {
        if( xDHCPTimer.bActive != pdFALSE_UNSIGNED )
        {
            if( xDHCPTimer.ulRemainingTime < xMaximumSleepTime )
            {
                xMaximumSleepTime = xDHCPTimer.ulRemainingTime;
            }
        }
    }
    #endif /* ipconfigUSE_DHCP */
    #if( ipconfigUSE_TCP == 1 )
    {
        if( xTCPTimer.ulRemainingTime < xMaximumSleepTime )
        {
            xMaximumSleepTime = xTCPTimer.ulRemainingTime;
        }
    }
    #endif
    #if( ipconfigDNS_USE_CALLBACKS != 0 )
    {
        if( xDNSTimer.bActive != pdFALSE )
        {
            if( xDNSTimer.ulRemainingTime < xMaximumSleepTime )
            {
                xMaximumSleepTime = xDNSTimer.ulRemainingTime;
            }
        }
    }
    #endif
    return xMaximumSleepTime;
}
/*-----------------------------------------------------------*/

static void prvCheckNetworkTimers( void )
{
    /*2016--11--26--12--37--16(ZJYC):��ARP�����ʱ������    */ 
    if( prvIPTimerCheck( &xARPTimer ) != pdFALSE )
    {
        xSendEventToIPTask( eARPTimerEvent );
    }
    #if( ipconfigUSE_DHCP == 1 )
    {
        /*2016--11--26--12--37--36(ZJYC):��DHCP�����ʱ������    */ 
        if( prvIPTimerCheck( &xDHCPTimer ) != pdFALSE )
        {
            xSendEventToIPTask( eDHCPEvent );
        }
    }
    #endif /* ipconfigUSE_DHCP */
    #if( ipconfigDNS_USE_CALLBACKS != 0 )
    {
    extern void vDNSCheckCallBack( void *pvSearchID );
        /*2016--11--26--12--37--58(ZJYC):��DNS�����ʱ������    */ 
        if( prvIPTimerCheck( &xDNSTimer ) != pdFALSE )
        {
            vDNSCheckCallBack( NULL );
        }
    }
    #endif /* ipconfigDNS_USE_CALLBACKS */
    #if( ipconfigUSE_TCP == 1 )
    {
    BaseType_t xWillSleep;
    /*2016--11--26--12--38--17(ZJYC):������һ�α���ʱ��������¼���
    ÿ�ε��ã������ᱻ����xTaskGetTickCount()��0��ʾ��ĿǰΪֹ��
    û��ʼ������Ȼ�����xTaskGetTickCount()Ҳ�᷵��0��������û��
    ��ģ�*/ 
    static TickType_t xStart = ( TickType_t ) 0;
    TickType_t xTimeNow, xNextTime;
    BaseType_t xCheckTCPSockets;
    extern uint32_t ulNextInitialSequenceNumber;
        if( uxQueueMessagesWaiting( xNetworkEventQueue ) == 0u )
        {
            xWillSleep = pdTRUE;
        }
        else
        {
            xWillSleep = pdFALSE;
        }
        xTimeNow = xTaskGetTickCount();
        if( xStart != ( TickType_t ) 0 )
        {
            /*2016--11--26--12--40--58(ZJYC):����ÿ�ĸ�΢������һ�����кţ���
            ÿms����250���⽫ʹ�õ��������Ѳ²����ǵ����к�*/ 
            ulNextInitialSequenceNumber += ipINITIAL_SEQUENCE_NUMBER_FACTOR * ( ( xTimeNow - xStart ) * portTICK_PERIOD_MS );
        }
        xStart = xTimeNow;
        /*2016--11--26--12--44--04(ZJYC):���TCP��ʱʱ�䵽�ˣ��׽�����Ҫ�����    */ 
        xCheckTCPSockets = prvIPTimerCheck( &xTCPTimer );
        /*2016--11--26--12--44--35(ZJYC):�����TCP��Ϣ����Ϣ�����ǿյģ�
        ����ʾxWillSleepΪ�棩    */ 
        if( ( xProcessedTCPMessage != pdFALSE ) && ( xWillSleep != pdFALSE ) )
        {
            xCheckTCPSockets = pdTRUE;
        }
        if( xCheckTCPSockets != pdFALSE )
        {
            /*2016--11--26--12--46--03(ZJYC):�����´��ظ�����ʱ��    */ 
            xNextTime = xTCPTimerCheck( xWillSleep );
            prvIPTimerStart( &xTCPTimer, xNextTime );
            xProcessedTCPMessage = 0;
        }
    }
    #endif /* ipconfigUSE_TCP == 1 */
}
/*-----------------------------------------------------------*/

static void prvIPTimerStart( IPTimer_t *pxTimer, TickType_t xTime )
{
    vTaskSetTimeOutState( &pxTimer->xTimeOut );
    pxTimer->ulRemainingTime = xTime;
    if( xTime == ( TickType_t ) 0 )
    {
        pxTimer->bExpired = pdTRUE_UNSIGNED;
    }
    else
    {
        pxTimer->bExpired = pdFALSE_UNSIGNED;
    }
    pxTimer->bActive = pdTRUE_UNSIGNED;
}
/*-----------------------------------------------------------*/

static void prvIPTimerReload( IPTimer_t *pxTimer, TickType_t xTime )
{
    pxTimer->ulReloadTime = xTime;
    prvIPTimerStart( pxTimer, xTime );
}
/*-----------------------------------------------------------*/

static BaseType_t prvIPTimerCheck( IPTimer_t *pxTimer )
{
BaseType_t xReturn;

    if( pxTimer->bActive == pdFALSE_UNSIGNED )
    {
        /*2016--11--26--12--50--22(ZJYC):��ʱ��������    */ 
        xReturn = pdFALSE;
    }
    else
    {
        /*2016--11--26--12--50--36(ZJYC):��ʱ�������λbExpired�ˣ����û�У�
        �Ա�xTimeOut��ulRemainingTime*/ 
        if( ( pxTimer->bExpired != pdFALSE_UNSIGNED ) ||
            ( xTaskCheckForTimeOut( &( pxTimer->xTimeOut ), &( pxTimer->ulRemainingTime ) ) != pdFALSE ) )
        {
            prvIPTimerStart( pxTimer, pxTimer->ulReloadTime );
            xReturn = pdTRUE;
        }
        else
        {
            xReturn = pdFALSE;
        }
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

void FreeRTOS_NetworkDown( void )
{
static const IPStackEvent_t xNetworkDownEvent = { eNetworkDownEvent, NULL };
const TickType_t xDontBlock = ( TickType_t ) 0;
    /*2016--11--26--12--51--58(ZJYC):�򵥵ķ�����ȷ���¼�    */ 
    if( xSendEventStructToIPTask( &xNetworkDownEvent, xDontBlock ) != pdPASS )
    {
        /*2016--11--26--12--52--32(ZJYC):���ܷ�����Ϣ�����ɵȴ�    */ 
        xNetworkDownEventPending = pdTRUE;
    }
    else
    {
        /*2016--11--26--12--53--04(ZJYC):��Ϣ�ѱ����������Բ����ڵȴ���    */ 
        xNetworkDownEventPending = pdFALSE;
    }

    iptraceNETWORK_DOWN();
}
/*-----------------------------------------------------------*/

BaseType_t FreeRTOS_NetworkDownFromISR( void )
{
static const IPStackEvent_t xNetworkDownEvent = { eNetworkDownEvent, NULL };
BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    /*2016--11--26--13--13--14(ZJYC):�򵥵ķ�����ȷ���¼�    */ 
    if( xQueueSendToBackFromISR( xNetworkEventQueue, &xNetworkDownEvent, &xHigherPriorityTaskWoken ) != pdPASS )
    {
        xNetworkDownEventPending = pdTRUE;
    }
    else
    {
        xNetworkDownEventPending = pdFALSE;
    }

    iptraceNETWORK_DOWN();

    return xHigherPriorityTaskWoken;
}
/*-----------------------------------------------------------*/

void *FreeRTOS_GetUDPPayloadBuffer( size_t xRequestedSizeBytes, TickType_t xBlockTimeTicks )
{
NetworkBufferDescriptor_t *pxNetworkBuffer;
void *pvReturn;
    /*2016--11--26--13--15--50(ZJYC):����������    */ 
    /* Cap the block time.  The reason for this is explained where
    ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS is defined (assuming an official
    FreeRTOSIPConfig.h header file is being used). */
    if( xBlockTimeTicks > ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS )
    {
        xBlockTimeTicks = ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS;
    }
    /*2016--11--26--13--17--17(ZJYC):������Ҫ�Ĵ洢����ȡ���绺��    */ 
    pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( sizeof( UDPPacket_t ) + xRequestedSizeBytes, xBlockTimeTicks );

    if( pxNetworkBuffer != NULL )
    {
        /*2016--11--26--13--17--57(ZJYC):����UDPͷ�Ŀռ�    */ 
        pvReturn = ( void * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipUDP_PAYLOAD_OFFSET_IPv4 ] );
    }
    else
    {
        pvReturn = NULL;
    }

    return ( void * ) pvReturn;
}
/*-----------------------------------------------------------*/

NetworkBufferDescriptor_t *pxDuplicateNetworkBufferWithDescriptor( NetworkBufferDescriptor_t * const pxNetworkBuffer,
    BaseType_t xNewLength )
{
NetworkBufferDescriptor_t * pxNewBuffer;
    /*2016--11--26--13--38--35(ZJYC):������ֻ��ipconfigZERO_COPY_TX_DRIVER��1ʱ�ſ�ʹ��
    ����������Ҫӵ�����绺������������쵼Ȩ����Ϊ������ѻ���ֱ�Ӵ��͵�DMA*/ 
    pxNewBuffer = pxGetNetworkBufferWithDescriptor( ( size_t ) xNewLength, ( TickType_t ) 0 );

    if( pxNewBuffer != NULL )
    {
        pxNewBuffer->ulIPAddress = pxNetworkBuffer->ulIPAddress;
        pxNewBuffer->usPort = pxNetworkBuffer->usPort;
        pxNewBuffer->usBoundPort = pxNetworkBuffer->usBoundPort;
        memcpy( pxNewBuffer->pucEthernetBuffer, pxNetworkBuffer->pucEthernetBuffer, pxNetworkBuffer->xDataLength );
    }

    return pxNewBuffer;
}
/*-----------------------------------------------------------*/

#if( ipconfigZERO_COPY_TX_DRIVER != 0 ) || ( ipconfigZERO_COPY_RX_DRIVER != 0 )

    NetworkBufferDescriptor_t *pxPacketBuffer_to_NetworkBuffer( void *pvBuffer )
    {
    uint8_t *pucBuffer;
    NetworkBufferDescriptor_t *pxResult;

        if( pvBuffer == NULL )
        {
            pxResult = NULL;
        }
        else
        {
            /*2016--11--26--13--40--39(ZJYC):��0����ָ���л�ȡ���绺��    */ 
            pucBuffer = ( uint8_t * ) pvBuffer;
            /*2016--11--26--13--41--12(ZJYC):�����������ָ���غɻ����ָ��
            ����ͷ���Ĵ�С��ͨ����8 + 2*/ 
            pucBuffer -= ipBUFFER_PADDING;
            /*2016--11--26--13--42--32(ZJYC):����һ��ָ�뱻��������������
            ��Ϊָ�뱻������ã�Ҫȷ������*/ 
            if( ( ( ( uint32_t ) pucBuffer ) & ( sizeof( pucBuffer ) - ( size_t ) 1 ) ) == ( uint32_t ) 0 )
            {
                pxResult = * ( ( NetworkBufferDescriptor_t ** ) pucBuffer );
            }
            else
            {
                pxResult = NULL;
            }
        }
        return pxResult;
    }

#endif /* ipconfigZERO_COPY_TX_DRIVER != 0 */
/*-----------------------------------------------------------*/

NetworkBufferDescriptor_t *pxUDPPayloadBuffer_to_NetworkBuffer( void *pvBuffer )
{
uint8_t *pucBuffer;
NetworkBufferDescriptor_t *pxResult;

    if( pvBuffer == NULL )
    {
        pxResult = NULL;
    }
    else
    {
        /*2016--11--26--13--44--44(ZJYC):��0����ָ���ȡ���绺��    */ 
        pucBuffer = ( uint8_t * ) pvBuffer;
        /*2016--11--26--13--45--15(ZJYC):�����������ָ���غɻ����ָ��
            ����ͷ���Ĵ�С��ͨ����8 + 2    */ 
        pucBuffer -= ( sizeof( UDPPacket_t ) + ipBUFFER_PADDING );
        /*2016--11--26--13--45--58(ZJYC): ����һ��ָ�뱻��������������
            ��Ϊָ�뱻������ã�Ҫȷ������   */ 
        if( ( ( ( uint32_t ) pucBuffer ) & ( sizeof( pucBuffer ) - 1 ) ) == 0 )
        {
            /*2016--11--26--13--46--25(ZJYC):���µĳ������ܻᴥ������    */ 
            /* The following statement may trigger a:
            warning: cast increases required alignment of target type [-Wcast-align].
            It has been confirmed though that the alignment is suitable. */
            pxResult = * ( ( NetworkBufferDescriptor_t ** ) pucBuffer );
        }
        else
        {
            pxResult = NULL;
        }
    }

    return pxResult;
}
/*-----------------------------------------------------------*/

void FreeRTOS_ReleaseUDPPayloadBuffer( void *pvBuffer )
{
    vReleaseNetworkBufferAndDescriptor( pxUDPPayloadBuffer_to_NetworkBuffer( pvBuffer ) );
}
/*-----------------------------------------------------------*/

/*_RB_ Should we add an error or assert if the task priorities are set such that the servers won't function as expected? */
/*_HT_ There was a bug in FreeRTOS_TCP_IP.c that only occurred when the applications' priority was too high.
 As that bug has been repaired, there is not an urgent reason to warn.
 It is better though to use the advised priority scheme. */
BaseType_t FreeRTOS_IPInit( const uint8_t ucIPAddress[ ipIP_ADDRESS_LENGTH_BYTES ], const uint8_t ucNetMask[ ipIP_ADDRESS_LENGTH_BYTES ], const uint8_t ucGatewayAddress[ ipIP_ADDRESS_LENGTH_BYTES ], const uint8_t ucDNSServerAddress[ ipIP_ADDRESS_LENGTH_BYTES ], const uint8_t ucMACAddress[ ipMAC_ADDRESS_LENGTH_BYTES ] )
{
BaseType_t xReturn = pdFALSE;
    /*2016--11--26--13--48--01(ZJYC):�������ֻ�ܱ�����һ��    */ 
    configASSERT( xIPIsNetworkTaskReady() == pdFALSE );
    configASSERT( xNetworkEventQueue == NULL );
    configASSERT( xIPTaskHandle == NULL );
    /*2016--11--26--13--48--21(ZJYC):���ṹ���Ƿ���ȷ    */ 
    configASSERT( sizeof( EthernetHeader_t ) == ipEXPECTED_EthernetHeader_t_SIZE );
    configASSERT( sizeof( ARPHeader_t ) == ipEXPECTED_ARPHeader_t_SIZE );
    configASSERT( sizeof( IPHeader_t ) == ipEXPECTED_IPHeader_t_SIZE );
    configASSERT( sizeof( ICMPHeader_t ) == ipEXPECTED_ICMPHeader_t_SIZE );
    configASSERT( sizeof( UDPHeader_t ) == ipEXPECTED_UDPHeader_t_SIZE );
    /*2016--11--26--13--48--54(ZJYC):���Խ���������IP-Task�����Ķ���    */ 
    xNetworkEventQueue = xQueueCreate( ( UBaseType_t ) ipconfigEVENT_QUEUE_LENGTH, ( UBaseType_t ) sizeof( IPStackEvent_t ) );
    configASSERT( xNetworkEventQueue );
    if( xNetworkEventQueue != NULL )
    {
        #if ( configQUEUE_REGISTRY_SIZE > 0 )
        {
            /*2016--11--26--13--49--28(ZJYC):���е�ע��ͨ������֧���ں˵���*/ 
            vQueueAddToRegistry( xNetworkEventQueue, "NetEvnt" );
        }
        #endif /* configQUEUE_REGISTRY_SIZE */

        if( xNetworkBuffersInitialise() == pdPASS )
        {
            /*2016--11--26--13--50--37(ZJYC):���汾��IP��MAC��ַ    */ 
            xNetworkAddressing.ulDefaultIPAddress = FreeRTOS_inet_addr_quick( ucIPAddress[ 0 ], ucIPAddress[ 1 ], ucIPAddress[ 2 ], ucIPAddress[ 3 ] );
            xNetworkAddressing.ulNetMask = FreeRTOS_inet_addr_quick( ucNetMask[ 0 ], ucNetMask[ 1 ], ucNetMask[ 2 ], ucNetMask[ 3 ] );
            xNetworkAddressing.ulGatewayAddress = FreeRTOS_inet_addr_quick( ucGatewayAddress[ 0 ], ucGatewayAddress[ 1 ], ucGatewayAddress[ 2 ], ucGatewayAddress[ 3 ] );
            xNetworkAddressing.ulDNSServerAddress = FreeRTOS_inet_addr_quick( ucDNSServerAddress[ 0 ], ucDNSServerAddress[ 1 ], ucDNSServerAddress[ 2 ], ucDNSServerAddress[ 3 ] );
            xNetworkAddressing.ulBroadcastAddress = ( xNetworkAddressing.ulDefaultIPAddress & xNetworkAddressing.ulNetMask ) |  ~xNetworkAddressing.ulNetMask;
            memcpy( &xDefaultAddressing, &xNetworkAddressing, sizeof( xDefaultAddressing ) );
            #if ipconfigUSE_DHCP == 1
            {
                /*2016--11--26--13--51--04(ZJYC):IP��ֱַ��DHCP��ɲŻὨ��    */ 
                *ipLOCAL_IP_ADDRESS_POINTER = 0x00UL;
            }
            #else
            {
                /*2016--11--26--13--51--36(ZJYC):IP��ַͨ������Ĳ�����ȷ��    */ 
                *ipLOCAL_IP_ADDRESS_POINTER = xNetworkAddressing.ulDefaultIPAddress;
                /*2016--11--26--13--52--09(ZJYC):������ڷ�ֹ������ص�ARP��ˮ��
                ȷ��������ͬһ������*/ 
                configASSERT( ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) == ( xNetworkAddressing.ulGatewayAddress & xNetworkAddressing.ulNetMask ) );
            }
            #endif /* ipconfigUSE_DHCP == 1 */
            /*2016--11--26--14--15--58(ZJYC):MAC��ַ���洢��Ĭ�ϵİ�ͷƬ�Σ����ڷ���UDP��ʱ�õ�    */ 
            memcpy( ( void * ) ipLOCAL_MAC_ADDRESS, ( void * ) ucMACAddress, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
            /*2016--11--26--14--17--08(ZJYC):׼���׽��ֽӿ�    */ 
            vNetworkSocketsInit();
            /*2016--11--26--14--17--57(ZJYC):����������̫����Э��ջ�¼�������    */ 
            xReturn = xTaskCreate( prvIPTask, "IP-task", ( uint16_t ) ipconfigIP_TASK_STACK_SIZE_WORDS, NULL, ( UBaseType_t ) ipconfigIP_TASK_PRIORITY, &xIPTaskHandle );
        }
        else
        {
            FreeRTOS_debug_printf( ( "FreeRTOS_IPInit: xNetworkBuffersInitialise() failed\n") );
            /*2016--11--26--14--18--30(ZJYC):����ɾ�    */ 
            vQueueDelete( xNetworkEventQueue );
            xNetworkEventQueue = NULL;
        }
    }
    else
    {
        FreeRTOS_debug_printf( ( "FreeRTOS_IPInit: Network event queue could not be created\n") );
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

void FreeRTOS_GetAddressConfiguration( uint32_t *pulIPAddress, uint32_t *pulNetMask, uint32_t *pulGatewayAddress, uint32_t *pulDNSServerAddress )
{
    /*2016--11--26--14--18--46(ZJYC):���ص�ַ������Ϣ��������    */ 
    if( pulIPAddress != NULL )
    {
        *pulIPAddress = *ipLOCAL_IP_ADDRESS_POINTER;
    }
    if( pulNetMask != NULL )
    {
        *pulNetMask = xNetworkAddressing.ulNetMask;
    }
    if( pulGatewayAddress != NULL )
    {
        *pulGatewayAddress = xNetworkAddressing.ulGatewayAddress;
    }
    if( pulDNSServerAddress != NULL )
    {
        *pulDNSServerAddress = xNetworkAddressing.ulDNSServerAddress;
    }
}
/*-----------------------------------------------------------*/

void FreeRTOS_SetAddressConfiguration( const uint32_t *pulIPAddress, const uint32_t *pulNetMask, const uint32_t *pulGatewayAddress, const uint32_t *pulDNSServerAddress )
{
    /*2016--11--26--14--19--13(ZJYC):���µ�ַ������Ϣ    */ 
    if( pulIPAddress != NULL )
    {
        *ipLOCAL_IP_ADDRESS_POINTER = *pulIPAddress;
    }
    if( pulNetMask != NULL )
    {
        xNetworkAddressing.ulNetMask = *pulNetMask;
    }
    if( pulGatewayAddress != NULL )
    {
        xNetworkAddressing.ulGatewayAddress = *pulGatewayAddress;
    }
    if( pulDNSServerAddress != NULL )
    {
        xNetworkAddressing.ulDNSServerAddress = *pulDNSServerAddress;
    }
}
/*-----------------------------------------------------------*/

#if ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )

    BaseType_t FreeRTOS_SendPingRequest( uint32_t ulIPAddress, size_t xNumberOfBytesToSend, TickType_t xBlockTimeTicks )
    {
    NetworkBufferDescriptor_t *pxNetworkBuffer;
    ICMPHeader_t *pxICMPHeader;
    BaseType_t xReturn = pdFAIL;
    static uint16_t usSequenceNumber = 0;
    uint8_t *pucChar;
    IPStackEvent_t xStackTxEvent = { eStackTxEvent, NULL };

        if( xNumberOfBytesToSend < ( ( ipconfigNETWORK_MTU - sizeof( IPHeader_t ) ) - sizeof( ICMPHeader_t ) ) )
        {
            pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( xNumberOfBytesToSend + sizeof( ICMPPacket_t ), xBlockTimeTicks );

            if( pxNetworkBuffer != NULL )
            {
                pxICMPHeader = ( ICMPHeader_t * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipIP_PAYLOAD_OFFSET ] );
                usSequenceNumber++;
                /*2016--11--26--14--21--18(ZJYC):������ͷ����Ϣ    */ 
                pxICMPHeader->ucTypeOfMessage = ipICMP_ECHO_REQUEST;
                pxICMPHeader->ucTypeOfService = 0;
                pxICMPHeader->usIdentifier = usSequenceNumber;
                pxICMPHeader->usSequenceNumber = usSequenceNumber;
                /*2016--11--26--14--21--36(ZJYC):�ҵ����ݵĿ�ʼ    */ 
                pucChar = ( uint8_t * ) pxICMPHeader;
                pucChar += sizeof( ICMPHeader_t );
                /*2016--11--26--14--28--40(ZJYC):    */ 
                /* Just memset the data to a fixed value. */
                memset( ( void * ) pucChar, ( int ) ipECHO_DATA_FILL_BYTE, xNumberOfBytesToSend );
                /*2016--11--26--14--28--46(ZJYC):��Ϣ������ɣ�IP��У����
                vProcessGeneratedUDPPacket����*/ 
                pxNetworkBuffer->pucEthernetBuffer[ ipSOCKET_OPTIONS_OFFSET ] = FREERTOS_SO_UDPCKSUM_OUT;
                pxNetworkBuffer->ulIPAddress = ulIPAddress;
                pxNetworkBuffer->usPort = ipPACKET_CONTAINS_ICMP_DATA;
                pxNetworkBuffer->xDataLength = xNumberOfBytesToSend + sizeof( ICMPHeader_t );
                /*2016--11--26--14--30--37(ZJYC):���͸�Э��ջ    */ 
                xStackTxEvent.pvData = pxNetworkBuffer;

                if( xSendEventStructToIPTask( &xStackTxEvent, xBlockTimeTicks) != pdPASS )
                {
                    vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
                    iptraceSTACK_TX_EVENT_LOST( ipSTACK_TX_EVENT );
                }
                else
                {
                    xReturn = usSequenceNumber;
                }
            }
        }
        else
        {
            /* The requested number of bytes will not fit in the available space
            in the network buffer. */
        }

        return xReturn;
    }

#endif /* ipconfigSUPPORT_OUTGOING_PINGS == 1 */
/*-----------------------------------------------------------*/

BaseType_t xSendEventToIPTask( eIPEvent_t eEvent )
{
IPStackEvent_t xEventMessage;
const TickType_t xDontBlock = ( TickType_t ) 0;

    xEventMessage.eEventType = eEvent;
    xEventMessage.pvData = ( void* )NULL;

    return xSendEventStructToIPTask( &xEventMessage, xDontBlock );
}
/*-----------------------------------------------------------*/

BaseType_t xSendEventStructToIPTask( const IPStackEvent_t *pxEvent, TickType_t xTimeout )
{
BaseType_t xReturn, xSendMessage;

    if( ( xIPIsNetworkTaskReady() == pdFALSE ) && ( pxEvent->eEventType != eNetworkDownEvent ) )
    {
        /*2016--11--26--14--31--54(ZJYC):���IP-Taskû׼���ã���ֻ����eNetworkDownEvent
        ͨ������ȥ���Է�����Ϣ�����Է���ʧ��*/ 
        xReturn = pdFAIL;
    }
    else
    {
        xSendMessage = pdTRUE;
        #if( ipconfigUSE_TCP == 1 )
        {
            if( pxEvent->eEventType == eTCPTimerEvent )
            {
                /*2016--11--26--14--34--20(ZJYC):����ʱ������ʱ��TCP��ʱ���¼�����
                ��ʱ�����񣬵������IP-Task�Ѿ��������ˣ��ٷ��;�û��������    */ 
                xTCPTimer.bExpired = pdTRUE_UNSIGNED;
                if( uxQueueMessagesWaiting( xNetworkEventQueue ) != 0u )
                {
                    /*2016--11--26--14--38--45(ZJYC):������������Ҫȥ������Ϣ������Ҳ������ʧ�ܣ�
                    ��Ϊ��Ϣ����Ҫ����*/ 
                    xSendMessage = pdFALSE;
                }
            }
        }
        #endif /* ipconfigUSE_TCP */
        if( xSendMessage != pdFALSE )
        {
            /*2016--11--26--14--42--29(ZJYC):IP-Task�ڵȴ�����Ļظ�ʱ���������Լ�    */ 
            if( ( xIsCallingFromIPTask() == pdTRUE ) && ( xTimeout > ( TickType_t ) 0 ) )
            {
                xTimeout = ( TickType_t ) 0;
            }
            xReturn = xQueueSendToBack( xNetworkEventQueue, pxEvent, xTimeout );
            if( xReturn == pdFAIL )
            {
                /*2016--11--26--14--43--51(ZJYC):һ����ϢӦ�������͵�����û��    */ 
                FreeRTOS_debug_printf( ( "xSendEventStructToIPTask: CAN NOT ADD %d\n", pxEvent->eEventType ) );
                iptraceSTACK_TX_EVENT_LOST( pxEvent->eEventType );
            }
        }
        else
        {
            /*2016--11--26--14--44--59(ZJYC):û�б�Ҫȥ������Ϣ�������¼���
            ��ʹ��ʹ��Ϣû�б����ͣ�������Ȼ�ǳɹ���*/ 
            xReturn = pdPASS;
        }
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

eFrameProcessingResult_t eConsiderFrameForProcessing( const uint8_t * const pucEthernetBuffer )
{
eFrameProcessingResult_t eReturn;
const EthernetHeader_t *pxEthernetHeader;
    pxEthernetHeader = ( const EthernetHeader_t * ) pucEthernetBuffer;
    if( memcmp( ( void * ) ipLOCAL_MAC_ADDRESS, ( void * ) &( pxEthernetHeader->xDestinationAddress ), sizeof( MACAddress_t ) ) == 0 )
    {
        /*2016--11--26--14--49--10(ZJYC):��ֱ��ָ��˽ڵ�--������    */ 
        eReturn = eProcessBuffer;
    }
    else if( memcmp( ( void * ) xBroadcastMACAddress.ucBytes, ( void * ) pxEthernetHeader->xDestinationAddress.ucBytes, sizeof( MACAddress_t ) ) == 0 )
    {
        /*2016--11--26--14--50--48(ZJYC):����һ���㲥��--������    */ 
        eReturn = eProcessBuffer;
    }
    else
#if( ipconfigUSE_LLMNR == 1 )
    if( memcmp( ( void * ) xLLMNR_MacAdress.ucBytes, ( void * ) pxEthernetHeader->xDestinationAddress.ucBytes, sizeof( MACAddress_t ) ) == 0 )
    {
        /*2016--11--26--14--51--20(ZJYC):����LLMNR���󣬴�����    */ 
        eReturn = eProcessBuffer;
    }
    else
#endif /* ipconfigUSE_LLMNR */
    {
        /*2016--11--26--14--54--50(ZJYC):������һ���㲥�������߶�������ڵ���˵����ȡ�κ��ж�    */ 
        eReturn = eReleaseBuffer;
    }

    #if( ipconfigFILTER_OUT_NON_ETHERNET_II_FRAMES == 1 )
    {
    uint16_t usFrameType;

        if( eReturn == eProcessBuffer )
        {
            usFrameType = pxEthernetHeader->usFrameType;
            usFrameType = FreeRTOS_ntohs( usFrameType );

            if( usFrameType <= 0x600U )
            {
                /*2016--11--26--14--55--47(ZJYC):������̫�� II �ܹ�    */ 
                eReturn = eReleaseBuffer;
            }
        }
    }
    #endif /* ipconfigFILTER_OUT_NON_ETHERNET_II_FRAMES == 1  */

    return eReturn;
}
/*-----------------------------------------------------------*/

static void prvProcessNetworkDownEvent( void )
{
    /*2016--11--26--15--03--13(ZJYC):û��������ֹͣARP��ʱ��    */ 
    xARPTimer.bActive = pdFALSE_UNSIGNED;

    #if ipconfigUSE_NETWORK_EVENT_HOOK == 1
    {
        static BaseType_t xCallEventHook = pdFALSE;
        /*2016--11--26--15--03--42(ZJYC):��һ�������¼���IP�������ȥ��ʼ���ײ�Ӳ��
        ���ԣ���Ҫ��һ�ε����¼��������*/ 
        if( xCallEventHook == pdTRUE )
        {
            vApplicationIPNetworkEventHook( eNetworkDown );
        }
        xCallEventHook = pdTRUE;
    }
    #endif
    /*2016--11--26--15--05--02(ZJYC):����Ͽ������߱���һ�γ�ʼ������ִ���κ�Ӳ�������Ǳ�Ҫ��
    ���ߣ��ȴ����ٴο��ã���������Ӳ��*/ 
    if( xNetworkInterfaceInitialise() != pdPASS )
    {
        /*2016--11--26--15--07--38(ZJYC):��������£�ֻ���������ʱ����ӿڳ�ʼ�������Ż᷵��
        ���������������������³�ʼ��֮ǰ�ȴ�һ��*/ 
        vTaskDelay( ipINITIALISATION_RETRY_DELAY );
        FreeRTOS_NetworkDown();
    }
    else
    {
        /*2016--11--26--15--13--08(ZJYC):��ʣ��ʱ����Ϊ0�����������̼���    */ 
        #if ipconfigUSE_DHCP == 1
        {
            /*2016--11--26--15--14--01(ZJYC):    */ 
            /* The network is not up until DHCP has completed. */
            vDHCPProcess( pdTRUE );
            xSendEventToIPTask( eDHCPEvent );
        }
        #else
        {
            /* Perform any necessary 'network up' processing. */
            vIPNetworkUpCalls();
        }
        #endif
    }
}
/*-----------------------------------------------------------*/

void vIPNetworkUpCalls( void )
{
    xNetworkUp = pdTRUE;

    #if( ipconfigUSE_NETWORK_EVENT_HOOK == 1 )
    {
        vApplicationIPNetworkEventHook( eNetworkUp );
    }
    #endif /* ipconfigUSE_NETWORK_EVENT_HOOK */

    #if( ipconfigDNS_USE_CALLBACKS != 0 )
    {
        /*2016--11--26--19--30--46(ZJYC):���µĺ�����FreeRTOS_DNS.c������������
        ���ڿ�˽�У���������*/ 
        extern void vDNSInitialise( void );
        vDNSInitialise();
    }
    #endif /* ipconfigDNS_USE_CALLBACKS != 0 */
    /*2016--11--26--19--31--45(ZJYC):��ʣ��ʱ������Ϊ0���������ᱻ��������    */ 
    prvIPTimerReload( &xARPTimer, pdMS_TO_TICKS( ipARP_TIMER_PERIOD_MS ) );
}
/*-----------------------------------------------------------*/

static void prvProcessEthernetPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer )
{
EthernetHeader_t *pxEthernetHeader;
volatile eFrameProcessingResult_t eReturned; 
    configASSERT( pxNetworkBuffer );

    /* Interpret the Ethernet frame. */
    eReturned = ipCONSIDER_FRAME_FOR_PROCESSING( pxNetworkBuffer->pucEthernetBuffer );
    pxEthernetHeader = ( EthernetHeader_t * ) ( pxNetworkBuffer->pucEthernetBuffer );

    if( eReturned == eProcessBuffer )
    {
        /*2016--11--26--19--32--53(ZJYC):�����յ�����̫�����ݰ�    */ 
        switch( pxEthernetHeader->usFrameType )
        {
            case ipARP_FRAME_TYPE :
                /*2016--11--26--19--33--24(ZJYC):��̫�����ݰ�����ARP    */ 
                eReturned = eARPProcessPacket( ( ARPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer );
                break;

            case ipIPv4_FRAME_TYPE :
                /*2016--11--26--19--33--48(ZJYC):��̫�����ݰ�����IP    */ 
                eReturned = prvProcessIPPacket( ( IPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer, pxNetworkBuffer );
                break;

            default :
                /* No other packet types are handled.  Nothing to do. */
                eReturned = eReleaseBuffer;
                break;
        }
    }

    /* Perform any actions that resulted from processing the Ethernet frame. */
    switch( eReturned )
    {
        case eReturnEthernetFrame :
            /*2016--11--26--19--35--28(ZJYC):��̫��֡�����Ѿ��������ˣ�
            ����������һ��ARP���������PING���󣿣�����Ӧ��ԭ·����*/ 
            vReturnEthernetFrame( pxNetworkBuffer, pdTRUE );
            /*2016--11--26--19--35--03(ZJYC):pdTRUE����һ�������ͼ��ͷ�    */ 
            break;

        case eFrameConsumed :
            /*2016--11--26--19--36--56(ZJYC):�û�������ʲô�ط�ʹ�ã����ڲ����ͷ�    */ 
            break;

        default :
            /*2016--11--26--19--37--30(ZJYC):��֡ʲô�ط����ò��������ң�***Ҫ�ͷ�    */ 
            vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
            break;
    }
}
/*-----------------------------------------------------------*/

static eFrameProcessingResult_t prvAllowIPPacket( const IPPacket_t * const pxIPPacket,
    NetworkBufferDescriptor_t * const pxNetworkBuffer, UBaseType_t uxHeaderLength )
{
eFrameProcessingResult_t eReturn = eProcessBuffer;

#if( ( ipconfigETHERNET_DRIVER_FILTERS_PACKETS == 0 ) || ( ipconfigDRIVER_INCLUDED_RX_IP_CHECKSUM == 0 ) )
    const IPHeader_t * pxIPHeader = &( pxIPPacket->xIPHeader );
#else
    /* or else, the parameter won't be used and the function will be optimised
    away */
    ( void ) pxIPPacket;
#endif

    #if( ipconfigETHERNET_DRIVER_FILTERS_PACKETS == 0 )
    {
        /*2016--11--26--19--39--50(ZJYC):��RAM��С��ϵͳ�У���ǰ��鵽��������
        ����һ�����Ƶģ�ͨ�������������÷�����������绺���ʹ����*/ 
        uint32_t ulDestinationIPAddress = pxIPHeader->ulDestinationIPAddress;
            /*2016--11--26--19--41--27(ZJYC):ȷ�����������ݰ�û�У�����    */ 
            /* Ensure that the incoming packet is not fragmented (only outgoing
            packets can be fragmented) as these are the only handled IP frames
            currently. */
            if( ( pxIPHeader->usFragmentOffset & ipFRAGMENT_OFFSET_BIT_MASK ) != 0U )
            {
                /* Can not handle, fragmented packet. */
                eReturn = eReleaseBuffer;
            }
            /* 0x45 means: IPv4 with an IP header of 5 x 4 = 20 bytes
             * 0x47 means: IPv4 with an IP header of 7 x 4 = 28 bytes */
            else if( ( pxIPHeader->ucVersionHeaderLength < 0x45u ) || ( pxIPHeader->ucVersionHeaderLength > 0x4Fu ) )
            {
                /* Can not handle, unknown or invalid header version. */
                eReturn = eReleaseBuffer;
            }
                /* Is the packet for this IP address? */
            else if( ( ulDestinationIPAddress != *ipLOCAL_IP_ADDRESS_POINTER ) &&
                /* Is it the global broadcast address 255.255.255.255 ? */
                ( ulDestinationIPAddress != ipBROADCAST_IP_ADDRESS ) &&
                /* Is it a specific broadcast address 192.168.1.255 ? */
                ( ulDestinationIPAddress != xNetworkAddressing.ulBroadcastAddress ) &&
            #if( ipconfigUSE_LLMNR == 1 )
                /* Is it the LLMNR multicast address? */
                ( ulDestinationIPAddress != ipLLMNR_IP_ADDR ) &&
            #endif
                /* Or (during DHCP negotiation) we have no IP-address yet? */
                ( *ipLOCAL_IP_ADDRESS_POINTER != 0UL ) )
            {
                /* Packet is not for this node, release it */
                eReturn = eReleaseBuffer;
            }
    }
    #endif /* ipconfigETHERNET_DRIVER_FILTERS_PACKETS */

    #if( ipconfigDRIVER_INCLUDED_RX_IP_CHECKSUM == 0 )
    {
        /* Some drivers of NIC's with checksum-offloading will enable the above
        define, so that the checksum won't be checked again here */
        if (eReturn == eProcessBuffer )
        {
            /* Is the IP header checksum correct? */
            if( ( pxIPHeader->ucProtocol != ( uint8_t ) ipPROTOCOL_ICMP ) &&
                ( usGenerateChecksum( 0UL, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ( size_t ) uxHeaderLength ) != ipCORRECT_CRC ) )
            {
                /* Check sum in IP-header not correct. */
                eReturn = eReleaseBuffer;
            }
            /* Is the upper-layer checksum (TCP/UDP/ICMP) correct? */
            else if( usGenerateProtocolChecksum( ( uint8_t * )( pxNetworkBuffer->pucEthernetBuffer ), pdFALSE ) != ipCORRECT_CRC )
            {
                /* Protocol checksum not accepted. */
                eReturn = eReleaseBuffer;
            }
        }
    }
    #else
    {
        /* to avoid warning unused parameters */
        ( void ) pxNetworkBuffer;
        ( void ) uxHeaderLength;
    }
    #endif /* ipconfigDRIVER_INCLUDED_RX_IP_CHECKSUM == 0 */

    return eReturn;
}
/*-----------------------------------------------------------*/

static eFrameProcessingResult_t prvProcessIPPacket( const IPPacket_t * const pxIPPacket, NetworkBufferDescriptor_t * const pxNetworkBuffer )
{
eFrameProcessingResult_t eReturn;
const IPHeader_t * pxIPHeader = &( pxIPPacket->xIPHeader );
UBaseType_t uxHeaderLength = ( UBaseType_t ) ( ( pxIPHeader->ucVersionHeaderLength & 0x0Fu ) << 2 );
uint8_t ucProtocol;

    ucProtocol = pxIPPacket->xIPHeader.ucProtocol;
    /* Check if the IP headers are acceptable and if it has our destination. */
    eReturn = prvAllowIPPacket( pxIPPacket, pxNetworkBuffer, uxHeaderLength );

    if( eReturn == eProcessBuffer )
    {
        if( uxHeaderLength > ipSIZE_OF_IPv4_HEADER )
        {
            /*2016--11--30--18--46--33(ZJYC): ��ѡ��   */ 
            const size_t optlen = ( ( size_t ) uxHeaderLength ) - ipSIZE_OF_IPv4_HEADER;
            /* From: the previous start of UDP/ICMP/TCP data */
            uint8_t *pucSource = ( ( uint8_t * ) pxIPHeader ) + uxHeaderLength;
            /* To: the usual start of UDP/ICMP/TCP data at offset 20 from IP header */
            uint8_t *pucTarget = ( ( uint8_t * ) pxIPHeader ) + ipSIZE_OF_IPv4_HEADER;
            /* How many: total length minus the options and the lower headers */
            const size_t  xMoveLen = pxNetworkBuffer->xDataLength - optlen - ipSIZE_OF_IPv4_HEADER - ipSIZE_OF_ETH_HEADER;
            /*2016--11--30--18--47--09(ZJYC): ��ϧ���ǲ���Ҫ��Щ����   */ 
            memmove( pucTarget, pucSource, xMoveLen );
            pxNetworkBuffer->xDataLength -= optlen;
        }
        if( ucProtocol != ( uint8_t ) ipPROTOCOL_UDP )
        {
            /*2016--11--30--18--47--48(ZJYC): ���뵽ARP������   */ 
            vARPRefreshCacheEntry( &( pxIPPacket->xEthernetHeader.xSourceAddress ), pxIPHeader->ulSourceIPAddress );
        }
        switch( ucProtocol )
        {
            case ipPROTOCOL_ICMP :
                #if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )
                {
                    ICMPPacket_t *pxICMPPacket = ( ICMPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
                    if( pxIPHeader->ulDestinationIPAddress == *ipLOCAL_IP_ADDRESS_POINTER )
                    {
                        eReturn = prvProcessICMPPacket( pxICMPPacket );
                    }
                }
                #endif /* ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 ) */
                break;
            case ipPROTOCOL_UDP :
                {
                    /* The IP packet contained a UDP frame. */
                    UDPPacket_t *pxUDPPacket = ( UDPPacket_t * ) ( pxNetworkBuffer->pucEthernetBuffer );
                    /* Note the header values required prior to the
                    checksum generation as the checksum pseudo header
                    may clobber some of these values. */
                    pxNetworkBuffer->xDataLength = FreeRTOS_ntohs( pxUDPPacket->xUDPHeader.usLength ) - sizeof( UDPHeader_t );
                    /* HT:endian: fields in pxNetworkBuffer (usPort, ulIPAddress) were network order */
                    pxNetworkBuffer->usPort = pxUDPPacket->xUDPHeader.usSourcePort;
                    pxNetworkBuffer->ulIPAddress = pxUDPPacket->xIPHeader.ulSourceIPAddress;

                    /* ipconfigDRIVER_INCLUDED_RX_IP_CHECKSUM:
                     * In some cases, the upper-layer checksum has been calculated
                     * by the NIC driver */
                    /* Pass the packet payload to the UDP sockets implementation. */
                    /* HT:endian: xProcessReceivedUDPPacket wanted network order */
                    if( xProcessReceivedUDPPacket( pxNetworkBuffer, pxUDPPacket->xUDPHeader.usDestinationPort ) == pdPASS )
                    {
                        eReturn = eFrameConsumed;
                    }
                }
                break;

#if ipconfigUSE_TCP == 1
            case ipPROTOCOL_TCP :
                {

                    if( xProcessReceivedTCPPacket( pxNetworkBuffer ) == pdPASS )
                    {
                        eReturn = eFrameConsumed;
                    }

                    /* Setting this variable will cause xTCPTimerCheck()
                    to be called just before the IP-task blocks. */
                    xProcessedTCPMessage++;
                }
                break;
#endif
            default :
                /* Not a supported frame type. */
                break;
        }
    }

    return eReturn;
}
/*-----------------------------------------------------------*/

#if ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )

    static void prvProcessICMPEchoReply( ICMPPacket_t * const pxICMPPacket )
    {
    ePingReplyStatus_t eStatus = eSuccess;
    uint16_t usDataLength, usCount;
    uint8_t *pucByte;

        /* Find the total length of the IP packet. */
        usDataLength = pxICMPPacket->xIPHeader.usLength;
        usDataLength = FreeRTOS_ntohs( usDataLength );

        /* Remove the length of the IP headers to obtain the length of the ICMP
        message itself. */
        usDataLength = ( uint16_t ) ( ( ( uint32_t ) usDataLength ) - ipSIZE_OF_IPv4_HEADER );

        /* Remove the length of the ICMP header, to obtain the length of
        data contained in the ping. */
        usDataLength = ( uint16_t ) ( ( ( uint32_t ) usDataLength ) - ipSIZE_OF_ICMP_HEADER );

        /* Checksum has already been checked before in prvProcessIPPacket */

        /* Find the first byte of the data within the ICMP packet. */
        pucByte = ( uint8_t * ) pxICMPPacket;
        pucByte += sizeof( ICMPPacket_t );

        /* Check each byte. */
        for( usCount = 0; usCount < usDataLength; usCount++ )
        {
            if( *pucByte != ipECHO_DATA_FILL_BYTE )
            {
                eStatus = eInvalidData;
                break;
            }

            pucByte++;
        }

        /* Call back into the application to pass it the result. */
        vApplicationPingReplyHook( eStatus, pxICMPPacket->xICMPHeader.usIdentifier );
    }

#endif
/*-----------------------------------------------------------*/

#if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 )

    static eFrameProcessingResult_t prvProcessICMPEchoRequest( ICMPPacket_t * const pxICMPPacket )
    {
    ICMPHeader_t *pxICMPHeader;
    IPHeader_t *pxIPHeader;
    uint16_t usRequest;

        pxICMPHeader = &( pxICMPPacket->xICMPHeader );
        pxIPHeader = &( pxICMPPacket->xIPHeader );

        /* HT:endian: changed back */
        iptraceSENDING_PING_REPLY( pxIPHeader->ulSourceIPAddress );

        /* The checksum can be checked here - but a ping reply should be
        returned even if the checksum is incorrect so the other end can
        tell that the ping was received - even if the ping reply contains
        invalid data. */
        pxICMPHeader->ucTypeOfMessage = ( uint8_t ) ipICMP_ECHO_REPLY;
        pxIPHeader->ulDestinationIPAddress = pxIPHeader->ulSourceIPAddress;
        pxIPHeader->ulSourceIPAddress = *ipLOCAL_IP_ADDRESS_POINTER;

        /* Update the checksum because the ucTypeOfMessage member in the header
        has been changed to ipICMP_ECHO_REPLY.  This is faster than calling
        usGenerateChecksum(). */

        /* due to compiler warning "integer operation result is out of range" */

        usRequest = ( uint16_t ) ( ( uint16_t )ipICMP_ECHO_REQUEST << 8 );

        if( pxICMPHeader->usChecksum >= FreeRTOS_htons( 0xFFFFu - usRequest ) )
        {
            pxICMPHeader->usChecksum = ( uint16_t )
                ( ( ( uint32_t ) pxICMPHeader->usChecksum ) +
                    FreeRTOS_htons( usRequest + 1UL ) );
        }
        else
        {
            pxICMPHeader->usChecksum = ( uint16_t )
                ( ( ( uint32_t ) pxICMPHeader->usChecksum ) +
                    FreeRTOS_htons( usRequest ) );
        }
        return eReturnEthernetFrame;
    }

#endif /* ipconfigREPLY_TO_INCOMING_PINGS == 1 */
/*-----------------------------------------------------------*/

#if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )

    static eFrameProcessingResult_t prvProcessICMPPacket( ICMPPacket_t * const pxICMPPacket )
    {
    eFrameProcessingResult_t eReturn = eReleaseBuffer;

        iptraceICMP_PACKET_RECEIVED();
        switch( pxICMPPacket->xICMPHeader.ucTypeOfMessage )
        {
            case ipICMP_ECHO_REQUEST    :
                #if ( ipconfigREPLY_TO_INCOMING_PINGS == 1 )
                {
                    eReturn = prvProcessICMPEchoRequest( pxICMPPacket );
                }
                #endif /* ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) */
                break;

            case ipICMP_ECHO_REPLY      :
                #if ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )
                {
                    prvProcessICMPEchoReply( pxICMPPacket );
                }
                #endif /* ipconfigSUPPORT_OUTGOING_PINGS */
                break;

            default :
                break;
        }

        return eReturn;
    }

#endif /* ( ipconfigREPLY_TO_INCOMING_PINGS == 1 ) || ( ipconfigSUPPORT_OUTGOING_PINGS == 1 ) */
/*-----------------------------------------------------------*/

uint16_t usGenerateProtocolChecksum( const uint8_t * const pucEthernetBuffer, BaseType_t xOutgoingPacket )
{
uint32_t ulLength;
uint16_t usChecksum, *pusChecksum;
const IPPacket_t * pxIPPacket;
UBaseType_t uxIPHeaderLength;
ProtocolPacket_t *pxProtPack;
uint8_t ucProtocol;
#if( ipconfigHAS_DEBUG_PRINTF != 0 )
    const char *pcType;
#endif

    pxIPPacket = ( const IPPacket_t * ) pucEthernetBuffer;
    uxIPHeaderLength = ( UBaseType_t ) ( 4u * ( pxIPPacket->xIPHeader.ucVersionHeaderLength & 0x0Fu ) ); /*_RB_ Why 4? */
    pxProtPack = ( ProtocolPacket_t * ) ( pucEthernetBuffer + ( uxIPHeaderLength - ipSIZE_OF_IPv4_HEADER ) );
    ucProtocol = pxIPPacket->xIPHeader.ucProtocol;

    if( ucProtocol == ( uint8_t ) ipPROTOCOL_UDP )
    {
        pusChecksum = ( uint16_t * ) ( &( pxProtPack->xUDPPacket.xUDPHeader.usChecksum ) );
        #if( ipconfigHAS_DEBUG_PRINTF != 0 )
        {
            pcType = "UDP";
        }
        #endif  /* ipconfigHAS_DEBUG_PRINTF != 0 */
    }
    else if( ucProtocol == ( uint8_t ) ipPROTOCOL_TCP )
    {
        pusChecksum = ( uint16_t * ) ( &( pxProtPack->xTCPPacket.xTCPHeader.usChecksum ) );
        #if( ipconfigHAS_DEBUG_PRINTF != 0 )
        {
            pcType = "TCP";
        }
        #endif  /* ipconfigHAS_DEBUG_PRINTF != 0 */
    }
    else if( ( ucProtocol == ( uint8_t ) ipPROTOCOL_ICMP ) ||
            ( ucProtocol == ( uint8_t ) ipPROTOCOL_IGMP ) )
    {
        pusChecksum = ( uint16_t * ) ( &( pxProtPack->xICMPPacket.xICMPHeader.usChecksum ) );

        #if( ipconfigHAS_DEBUG_PRINTF != 0 )
        {
            if( ucProtocol == ( uint8_t ) ipPROTOCOL_ICMP )
            {
                pcType = "ICMP";
            }
            else
            {
                pcType = "IGMP";
            }
        }
        #endif  /* ipconfigHAS_DEBUG_PRINTF != 0 */
    }
    else
    {
        /* Unhandled protocol, other than ICMP, IGMP, UDP, or TCP. */
        return ipUNHANDLED_PROTOCOL;
    }

    if( xOutgoingPacket != pdFALSE )
    {
        /* This is an outgoing packet. Before calculating the checksum, set it
        to zero. */
        *( pusChecksum ) = 0u;
    }
    else if ( *pusChecksum == 0u )
    {
        /* Sender hasn't set the checksum, no use to calculate it. */
        return ipCORRECT_CRC;
    }

    ulLength = ( uint32_t )
        ( FreeRTOS_ntohs( pxIPPacket->xIPHeader.usLength ) - ( ( uint16_t ) uxIPHeaderLength ) ); /* normally minus 20 */

    if( ( ulLength < sizeof( pxProtPack->xUDPPacket.xUDPHeader ) ) ||
        ( ulLength > ( uint32_t )( ipconfigNETWORK_MTU - uxIPHeaderLength ) ) )
    {
        #if( ipconfigHAS_DEBUG_PRINTF != 0 )
        {
            FreeRTOS_debug_printf( ( "usGenerateProtocolChecksum[%s]: len invalid: %lu\n", pcType, ulLength ) );
        }
        #endif  /* ipconfigHAS_DEBUG_PRINTF != 0 */

        /* Again, in a 16-bit return value there is no space to indicate an
        error.  For incoming packets, 0x1234 will cause dropping of the packet.
        For outgoing packets, there is a serious problem with the
        format/length */
        return ipINVALID_LENGTH;
    }
    if( ucProtocol <= ( uint8_t ) ipPROTOCOL_IGMP )
    {
        /* ICMP/IGMP do not have a pseudo header for CRC-calculation. */
        usChecksum = ( uint16_t )
            ( ~usGenerateChecksum( 0UL,
                ( uint8_t * ) &( pxProtPack->xTCPPacket.xTCPHeader ), ( size_t ) ulLength ) );
    }
    else
    {
        /* For UDP and TCP, sum the pseudo header, i.e. IP protocol + length
        fields */
        usChecksum = ( uint16_t ) ( ulLength + ( ( uint16_t ) ucProtocol ) );

        /* And then continue at the IPv4 source and destination addresses. */
        usChecksum = ( uint16_t )
            ( ~usGenerateChecksum( ( uint32_t ) usChecksum, ( uint8_t * )&( pxIPPacket->xIPHeader.ulSourceIPAddress ),
                ( 2u * sizeof( pxIPPacket->xIPHeader.ulSourceIPAddress ) + ulLength ) ) );

        /* Sum TCP header and data. */
    }

    if( usChecksum == 0u )
    {
        #if( ipconfigHAS_DEBUG_PRINTF != 0 )
        {
            if( xOutgoingPacket != pdFALSE )
            {
                FreeRTOS_debug_printf( ( "usGenerateProtocolChecksum[%s]: crc swap: %04X\n", pcType, usChecksum ) );
            }
        }
        #endif  /* ipconfigHAS_DEBUG_PRINTF != 0 */

        usChecksum = ipCORRECT_CRC;
    }
    else
    {
        usChecksum = FreeRTOS_htons( usChecksum );
    }

    if( xOutgoingPacket != pdFALSE )
    {
        *( pusChecksum ) = usChecksum;
    }
    #if( ipconfigHAS_DEBUG_PRINTF != 0 )
    else if( usChecksum != ipCORRECT_CRC )
    {
        FreeRTOS_debug_printf( ( "usGenerateProtocolChecksum[%s]: ID %04X: from %lxip to %lxip bad crc: %04X\n",
            pcType,
            FreeRTOS_ntohs( pxIPPacket->xIPHeader.usIdentification ),
            FreeRTOS_ntohl( pxIPPacket->xIPHeader.ulSourceIPAddress ),
            FreeRTOS_ntohl( pxIPPacket->xIPHeader.ulDestinationIPAddress ),
            FreeRTOS_ntohs( *pusChecksum ) ) );
    }
    #endif  /* ipconfigHAS_DEBUG_PRINTF != 0 */

    return usChecksum;
}
/*-----------------------------------------------------------*/

uint16_t usGenerateChecksum( uint32_t ulSum, const uint8_t * pucNextData, size_t uxDataLengthBytes )
{
xUnion32 xSum2, xSum, xTerm;
xUnionPtr xSource;      /* Points to first byte */
xUnionPtr xLastSource;  /* Points to last byte plus one */
uint32_t ulAlignBits, ulCarry = 0ul;

    /* Small MCUs often spend up to 30% of the time doing checksum calculations
    This function is optimised for 32-bit CPUs; Each time it will try to fetch
    32-bits, sums it with an accumulator and counts the number of carries. */

    /* Swap the input (little endian platform only). */
    xSum.u32 = FreeRTOS_ntohs( ulSum );
    xTerm.u32 = 0ul;

    xSource.u8ptr = ( uint8_t * ) pucNextData;
    ulAlignBits = ( ( ( uint32_t ) pucNextData ) & 0x03u ); /* gives 0, 1, 2, or 3 */

    /* If byte (8-bit) aligned... */
    if( ( ( ulAlignBits & 1ul ) != 0ul ) && ( uxDataLengthBytes >= ( size_t ) 1 ) )
    {
        xTerm.u8[ 1 ] = *( xSource.u8ptr );
        ( xSource.u8ptr )++;
        uxDataLengthBytes--;
        /* Now xSource is word (16-bit) aligned. */
    }

    /* If half-word (16-bit) aligned... */
    if( ( ( ulAlignBits == 1u ) || ( ulAlignBits == 2u ) ) && ( uxDataLengthBytes >= 2u ) )
    {
        xSum.u32 += *(xSource.u16ptr);
        ( xSource.u16ptr )++;
        uxDataLengthBytes -= 2u;
        /* Now xSource is word (32-bit) aligned. */
    }

    /* Word (32-bit) aligned, do the most part. */
    xLastSource.u32ptr = ( xSource.u32ptr + ( uxDataLengthBytes / 4u ) ) - 3u;

    /* In this loop, four 32-bit additions will be done, in total 16 bytes.
    Indexing with constants (0,1,2,3) gives faster code than using
    post-increments. */
    while( xSource.u32ptr < xLastSource.u32ptr )
    {
        /* Use a secondary Sum2, just to see if the addition produced an
        overflow. */
        xSum2.u32 = xSum.u32 + xSource.u32ptr[ 0 ];
        if( xSum2.u32 < xSum.u32 )
        {
            ulCarry++;
        }

        /* Now add the secondary sum to the major sum, and remember if there was
        a carry. */
        xSum.u32 = xSum2.u32 + xSource.u32ptr[ 1 ];
        if( xSum2.u32 > xSum.u32 )
        {
            ulCarry++;
        }

        /* And do the same trick once again for indexes 2 and 3 */
        xSum2.u32 = xSum.u32 + xSource.u32ptr[ 2 ];
        if( xSum2.u32 < xSum.u32 )
        {
            ulCarry++;
        }

        xSum.u32 = xSum2.u32 + xSource.u32ptr[ 3 ];

        if( xSum2.u32 > xSum.u32 )
        {
            ulCarry++;
        }

        /* And finally advance the pointer 4 * 4 = 16 bytes. */
        xSource.u32ptr += 4;
    }

    /* Now add all carries. */
    xSum.u32 = ( uint32_t )xSum.u16[ 0 ] + xSum.u16[ 1 ] + ulCarry;

    uxDataLengthBytes %= 16u;
    xLastSource.u8ptr = ( uint8_t * ) ( xSource.u8ptr + ( uxDataLengthBytes & ~( ( size_t ) 1 ) ) );

    /* Half-word aligned. */
    while( xSource.u16ptr < xLastSource.u16ptr )
    {
        /* At least one more short. */
        xSum.u32 += xSource.u16ptr[ 0 ];
        xSource.u16ptr++;
    }

    if( ( uxDataLengthBytes & ( size_t ) 1 ) != 0u )    /* Maybe one more ? */
    {
        xTerm.u8[ 0 ] = xSource.u8ptr[ 0 ];
    }
    xSum.u32 += xTerm.u32;

    /* Now add all carries again. */
    xSum.u32 = ( uint32_t ) xSum.u16[ 0 ] + xSum.u16[ 1 ];

    /* The previous summation might have given a 16-bit carry. */
    xSum.u32 = ( uint32_t ) xSum.u16[ 0 ] + xSum.u16[ 1 ];

    if( ( ulAlignBits & 1u ) != 0u )
    {
        /* Quite unlikely, but pucNextData might be non-aligned, which would
         mean that a checksum is calculated starting at an odd position. */
        xSum.u32 = ( ( xSum.u32 & 0xffu ) << 8 ) | ( ( xSum.u32 & 0xff00u ) >> 8 );
    }

    /* swap the output (little endian platform only). */
    return FreeRTOS_htons( ( (uint16_t) xSum.u32 ) );
}
/*-----------------------------------------------------------*/

void vReturnEthernetFrame( NetworkBufferDescriptor_t * pxNetworkBuffer, BaseType_t xReleaseAfterSend )
{
EthernetHeader_t *pxEthernetHeader;

#if( ipconfigZERO_COPY_TX_DRIVER != 0 )
    NetworkBufferDescriptor_t *pxNewBuffer;
#endif

    #if defined( ipconfigETHERNET_MINIMUM_PACKET_BYTES )
    {
        if( pxNetworkBuffer->xDataLength < ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES )
        {
        BaseType_t xIndex;

            FreeRTOS_printf( ( "vReturnEthernetFrame: length %lu\n", pxNetworkBuffer->xDataLength ) );
            for( xIndex = ( BaseType_t ) pxNetworkBuffer->xDataLength; xIndex < ( BaseType_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES; xIndex++ )
            {
                pxNetworkBuffer->pucEthernetBuffer[ xIndex ] = 0u;
            }
            pxNetworkBuffer->xDataLength = ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES;
        }
    }
    #endif

#if( ipconfigZERO_COPY_TX_DRIVER != 0 )

    if( xReleaseAfterSend == pdFALSE )
    {
        pxNewBuffer = pxDuplicateNetworkBufferWithDescriptor( pxNetworkBuffer, ( BaseType_t ) pxNetworkBuffer->xDataLength );
        xReleaseAfterSend = pdTRUE;
        pxNetworkBuffer = pxNewBuffer;
    }

    if( pxNetworkBuffer != NULL )
#endif
    {
        pxEthernetHeader = ( EthernetHeader_t * ) ( pxNetworkBuffer->pucEthernetBuffer );

        /* Swap source and destination MAC addresses. */
        memcpy( ( void * ) &( pxEthernetHeader->xDestinationAddress ), ( void * ) &( pxEthernetHeader->xSourceAddress ), sizeof( pxEthernetHeader->xDestinationAddress ) );
        memcpy( ( void * ) &( pxEthernetHeader->xSourceAddress) , ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );

        /* Send! */
        xNetworkInterfaceOutput( pxNetworkBuffer, xReleaseAfterSend );
    }
}
/*-----------------------------------------------------------*/

uint32_t FreeRTOS_GetIPAddress( void )
{
    /* Returns the IP address of the NIC. */
    return *ipLOCAL_IP_ADDRESS_POINTER;
}
/*-----------------------------------------------------------*/

void FreeRTOS_SetIPAddress( uint32_t ulIPAddress )
{
    /* Sets the IP address of the NIC. */
    *ipLOCAL_IP_ADDRESS_POINTER = ulIPAddress;
}
/*-----------------------------------------------------------*/

uint32_t FreeRTOS_GetGatewayAddress( void )
{
    return xNetworkAddressing.ulGatewayAddress;
}
/*-----------------------------------------------------------*/

uint32_t FreeRTOS_GetDNSServerAddress( void )
{
    return xNetworkAddressing.ulDNSServerAddress;
}
/*-----------------------------------------------------------*/

uint32_t FreeRTOS_GetNetmask( void )
{
    return xNetworkAddressing.ulNetMask;
}
/*-----------------------------------------------------------*/

const uint8_t * FreeRTOS_GetMACAddress( void )
{
    return ipLOCAL_MAC_ADDRESS;
}
/*-----------------------------------------------------------*/

void FreeRTOS_SetNetmask ( uint32_t ulNetmask )
{
    xNetworkAddressing.ulNetMask = ulNetmask;
}
/*-----------------------------------------------------------*/

void FreeRTOS_SetGatewayAddress ( uint32_t ulGatewayAddress )
{
    xNetworkAddressing.ulGatewayAddress = ulGatewayAddress;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_DHCP == 1 )
    void vIPSetDHCPTimerEnableState( BaseType_t xEnableState )
    {
        if( xEnableState != pdFALSE )
        {
            xDHCPTimer.bActive = pdTRUE_UNSIGNED;
        }
        else
        {
            xDHCPTimer.bActive = pdFALSE_UNSIGNED;
        }
    }
#endif /* ipconfigUSE_DHCP */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_DHCP == 1 )
    void vIPReloadDHCPTimer( uint32_t ulLeaseTime )
    {
        prvIPTimerReload( &xDHCPTimer, ulLeaseTime );
    }
#endif /* ipconfigUSE_DHCP */
/*-----------------------------------------------------------*/

#if( ipconfigDNS_USE_CALLBACKS == 1 )
    void vIPSetDnsTimerEnableState( BaseType_t xEnableState )
    {
        if( xEnableState != 0 )
        {
            xDNSTimer.bActive = pdTRUE;
        }
        else
        {
            xDNSTimer.bActive = pdFALSE;
        }
    }
#endif /* ipconfigUSE_DHCP */
/*-----------------------------------------------------------*/

#if( ipconfigDNS_USE_CALLBACKS != 0 )
    void vIPReloadDNSTimer( uint32_t ulCheckTime )
    {
        prvIPTimerReload( &xDNSTimer, ulCheckTime );
    }
#endif /* ipconfigDNS_USE_CALLBACKS != 0 */
/*-----------------------------------------------------------*/

BaseType_t xIPIsNetworkTaskReady( void )
{
    return xIPTaskInitialised;
}
/*-----------------------------------------------------------*/

BaseType_t FreeRTOS_IsNetworkUp( void )
{
    return xNetworkUp;
}
/*-----------------------------------------------------------*/

#if( ipconfigCHECK_IP_QUEUE_SPACE != 0 )
    UBaseType_t uxGetMinimumIPQueueSpace( void )
    {
        return uxQueueMinimumSpace;
    }
#endif
/*-----------------------------------------------------------*/
