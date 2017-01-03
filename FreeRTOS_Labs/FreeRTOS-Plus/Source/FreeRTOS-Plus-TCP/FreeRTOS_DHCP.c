
/* ��׼ͷ�ļ� */
#include <stdint.h>

/*2016--12--01--11--08--51(ZJYC): FREERTOSͷ�ļ�   */ 
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

/*2016--12--01--11--08--51(ZJYC): FREERTOS+TCPͷ�ļ�   */ 
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_TCP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "FreeRTOS_ARP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"

/*2016--12--01--11--08--51(ZJYC): ���DHCPδʹ�����ų�����   */ 
#if( ipconfigUSE_DHCP != 0 )

#if ( ipconfigUSE_DHCP != 0 ) && ( ipconfigNETWORK_MTU < 586u )
    /*2016--12--01--11--10--21(ZJYC): DHCP�����ܹ�����312�ֽڵ�ѡ������DHCP
    ���ĵĹ̶�������240�ֽڣ�����IP/UDPͷ��ռ��28�ֽڣ�312+240+28 = 580������*/ 
    #error ipconfigNETWORK_MTU needs to be at least 586 to use DHCP
#endif

/*2016--12--01--14--00--49(ZJYC): DHCP���Ĳ���   */ 
#define dhcpCLIENT_HARDWARE_ADDRESS_LENGTH      16
#define dhcpSERVER_HOST_NAME_LENGTH             64
#define dhcpBOOT_FILE_NAME_LENGTH               128

/*2016--12--01--14--01--05(ZJYC): DHCPʱ�����   */ 
#ifndef dhcpINITIAL_DHCP_TX_PERIOD
    #define dhcpINITIAL_TIMER_PERIOD            ( pdMS_TO_TICKS( 250 ) )
    #define dhcpINITIAL_DHCP_TX_PERIOD          ( pdMS_TO_TICKS( 5000 ) )
#endif

/*2016--12--01--14--01--24(ZJYC): DHCPѡ�������õı�־   */ 
/*2016--12--02--08--39--18(ZJYC): 0 ����ֽ� ����0   */ 
#define dhcpZERO_PAD_OPTION_CODE                ( 0u )
/*2016--12--02--08--39--31(ZJYC): 1 �������� ����4   */ 
#define dhcpSUBNET_MASK_OPTION_CODE             ( 1u )
/*2016--12--02--08--47--51(ZJYC): 2 ʱ��ƫ�� ����4   */ 
/*2016--12--02--08--39--59(ZJYC): 3 ·�ɵ�ַ ���� n*4   */ 
#define dhcpGATEWAY_OPTION_CODE                 ( 3u )
/*2016--12--02--08--49--19(ZJYC): 4 ʱ������� ���� n*4   */ 
/*2016--12--02--08--49--42(ZJYC): 5 ���Ʒ����� ���� n*4   */ 
/*2016--12--02--08--50--17(ZJYC): 6 ���������� ���� n*4   */ 
#define dhcpDNS_SERVER_OPTIONS_CODE             ( 6u )
/*2016--12--02--08--50--42(ZJYC): 7 ��־������ ���� n*4   */ 
/*2016--12--02--08--52--59(ZJYC): 8 Cookie������ ���� n*4   */
/*2016--12--02--08--53--41(ZJYC): 9 LPR������ ���� n*4   */ 
/*2016--12--02--08--54--34(ZJYC): 10 Impress ������ ���� n*4   */ 
/*2016--12--02--08--55--32(ZJYC): 11 ��Դλ�÷����� ���� n*4   */ 
/*2016--12--02--08--56--25(ZJYC): 12 ������ ���� ����1�ֽ�  */ 
#define dhcpDNS_HOSTNAME_OPTIONS_CODE           ( 12u )
/*2016--12--02--08--57--12(ZJYC): 13 �����ļ���С ���� 2�ֽ�   */ 
/*2016--12--02--08--58--57(ZJYC): 14 ת���ļ� ���� ����1�ֽ�  */ 
/*2016--12--02--09--05--45(ZJYC): 15 ���� ���� ����1�ֽ�   */ 
/*2016--12--02--09--06--10(ZJYC): 16 ���������� ����4�ֽ�   */ 
/*2016--12--02--09--08--44(ZJYC): 17 ��·�� ���� ����1�ֽ�  */ 
/*2016--12--02--09--09--16(ZJYC): 18 ��չ·�� ���� ����1�ֽ�  */ 
/*2016--12--02--09--10--31(ZJYC): 50 �����IP��ַ ���� 4�ֽ�   */ 
#define dhcpREQUEST_IP_ADDRESS_OPTION_CODE      ( 50u )
/*2016--12--02--09--11--02(ZJYC): 51 IP��ַ���� ���� 4�ֽ�   */ 
#define dhcpLEASE_TIME_OPTION_CODE              ( 51u )
/*2016--12--02--09--11--26(ZJYC): 53 ��Ϣ���� ���� 1�ֽ�   */ 
#define dhcpMESSAGE_TYPE_OPTION_CODE            ( 53u )
/*2016--12--02--09--17--20(ZJYC): 54 ��������ʾ 4�ֽ�   */ 
#define dhcpSERVER_IP_ADDRESS_OPTION_CODE       ( 54u )
/*2016--12--02--09--17--42(ZJYC): 55 �����嵥 ����1�ֽ�   */ 
#define dhcpPARAMETER_REQUEST_OPTION_CODE       ( 55u )
/*2016--12--02--09--18--12(ZJYC): 61 �ͻ��˱�ʾ ����2�ֽ�   */ 
#define dhcpCLIENT_IDENTIFIER_OPTION_CODE       ( 61u )
/*2016--12--02--09--09--45(ZJYC): 255 ������   */ 
/*2016--12--01--14--08--22(ZJYC): ����DHCP��Ϣ����   */ 
#define dhcpMESSAGE_TYPE_DISCOVER               ( 1 )
#define dhcpMESSAGE_TYPE_OFFER                  ( 2 )
#define dhcpMESSAGE_TYPE_REQUEST                ( 3 )
#define dhcpMESSAGE_TYPE_ACK                    ( 5 )
#define dhcpMESSAGE_TYPE_NACK                   ( 6 )

/*2016--12--01--14--08--22(ZJYC): ������Ϣ��DHCP�����е�����   */ 
#define dhcpCLIENT_IDENTIFIER_OFFSET            ( 5 )
#define dhcpREQUESTED_IP_ADDRESS_OFFSET         ( 13 )
#define dhcpDHCP_SERVER_IP_ADDRESS_OFFSET       ( 19 )

/*2016--12--01--14--10--34(ZJYC): DHCP������ֵ   */ 
#define dhcpREQUEST_OPCODE                      ( 1 )
#define dhcpREPLY_OPCODE                        ( 2 )
#define dhcpADDRESS_TYPE_ETHERNET               ( 1 )
#define dhcpETHERNET_ADDRESS_LENGTH             ( 6 )
/*2016--12--01--14--11--15(ZJYC): �����Լδ����ʹ��Ĭ�ϵ�2�죬48H��ticks��ʾ��
����ʹ��pdMS_TO_TICKS()����Ϊ�����   */ 
#define dhcpDEFAULT_LEASE_TIME                  ( ( 48UL * 60UL * 60UL ) * configTICK_RATE_HZ )

/*2016--12--01--14--24--12(ZJYC): ��������Լʱ��̫��   */ 
#define dhcpMINIMUM_LEASE_TIME                  ( pdMS_TO_TICKS( 60000UL ) )    /* 60 seconds in ticks. */

/*2016--12--01--14--24--43(ZJYC): ���ѡ���ֶν�����־   */ 
#define dhcpOPTION_END_BYTE 0xffu

/*2016--12--01--14--27--22(ZJYC): ѡ���ֶε�����240   */ 
#define dhcpFIRST_OPTION_BYTE_OFFSET            ( 0xf0 )
/*2016--12--01--14--28--15(ZJYC): �������ɱ䳤��ѡ���ֶΣ�һ�±������Ա��� 
���ᳬ��ѡ���ֶΣ�������2�ֽڱ�ʾ����С1���ֽ�   */ 
#define dhcpMAX_OPTION_LENGTH_OF_INTEREST       ( 2L )
/*2016--12--01--14--29--58(ZJYC): ��׼DHCP�˿ںź�magic cookieֵ   */ 
#if( ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN )
    #define dhcpCLIENT_PORT 0x4400u
    #define dhcpSERVER_PORT 0x4300u
    #define dhcpCOOKIE      0x63538263ul
    #define dhcpBROADCAST   0x0080u
#else
    #define dhcpCLIENT_PORT 0x0044u
    #define dhcpSERVER_PORT 0x0043u
    #define dhcpCOOKIE      0x63825363ul
    #define dhcpBROADCAST   0x8000u
#endif /* ipconfigBYTE_ORDER */

#include "pack_struct_start.h"
struct xDHCPMessage
{
    uint8_t ucOpcode;
    uint8_t ucAddressType;
    uint8_t ucAddressLength;
    uint8_t ucHops;
    uint32_t ulTransactionID;
    uint16_t usElapsedTime;
    uint16_t usFlags;
    uint32_t ulClientIPAddress_ciaddr;
    uint32_t ulYourIPAddress_yiaddr;
    uint32_t ulServerIPAddress_siaddr;
    uint32_t ulRelayAgentIPAddress_giaddr;
    uint8_t ucClientHardwareAddress[ dhcpCLIENT_HARDWARE_ADDRESS_LENGTH ];
    uint8_t ucServerHostName[ dhcpSERVER_HOST_NAME_LENGTH ];
    uint8_t ucBootFileName[ dhcpBOOT_FILE_NAME_LENGTH ];
    uint32_t ulDHCPCookie;
    uint8_t ucFirstOptionByte;
}
#include "pack_struct_end.h"
typedef struct xDHCPMessage DHCPMessage_t;

/*2016--12--01--14--30--49(ZJYC): DHCP״̬��   */ 
typedef enum
{
    eWaitingSendFirstDiscover = 0,  /*2016--12--01--14--31--04(ZJYC): ��ʼ״̬���ȷ���Discover������λ���ж�ʱ��   */ 
    eWaitingOffer,                  /*2016--12--01--14--32--58(ZJYC): �������·���Discover���������offer��������������һ����   */
    eWaitingAcknowledge,            /*2016--12--01--14--35--22(ZJYC): �������·�������   */ 
    #if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
        eGetLinkLayerAddress,       /*2016--12--01--14--36--12(ZJYC): ��DHCPû�лظ������Ի�ȡ��·���ַ168.254.x.x.   */
    #endif
    eLeasedAddress,                 /*2016--12--01--14--37--06(ZJYC): �ʵ���ʱ�����·��������Ѹ�����Լ   */ 
    eNotUsingLeasedAddress          /*2016--12--01--14--37--35(ZJYC): DHCPʧ�ܣ�Ĭ�ϵ�ַ��ʹ��   */ 
} eDHCPState_t;

/*2016--12--01--14--38--03(ZJYC): ��DHCP״̬���д洢��Ϣ   */ 
struct xDHCP_DATA
{
    uint32_t ulTransactionId;
    uint32_t ulOfferedIPAddress;
    uint32_t ulDHCPServerAddress;
    uint32_t ulLeaseTime;
    /*2016--12--01--14--39--35(ZJYC): ���浱ǰ��ʱ��״̬   */ 
    TickType_t xDHCPTxTime;
    TickType_t xDHCPTxPeriod;
    /*2016--12--01--14--43--49(ZJYC): ���Բ����д��Ź㲥��־������   */ 
    BaseType_t xUseBroadcast;
    /*2016--12--01--14--45--03(ZJYC): ״̬��״̬   */ 
    eDHCPState_t eDHCPState;
    /*2016--12--01--14--45--23(ZJYC): UDP�׽��֣��������н�������   */ 
    Socket_t xDHCPSocket;
};

typedef struct xDHCP_DATA DHCPData_t;

#if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
    /*2016--12--01--14--46--05(ZJYC): ������·��IP��ַ169.254.x.x   */ 
    #define LINK_LAYER_ADDRESS_0    169
    #define LINK_LAYER_ADDRESS_1    254
    /*2016--12--01--14--46--31(ZJYC): ����Ĭ�ϵ���������255.255.0.0   */ 
    #define LINK_LAYER_NETMASK_0    255
    #define LINK_LAYER_NETMASK_1    255
    #define LINK_LAYER_NETMASK_2    0
    #define LINK_LAYER_NETMASK_3    0
#endif

/*2016--12--01--14--47--02(ZJYC): ����DHCP��Ϣ�����͵�DHCP�׽���   */ 
static void prvSendDHCPDiscover( void );

/*2016--12--01--16--11--36(ZJYC): �����DHCPЭ��ջ�Ͻ��ܵ���Ϣ   */ 
static BaseType_t prvProcessDHCPReplies( BaseType_t xExpectedMessageType );

/*2016--12--01--16--12--30(ZJYC): ����DHCP������Ϣ�����͵�DHCP�׽�����   */ 
static void prvSendDHCPRequest( void );

/*2016--12--01--16--12--59(ZJYC): ׼����ʼDHCP���ף����ʼ��һЩ״̬�������б�Ҫ�Ļ������׽���   */ 
static void prvInitialiseDHCP( void );

/*2016--12--01--17--01--43(ZJYC): �������ⷢ�͵����ݰ��й�ͬ�Ĳ���   */ 
static uint8_t *prvCreatePartDHCPMessage( struct freertos_sockaddr *pxAddress, BaseType_t xOpcode, const uint8_t * const pucOptionsArray, size_t *pxOptionsArraySize );

/*2016--12--01--17--02--33(ZJYC): ����DHCP�׽��֣����û�д����Ļ�   */ 
static void prvCreateDHCPSocket( void );

/*2016--12--01--17--03--25(ZJYC): DHCPû�лش𣬾�ȫ��ȥ��ʼ������·��IP��ַ��ʹ������ķ���
����һ���ARP���ȴ��Ƿ����˻ظ�   */ 
#if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
    static void prvPrepareLinkLayerIPLookUp( void );
#endif

/*-----------------------------------------------------------*/

/*2016--12--01--17--06--04(ZJYC): ��һ��DHCP����ID   */ 
static DHCPData_t xDHCPData;

/*-----------------------------------------------------------*/

BaseType_t xIsDHCPSocket( Socket_t xSocket )
{
BaseType_t xReturn;

    if( xDHCPData.xDHCPSocket == xSocket )
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

void vDHCPProcess( BaseType_t xReset )
{
BaseType_t xGivingUp = pdFALSE;
#if( ipconfigUSE_DHCP_HOOK != 0 )
    eDHCPCallbackAnswer_t eAnswer;
#endif  /* ipconfigUSE_DHCP_HOOK */

    /*2016--12--01--17--07--33(ZJYC): DHCP���¿�ʼ��   */ 
    if( xReset != pdFALSE )
    {
        xDHCPData.eDHCPState = eWaitingSendFirstDiscover;
    }

    switch( xDHCPData.eDHCPState )
    {
        case eWaitingSendFirstDiscover :
            /*2016--12--01--17--08--05(ZJYC): ���û����Ƿ���ҪDHCP Discovery   */ 
        #if( ipconfigUSE_DHCP_HOOK != 0 )
            eAnswer = xApplicationDHCPHook( eDHCPPhasePreDiscover, xNetworkAddressing.ulDefaultIPAddress );
            if( eAnswer == eDHCPContinue )
        #endif  /* ipconfigUSE_DHCP_HOOK */
            {
                /*2016--12--01--17--09--25(ZJYC): ��ʼ״̬ ����DHCP�׽��֣���ʱ���ȵ�
                �������û�б������Ļ�*/ 
                prvInitialiseDHCP();
                /*2016--12--01--17--10--20(ZJYC): �鿴�Ƿ�if prvInitialiseDHCP()�Ѿ������׽���   */ 
                if( xDHCPData.xDHCPSocket == NULL )
                {
                    xGivingUp = pdTRUE;
                    break;
                }
                *ipLOCAL_IP_ADDRESS_POINTER = 0UL;
                /*2016--12--01--17--10--52(ZJYC): ���͵�һ��Discovery��Ϣ   */ 
                if( xDHCPData.xDHCPSocket != NULL )
                {
                    xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                    prvSendDHCPDiscover( );
                    xDHCPData.eDHCPState = eWaitingOffer;
                }
            }
        #if( ipconfigUSE_DHCP_HOOK != 0 )
            else
            {
                if( eAnswer == eDHCPUseDefaults )
                {
                    memcpy( &xNetworkAddressing, &xDefaultAddressing, sizeof( xNetworkAddressing ) );
                }

                /*2016--12--01--17--15--05(ZJYC): �û���ʾDHCP��������������   */ 
                xGivingUp = pdTRUE;
            }
        #endif  /* ipconfigUSE_DHCP_HOOK */
            break;

        case eWaitingOffer :

            xGivingUp = pdFALSE;

            /*2016--12--01--17--15--40(ZJYC): �ȴ�offer�ĵ���   */ 
            if( prvProcessDHCPReplies( dhcpMESSAGE_TYPE_OFFER ) == pdPASS )
            {
            #if( ipconfigUSE_DHCP_HOOK != 0 )
                /*2016--12--01--17--15--58(ZJYC): ���û��Ƿ���ҪDHCP����   */ 
                eAnswer = xApplicationDHCPHook( eDHCPPhasePreRequest, xDHCPData.ulOfferedIPAddress );

                if( eAnswer == eDHCPContinue )
            #endif  /* ipconfigUSE_DHCP_HOOK */
                {
                    /*2016--12--01--17--18--07(ZJYC): �Ѿ��յ�һoffer���û�ϣ����������������   */ 
                    xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                    xDHCPData.xDHCPTxPeriod = dhcpINITIAL_DHCP_TX_PERIOD;
                    prvSendDHCPRequest( );
                    xDHCPData.eDHCPState = eWaitingAcknowledge;
                    break;
                }
            #if( ipconfigUSE_DHCP_HOOK != 0 )
                if( eAnswer == eDHCPUseDefaults )
                {
                    memcpy( &xNetworkAddressing, &xDefaultAddressing, sizeof( xNetworkAddressing ) );
                }
                /*2016--12--01--17--26--33(ZJYC): �û���ʾDHCP��������������   */ 
                xGivingUp = pdTRUE;
            #endif  /* ipconfigUSE_DHCP_HOOK */
            }
            else if( ( xTaskGetTickCount() - xDHCPData.xDHCPTxTime ) > xDHCPData.xDHCPTxPeriod )
            {
                /*2016--12--01--17--27--09(ZJYC): ��ʱ������һ��Discovery�ˣ�����ʱ�䣬�����û
                ��������ʱ�򣬷�����һ��Discovery*/ 
                xDHCPData.xDHCPTxPeriod <<= 1;
                if( xDHCPData.xDHCPTxPeriod <= ipconfigMAXIMUM_DISCOVER_TX_PERIOD )
                {
                    xDHCPData.ulTransactionId++;
                    xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                    xDHCPData.xUseBroadcast = !xDHCPData.xUseBroadcast;
                    prvSendDHCPDiscover( );
                    FreeRTOS_debug_printf( ( "vDHCPProcess: timeout %lu ticks\n", xDHCPData.xDHCPTxPeriod ) );
                }
                else
                {
                    FreeRTOS_debug_printf( ( "vDHCPProcess: giving up %lu > %lu ticks\n", xDHCPData.xDHCPTxPeriod, ipconfigMAXIMUM_DISCOVER_TX_PERIOD ) );
                    #if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
                    {
                        /*2016--12--01--17--29--14(ZJYC): ���Ĭ�ϵ�ַΪ0����ʹ����·���ַ����ֻ��
                        ���ͼ�ACK����ʼ���������·���ַ����һ״̬������eGetLinkLayerAddress*/ 
                        prvPrepareLinkLayerIPLookUp();
                        /*2016--12--01--17--32--28(ZJYC): �ֶ�����IP��ַ����������Ϊ��ʹ����Լ��ַ   */ 
                        xDHCPData.eDHCPState = eGetLinkLayerAddress;
                    }
                    #else
                    {
                        xGivingUp = pdTRUE;
                    }
                    #endif /* ipconfigDHCP_FALL_BACK_AUTO_IP */
                }
            }
            break;
        case eWaitingAcknowledge :
            /*2016--12--01--17--33--29(ZJYC): �ȴ�ACK�ĵ���   */ 
            if( prvProcessDHCPReplies( dhcpMESSAGE_TYPE_ACK ) == pdPASS )
            {
                FreeRTOS_debug_printf( ( "vDHCPProcess: acked %lxip\n", FreeRTOS_ntohl( xDHCPData.ulOfferedIPAddress ) ) );
                /*2016--12--01--17--33--44(ZJYC): DHCP��ɣ�IP��ַ���ڿ���ʹ���ˣ�Ȼ��������Լ��ʱʱ��   */ 
                *ipLOCAL_IP_ADDRESS_POINTER = xDHCPData.ulOfferedIPAddress;
                /*2016--12--01--17--34--36(ZJYC): ���ñ��ع㲥��ַ��������192.168.1.255   */ 
                xNetworkAddressing.ulBroadcastAddress = ( xDHCPData.ulOfferedIPAddress & xNetworkAddressing.ulNetMask ) |  ~xNetworkAddressing.ulNetMask;
                xDHCPData.eDHCPState = eLeasedAddress;
                iptraceDHCP_SUCCEDEED( xDHCPData.ulOfferedIPAddress );
                /*2016--12--01--17--35--27(ZJYC): ����network-up�¼���������ARP��ʱ��   */ 
                vIPNetworkUpCalls( );
                /*2016--12--01--17--38--28(ZJYC): �ر��׽��֣�ȷ�����ݰ��������������Ŷ�   */ 
                vSocketClose( xDHCPData.xDHCPSocket );
                xDHCPData.xDHCPSocket = NULL;
                if( xDHCPData.ulLeaseTime == 0UL )
                {
                    xDHCPData.ulLeaseTime = dhcpDEFAULT_LEASE_TIME;
                }
                else if( xDHCPData.ulLeaseTime < dhcpMINIMUM_LEASE_TIME )
                {
                    xDHCPData.ulLeaseTime = dhcpMINIMUM_LEASE_TIME;
                }
                else
                {
                    /* The lease time is already valid. */
                }
                /*2016--12--01--18--27--36(ZJYC): �����ײ   */ 
                vARPSendGratuitous();
                vIPReloadDHCPTimer( xDHCPData.ulLeaseTime );
            }
            else
            {
                /*2016--12--01--18--28--22(ZJYC): ��ʱ������һ��Discovery��   */ 
                if( ( xTaskGetTickCount() - xDHCPData.xDHCPTxTime ) > xDHCPData.xDHCPTxPeriod )
                {
                    /*2016--12--01--18--28--49(ZJYC): �����¼��������û��������ʱ�򣬷�����һ������   */ 
                    xDHCPData.xDHCPTxPeriod <<= 1;
                    if( xDHCPData.xDHCPTxPeriod <= ipconfigMAXIMUM_DISCOVER_TX_PERIOD )
                    {
                        xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                        prvSendDHCPRequest( );
                    }
                    else
                    {
                        /*2016--12--01--18--29--25(ZJYC): �ٿ�ʼһ��   */ 
                        xDHCPData.eDHCPState = eWaitingSendFirstDiscover;
                    }
                }
            }
            break;
    #if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
        case eGetLinkLayerAddress:
            if( ( xTaskGetTickCount() - xDHCPData.xDHCPTxTime ) > xDHCPData.xDHCPTxPeriod )
            {
                if( xARPHadIPClash == pdFALSE )
                {
                    /*2016--12--01--18--30--50(ZJYC): ARP��ⲻ��ײ����������   */ 
                    iptraceDHCP_SUCCEDEED( xDHCPData.ulOfferedIPAddress );
                    /*2016--12--01--18--31--15(ZJYC): �Զ�IP������ɣ�Ĭ�����õ�IP��ַ����ʹ��
                    ���ڣ�����vIPNetworkUpCalls()����network-up �¼�������ARP��ʱ��*/ 
                    vIPNetworkUpCalls( );
                    xDHCPData.eDHCPState = eNotUsingLeasedAddress;
                }
                else
                {
                    /*2016--12--01--18--32--39(ZJYC): ARP������ײ��������һ��IP��ַ   */ 
                    prvPrepareLinkLayerIPLookUp();
                    /*2016--12--01--18--33--12(ZJYC): �ֶ�����IP��ַ�����Բ���ʹ����Լ��ַ   */ 
                    xDHCPData.eDHCPState = eGetLinkLayerAddress;
                }
            }
            break;
    #endif  /* ipconfigDHCP_FALL_BACK_AUTO_IP */
        case eLeasedAddress :
            /*2016--12--01--18--33--57(ZJYC): ���ʵ���ʱ�����·��������Ը�����Լ   */ 
            prvCreateDHCPSocket();

            if( xDHCPData.xDHCPSocket != NULL )
            {
                xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                xDHCPData.xDHCPTxPeriod = dhcpINITIAL_DHCP_TX_PERIOD;
                prvSendDHCPRequest( );
                xDHCPData.eDHCPState = eWaitingAcknowledge;
                /*2016--12--01--18--34--49(ZJYC): �����ڿ�ʼ�����ǽ��ᱻ��������   */ 
                vIPReloadDHCPTimer( dhcpINITIAL_TIMER_PERIOD );
            }
            break;
        case eNotUsingLeasedAddress:
            vIPSetDHCPTimerEnableState( pdFALSE );
            break;
        default:
            break;
    }
    if( xGivingUp != pdFALSE )
    {
        /*2016--12--01--18--37--10(ZJYC): ������Ϊ��ʱ������xApplicationDHCPHook���س���
        eDHCPContinue���������ֵ����ζ��ȡ��DHCP*/ 
        /*2016--12--01--18--38--20(ZJYC): �ָ�����̬IP��ַ   */ 
        taskENTER_CRITICAL();
        {
            *ipLOCAL_IP_ADDRESS_POINTER = xNetworkAddressing.ulDefaultIPAddress;
            iptraceDHCP_REQUESTS_FAILED_USING_DEFAULT_IP_ADDRESS( xNetworkAddressing.ulDefaultIPAddress );
        }
        taskEXIT_CRITICAL();

        xDHCPData.eDHCPState = eNotUsingLeasedAddress;
        vIPSetDHCPTimerEnableState( pdFALSE );
        /*2016--12--01--18--38--42(ZJYC): DHCPʧ���ˣ�Ĭ�����õ�IP��ַ����ʹ��
        ���ڣ�����vIPNetworkUpCalls()����network-up �¼�������ARP��ʱ��   */ 
        vIPNetworkUpCalls( );
        /*2016--12--01--18--39--46(ZJYC): ����׽����Ƿ���Ľ�����   */ 
        if( xDHCPData.xDHCPSocket != NULL )
        {
            /*2016--12--01--18--40--05(ZJYC): �ر��׽��֣���ȷ�����ݰ������������Ŷ�   */ 
            vSocketClose( xDHCPData.xDHCPSocket );
            xDHCPData.xDHCPSocket = NULL;
        }
    }
}
/*-----------------------------------------------------------*/

static void prvCreateDHCPSocket( void )
{
struct freertos_sockaddr xAddress;
BaseType_t xReturn;
TickType_t xTimeoutTime = ( TickType_t ) 0;
    /*2016--12--01--18--40--41(ZJYC): �����û�����Ļ���������   */ 
    if( xDHCPData.xDHCPSocket == NULL )
    {
        xDHCPData.xDHCPSocket = FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_DGRAM, FREERTOS_IPPROTO_UDP );
        if( xDHCPData.xDHCPSocket != FREERTOS_INVALID_SOCKET )
        {
            /*2016--12--01--18--41--03(ZJYC): ȷ��Rx��Tx��ʱʱ��Ϊ0.��ΪDHCP��IP������ִ��   */ 
            FreeRTOS_setsockopt( xDHCPData.xDHCPSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
            FreeRTOS_setsockopt( xDHCPData.xDHCPSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
            /*2016--12--01--18--42--57(ZJYC): �󶨵���׼DHCP�ͻ��˿�0x44   */ 
            xAddress.sin_port = ( uint16_t ) dhcpCLIENT_PORT;
            xReturn = vSocketBind( xDHCPData.xDHCPSocket, &xAddress, sizeof( xAddress ), pdFALSE );
            if( xReturn != 0 )
            {
                /*2016--12--01--18--43--56(ZJYC): ��ʧ�ܣ��ٴιر��׽���   */ 
                vSocketClose( xDHCPData.xDHCPSocket );
                xDHCPData.xDHCPSocket = NULL;
            }
        }
        else
        {
            /*2016--12--01--18--44--44(ZJYC): ������Ϊ0һ�����ļ�⵽��   */ 
            xDHCPData.xDHCPSocket = NULL;
        }
    }
}
/*-----------------------------------------------------------*/

static void prvInitialiseDHCP( void )
{
    /*2016--12--01--18--45--11(ZJYC): ��ʼ��DHCP������Ҫ�Ĳ���   */ 
    if( xDHCPData.ulTransactionId == 0ul )
    {
        xDHCPData.ulTransactionId = ipconfigRAND32();
    }
    else
    {
        xDHCPData.ulTransactionId++;
    }
    xDHCPData.xUseBroadcast = 0;
    xDHCPData.ulOfferedIPAddress = 0UL;
    xDHCPData.ulDHCPServerAddress = 0UL;
    xDHCPData.xDHCPTxPeriod = dhcpINITIAL_DHCP_TX_PERIOD;
    /*2016--12--01--18--45--47(ZJYC): ���û���򴴽��׽���   */ 
    prvCreateDHCPSocket();
    FreeRTOS_debug_printf( ( "prvInitialiseDHCP: start after %lu ticks\n", dhcpINITIAL_TIMER_PERIOD ) );
    vIPReloadDHCPTimer( dhcpINITIAL_TIMER_PERIOD );
}
/*-----------------------------------------------------------*/

static BaseType_t prvProcessDHCPReplies( BaseType_t xExpectedMessageType )
{
uint8_t *pucUDPPayload, *pucLastByte;
struct freertos_sockaddr xClient;
uint32_t xClientLength = sizeof( xClient );
int32_t lBytes;
DHCPMessage_t *pxDHCPMessage;
uint8_t *pucByte, ucOptionCode, ucLength;
uint32_t ulProcessed, ulParameter;
BaseType_t xReturn = pdFALSE;
const uint32_t ulMandatoryOptions = 2ul; 
    /*2016--12--01--18--46--22(ZJYC): DHCP��������ַ����ȷ��DHCP��Ϣ���ͱ�����ѡ������ʾ   */ 
    lBytes = FreeRTOS_recvfrom( xDHCPData.xDHCPSocket, ( void * ) &pucUDPPayload, 0ul, FREERTOS_ZERO_COPY, &xClient, &xClientLength );
    if( lBytes > 0 )
    {
        /*2016--12--01--18--47--30(ZJYC): ӳ�䵽���յ�����Ϣ   */ 
        pxDHCPMessage = ( DHCPMessage_t * ) ( pucUDPPayload );
        /*2016--12--01--18--48--58(ZJYC): �����Լ��   */ 
        if( ( pxDHCPMessage->ulDHCPCookie == ( uint32_t ) dhcpCOOKIE ) &&
            ( pxDHCPMessage->ucOpcode == ( uint8_t ) dhcpREPLY_OPCODE ) &&
            ( pxDHCPMessage->ulTransactionID == FreeRTOS_htonl( xDHCPData.ulTransactionId ) ) )
        {
            /*2016--12--01--18--49--50(ZJYC): �ȶ��û�Ӳ����ַ   */ 
            if( memcmp( ( void * ) &( pxDHCPMessage->ucClientHardwareAddress ), ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) ) == 0 )
            {
                /*2016--12--01--18--50--03(ZJYC): ���ڹؼ�ѡ����Ϣһ��Ҳû������   */ 
                ulProcessed = 0ul;
                /*2016--12--01--18--50--41(ZJYC): ����ѡ��ֱ��dhcpOPTION_END_BYTE�����֣�
                ע�ⲻҪ�ܶ���*/ 
                pucByte = &( pxDHCPMessage->ucFirstOptionByte );
                pucLastByte = &( pucUDPPayload[ lBytes - dhcpMAX_OPTION_LENGTH_OF_INTEREST ] );
                while( pucByte < pucLastByte )
                {
                    ucOptionCode = pucByte[ 0 ];
                    if( ucOptionCode == dhcpOPTION_END_BYTE )
                    {
                        /*2016--12--01--18--51--39(ZJYC): ���������һ���ֽ�   */ 
                        break;
                    }
                    if( ucOptionCode == dhcpZERO_PAD_OPTION_CODE )
                    {
                        /*2016--12--01--18--52--38(ZJYC): ����ֽڣ����治����ų���   */ 
                        pucByte += 1;
                        continue;
                    }
                    ucLength = pucByte[ 1 ];
                    pucByte += 2;
                    /* In most cases, a 4-byte network-endian parameter follows,
                    just get it once here and use later */
                    /*2016--12--01--18--53--04(ZJYC): �󲿷�����£�4�ֽ�   */ 
                    memcpy( ( void * ) &( ulParameter ), ( void * ) pucByte, ( size_t ) sizeof( ulParameter ) );

                    switch( ucOptionCode )
                    {
                        /*2016--12--01--18--57--20(ZJYC): 0x53��Ϣ����
                        1-DHCPDISCOVER 
                        2-DHCPOFFER 
                        3-DHCPREQUEST 
                        4-DHCPDECLINE 
                        5-DHCPACK 
                        6-DHCPNAK 
                        7-DHCPRELEASE 
                        8-DHCPINFORM
                        */ 
                        case dhcpMESSAGE_TYPE_OPTION_CODE   :

                            if( *pucByte == ( uint8_t ) xExpectedMessageType )
                            {
                                /*2016--12--01--18--59--29(ZJYC): ���������ָ������Ҫ����Ϣ   */ 
                                ulProcessed++;
                            }
                            else if( *pucByte == ( uint8_t ) dhcpMESSAGE_TYPE_NACK )
                            {
                                if( xExpectedMessageType == ( BaseType_t ) dhcpMESSAGE_TYPE_ACK )
                                {
                                    /*2016--12--01--19--00--02(ZJYC): ���ܾ��ˣ����¿�ʼ��   */ 
                                    xDHCPData.eDHCPState = eWaitingSendFirstDiscover;
                                }
                            }
                            else
                            {
                                /* Don't process other message types. */
                            }
                            break;
                        /*2016--12--01--19--00--46(ZJYC): 1 ��������   */ 
                        case dhcpSUBNET_MASK_OPTION_CODE :
                            if( ucLength == sizeof( uint32_t ) )
                            {
                                xNetworkAddressing.ulNetMask = ulParameter;
                            }
                            break;
                        /*2016--12--01--19--02--10(ZJYC): 3 ���ص�ַ   */ 
                        case dhcpGATEWAY_OPTION_CODE :

                            if( ucLength == sizeof( uint32_t ) )
                            {
                                /*2016--12--01--19--02--44(ZJYC): ulProcessed�����ﲻ�����ˣ���Ϊ������Ҫ   */ 
                                xNetworkAddressing.ulGatewayAddress = ulParameter;
                            }
                            break;
                        /*2016--12--01--19--03--32(ZJYC): 6 DNS������   */ 
                        case dhcpDNS_SERVER_OPTIONS_CODE :
                            /*2016--12--01--19--03--52(ZJYC): ulProcessed������Ͳ������ˣ���ΪDNS����������Ҫ
                            ֻ�е�һ��DNS������������*/ 
                            xNetworkAddressing.ulDNSServerAddress = ulParameter;
                            break;
                            /*2016--12--01--19--05--16(ZJYC): DHCP��������ʶ��   */ 
                        case dhcpSERVER_IP_ADDRESS_OPTION_CODE :

                            if( ucLength == sizeof( uint32_t ) )
                            {
                                if( xExpectedMessageType == ( BaseType_t ) dhcpMESSAGE_TYPE_OFFER )
                                {
                                    /* Offers state the replying server. */
                                    ulProcessed++;
                                    xDHCPData.ulDHCPServerAddress = ulParameter;
                                }
                                else
                                {
                                    /* The ack must come from the expected server. */
                                    if( xDHCPData.ulDHCPServerAddress == ulParameter )
                                    {
                                        ulProcessed++;
                                    }
                                }
                            }
                            break;
                        /*2016--12--01--19--06--44(ZJYC): ��ַ����   */ 
                        case dhcpLEASE_TIME_OPTION_CODE :

                            if( ucLength == sizeof( &( xDHCPData.ulLeaseTime ) ) )
                            {
                                /*2016--12--01--19--07--28(ZJYC): ulProcessed�����ӣ���Ϊ����Ҫ
                                ��ʱ������Ϊ��λ��ת�������ǵĸ�ʽ*/ 
                                xDHCPData.ulLeaseTime = FreeRTOS_ntohl( ulParameter );
                                /*2016--12--01--19--08--26(ZJYC): ���ڳ���2���Ա�֤��ǰ��������   */ 
                                xDHCPData.ulLeaseTime >>= 1UL;
                                /*2016--12--01--19--09--09(ZJYC): ת��Ϊ�δ���   */ 
                                xDHCPData.ulLeaseTime = configTICK_RATE_HZ * xDHCPData.ulLeaseTime;
                            }
                            break;
                        default :
                            /* Not interested in this field. */
                            break;
                    }
                    /*2016--12--01--19--09--40(ZJYC): ����������Ѱ����һ��ѡ��   */ 
                    if( ucLength == 0u )
                    {
                        break;
                    }
                    else
                    {
                        pucByte += ucLength;
                    }
                }
                /*2016--12--01--19--10--03(ZJYC): �Ƿ�����ǿ������Ϣ���յ���   */ 
                if( ulProcessed >= ulMandatoryOptions )
                {
                    /*2016--12--01--19--11--03(ZJYC): �����µĵ�ַ   */ 
                    xDHCPData.ulOfferedIPAddress = pxDHCPMessage->ulYourIPAddress_yiaddr;
                    FreeRTOS_printf( ( "vDHCPProcess: offer %lxip\n", FreeRTOS_ntohl( xDHCPData.ulOfferedIPAddress ) ) );
                    xReturn = pdPASS;
                }
            }
        }

        FreeRTOS_ReleaseUDPPayloadBuffer( ( void * ) pucUDPPayload );
    }

    return xReturn;
}
/*-----------------------------------------------------------*/

static uint8_t *prvCreatePartDHCPMessage( struct freertos_sockaddr *pxAddress, BaseType_t xOpcode, const uint8_t * const pucOptionsArray, size_t *pxOptionsArraySize )
{
DHCPMessage_t *pxDHCPMessage;
size_t xRequiredBufferSize = sizeof( DHCPMessage_t ) + *pxOptionsArraySize;
uint8_t *pucUDPPayloadBuffer;

#if( ipconfigDHCP_REGISTER_HOSTNAME == 1 )
    const char *pucHostName = pcApplicationHostnameHook ();
    size_t xNameLength = strlen( pucHostName );
    uint8_t *pucPtr;

    xRequiredBufferSize += ( 2 + xNameLength );
#endif
    /*2016--12--01--19--11--31(ZJYC): ��ȡһ���棬����������ӳ٣�ͬʱҲ��������ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS
    ���Է���ֵ��Ҫ���*/ 
    do
    {
    } while( ( pucUDPPayloadBuffer = ( uint8_t * ) FreeRTOS_GetUDPPayloadBuffer( xRequiredBufferSize, portMAX_DELAY ) ) == NULL );
    pxDHCPMessage = ( DHCPMessage_t * ) pucUDPPayloadBuffer;
    /*2016--12--01--19--12--58(ZJYC): ����   */ 
    memset( ( void * ) pxDHCPMessage, 0x00, sizeof( DHCPMessage_t ) );
    /*2016--12--01--19--13--11(ZJYC): ������Ϣ   */ 
    pxDHCPMessage->ucOpcode = ( uint8_t ) xOpcode;
    pxDHCPMessage->ucAddressType = ( uint8_t ) dhcpADDRESS_TYPE_ETHERNET;
    pxDHCPMessage->ucAddressLength = ( uint8_t ) dhcpETHERNET_ADDRESS_LENGTH;
    /*2016--12--01--19--13--19(ZJYC): ulTransactionIDȷʵ����Ҫ�ֽڻ��򣬵��ǵ�DHCP
    ��ʱ������������ӵ�ID����*/ 
    pxDHCPMessage->ulTransactionID = FreeRTOS_htonl( xDHCPData.ulTransactionId );
    pxDHCPMessage->ulDHCPCookie = ( uint32_t ) dhcpCOOKIE;
    if( xDHCPData.xUseBroadcast != pdFALSE )
    {
        pxDHCPMessage->usFlags = ( uint16_t ) dhcpBROADCAST;
    }
    else
    {
        pxDHCPMessage->usFlags = 0u;
    }
    /*2016--12--01--19--15--34(ZJYC): ��䱾��MAC��ַ   */ 
    memcpy( ( void * ) &( pxDHCPMessage->ucClientHardwareAddress[ 0 ] ), ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) );
    /*2016--12--01--19--16--00(ZJYC): ���Ƴ���ѡ���ֶ�   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET ] ), ( void * ) pucOptionsArray, *pxOptionsArraySize );
    #if( ipconfigDHCP_REGISTER_HOSTNAME == 1 )
    {
        /*2016--12--01--19--16--41(ZJYC): �����ѡ����������Ա�ע����·��
        ������Ѱ��*/ 
        /*2016--12--01--19--18--13(ZJYC): ָ��OPTION_END���ڵأ��������Ϣ   */ 
        pucPtr = &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + ( *pxOptionsArraySize - 1 ) ] );
        pucPtr[ 0 ] = dhcpDNS_HOSTNAME_OPTIONS_CODE;
        pucPtr[ 1 ] = ( uint8_t ) xNameLength;
        memcpy( ( void *) ( pucPtr + 2 ), pucHostName, xNameLength );
        pucPtr[ 2 + xNameLength ] = dhcpOPTION_END_BYTE;
        *pxOptionsArraySize += ( 2 + xNameLength );
    }
    #endif
    /*2016--12--01--19--18--59(ZJYC): ����ͻ��˱��   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + dhcpCLIENT_IDENTIFIER_OFFSET ] ),
        ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) );
    /*2016--12--01--19--19--13(ZJYC): ���õ�ַ   */ 
    pxAddress->sin_addr = ipBROADCAST_IP_ADDRESS;
    pxAddress->sin_port = ( uint16_t ) dhcpSERVER_PORT;

    return pucUDPPayloadBuffer;
}
/*-----------------------------------------------------------*/

static void prvSendDHCPRequest( void )
{
uint8_t *pucUDPPayloadBuffer;
struct freertos_sockaddr xAddress;
static const uint8_t ucDHCPRequestOptions[] =
{
    /*2016--12--01--19--19--34(ZJYC): ��Ҫ�ٲ��ı�dhcpCLIENT_IDENTIFIER_OFFSET��
    dhcpREQUESTED_IP_ADDRESS_OFFSET �� dhcpDHCP_SERVER_IP_ADDRESS_OFFSET������¸���˳��*/ 
    dhcpMESSAGE_TYPE_OPTION_CODE, 1, dhcpMESSAGE_TYPE_REQUEST,      /*2016--12--01--19--20--52(ZJYC): ��Ϣ����   */ 
    dhcpCLIENT_IDENTIFIER_OPTION_CODE, 6, 0, 0, 0, 0, 0, 0,         /*2016--12--01--19--21--01(ZJYC): �û���ʶ   */ 
    dhcpREQUEST_IP_ADDRESS_OPTION_CODE, 4, 0, 0, 0, 0,              /*2016--12--01--19--21--17(ZJYC): ��Ҫ��IP��ַ   */ 
    dhcpSERVER_IP_ADDRESS_OPTION_CODE, 4, 0, 0, 0, 0,               /*2016--12--01--19--21--30(ZJYC): DHCP��������ַ   */ 
    dhcpOPTION_END_BYTE
};
size_t xOptionsLength = sizeof( ucDHCPRequestOptions );
    pucUDPPayloadBuffer = prvCreatePartDHCPMessage( &xAddress, dhcpREQUEST_OPCODE, ucDHCPRequestOptions, &xOptionsLength );
    /*2016--12--01--19--22--09(ZJYC): ���ƽ�ȥ����ĵ�ַ   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + dhcpREQUESTED_IP_ADDRESS_OFFSET ] ),
        ( void * ) &( xDHCPData.ulOfferedIPAddress ), sizeof( xDHCPData.ulOfferedIPAddress ) );
    /*2016--12--01--19--22--23(ZJYC): ���Ʒ�������ַ   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + dhcpDHCP_SERVER_IP_ADDRESS_OFFSET ] ),
        ( void * ) &( xDHCPData.ulDHCPServerAddress ), sizeof( xDHCPData.ulDHCPServerAddress ) );
    FreeRTOS_debug_printf( ( "vDHCPProcess: reply %lxip\n", FreeRTOS_ntohl( xDHCPData.ulOfferedIPAddress ) ) );
    iptraceSENDING_DHCP_REQUEST();
    if( FreeRTOS_sendto( xDHCPData.xDHCPSocket, pucUDPPayloadBuffer, ( sizeof( DHCPMessage_t ) + xOptionsLength ), FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) ) == 0 )
    {
        /*2016--12--01--19--22--42(ZJYC): ����ʧ��   */ 
        FreeRTOS_ReleaseUDPPayloadBuffer( pucUDPPayloadBuffer );
    }
}
/*-----------------------------------------------------------*/

static void prvSendDHCPDiscover( void )
{
uint8_t *pucUDPPayloadBuffer;
struct freertos_sockaddr xAddress;
static const uint8_t ucDHCPDiscoverOptions[] =
{
    /*2016--12--01--19--23--14(ZJYC): ��Ҫ�ٲ��ı�dhcpCLIENT_IDENTIFIER_OFFSET������¸ı�˳��   */ 
    dhcpMESSAGE_TYPE_OPTION_CODE, 1, dhcpMESSAGE_TYPE_DISCOVER,                 /*2016--12--01--19--23--39(ZJYC): ��Ϣ����   */ 
    dhcpCLIENT_IDENTIFIER_OPTION_CODE, 6, 0, 0, 0, 0, 0, 0,                     /*2016--12--01--19--23--49(ZJYC): �û���ʶ   */ 
    dhcpPARAMETER_REQUEST_OPTION_CODE, 3, dhcpSUBNET_MASK_OPTION_CODE, dhcpGATEWAY_OPTION_CODE, dhcpDNS_SERVER_OPTIONS_CODE,    /*2016--12--01--19--24--07(ZJYC): ����ѡ��   */ 
    dhcpOPTION_END_BYTE
};
size_t xOptionsLength = sizeof( ucDHCPDiscoverOptions );

    pucUDPPayloadBuffer = prvCreatePartDHCPMessage( &xAddress, dhcpREQUEST_OPCODE, ucDHCPDiscoverOptions, &xOptionsLength );

    FreeRTOS_debug_printf( ( "vDHCPProcess: discover\n" ) );
    iptraceSENDING_DHCP_DISCOVER();

    if( FreeRTOS_sendto( xDHCPData.xDHCPSocket, pucUDPPayloadBuffer, ( sizeof( DHCPMessage_t ) + xOptionsLength ), FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) ) == 0 )
    {
        /*2016--12--01--19--24--32(ZJYC): ����ʧ��   */ 
        FreeRTOS_ReleaseUDPPayloadBuffer( pucUDPPayloadBuffer );
    }
}
/*-----------------------------------------------------------*/

#if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )

    static void prvPrepareLinkLayerIPLookUp( void )
    {
    uint8_t ucLinkLayerIPAddress[ 2 ];
        /*2016--12--01--19--24--45(ZJYC): DHCP����ظ�ʧ��֮��׼������ȥ��ȡ��·���ַ��
        ��ʹ������ķ���*/ 
        xDHCPData.xDHCPTxTime = xTaskGetTickCount();
        ucLinkLayerIPAddress[ 0 ] = ( uint8_t )1 + ( uint8_t )( ipconfigRAND32() % 0xFDu );     /* get value 1..254 for IP-address 3rd byte of IP address to try. */
        ucLinkLayerIPAddress[ 1 ] = ( uint8_t )1 + ( uint8_t )( ipconfigRAND32() % 0xFDu );     /* get value 1..254 for IP-address 4th byte of IP address to try. */
        xNetworkAddressing.ulGatewayAddress = FreeRTOS_htonl( 0xA9FE0203 );
        /*2016--12--01--19--25--52(ZJYC): ׼��xDHCPData����   */ 
        xDHCPData.ulOfferedIPAddress =
            FreeRTOS_inet_addr_quick( LINK_LAYER_ADDRESS_0, LINK_LAYER_ADDRESS_1, ucLinkLayerIPAddress[ 0 ], ucLinkLayerIPAddress[ 1 ] );
        xDHCPData.ulLeaseTime = dhcpDEFAULT_LEASE_TIME;
        /*2016--12--01--19--26--39(ZJYC): ��Ҫ�������ڣ�   */ 
        xNetworkAddressing.ulNetMask =
            FreeRTOS_inet_addr_quick( LINK_LAYER_NETMASK_0, LINK_LAYER_NETMASK_1, LINK_LAYER_NETMASK_2, LINK_LAYER_NETMASK_3 );
        /*2016--12--01--19--27--09(ZJYC): DHCP��ɣ�IP��ַ���ڻ�����ʹ��
        ������Լ��ʱʱ��*/ 
        *ipLOCAL_IP_ADDRESS_POINTER = xDHCPData.ulOfferedIPAddress;
        /*2016--12--01--19--27--53(ZJYC): ���ñ��ع㲥��ַ��������192.168.1.255   */ 
        xNetworkAddressing.ulBroadcastAddress = ( xDHCPData.ulOfferedIPAddress & xNetworkAddressing.ulNetMask ) |  ~xNetworkAddressing.ulNetMask;
        /*2016--12--01--19--28--23(ZJYC): �ر��׽���ȷ�����Ŷӣ���ΪDHCPʧ�����Բ������׽��֡�������Ȼ��Ҫ��ʱ���Խ���ARP���   */ 
        vSocketClose( xDHCPData.xDHCPSocket );
        xDHCPData.xDHCPSocket = NULL;
        xDHCPData.xDHCPTxPeriod = pdMS_TO_TICKS( 3000ul + ( ipconfigRAND32() & 0x3fful ) ); 
        /*2016--12--01--19--29--42(ZJYC): ÿ 3 + 0-1024mS)��һ��ARP���  */ 
        /*2016--12--01--19--30--07(ZJYC): ��λARP��ײ����   */ 
        xARPHadIPClash = pdFALSE;
        vARPSendGratuitous();
    }

#endif /* ipconfigDHCP_FALL_BACK_AUTO_IP */
/*-----------------------------------------------------------*/

#endif /* ipconfigUSE_DHCP != 0 */


