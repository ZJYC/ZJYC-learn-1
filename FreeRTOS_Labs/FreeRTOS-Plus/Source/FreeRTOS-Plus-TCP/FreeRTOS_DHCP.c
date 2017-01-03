
/* 标准头文件 */
#include <stdint.h>

/*2016--12--01--11--08--51(ZJYC): FREERTOS头文件   */ 
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

/*2016--12--01--11--08--51(ZJYC): FREERTOS+TCP头文件   */ 
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_TCP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "FreeRTOS_ARP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"

/*2016--12--01--11--08--51(ZJYC): 如果DHCP未使能则排除所有   */ 
#if( ipconfigUSE_DHCP != 0 )

#if ( ipconfigUSE_DHCP != 0 ) && ( ipconfigNETWORK_MTU < 586u )
    /*2016--12--01--11--10--21(ZJYC): DHCP必须能够接收312字节的选项区域，DHCP
    报文的固定部分是240字节，而且IP/UDP头部占用28字节，312+240+28 = 580？？？*/ 
    #error ipconfigNETWORK_MTU needs to be at least 586 to use DHCP
#endif

/*2016--12--01--14--00--49(ZJYC): DHCP包的参数   */ 
#define dhcpCLIENT_HARDWARE_ADDRESS_LENGTH      16
#define dhcpSERVER_HOST_NAME_LENGTH             64
#define dhcpBOOT_FILE_NAME_LENGTH               128

/*2016--12--01--14--01--05(ZJYC): DHCP时间参数   */ 
#ifndef dhcpINITIAL_DHCP_TX_PERIOD
    #define dhcpINITIAL_TIMER_PERIOD            ( pdMS_TO_TICKS( 250 ) )
    #define dhcpINITIAL_DHCP_TX_PERIOD          ( pdMS_TO_TICKS( 5000 ) )
#endif

/*2016--12--01--14--01--24(ZJYC): DHCP选项区有用的标志   */ 
/*2016--12--02--08--39--18(ZJYC): 0 填充字节 长度0   */ 
#define dhcpZERO_PAD_OPTION_CODE                ( 0u )
/*2016--12--02--08--39--31(ZJYC): 1 子网掩码 长度4   */ 
#define dhcpSUBNET_MASK_OPTION_CODE             ( 1u )
/*2016--12--02--08--47--51(ZJYC): 2 时间偏移 长度4   */ 
/*2016--12--02--08--39--59(ZJYC): 3 路由地址 长度 n*4   */ 
#define dhcpGATEWAY_OPTION_CODE                 ( 3u )
/*2016--12--02--08--49--19(ZJYC): 4 时间服务器 长度 n*4   */ 
/*2016--12--02--08--49--42(ZJYC): 5 名称服务器 长度 n*4   */ 
/*2016--12--02--08--50--17(ZJYC): 6 域名服务器 长度 n*4   */ 
#define dhcpDNS_SERVER_OPTIONS_CODE             ( 6u )
/*2016--12--02--08--50--42(ZJYC): 7 日志服务器 长度 n*4   */ 
/*2016--12--02--08--52--59(ZJYC): 8 Cookie服务器 长度 n*4   */
/*2016--12--02--08--53--41(ZJYC): 9 LPR服务器 长度 n*4   */ 
/*2016--12--02--08--54--34(ZJYC): 10 Impress 服务器 长度 n*4   */ 
/*2016--12--02--08--55--32(ZJYC): 11 资源位置服务器 长度 n*4   */ 
/*2016--12--02--08--56--25(ZJYC): 12 主机名 长度 至少1字节  */ 
#define dhcpDNS_HOSTNAME_OPTIONS_CODE           ( 12u )
/*2016--12--02--08--57--12(ZJYC): 13 启动文件大小 长度 2字节   */ 
/*2016--12--02--08--58--57(ZJYC): 14 转储文件 长度 至少1字节  */ 
/*2016--12--02--09--05--45(ZJYC): 15 域名 长度 至少1字节   */ 
/*2016--12--02--09--06--10(ZJYC): 16 交换服务器 长度4字节   */ 
/*2016--12--02--09--08--44(ZJYC): 17 根路径 长度 至少1字节  */ 
/*2016--12--02--09--09--16(ZJYC): 18 拓展路径 长度 至少1字节  */ 
/*2016--12--02--09--10--31(ZJYC): 50 请求的IP地址 长度 4字节   */ 
#define dhcpREQUEST_IP_ADDRESS_OPTION_CODE      ( 50u )
/*2016--12--02--09--11--02(ZJYC): 51 IP地址租期 长度 4字节   */ 
#define dhcpLEASE_TIME_OPTION_CODE              ( 51u )
/*2016--12--02--09--11--26(ZJYC): 53 消息类型 长度 1字节   */ 
#define dhcpMESSAGE_TYPE_OPTION_CODE            ( 53u )
/*2016--12--02--09--17--20(ZJYC): 54 服务器标示 4字节   */ 
#define dhcpSERVER_IP_ADDRESS_OPTION_CODE       ( 54u )
/*2016--12--02--09--17--42(ZJYC): 55 参数清单 至少1字节   */ 
#define dhcpPARAMETER_REQUEST_OPTION_CODE       ( 55u )
/*2016--12--02--09--18--12(ZJYC): 61 客户端标示 至少2字节   */ 
#define dhcpCLIENT_IDENTIFIER_OPTION_CODE       ( 61u )
/*2016--12--02--09--09--45(ZJYC): 255 结束符   */ 
/*2016--12--01--14--08--22(ZJYC): 四种DHCP消息类型   */ 
#define dhcpMESSAGE_TYPE_DISCOVER               ( 1 )
#define dhcpMESSAGE_TYPE_OFFER                  ( 2 )
#define dhcpMESSAGE_TYPE_REQUEST                ( 3 )
#define dhcpMESSAGE_TYPE_ACK                    ( 5 )
#define dhcpMESSAGE_TYPE_NACK                   ( 6 )

/*2016--12--01--14--08--22(ZJYC): 部分信息在DHCP报文中的索引   */ 
#define dhcpCLIENT_IDENTIFIER_OFFSET            ( 5 )
#define dhcpREQUESTED_IP_ADDRESS_OFFSET         ( 13 )
#define dhcpDHCP_SERVER_IP_ADDRESS_OFFSET       ( 19 )

/*2016--12--01--14--10--34(ZJYC): DHCP常用数值   */ 
#define dhcpREQUEST_OPCODE                      ( 1 )
#define dhcpREPLY_OPCODE                        ( 2 )
#define dhcpADDRESS_TYPE_ETHERNET               ( 1 )
#define dhcpETHERNET_ADDRESS_LENGTH             ( 6 )
/*2016--12--01--14--11--15(ZJYC): 如果租约未到，使用默认的2天，48H用ticks表示，
不能使用pdMS_TO_TICKS()，因为会溢出   */ 
#define dhcpDEFAULT_LEASE_TIME                  ( ( 48UL * 60UL * 60UL ) * configTICK_RATE_HZ )

/*2016--12--01--14--24--12(ZJYC): 不能让租约时间太短   */ 
#define dhcpMINIMUM_LEASE_TIME                  ( pdMS_TO_TICKS( 60000UL ) )    /* 60 seconds in ticks. */

/*2016--12--01--14--24--43(ZJYC): 标记选项字段结束标志   */ 
#define dhcpOPTION_END_BYTE 0xffu

/*2016--12--01--14--27--22(ZJYC): 选项字段的索引240   */ 
#define dhcpFIRST_OPTION_BYTE_OFFSET            ( 0xf0 )
/*2016--12--01--14--28--15(ZJYC): 当遍历可变长度选项字段，一下变量用以保障 
不会超出选项字段，长度用2字节表示，最小1个字节   */ 
#define dhcpMAX_OPTION_LENGTH_OF_INTEREST       ( 2L )
/*2016--12--01--14--29--58(ZJYC): 标准DHCP端口号和magic cookie值   */ 
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

/*2016--12--01--14--30--49(ZJYC): DHCP状态机   */ 
typedef enum
{
    eWaitingSendFirstDiscover = 0,  /*2016--12--01--14--31--04(ZJYC): 初始状态首先发送Discover，并复位所有定时器   */ 
    eWaitingOffer,                  /*2016--12--01--14--32--58(ZJYC): 或者重新发送Discover，或者如果offer即将到来，发送一请求   */
    eWaitingAcknowledge,            /*2016--12--01--14--35--22(ZJYC): 或者重新发送请求   */ 
    #if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
        eGetLinkLayerAddress,       /*2016--12--01--14--36--12(ZJYC): 当DHCP没有回复，尝试获取链路层地址168.254.x.x.   */
    #endif
    eLeasedAddress,                 /*2016--12--01--14--37--06(ZJYC): 适当的时刻重新发送请求已更新租约   */ 
    eNotUsingLeasedAddress          /*2016--12--01--14--37--35(ZJYC): DHCP失败，默认地址被使用   */ 
} eDHCPState_t;

/*2016--12--01--14--38--03(ZJYC): 在DHCP状态机中存储信息   */ 
struct xDHCP_DATA
{
    uint32_t ulTransactionId;
    uint32_t ulOfferedIPAddress;
    uint32_t ulDHCPServerAddress;
    uint32_t ulLeaseTime;
    /*2016--12--01--14--39--35(ZJYC): 保存当前定时器状态   */ 
    TickType_t xDHCPTxTime;
    TickType_t xDHCPTxPeriod;
    /*2016--12--01--14--43--49(ZJYC): 尝试不带盒带着广播标志？？？   */ 
    BaseType_t xUseBroadcast;
    /*2016--12--01--14--45--03(ZJYC): 状态机状态   */ 
    eDHCPState_t eDHCPState;
    /*2016--12--01--14--45--23(ZJYC): UDP套接字，用于所有进出流量   */ 
    Socket_t xDHCPSocket;
};

typedef struct xDHCP_DATA DHCPData_t;

#if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
    /*2016--12--01--14--46--05(ZJYC): 定义链路层IP地址169.254.x.x   */ 
    #define LINK_LAYER_ADDRESS_0    169
    #define LINK_LAYER_ADDRESS_1    254
    /*2016--12--01--14--46--31(ZJYC): 定义默认的子网掩码255.255.0.0   */ 
    #define LINK_LAYER_NETMASK_0    255
    #define LINK_LAYER_NETMASK_1    255
    #define LINK_LAYER_NETMASK_2    0
    #define LINK_LAYER_NETMASK_3    0
#endif

/*2016--12--01--14--47--02(ZJYC): 产生DHCP消息并发送到DHCP套接字   */ 
static void prvSendDHCPDiscover( void );

/*2016--12--01--16--11--36(ZJYC): 翻译从DHCP协议栈上接受的消息   */ 
static BaseType_t prvProcessDHCPReplies( BaseType_t xExpectedMessageType );

/*2016--12--01--16--12--30(ZJYC): 长生DHCP请求消息并发送到DHCP套接字上   */ 
static void prvSendDHCPRequest( void );

/*2016--12--01--16--12--59(ZJYC): 准备开始DHCP交易，这初始化一些状态变量，有必要的话创建套接字   */ 
static void prvInitialiseDHCP( void );

/*2016--12--01--17--01--43(ZJYC): 创建向外发送的数据包中共同的部分   */ 
static uint8_t *prvCreatePartDHCPMessage( struct freertos_sockaddr *pxAddress, BaseType_t xOpcode, const uint8_t * const pucOptionsArray, size_t *pxOptionsArraySize );

/*2016--12--01--17--02--33(ZJYC): 创建DHCP套接字，如果没有创建的话   */ 
static void prvCreateDHCPSocket( void );

/*2016--12--01--17--03--25(ZJYC): DHCP没有回答，尽全力去开始搜索链路层IP地址，使用随机的方法
发送一免费ARP并等待是否有人回复   */ 
#if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )
    static void prvPrepareLinkLayerIPLookUp( void );
#endif

/*-----------------------------------------------------------*/

/*2016--12--01--17--06--04(ZJYC): 下一个DHCP交易ID   */ 
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

    /*2016--12--01--17--07--33(ZJYC): DHCP重新开始吗   */ 
    if( xReset != pdFALSE )
    {
        xDHCPData.eDHCPState = eWaitingSendFirstDiscover;
    }

    switch( xDHCPData.eDHCPState )
    {
        case eWaitingSendFirstDiscover :
            /*2016--12--01--17--08--05(ZJYC): 问用户：是否需要DHCP Discovery   */ 
        #if( ipconfigUSE_DHCP_HOOK != 0 )
            eAnswer = xApplicationDHCPHook( eDHCPPhasePreDiscover, xNetworkAddressing.ulDefaultIPAddress );
            if( eAnswer == eDHCPContinue )
        #endif  /* ipconfigUSE_DHCP_HOOK */
            {
                /*2016--12--01--17--09--25(ZJYC): 初始状态 创建DHCP套接字，定时器等等
                如果他们没有被创建的话*/ 
                prvInitialiseDHCP();
                /*2016--12--01--17--10--20(ZJYC): 查看是否if prvInitialiseDHCP()已经创建套接字   */ 
                if( xDHCPData.xDHCPSocket == NULL )
                {
                    xGivingUp = pdTRUE;
                    break;
                }
                *ipLOCAL_IP_ADDRESS_POINTER = 0UL;
                /*2016--12--01--17--10--52(ZJYC): 发送第一个Discovery信息   */ 
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

                /*2016--12--01--17--15--05(ZJYC): 用户表示DHCP服务不用再运行了   */ 
                xGivingUp = pdTRUE;
            }
        #endif  /* ipconfigUSE_DHCP_HOOK */
            break;

        case eWaitingOffer :

            xGivingUp = pdFALSE;

            /*2016--12--01--17--15--40(ZJYC): 等待offer的到来   */ 
            if( prvProcessDHCPReplies( dhcpMESSAGE_TYPE_OFFER ) == pdPASS )
            {
            #if( ipconfigUSE_DHCP_HOOK != 0 )
                /*2016--12--01--17--15--58(ZJYC): 问用户是否需要DHCP请求   */ 
                eAnswer = xApplicationDHCPHook( eDHCPPhasePreRequest, xDHCPData.ulOfferedIPAddress );

                if( eAnswer == eDHCPContinue )
            #endif  /* ipconfigUSE_DHCP_HOOK */
                {
                    /*2016--12--01--17--18--07(ZJYC): 已经收到一offer，用户希望继续，生成请求   */ 
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
                /*2016--12--01--17--26--33(ZJYC): 用户表示DHCP服务不用再运行了   */ 
                xGivingUp = pdTRUE;
            #endif  /* ipconfigUSE_DHCP_HOOK */
            }
            else if( ( xTaskGetTickCount() - xDHCPData.xDHCPTxTime ) > xDHCPData.xDHCPTxPeriod )
            {
                /*2016--12--01--17--27--09(ZJYC): 是时候发送下一个Discovery了，增加时间，如果还没
                到放弃的时候，发送下一个Discovery*/ 
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
                        /*2016--12--01--17--29--14(ZJYC): 如果默认地址为0并且使用链路层地址，则只会
                        发送假ACK。开始搜索免费链路层地址，下一状态将会是eGetLinkLayerAddress*/ 
                        prvPrepareLinkLayerIPLookUp();
                        /*2016--12--01--17--32--28(ZJYC): 手动设置IP地址，所以设置为不使用租约地址   */ 
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
            /*2016--12--01--17--33--29(ZJYC): 等待ACK的到来   */ 
            if( prvProcessDHCPReplies( dhcpMESSAGE_TYPE_ACK ) == pdPASS )
            {
                FreeRTOS_debug_printf( ( "vDHCPProcess: acked %lxip\n", FreeRTOS_ntohl( xDHCPData.ulOfferedIPAddress ) ) );
                /*2016--12--01--17--33--44(ZJYC): DHCP完成，IP地址现在可以使用了，然后设置租约超时时间   */ 
                *ipLOCAL_IP_ADDRESS_POINTER = xDHCPData.ulOfferedIPAddress;
                /*2016--12--01--17--34--36(ZJYC): 设置本地广播地址，类似于192.168.1.255   */ 
                xNetworkAddressing.ulBroadcastAddress = ( xDHCPData.ulOfferedIPAddress & xNetworkAddressing.ulNetMask ) |  ~xNetworkAddressing.ulNetMask;
                xDHCPData.eDHCPState = eLeasedAddress;
                iptraceDHCP_SUCCEDEED( xDHCPData.ulOfferedIPAddress );
                /*2016--12--01--17--35--27(ZJYC): 发送network-up事件，并启动ARP定时器   */ 
                vIPNetworkUpCalls( );
                /*2016--12--01--17--38--28(ZJYC): 关闭套接字，确保数据包不再在他上面排队   */ 
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
                /*2016--12--01--18--27--36(ZJYC): 检测碰撞   */ 
                vARPSendGratuitous();
                vIPReloadDHCPTimer( xDHCPData.ulLeaseTime );
            }
            else
            {
                /*2016--12--01--18--28--22(ZJYC): 是时候发送另一个Discovery？   */ 
                if( ( xTaskGetTickCount() - xDHCPData.xDHCPTxTime ) > xDHCPData.xDHCPTxPeriod )
                {
                    /*2016--12--01--18--28--49(ZJYC): 增减事件，如果还没到放弃的时候，发送另一个请求   */ 
                    xDHCPData.xDHCPTxPeriod <<= 1;
                    if( xDHCPData.xDHCPTxPeriod <= ipconfigMAXIMUM_DISCOVER_TX_PERIOD )
                    {
                        xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                        prvSendDHCPRequest( );
                    }
                    else
                    {
                        /*2016--12--01--18--29--25(ZJYC): 再开始一次   */ 
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
                    /*2016--12--01--18--30--50(ZJYC): ARP检测不碰撞，继续。。   */ 
                    iptraceDHCP_SUCCEDEED( xDHCPData.ulOfferedIPAddress );
                    /*2016--12--01--18--31--15(ZJYC): 自动IP配置完成，默认配置的IP地址将会使用
                    现在，调用vIPNetworkUpCalls()发送network-up 事件并启动ARP定时器*/ 
                    vIPNetworkUpCalls( );
                    xDHCPData.eDHCPState = eNotUsingLeasedAddress;
                }
                else
                {
                    /*2016--12--01--18--32--39(ZJYC): ARP发生碰撞，尝试另一个IP地址   */ 
                    prvPrepareLinkLayerIPLookUp();
                    /*2016--12--01--18--33--12(ZJYC): 手动设置IP地址，所以不再使用租约地址   */ 
                    xDHCPData.eDHCPState = eGetLinkLayerAddress;
                }
            }
            break;
    #endif  /* ipconfigDHCP_FALL_BACK_AUTO_IP */
        case eLeasedAddress :
            /*2016--12--01--18--33--57(ZJYC): 在适当的时间重新发送请求以更新租约   */ 
            prvCreateDHCPSocket();

            if( xDHCPData.xDHCPSocket != NULL )
            {
                xDHCPData.xDHCPTxTime = xTaskGetTickCount();
                xDHCPData.xDHCPTxPeriod = dhcpINITIAL_DHCP_TX_PERIOD;
                prvSendDHCPRequest( );
                xDHCPData.eDHCPState = eWaitingAcknowledge;
                /*2016--12--01--18--34--49(ZJYC): 从现在开始，我们将会被经常调用   */ 
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
        /*2016--12--01--18--37--10(ZJYC): 可能因为超时或者是xApplicationDHCPHook返回除了
        eDHCPContinue以外的其他值，意味着取消DHCP*/ 
        /*2016--12--01--18--38--20(ZJYC): 恢复到静态IP地址   */ 
        taskENTER_CRITICAL();
        {
            *ipLOCAL_IP_ADDRESS_POINTER = xNetworkAddressing.ulDefaultIPAddress;
            iptraceDHCP_REQUESTS_FAILED_USING_DEFAULT_IP_ADDRESS( xNetworkAddressing.ulDefaultIPAddress );
        }
        taskEXIT_CRITICAL();

        xDHCPData.eDHCPState = eNotUsingLeasedAddress;
        vIPSetDHCPTimerEnableState( pdFALSE );
        /*2016--12--01--18--38--42(ZJYC): DHCP失败了，默认配置的IP地址将会使用
        现在，调用vIPNetworkUpCalls()发送network-up 事件并启动ARP定时器   */ 
        vIPNetworkUpCalls( );
        /*2016--12--01--18--39--46(ZJYC): 检测套接字是否真的建立了   */ 
        if( xDHCPData.xDHCPSocket != NULL )
        {
            /*2016--12--01--18--40--05(ZJYC): 关闭套接字，以确保数据包不会在它上排队   */ 
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
    /*2016--12--01--18--40--41(ZJYC): 如果还没创建的话，创建他   */ 
    if( xDHCPData.xDHCPSocket == NULL )
    {
        xDHCPData.xDHCPSocket = FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_DGRAM, FREERTOS_IPPROTO_UDP );
        if( xDHCPData.xDHCPSocket != FREERTOS_INVALID_SOCKET )
        {
            /*2016--12--01--18--41--03(ZJYC): 确保Rx和Tx超时时间为0.因为DHCP在IP任务中执行   */ 
            FreeRTOS_setsockopt( xDHCPData.xDHCPSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
            FreeRTOS_setsockopt( xDHCPData.xDHCPSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
            /*2016--12--01--18--42--57(ZJYC): 绑定到标准DHCP客户端口0x44   */ 
            xAddress.sin_port = ( uint16_t ) dhcpCLIENT_PORT;
            xReturn = vSocketBind( xDHCPData.xDHCPSocket, &xAddress, sizeof( xAddress ), pdFALSE );
            if( xReturn != 0 )
            {
                /*2016--12--01--18--43--56(ZJYC): 绑定失败，再次关闭套接字   */ 
                vSocketClose( xDHCPData.xDHCPSocket );
                xDHCPData.xDHCPSocket = NULL;
            }
        }
        else
        {
            /*2016--12--01--18--44--44(ZJYC): 把它变为0一遍更早的检测到他   */ 
            xDHCPData.xDHCPSocket = NULL;
        }
    }
}
/*-----------------------------------------------------------*/

static void prvInitialiseDHCP( void )
{
    /*2016--12--01--18--45--11(ZJYC): 初始化DHCP处理需要的参数   */ 
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
    /*2016--12--01--18--45--47(ZJYC): 如果没有则创建套接字   */ 
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
    /*2016--12--01--18--46--22(ZJYC): DHCP服务器地址，正确的DHCP信息类型必须在选项中显示   */ 
    lBytes = FreeRTOS_recvfrom( xDHCPData.xDHCPSocket, ( void * ) &pucUDPPayload, 0ul, FREERTOS_ZERO_COPY, &xClient, &xClientLength );
    if( lBytes > 0 )
    {
        /*2016--12--01--18--47--30(ZJYC): 映射到接收到的信息   */ 
        pxDHCPMessage = ( DHCPMessage_t * ) ( pucUDPPayload );
        /*2016--12--01--18--48--58(ZJYC): 完整性检查   */ 
        if( ( pxDHCPMessage->ulDHCPCookie == ( uint32_t ) dhcpCOOKIE ) &&
            ( pxDHCPMessage->ucOpcode == ( uint8_t ) dhcpREPLY_OPCODE ) &&
            ( pxDHCPMessage->ulTransactionID == FreeRTOS_htonl( xDHCPData.ulTransactionId ) ) )
        {
            /*2016--12--01--18--49--50(ZJYC): 比对用户硬件地址   */ 
            if( memcmp( ( void * ) &( pxDHCPMessage->ucClientHardwareAddress ), ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) ) == 0 )
            {
                /*2016--12--01--18--50--03(ZJYC): 现在关键选项信息一个也没处理呢   */ 
                ulProcessed = 0ul;
                /*2016--12--01--18--50--41(ZJYC): 遍历选项直到dhcpOPTION_END_BYTE被发现，
                注意不要跑丢了*/ 
                pucByte = &( pxDHCPMessage->ucFirstOptionByte );
                pucLastByte = &( pucUDPPayload[ lBytes - dhcpMAX_OPTION_LENGTH_OF_INTEREST ] );
                while( pucByte < pucLastByte )
                {
                    ucOptionCode = pucByte[ 0 ];
                    if( ucOptionCode == dhcpOPTION_END_BYTE )
                    {
                        /*2016--12--01--18--51--39(ZJYC): 碰到了最后一个字节   */ 
                        break;
                    }
                    if( ucOptionCode == dhcpZERO_PAD_OPTION_CODE )
                    {
                        /*2016--12--01--18--52--38(ZJYC): 填充字节，后面不会带着长度   */ 
                        pucByte += 1;
                        continue;
                    }
                    ucLength = pucByte[ 1 ];
                    pucByte += 2;
                    /* In most cases, a 4-byte network-endian parameter follows,
                    just get it once here and use later */
                    /*2016--12--01--18--53--04(ZJYC): 大部分情况下，4字节   */ 
                    memcpy( ( void * ) &( ulParameter ), ( void * ) pucByte, ( size_t ) sizeof( ulParameter ) );

                    switch( ucOptionCode )
                    {
                        /*2016--12--01--18--57--20(ZJYC): 0x53消息类型
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
                                /*2016--12--01--18--59--29(ZJYC): 这就是我们指定的想要的信息   */ 
                                ulProcessed++;
                            }
                            else if( *pucByte == ( uint8_t ) dhcpMESSAGE_TYPE_NACK )
                            {
                                if( xExpectedMessageType == ( BaseType_t ) dhcpMESSAGE_TYPE_ACK )
                                {
                                    /*2016--12--01--19--00--02(ZJYC): 被拒绝了，重新开始吧   */ 
                                    xDHCPData.eDHCPState = eWaitingSendFirstDiscover;
                                }
                            }
                            else
                            {
                                /* Don't process other message types. */
                            }
                            break;
                        /*2016--12--01--19--00--46(ZJYC): 1 子网掩码   */ 
                        case dhcpSUBNET_MASK_OPTION_CODE :
                            if( ucLength == sizeof( uint32_t ) )
                            {
                                xNetworkAddressing.ulNetMask = ulParameter;
                            }
                            break;
                        /*2016--12--01--19--02--10(ZJYC): 3 网关地址   */ 
                        case dhcpGATEWAY_OPTION_CODE :

                            if( ucLength == sizeof( uint32_t ) )
                            {
                                /*2016--12--01--19--02--44(ZJYC): ulProcessed在这里不增加了，因为他不重要   */ 
                                xNetworkAddressing.ulGatewayAddress = ulParameter;
                            }
                            break;
                        /*2016--12--01--19--03--32(ZJYC): 6 DNS服务器   */ 
                        case dhcpDNS_SERVER_OPTIONS_CODE :
                            /*2016--12--01--19--03--52(ZJYC): ulProcessed在这里就不增加了，因为DNS服务器不重要
                            只有第一个DNS服务器被采纳*/ 
                            xNetworkAddressing.ulDNSServerAddress = ulParameter;
                            break;
                            /*2016--12--01--19--05--16(ZJYC): DHCP服务器标识符   */ 
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
                        /*2016--12--01--19--06--44(ZJYC): 地址租期   */ 
                        case dhcpLEASE_TIME_OPTION_CODE :

                            if( ucLength == sizeof( &( xDHCPData.ulLeaseTime ) ) )
                            {
                                /*2016--12--01--19--07--28(ZJYC): ulProcessed不增加，因为不重要
                                本时间以秒为单位，转换成我们的格式*/ 
                                xDHCPData.ulLeaseTime = FreeRTOS_ntohl( ulParameter );
                                /*2016--12--01--19--08--26(ZJYC): 租期除以2，以保证提前发送续租   */ 
                                xDHCPData.ulLeaseTime >>= 1UL;
                                /*2016--12--01--19--09--09(ZJYC): 转换为滴答数   */ 
                                xDHCPData.ulLeaseTime = configTICK_RATE_HZ * xDHCPData.ulLeaseTime;
                            }
                            break;
                        default :
                            /* Not interested in this field. */
                            break;
                    }
                    /*2016--12--01--19--09--40(ZJYC): 跳过数据以寻找下一个选项   */ 
                    if( ucLength == 0u )
                    {
                        break;
                    }
                    else
                    {
                        pucByte += ucLength;
                    }
                }
                /*2016--12--01--19--10--03(ZJYC): 是否所有强制性信息已收到？   */ 
                if( ulProcessed >= ulMandatoryOptions )
                {
                    /*2016--12--01--19--11--03(ZJYC): 采用新的地址   */ 
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
    /*2016--12--01--19--11--31(ZJYC): 获取一缓存，这采用最大的延迟，同时也被限制在ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS
    所以返回值需要检查*/ 
    do
    {
    } while( ( pucUDPPayloadBuffer = ( uint8_t * ) FreeRTOS_GetUDPPayloadBuffer( xRequiredBufferSize, portMAX_DELAY ) ) == NULL );
    pxDHCPMessage = ( DHCPMessage_t * ) pucUDPPayloadBuffer;
    /*2016--12--01--19--12--58(ZJYC): 清零   */ 
    memset( ( void * ) pxDHCPMessage, 0x00, sizeof( DHCPMessage_t ) );
    /*2016--12--01--19--13--11(ZJYC): 创建消息   */ 
    pxDHCPMessage->ucOpcode = ( uint8_t ) xOpcode;
    pxDHCPMessage->ucAddressType = ( uint8_t ) dhcpADDRESS_TYPE_ETHERNET;
    pxDHCPMessage->ucAddressLength = ( uint8_t ) dhcpETHERNET_ADDRESS_LENGTH;
    /*2016--12--01--19--13--19(ZJYC): ulTransactionID确实不需要字节换序，但是当DHCP
    超时，最好是逐渐增加的ID区域*/ 
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
    /*2016--12--01--19--15--34(ZJYC): 填充本地MAC地址   */ 
    memcpy( ( void * ) &( pxDHCPMessage->ucClientHardwareAddress[ 0 ] ), ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) );
    /*2016--12--01--19--16--00(ZJYC): 复制常量选项字段   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET ] ), ( void * ) pucOptionsArray, *pxOptionsArraySize );
    #if( ipconfigDHCP_REGISTER_HOSTNAME == 1 )
    {
        /*2016--12--01--19--16--41(ZJYC): 有这个选项，主机名可以被注册在路由
        更方便寻找*/ 
        /*2016--12--01--19--18--13(ZJYC): 指向OPTION_END所在地，并添加信息   */ 
        pucPtr = &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + ( *pxOptionsArraySize - 1 ) ] );
        pucPtr[ 0 ] = dhcpDNS_HOSTNAME_OPTIONS_CODE;
        pucPtr[ 1 ] = ( uint8_t ) xNameLength;
        memcpy( ( void *) ( pucPtr + 2 ), pucHostName, xNameLength );
        pucPtr[ 2 + xNameLength ] = dhcpOPTION_END_BYTE;
        *pxOptionsArraySize += ( 2 + xNameLength );
    }
    #endif
    /*2016--12--01--19--18--59(ZJYC): 加入客户端标记   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + dhcpCLIENT_IDENTIFIER_OFFSET ] ),
        ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) );
    /*2016--12--01--19--19--13(ZJYC): 设置地址   */ 
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
    /*2016--12--01--19--19--34(ZJYC): 不要再不改变dhcpCLIENT_IDENTIFIER_OFFSET，
    dhcpREQUESTED_IP_ADDRESS_OFFSET 和 dhcpDHCP_SERVER_IP_ADDRESS_OFFSET的情况下更改顺序*/ 
    dhcpMESSAGE_TYPE_OPTION_CODE, 1, dhcpMESSAGE_TYPE_REQUEST,      /*2016--12--01--19--20--52(ZJYC): 消息类型   */ 
    dhcpCLIENT_IDENTIFIER_OPTION_CODE, 6, 0, 0, 0, 0, 0, 0,         /*2016--12--01--19--21--01(ZJYC): 用户标识   */ 
    dhcpREQUEST_IP_ADDRESS_OPTION_CODE, 4, 0, 0, 0, 0,              /*2016--12--01--19--21--17(ZJYC): 需要的IP地址   */ 
    dhcpSERVER_IP_ADDRESS_OPTION_CODE, 4, 0, 0, 0, 0,               /*2016--12--01--19--21--30(ZJYC): DHCP服务器地址   */ 
    dhcpOPTION_END_BYTE
};
size_t xOptionsLength = sizeof( ucDHCPRequestOptions );
    pucUDPPayloadBuffer = prvCreatePartDHCPMessage( &xAddress, dhcpREQUEST_OPCODE, ucDHCPRequestOptions, &xOptionsLength );
    /*2016--12--01--19--22--09(ZJYC): 复制进去请求的地址   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + dhcpREQUESTED_IP_ADDRESS_OFFSET ] ),
        ( void * ) &( xDHCPData.ulOfferedIPAddress ), sizeof( xDHCPData.ulOfferedIPAddress ) );
    /*2016--12--01--19--22--23(ZJYC): 复制服务器地址   */ 
    memcpy( ( void * ) &( pucUDPPayloadBuffer[ dhcpFIRST_OPTION_BYTE_OFFSET + dhcpDHCP_SERVER_IP_ADDRESS_OFFSET ] ),
        ( void * ) &( xDHCPData.ulDHCPServerAddress ), sizeof( xDHCPData.ulDHCPServerAddress ) );
    FreeRTOS_debug_printf( ( "vDHCPProcess: reply %lxip\n", FreeRTOS_ntohl( xDHCPData.ulOfferedIPAddress ) ) );
    iptraceSENDING_DHCP_REQUEST();
    if( FreeRTOS_sendto( xDHCPData.xDHCPSocket, pucUDPPayloadBuffer, ( sizeof( DHCPMessage_t ) + xOptionsLength ), FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) ) == 0 )
    {
        /*2016--12--01--19--22--42(ZJYC): 发送失败   */ 
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
    /*2016--12--01--19--23--14(ZJYC): 不要再不改变dhcpCLIENT_IDENTIFIER_OFFSET的情况下改变顺序   */ 
    dhcpMESSAGE_TYPE_OPTION_CODE, 1, dhcpMESSAGE_TYPE_DISCOVER,                 /*2016--12--01--19--23--39(ZJYC): 消息类型   */ 
    dhcpCLIENT_IDENTIFIER_OPTION_CODE, 6, 0, 0, 0, 0, 0, 0,                     /*2016--12--01--19--23--49(ZJYC): 用户标识   */ 
    dhcpPARAMETER_REQUEST_OPTION_CODE, 3, dhcpSUBNET_MASK_OPTION_CODE, dhcpGATEWAY_OPTION_CODE, dhcpDNS_SERVER_OPTIONS_CODE,    /*2016--12--01--19--24--07(ZJYC): 请求选项   */ 
    dhcpOPTION_END_BYTE
};
size_t xOptionsLength = sizeof( ucDHCPDiscoverOptions );

    pucUDPPayloadBuffer = prvCreatePartDHCPMessage( &xAddress, dhcpREQUEST_OPCODE, ucDHCPDiscoverOptions, &xOptionsLength );

    FreeRTOS_debug_printf( ( "vDHCPProcess: discover\n" ) );
    iptraceSENDING_DHCP_DISCOVER();

    if( FreeRTOS_sendto( xDHCPData.xDHCPSocket, pucUDPPayloadBuffer, ( sizeof( DHCPMessage_t ) + xOptionsLength ), FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) ) == 0 )
    {
        /*2016--12--01--19--24--32(ZJYC): 发送失败   */ 
        FreeRTOS_ReleaseUDPPayloadBuffer( pucUDPPayloadBuffer );
    }
}
/*-----------------------------------------------------------*/

#if( ipconfigDHCP_FALL_BACK_AUTO_IP != 0 )

    static void prvPrepareLinkLayerIPLookUp( void )
    {
    uint8_t ucLinkLayerIPAddress[ 2 ];
        /*2016--12--01--19--24--45(ZJYC): DHCP服务回复失败之后，准备尽力去获取链路层地址，
        ，使用随机的方法*/ 
        xDHCPData.xDHCPTxTime = xTaskGetTickCount();
        ucLinkLayerIPAddress[ 0 ] = ( uint8_t )1 + ( uint8_t )( ipconfigRAND32() % 0xFDu );     /* get value 1..254 for IP-address 3rd byte of IP address to try. */
        ucLinkLayerIPAddress[ 1 ] = ( uint8_t )1 + ( uint8_t )( ipconfigRAND32() % 0xFDu );     /* get value 1..254 for IP-address 4th byte of IP address to try. */
        xNetworkAddressing.ulGatewayAddress = FreeRTOS_htonl( 0xA9FE0203 );
        /*2016--12--01--19--25--52(ZJYC): 准备xDHCPData数据   */ 
        xDHCPData.ulOfferedIPAddress =
            FreeRTOS_inet_addr_quick( LINK_LAYER_ADDRESS_0, LINK_LAYER_ADDRESS_1, ucLinkLayerIPAddress[ 0 ], ucLinkLayerIPAddress[ 1 ] );
        xDHCPData.ulLeaseTime = dhcpDEFAULT_LEASE_TIME;
        /*2016--12--01--19--26--39(ZJYC): 不要关心租期，   */ 
        xNetworkAddressing.ulNetMask =
            FreeRTOS_inet_addr_quick( LINK_LAYER_NETMASK_0, LINK_LAYER_NETMASK_1, LINK_LAYER_NETMASK_2, LINK_LAYER_NETMASK_3 );
        /*2016--12--01--19--27--09(ZJYC): DHCP完成，IP地址现在还不能使用
        设置租约超时时间*/ 
        *ipLOCAL_IP_ADDRESS_POINTER = xDHCPData.ulOfferedIPAddress;
        /*2016--12--01--19--27--53(ZJYC): 设置本地广播地址，类似于192.168.1.255   */ 
        xNetworkAddressing.ulBroadcastAddress = ( xDHCPData.ulOfferedIPAddress & xNetworkAddressing.ulNetMask ) |  ~xNetworkAddressing.ulNetMask;
        /*2016--12--01--19--28--23(ZJYC): 关闭套接字确保不排队，因为DHCP失败所以不再需套接字。但是仍然需要定时器以进行ARP检查   */ 
        vSocketClose( xDHCPData.xDHCPSocket );
        xDHCPData.xDHCPSocket = NULL;
        xDHCPData.xDHCPTxPeriod = pdMS_TO_TICKS( 3000ul + ( ipconfigRAND32() & 0x3fful ) ); 
        /*2016--12--01--19--29--42(ZJYC): 每 3 + 0-1024mS)做一次ARP检查  */ 
        /*2016--12--01--19--30--07(ZJYC): 复位ARP碰撞机制   */ 
        xARPHadIPClash = pdFALSE;
        vARPSendGratuitous();
    }

#endif /* ipconfigDHCP_FALL_BACK_AUTO_IP */
/*-----------------------------------------------------------*/

#endif /* ipconfigUSE_DHCP != 0 */


