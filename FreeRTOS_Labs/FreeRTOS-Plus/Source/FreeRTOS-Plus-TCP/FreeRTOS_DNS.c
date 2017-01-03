
/*2016--12--02--09--44--48(ZJYC): 标准头文件   */ 
#include <stdint.h>

/*2016--12--02--09--45--00(ZJYC): FREERTOS头文件   */ 
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "list.h"
#include "semphr.h"

/*2016--12--02--09--45--12(ZJYC): FREERTOS+TCP头文件   */ 
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DNS.h"
#include "NetworkBufferManagement.h"
#include "NetworkInterface.h"
#include "IPTraceMacroDefaults.h"

/*2016--12--02--09--45--28(ZJYC): 如果DNS不是能则排除所有   */ 
#if( ipconfigUSE_DNS != 0 )

#if( ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN )
    #define dnsDNS_PORT                     0x3500
    #define dnsONE_QUESTION                 0x0100
    #define dnsOUTGOING_FLAGS               0x0001 /*2016--12--02--09--45--53(ZJYC): 标准请求   */ 
    #define dnsRX_FLAGS_MASK                0x0f80 /*2016--12--02--09--46--11(ZJYC): 标志位掩码   */ 
    #define dnsEXPECTED_RX_FLAGS            0x0080 /*2016--12--02--09--46--37(ZJYC): DNS回复标志，并且没有任何错误   */ 
#else
    #define dnsDNS_PORT                     0x0035
    #define dnsONE_QUESTION                 0x0001
    #define dnsOUTGOING_FLAGS               0x0100 /*2016--12--02--09--45--53(ZJYC): 标准请求   */ 
    #define dnsRX_FLAGS_MASK                0x800f /*2016--12--02--09--46--11(ZJYC): 标志位掩码   */ 
    #define dnsEXPECTED_RX_FLAGS            0x8000 /*2016--12--02--09--46--37(ZJYC): DNS回复标志，并且没有任何错误   */ 

#endif /* ipconfigBYTE_ORDER */

/*2016--12--02--09--47--55(ZJYC): 在未放弃之前，收不到回复的情况下，多长时间再次发送请求   */ 
#ifndef ipconfigDNS_REQUEST_ATTEMPTS
    #define ipconfigDNS_REQUEST_ATTEMPTS        5
#endif

/*2016--12--02--09--49--12(ZJYC): 名字区域的第一字节的高两位被置位，则标明
此为到达字符串的偏移而不是真的字符串   */ 
/*2016--12--02--10--31--37(ZJYC): 这是一种压缩DNS报文，即将重复的字符使用索引表示   */ 
#define dnsNAME_IS_OFFSET                   ( ( uint8_t ) 0xc0 )

/*2016--12--02--09--50--46(ZJYC): NBNS标志   */ 
#define dnsNBNS_FLAGS_RESPONSE              0x8000
#define dnsNBNS_FLAGS_OPCODE_MASK           0x7800
#define dnsNBNS_FLAGS_OPCODE_QUERY          0x0000
#define dnsNBNS_FLAGS_OPCODE_REGISTRATION   0x2800

/* Host types. */
#define dnsTYPE_A_HOST                      0x01
#define dnsCLASS_IN                         0x01

/* LLMNR constants. */
#define dnsLLMNR_TTL_VALUE                  300000
#define dnsLLMNR_FLAGS_IS_REPONSE           0x8000

/* NBNS constants. */
#define dnsNBNS_TTL_VALUE                   3600 /* 1 hour valid */
#define dnsNBNS_TYPE_NET_BIOS               0x0020
#define dnsNBNS_CLASS_IN                    0x01
#define dnsNBNS_NAME_FLAGS                  0x6000
#define dnsNBNS_ENCODED_NAME_LENGTH         32

/*2016--12--02--10--54--00(ZJYC): 如果请求的名字与器件名字匹配，回复中将会带着此标志   */ 
#define dnsNBNS_QUERY_RESPONSE_FLAGS    ( 0x8500 )

/*2016--12--02--10--54--40(ZJYC): 创建套接字并绑定到标准DNS端口，返回创建的套接字
如果为NULL，，，则不绑定   */ 
static Socket_t prvCreateDNSSocket( void );

/*2016--12--02--10--55--41(ZJYC): 在第一个参数传递的零复制缓冲区中创建DNS信息   */ 
static size_t prvCreateDNSMessage( uint8_t *pucUDPPayloadBuffer, const char *pcHostName, TickType_t xIdentifier );

/*2016--12--02--10--56--31(ZJYC): 跳过资源记录中的名字区域   */ 
static uint8_t *prvSkipNameField( uint8_t *pucByte );

/*2016--12--02--10--57--28(ZJYC): 处理来自DNS服务器的回复   */ 
static uint32_t prvParseDNSReply( uint8_t *pucUDPPayloadBuffer, TickType_t xIdentifier );

/*2016--12--02--10--57--55(ZJYC): 准备发送DNS消息到DNS服务器，xReadTimeOut_ms为0 以防
用户提供了回调函数   */ 
static uint32_t prvGetHostByName( const char *pcHostName, TickType_t xIdentifier, TickType_t xReadTimeOut_ms );

/*2016--12--02--10--59--02(ZJYC): NBNS协议和LLMNR协议共享回复函数   */ 
#if( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) )
    static void prvReplyDNSMessage( NetworkBufferDescriptor_t *pxNetworkBuffer, BaseType_t lNetLength );
#endif

#if( ipconfigUSE_NBNS == 1 )
    static portINLINE void prvTreatNBNS( uint8_t *pucUDPPayloadBuffer, uint32_t ulIPAddress );
#endif /* ipconfigUSE_NBNS */

#if( ipconfigUSE_DNS_CACHE == 1 )
    static uint8_t *prvReadNameField( uint8_t *pucByte, char *pcName, BaseType_t xLen );
    static void prvProcessDNSCache( const char *pcName, uint32_t *pulIP, BaseType_t xLookUp );

    typedef struct xDNS_CACHE_TABLE_ROW
    {
        uint32_t ulIPAddress;       /*2016--12--02--11--00--00(ZJYC): ARP缓存入口的IP地址   */ 
        char pcName[ipconfigDNS_CACHE_NAME_LENGTH];  /*2016--12--02--11--00--30(ZJYC): 主机名称   */ 
        uint8_t ucAge;              /*2016--12--02--11--01--41(ZJYC): 周期递减的数值，可以被沟通刷新，如果到达0，ARP缓存表中对应的项会被清除   */ 
    } DNSCacheRow_t;

    static DNSCacheRow_t xDNSCache[ ipconfigDNS_CACHE_ENTRIES ];
#endif /* ipconfigUSE_DNS_CACHE == 1 */

#if( ipconfigUSE_LLMNR == 1 )
    const MACAddress_t xLLMNR_MacAdress = { { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc } };
#endif  /* ipconfigUSE_LLMNR == 1 */

/*-----------------------------------------------------------*/

#include "pack_struct_start.h"
struct xDNSMessage
{
    uint16_t usIdentifier;
    uint16_t usFlags;
    uint16_t usQuestions;
    uint16_t usAnswers;
    uint16_t usAuthorityRRs;
    uint16_t usAdditionalRRs;
}
#include "pack_struct_end.h"
typedef struct xDNSMessage DNSMessage_t;

/*2016--12--02--11--02--53(ZJYC): DNS查询包括头部（如xDNSMessage描述），紧随其后的事1或多个问题
每一个包括名称和类型和class   */ 
#include "pack_struct_start.h"
struct xDNSTail
{
    uint16_t usType;
    uint16_t usClass;
}
#include "pack_struct_end.h"
typedef struct xDNSTail DNSTail_t;

#if( ipconfigUSE_LLMNR == 1 )

    #include "pack_struct_start.h"
    struct xLLMNRAnswer
    {
        uint8_t ucNameCode;
        uint8_t ucNameOffset;   /*2016--12--02--13--39--40(ZJYC): 名称不会重复出现，只会给与一偏移量   */ 
        uint16_t usType;
        uint16_t usClass;
        uint32_t ulTTL;
        uint16_t usDataLength;
        uint32_t ulIPAddress;
    }
    #include "pack_struct_end.h"
    typedef struct xLLMNRAnswer LLMNRAnswer_t;

#endif /* ipconfigUSE_LLMNR == 1 */

#if( ipconfigUSE_NBNS == 1 )

    #include "pack_struct_start.h"
    struct xNBNSRequest
    {
        uint16_t usRequestId;
        uint16_t usFlags;
        uint16_t ulRequestCount;
        uint16_t usAnswerRSS;
        uint16_t usAuthRSS;
        uint16_t usAdditionalRSS;
        uint8_t ucNameSpace;
        uint8_t ucName[ dnsNBNS_ENCODED_NAME_LENGTH ];
        uint8_t ucNameZero;
        uint16_t usType;
        uint16_t usClass;
    }
    #include "pack_struct_end.h"
    typedef struct xNBNSRequest NBNSRequest_t;

    #include "pack_struct_start.h"
    struct xNBNSAnswer
    {
        uint16_t usType;
        uint16_t usClass;
        uint32_t ulTTL;
        uint16_t usDataLength;
        uint16_t usNbFlags;     /* NetBIOS flags 0x6000 : IP-address, big-endian */
        uint32_t ulIPAddress;
    }
    #include "pack_struct_end.h"
    typedef struct xNBNSAnswer NBNSAnswer_t;

#endif /* ipconfigUSE_NBNS == 1 */

/*-----------------------------------------------------------*/

#if( ipconfigUSE_DNS_CACHE == 1 )
    uint32_t FreeRTOS_dnslookup( const char *pcHostName )
    {
    uint32_t ulIPAddress = 0UL;
        prvProcessDNSCache( pcHostName, &ulIPAddress, pdTRUE );
        return ulIPAddress;
    }
#endif /* ipconfigUSE_DNS_CACHE == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigDNS_USE_CALLBACKS != 0 )

    typedef struct xDNS_Callback {
        TickType_t xRemaningTime;       /*2016--12--02--13--40--31(ZJYC): 超时ms单位   */ 
        FOnDNSEvent pCallbackFunction;  /*2016--12--02--13--40--47(ZJYC): 当超时或者获取一IP地址之后调用的函数   */ 
        TimeOut_t xTimeoutState;
        void *pvSearchID;
        struct xLIST_ITEM xListItem;
        char pcName[ 1 ];
    } DNSCallback_t;
    static List_t xCallbackList;
    /* Define FreeRTOS_gethostbyname() as a normal blocking call. */
    uint32_t FreeRTOS_gethostbyname( const char *pcHostName )
    {
        return FreeRTOS_gethostbyname_a( pcHostName, ( FOnDNSEvent ) NULL, ( void* )NULL, 0 );
    }
    /*-----------------------------------------------------------*/
    /*2016--12--02--13--41--48(ZJYC): 初始化回调结构   */ 
    void vDNSInitialise( void );
    void vDNSInitialise( void )
    {
        vListInitialise( &xCallbackList );
    }
    /*-----------------------------------------------------------*/
    /*2016--12--02--14--06--08(ZJYC): 遍历回调结构体并且删除旧的超时的
    一旦列表变为空，DNS计时器将会停止，用户取消DNS请求，则会提供pvSearchID
    */ 
    void vDNSCheckCallBack( void *pvSearchID );
    void vDNSCheckCallBack( void *pvSearchID )
    {
    const ListItem_t *pxIterator;
    const MiniListItem_t* xEnd = ( const MiniListItem_t* )listGET_END_MARKER( &xCallbackList );

        vTaskSuspendAll();
        {
            for( pxIterator  = ( const ListItem_t * ) listGET_NEXT( xEnd );
                 pxIterator != ( const ListItem_t * ) xEnd;
                  )
            {
                DNSCallback_t *pxCallback = ( DNSCallback_t * ) listGET_LIST_ITEM_OWNER( pxIterator );
                /*2016--12--02--14--08--31(ZJYC): 走到下一个列表因为我们要删掉这个列表   */ 
                pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxIterator );
                if( ( pvSearchID != NULL ) && ( pvSearchID == pxCallback->pvSearchID ) )
                {
                    uxListRemove( &pxCallback->xListItem );
                    vPortFree( pxCallback );
                }
                else if( xTaskCheckForTimeOut( &pxCallback->xTimeoutState, &pxCallback->xRemaningTime ) != pdFALSE )
                {
                    pxCallback->pCallbackFunction( pxCallback->pcName, pxCallback->pvSearchID, 0 );
                    uxListRemove( &pxCallback->xListItem );
                    vPortFree( ( void * ) pxCallback );
                }
            }
        }
        xTaskResumeAll();

        if( listLIST_IS_EMPTY( &xCallbackList ) )
        {
            vIPSetDnsTimerEnableState( pdFALSE );
        }
    }
    /*-----------------------------------------------------------*/

    void FreeRTOS_gethostbyname_cancel( void *pvSearchID )
    {
        /* _HT_ Should better become a new API call to have the IP-task remove the callback */
        vDNSCheckCallBack( pvSearchID );
    }
    /*-----------------------------------------------------------*/
    /*2016--12--02--14--09--16(ZJYC): FreeRTOS_gethostbyname_a()伴随着回调参数调用
    存储之以便后续使用*/ 
    static void vDNSSetCallBack( const char *pcHostName, void *pvSearchID, FOnDNSEvent pCallbackFunction, TickType_t xTimeout, TickType_t xIdentifier );
    static void vDNSSetCallBack( const char *pcHostName, void *pvSearchID, FOnDNSEvent pCallbackFunction, TickType_t xTimeout, TickType_t xIdentifier )
    {
        size_t lLength = strlen( pcHostName );
        DNSCallback_t *pxCallback = ( DNSCallback_t * )pvPortMalloc( sizeof( *pxCallback ) + lLength );
        /*2016--12--02--14--10--26(ZJYC): 由ms转变为时钟滴答   */ 
        xTimeout /= portTICK_PERIOD_MS;
        if( pxCallback != NULL )
        {
            if( listLIST_IS_EMPTY( &xCallbackList ) )
            {
                /*2016--12--02--14--10--54(ZJYC): 这是第一个，启动DNS定时器来检查是否超时   */ 
                vIPReloadDNSTimer( FreeRTOS_min_uint32( 1000U, xTimeout ) );
            }
            strcpy( pxCallback->pcName, pcHostName );
            pxCallback->pCallbackFunction = pCallbackFunction;
            pxCallback->pvSearchID = pvSearchID;
            pxCallback->xRemaningTime = xTimeout;
            vTaskSetTimeOutState( &pxCallback->xTimeoutState );
            listSET_LIST_ITEM_OWNER( &( pxCallback->xListItem ), ( void* ) pxCallback );
            listSET_LIST_ITEM_VALUE( &( pxCallback->xListItem ), xIdentifier );
            vTaskSuspendAll();
            {
                vListInsertEnd( &xCallbackList, &pxCallback->xListItem );
            }
            xTaskResumeAll();
        }
    }
    /*-----------------------------------------------------------*/
    /*2016--12--02--14--11--25(ZJYC): DNS回复被接收，看看是否有匹配的
    入口并调用句柄*/ 
    static void vDNSDoCallback( TickType_t xIdentifier, const char *pcName, uint32_t ulIPAddress );
    static void vDNSDoCallback( TickType_t xIdentifier, const char *pcName, uint32_t ulIPAddress )
    {
        const ListItem_t *pxIterator;
        const MiniListItem_t* xEnd = ( const MiniListItem_t* )listGET_END_MARKER( &xCallbackList );

        vTaskSuspendAll();
        {
            for( pxIterator  = ( const ListItem_t * ) listGET_NEXT( xEnd );
                 pxIterator != ( const ListItem_t * ) xEnd;
                 pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
            {
                if( listGET_LIST_ITEM_VALUE( pxIterator ) == xIdentifier )
                {
                    DNSCallback_t *pxCallback = ( DNSCallback_t * ) listGET_LIST_ITEM_OWNER( pxIterator );
                    pxCallback->pCallbackFunction( pcName, pxCallback->pvSearchID, ulIPAddress );
                    uxListRemove( &pxCallback->xListItem );
                    vPortFree( pxCallback );
                    if( listLIST_IS_EMPTY( &xCallbackList ) )
                    {
                        vIPSetDnsTimerEnableState( pdFALSE );
                    }
                    break;
                }
            }
        }
        xTaskResumeAll();
    }

#endif  /* ipconfigDNS_USE_CALLBACKS != 0 */
/*-----------------------------------------------------------*/

#if( ipconfigDNS_USE_CALLBACKS == 0 )
uint32_t FreeRTOS_gethostbyname( const char *pcHostName )
#else
uint32_t FreeRTOS_gethostbyname_a( const char *pcHostName, FOnDNSEvent pCallback, void *pvSearchID, TickType_t xTimeout )
#endif
{
uint32_t ulIPAddress = 0UL;
static uint16_t usIdentifier = 0u;
TickType_t xReadTimeOut_ms = 1200U;
/*2016--12--02--14--12--15(ZJYC): 产生一独一的标示符，把他保存在局部变量
因为 gethostbyname() 会被不同的线程调用   */ 
TickType_t xIdentifier = ( TickType_t )usIdentifier++;
    /*2016--12--02--14--13--22(ZJYC): 如果使能DNS缓存，首先会检查是否有这个存储项   */ 
    #if( ipconfigUSE_DNS_CACHE == 1 )
    {
        ulIPAddress = FreeRTOS_dnslookup( pcHostName );
        if( ulIPAddress != 0 )
        {
            FreeRTOS_debug_printf( ( "FreeRTOS_gethostbyname: found '%s' in cache: %lxip\n", pcHostName, ulIPAddress ) );
        }
        else
        {
            /* prvGetHostByName will be called to start a DNS lookup */
        }
    }
    #endif /* ipconfigUSE_DNS_CACHE == 1 */

    #if( ipconfigDNS_USE_CALLBACKS != 0 )
    {
        if( pCallback != NULL )
        {
            if( ulIPAddress == 0UL )
            {
                /*2016--12--02--14--14--13(ZJYC): 用户提供了回调函数，所以，不能在recvfrom()堵塞   */ 
                xReadTimeOut_ms  = 0;
                vDNSSetCallBack( pcHostName, pvSearchID, pCallback, xTimeout, ( TickType_t ) xIdentifier );
            }
            else
            {
                /*2016--12--02--14--14--47(ZJYC): 如果IP地址知晓了，执行回调函数   */ 
                pCallback( pcHostName, pvSearchID, ulIPAddress );
            }
        }
    }
    #endif

    if( ulIPAddress == 0UL)
    {
        ulIPAddress = prvGetHostByName( pcHostName, xIdentifier, xReadTimeOut_ms );
    }

    return ulIPAddress;
}
/*-----------------------------------------------------------*/

static uint32_t prvGetHostByName( const char *pcHostName, TickType_t xIdentifier, TickType_t xReadTimeOut_ms )
{
struct freertos_sockaddr xAddress;
Socket_t xDNSSocket;
uint32_t ulIPAddress = 0UL;
uint8_t *pucUDPPayloadBuffer;
static uint32_t ulAddressLength;
BaseType_t xAttempt;
int32_t lBytes;
size_t xPayloadLength, xExpectedPayloadLength;
TickType_t xWriteTimeOut_ms = 100U;

#if( ipconfigUSE_LLMNR == 1 )
    BaseType_t bHasDot = pdFALSE;
#endif /* ipconfigUSE_LLMNR == 1 */
    /*2016--12--02--14--15--41(ZJYC): 如果LLMNR被使用，然后判断是否主机名包括'.'，
    如果不，LLMNR可以被作为一种搜索方法*/ 
    #if( ipconfigUSE_LLMNR == 1 )
    {
        const char *pucPtr;
        for( pucPtr = pcHostName; *pucPtr; pucPtr++ )
        {
            if( *pucPtr == '.' )
            {
                bHasDot = pdTRUE;
                break;
            }
        }
    }
    #endif /* ipconfigUSE_LLMNR == 1 */
    /*2016--12--02--14--19--21(ZJYC): 后边那个2是结束符和   */ 
    /* Two is added at the end for the count of characters in the first
    subdomain part and the string end byte. */
    xExpectedPayloadLength = sizeof( DNSMessage_t ) + strlen( pcHostName ) + sizeof( uint16_t ) + sizeof( uint16_t ) + 2u;

    xDNSSocket = prvCreateDNSSocket();

    if( xDNSSocket != NULL )
    {
        FreeRTOS_setsockopt( xDNSSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xWriteTimeOut_ms, sizeof( TickType_t ) );
        FreeRTOS_setsockopt( xDNSSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xReadTimeOut_ms,  sizeof( TickType_t ) );

        for( xAttempt = 0; xAttempt < ipconfigDNS_REQUEST_ATTEMPTS; xAttempt++ )
        {
            /*2016--12--02--14--21--06(ZJYC): 获取一缓冲，使用最大的延迟，但是延迟会被
            限制在ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS所以返回值需要被检查*/ 
            pucUDPPayloadBuffer = ( uint8_t * ) FreeRTOS_GetUDPPayloadBuffer( xExpectedPayloadLength, portMAX_DELAY );
            if( pucUDPPayloadBuffer != NULL )
            {
                /*2016--12--02--14--22--11(ZJYC): 在获取的缓冲力产生DNS消息   */ 
                xPayloadLength = prvCreateDNSMessage( pucUDPPayloadBuffer, pcHostName, xIdentifier );
                iptraceSENDING_DNS_REQUEST();
                /*2016--12--02--14--22--40(ZJYC): 获取DNS服务器地址   */ 
                FreeRTOS_GetAddressConfiguration( NULL, NULL, NULL, &ulIPAddress );
                /*2016--12--02--14--22--58(ZJYC): 发送DNS消息   */ 
                /* Send the DNS message. */
#if( ipconfigUSE_LLMNR == 1 )
                if( bHasDot == pdFALSE )
                {
                    /*2016--12--02--14--23--13(ZJYC): 使用LLMNR地址   */ 
                    ( ( DNSMessage_t * ) pucUDPPayloadBuffer) -> usFlags = 0;
                    xAddress.sin_addr = ipLLMNR_IP_ADDR;    /* Is in network byte order. */
                    xAddress.sin_port = FreeRTOS_ntohs( ipLLMNR_PORT );
                }
                else
#endif
                {
                    /*2016--12--02--14--23--44(ZJYC): 使用DNS服务器   */ 
                    xAddress.sin_addr = ulIPAddress;
                    xAddress.sin_port = dnsDNS_PORT;
                }
                ulIPAddress = 0UL;
                if( FreeRTOS_sendto( xDNSSocket, pucUDPPayloadBuffer, xPayloadLength, FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) ) != 0 )
                {
                    /*2016--12--02--14--24--10(ZJYC): 等待回复   */ 
                    lBytes = FreeRTOS_recvfrom( xDNSSocket, &pucUDPPayloadBuffer, 0, FREERTOS_ZERO_COPY, &xAddress, &ulAddressLength );
                    if( lBytes > 0 )
                    {
                        /*2016--12--02--14--31--16(ZJYC): 收到回复，处理它   */ 
                        ulIPAddress = prvParseDNSReply( pucUDPPayloadBuffer, xIdentifier );
                        /*2016--12--02--14--31--32(ZJYC): 处理完毕，零复制接口已经被使用，所以缓冲可以被释放了   */ 
                        FreeRTOS_ReleaseUDPPayloadBuffer( ( void * ) pucUDPPayloadBuffer );
                        if( ulIPAddress != 0UL )
                        {
                            /* All done. */
                            break;
                        }
                    }
                }
                else
                {
                    /*2016--12--02--14--42--05(ZJYC): 信息没有被发送，所以不会通过零复制释放，必须在这里释放   */ 
                    FreeRTOS_ReleaseUDPPayloadBuffer( ( void * ) pucUDPPayloadBuffer );
                }
            }
        }
        /* Finished with the socket. */
        FreeRTOS_closesocket( xDNSSocket );
    }

    return ulIPAddress;
}
/*-----------------------------------------------------------*/

static size_t prvCreateDNSMessage( uint8_t *pucUDPPayloadBuffer, const char *pcHostName, TickType_t xIdentifier )
{
DNSMessage_t *pxDNSMessageHeader;
uint8_t *pucStart, *pucByte;
DNSTail_t *pxTail;
static const DNSMessage_t xDefaultPartDNSHeader =
{
    0,                  /*2016--12--02--14--44--07(ZJYC): 标示符会被重写   */ 
    dnsOUTGOING_FLAGS,  /*2016--12--02--14--45--33(ZJYC): 标准请求   */ 
    dnsONE_QUESTION,    /*2016--12--02--14--45--44(ZJYC): 只有一个问题   */ 
    0,                  /*2016--12--02--14--45--55(ZJYC): 没有回复   */ 
    0,                  /*2016--12--02--14--46--05(ZJYC): 没有权威   */ 
    0                   /*2016--12--02--14--46--16(ZJYC): 没有额外   */ 
};

    /*2016--12--02--14--46--33(ZJYC): 复制头部常量部分   */ 
    memcpy( ( void * ) pucUDPPayloadBuffer, ( void * ) &xDefaultPartDNSHeader, sizeof( xDefaultPartDNSHeader ) );
    /*2016--12--02--14--46--51(ZJYC): 写入唯一标识号   */ 
    pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;
    pxDNSMessageHeader->usIdentifier = ( uint16_t ) xIdentifier;
    /*2016--12--02--14--47--04(ZJYC): 在头部末尾创建资源记录，首先找到头的尾部   */ 
    pucStart = pucUDPPayloadBuffer + sizeof( xDefaultPartDNSHeader );
    /*2016--12--02--14--47--52(ZJYC): 为长度字节留出空间   */ 
    pucByte = pucStart + 1;
    /*2016--12--02--14--48--26(ZJYC): 复制主机名   */ 
    strcpy( ( char * ) pucByte, pcHostName );
    /*2016--12--02--14--48--59(ZJYC): 标记字符结束位   */ 
    pucByte += strlen( pcHostName );
    *pucByte = 0x00u;
    /*2016--12--02--14--49--15(ZJYC): 遍历并替换'.'为长度   */ 
    pucByte = pucStart;
    do
    {
        pucByte++;
        while( ( *pucByte != 0x00 ) && ( *pucByte != '.' ) )
        {
            pucByte++;
        }
        /*2016--12--02--14--49--40(ZJYC): 填充字节计数   */ 
        *pucStart = ( uint8_t ) ( ( uint32_t ) pucByte - ( uint32_t ) pucStart );
        ( *pucStart )--;
        pucStart = pucByte;
    } while( *pucByte != 0x00 );
    /*2016--12--02--14--50--14(ZJYC): 完成记录的填充   */ 
    pxTail = (DNSTail_t *)( pucByte + 1 );
    vSetField16( pxTail, DNSTail_t, usType, dnsTYPE_A_HOST );   /* Type A: host */
    vSetField16( pxTail, DNSTail_t, usClass, dnsCLASS_IN ); /* 1: Class IN */
    /*2016--12--02--14--50--36(ZJYC): 返回所产生信息的总长度，起始于最后一个被写入的字节
    结束于缓冲头部*/ 
    return ( ( uint32_t ) pucByte - ( uint32_t ) pucUDPPayloadBuffer + 1 ) + sizeof( *pxTail );
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_DNS_CACHE == 1 )
    static uint8_t *prvReadNameField( uint8_t *pucByte, char *pcName, BaseType_t xLen )
    {
    BaseType_t xNameLen = 0;
        /*2016--12--02--14--51--57(ZJYC): 判断是否名字为完全编码名称，或者是一个偏移指向其他地方   */ 
        if( ( *pucByte & dnsNAME_IS_OFFSET ) == dnsNAME_IS_OFFSET )
        {
            /*2016--12--02--14--53--10(ZJYC): 跳过两字节偏移   */ 
            pucByte += sizeof( uint16_t );
        }
        else
        {
            /*2016--12--02--14--53--33(ZJYC): pucByte指向全字符编码，遍历字符串   */ 
            while( *pucByte != 0x00 )
            {
                BaseType_t xCount;
                if( xNameLen && xNameLen < xLen - 1 )
                    pcName[xNameLen++] = '.';
                for( xCount = *(pucByte++); xCount--; pucByte++ )
                {
                    if( xNameLen < xLen - 1 )
                        pcName[xNameLen++] = *( ( char * ) pucByte );
                }
            }

            pucByte++;
        }

        return pucByte;
    }
#endif  /* ipconfigUSE_DNS_CACHE == 1 */
/*-----------------------------------------------------------*/

static uint8_t *prvSkipNameField( uint8_t *pucByte )
{
    /*2016--12--02--14--54--10(ZJYC): 决定是否为全字符名字，还是一偏移指向其他地方   */ 
    if( ( *pucByte & dnsNAME_IS_OFFSET ) == dnsNAME_IS_OFFSET )
    {
        /* Jump over the two byte offset. */
        pucByte += sizeof( uint16_t );
    }
    else
    {
        /*2016--12--02--14--55--01(ZJYC): 指向全字符名，遍历字符串   */ 
        while( *pucByte != 0x00 )
        {
            /*2016--12--02--14--55--28(ZJYC): 数量制定了其后的字符串长度，方便我们跳过   */ 
            pucByte += ( *pucByte + 1 );
        }
        pucByte++;
    }
    return pucByte;
}
/*-----------------------------------------------------------*/

uint32_t ulDNSHandlePacket( NetworkBufferDescriptor_t *pxNetworkBuffer )
{
uint8_t *pucUDPPayloadBuffer = pxNetworkBuffer->pucEthernetBuffer + sizeof( UDPPacket_t );
DNSMessage_t *pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;

    prvParseDNSReply( pucUDPPayloadBuffer, ( uint32_t ) pxDNSMessageHeader->usIdentifier );

    /*2016--12--02--15--24--46(ZJYC): 包没有被消耗   */ 
    return pdFAIL;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_NBNS == 1 )

    uint32_t ulNBNSHandlePacket (NetworkBufferDescriptor_t *pxNetworkBuffer )
    {
    UDPPacket_t *pxUDPPacket = ( UDPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;
    uint8_t *pucUDPPayloadBuffer = pxNetworkBuffer->pucEthernetBuffer + sizeof( *pxUDPPacket );

        prvTreatNBNS( pucUDPPayloadBuffer, pxUDPPacket->xIPHeader.ulSourceIPAddress );

        /*2016--12--02--15--24--46(ZJYC): 包没有被消耗   */ 
        return pdFAIL;
    }

#endif /* ipconfigUSE_NBNS */
/*-----------------------------------------------------------*/

static uint32_t prvParseDNSReply( uint8_t *pucUDPPayloadBuffer, TickType_t xIdentifier )
{
DNSMessage_t *pxDNSMessageHeader;
uint32_t ulIPAddress = 0UL;
#if( ipconfigUSE_LLMNR == 1 )
    char *pcRequestedName = NULL;
#endif
uint8_t *pucByte;
uint16_t x, usDataLength, usQuestions;
#if( ipconfigUSE_LLMNR == 1 )
    uint16_t usType = 0, usClass = 0;
#endif
#if( ipconfigUSE_DNS_CACHE == 1 )
    char pcName[128] = ""; /*_RB_ What is the significance of 128?  Probably too big to go on the stack for a small MCU but don't know how else it could be made re-entrant.  Might be necessary. */
#endif

    pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;
    if( pxDNSMessageHeader->usIdentifier == ( uint16_t ) xIdentifier )
    {
        /*2016--12--02--15--25--24(ZJYC): 从头部之后的第一个字节开始   */ 
        pucByte = pucUDPPayloadBuffer + sizeof( DNSMessage_t );
        /*2016--12--02--15--25--42(ZJYC): 跳过所有问题记录   */ 
        usQuestions = FreeRTOS_ntohs( pxDNSMessageHeader->usQuestions );
        for( x = 0; x < usQuestions; x++ )
        {
            #if( ipconfigUSE_LLMNR == 1 )
            {
                if( x == 0 )
                {
                    pcRequestedName = ( char * ) pucByte;
                }
            }
            #endif
#if( ipconfigUSE_DNS_CACHE == 1 )
            if( x == 0 )
            {
                pucByte = prvReadNameField( pucByte, pcName, sizeof( pcName ) );
            }
            else
#endif /* ipconfigUSE_DNS_CACHE */
            {
                /*2016--12--02--15--26--20(ZJYC): 跳过变量长   */ 
                pucByte = prvSkipNameField( pucByte );
            }
            #if( ipconfigUSE_LLMNR == 1 )
            {
                /* usChar2u16 returns value in host endianness */
                usType = usChar2u16( pucByte );
                usClass = usChar2u16( pucByte + 2 );
            }
            #endif /* ipconfigUSE_LLMNR */

            /*2016--12--02--15--26--44(ZJYC): 跳过Type和Class区域   */ 
            pucByte += sizeof( uint32_t );
        }
        /*2016--12--02--15--27--01(ZJYC): 从回答记录开始寻找   */ 
        pxDNSMessageHeader->usAnswers = FreeRTOS_ntohs( pxDNSMessageHeader->usAnswers );
        if( ( pxDNSMessageHeader->usFlags & dnsRX_FLAGS_MASK ) == dnsEXPECTED_RX_FLAGS )
        {
            for( x = 0; x < pxDNSMessageHeader->usAnswers; x++ )
            {
                pucByte = prvSkipNameField( pucByte );

                /*2016--12--02--15--28--25(ZJYC): 是否是A类型   */ 
                if( usChar2u16( pucByte ) == dnsTYPE_A_HOST )
                {
                    /*2016--12--02--15--33--13(ZJYC): 这是我们需要的记录，跳过类型，Class和TTL，加上
                    第一个长度*/ 
                    pucByte += ( sizeof( uint32_t ) + sizeof( uint32_t ) + sizeof( uint8_t ) );
                    /*2016--12--02--15--34--13(ZJYC): 完整性检查数据长度   */ 
                    if( ( size_t ) *pucByte == sizeof( uint32_t ) )
                    {
                        /*2016--12--02--15--34--28(ZJYC): 跳过第二个长度   */ 
                        pucByte++;
                        /*2016--12--02--15--38--51(ZJYC): 复制IP地址   */ 
                        memcpy( ( void * ) &ulIPAddress, ( void * ) pucByte, sizeof( uint32_t ) );
                        #if( ipconfigUSE_DNS_CACHE == 1 )
                        {
                            prvProcessDNSCache( pcName, &ulIPAddress, pdFALSE );
                        }
                        #endif /* ipconfigUSE_DNS_CACHE */
                        #if( ipconfigDNS_USE_CALLBACKS != 0 )
                        {
                            /*2016--12--02--15--39--04(ZJYC): 查看是否发生对于FreeRTOS_gethostbyname_a异步访问   */ 
                            vDNSDoCallback( ( TickType_t ) pxDNSMessageHeader->usIdentifier, pcName, ulIPAddress );
                        }
                        #endif  /* ipconfigDNS_USE_CALLBACKS != 0 */
                    }
                    break;
                }
                else
                {
                    /*2016--12--02--15--39--48(ZJYC): 跳过type、class和TTL   */ 
                    pucByte += ( sizeof( uint32_t ) + sizeof( uint32_t ) );
                    /*2016--12--02--15--40--10(ZJYC): 决定数据的长度   */ 
                    memcpy( ( void * ) &usDataLength, ( void * ) pucByte, sizeof( uint16_t ) );
                    usDataLength = FreeRTOS_ntohs( usDataLength );
                    /*2016--12--02--15--40--30(ZJYC): 跳过数据长和数据本身   */ 
                    pucByte += usDataLength + sizeof( uint16_t );
                }
            }
        }
#if( ipconfigUSE_LLMNR == 1 )
        else if( usQuestions && ( usType == dnsTYPE_A_HOST ) && ( usClass == dnsCLASS_IN ) )
        {
            /*2016--12--02--15--41--06(ZJYC): 这不是对我们的DNS的应答，有可能是LLMNR   */ 
            if( xApplicationDNSQueryHook ( ( pcRequestedName + 1 ) ) )
            {
            int16_t usLength;
            NetworkBufferDescriptor_t *pxNewBuffer = NULL;
            NetworkBufferDescriptor_t *pxNetworkBuffer = pxUDPPayloadBuffer_to_NetworkBuffer( pucUDPPayloadBuffer );
            LLMNRAnswer_t *pxAnswer;

                if( ( xBufferAllocFixedSize == pdFALSE ) && ( pxNetworkBuffer != NULL ) )
                {
                BaseType_t xDataLength = pxNetworkBuffer->xDataLength + sizeof( UDPHeader_t ) +
                    sizeof( EthernetHeader_t ) + sizeof( IPHeader_t );
                    /*2016--12--02--15--41--28(ZJYC):    */ 
                    /* The field xDataLength was set to the length of the UDP payload.
                    The answer (reply) will be longer than the request, so the packet
                    must be duplicaed into a bigger buffer */
                    pxNetworkBuffer->xDataLength = xDataLength;
                    pxNewBuffer = pxDuplicateNetworkBufferWithDescriptor( pxNetworkBuffer, xDataLength + 16 );
                    if( pxNewBuffer != NULL )
                    {
                    BaseType_t xOffset1, xOffset2;

                        xOffset1 = ( BaseType_t ) ( pucByte - pucUDPPayloadBuffer );
                        xOffset2 = ( BaseType_t ) ( ( ( uint8_t * ) pcRequestedName ) - pucUDPPayloadBuffer );

                        pxNetworkBuffer = pxNewBuffer;
                        pucUDPPayloadBuffer = pxNetworkBuffer->pucEthernetBuffer + ipUDP_PAYLOAD_OFFSET_IPv4;

                        pucByte = pucUDPPayloadBuffer + xOffset1;
                        pcRequestedName = ( char * ) ( pucUDPPayloadBuffer + xOffset2 );
                        pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;

                    }
                    else
                    {
                        /* Just to indicate that the message may not be answered. */
                        pxNetworkBuffer = NULL;
                    }
                }
                if( pxNetworkBuffer != NULL )
                {
                    pxAnswer = (LLMNRAnswer_t *)pucByte;

                    /* We leave 'usIdentifier' and 'usQuestions' untouched */
                    vSetField16( pxDNSMessageHeader, DNSMessage_t, usFlags, dnsLLMNR_FLAGS_IS_REPONSE );    /* Set the response flag */
                    vSetField16( pxDNSMessageHeader, DNSMessage_t, usAnswers, 1 );  /* Provide a single answer */
                    vSetField16( pxDNSMessageHeader, DNSMessage_t, usAuthorityRRs, 0 ); /* No authority */
                    vSetField16( pxDNSMessageHeader, DNSMessage_t, usAdditionalRRs, 0 );    /* No additional info */

                    pxAnswer->ucNameCode = dnsNAME_IS_OFFSET;
                    pxAnswer->ucNameOffset = ( uint8_t )( pcRequestedName - ( char * ) pucUDPPayloadBuffer );

                    vSetField16( pxAnswer, LLMNRAnswer_t, usType, dnsTYPE_A_HOST ); /* Type A: host */
                    vSetField16( pxAnswer, LLMNRAnswer_t, usClass, dnsCLASS_IN );   /* 1: Class IN */
                    vSetField32( pxAnswer, LLMNRAnswer_t, ulTTL, dnsLLMNR_TTL_VALUE );
                    vSetField16( pxAnswer, LLMNRAnswer_t, usDataLength, 4 );
                    vSetField32( pxAnswer, LLMNRAnswer_t, ulIPAddress, FreeRTOS_ntohl( *ipLOCAL_IP_ADDRESS_POINTER ) );

                    usLength = ( int16_t ) ( sizeof( *pxAnswer ) + ( size_t ) ( pucByte - pucUDPPayloadBuffer ) );

                    prvReplyDNSMessage( pxNetworkBuffer, usLength );

                    if( pxNewBuffer != NULL )
                    {
                        vReleaseNetworkBufferAndDescriptor( pxNewBuffer );
                    }
                }
            }
        }
#endif /* ipconfigUSE_LLMNR == 1 */
    }

    return ulIPAddress;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_NBNS == 1 )

    static void prvTreatNBNS( uint8_t *pucUDPPayloadBuffer, uint32_t ulIPAddress )
    {
        uint16_t usFlags, usType, usClass;
        uint8_t *pucSource, *pucTarget;
        uint8_t ucByte;
        uint8_t ucNBNSName[ 17 ];

        usFlags = usChar2u16( pucUDPPayloadBuffer + offsetof( NBNSRequest_t, usFlags ) );

        if( ( usFlags & dnsNBNS_FLAGS_OPCODE_MASK ) == dnsNBNS_FLAGS_OPCODE_QUERY )
        {
            usType  = usChar2u16( pucUDPPayloadBuffer + offsetof( NBNSRequest_t, usType ) );
            usClass = usChar2u16( pucUDPPayloadBuffer + offsetof( NBNSRequest_t, usClass ) );

            /* Not used for now */
            ( void )usClass;
            /* For NBNS a name is 16 bytes long, written with capitals only.
            Make sure that the copy is terminated with a zero. */
            pucTarget = ucNBNSName + sizeof(ucNBNSName ) - 2;
            pucTarget[ 1 ] = '\0';

            /* Start with decoding the last 2 bytes. */
            pucSource = pucUDPPayloadBuffer + ( offsetof( NBNSRequest_t, ucName ) + ( dnsNBNS_ENCODED_NAME_LENGTH - 2 ) );

            for( ;; )
            {
                ucByte = ( uint8_t ) ( ( ( pucSource[ 0 ] - 0x41 ) << 4 ) | ( pucSource[ 1 ] - 0x41 ) );

                /* Make sure there are no trailing spaces in the name. */
                if( ( ucByte == ' ' ) && ( pucTarget[ 1 ] == '\0' ) )
                {
                    ucByte = '\0';
                }

                *pucTarget = ucByte;

                if( pucTarget == ucNBNSName )
                {
                    break;
                }

                pucTarget -= 1;
                pucSource -= 2;
            }

            #if( ipconfigUSE_DNS_CACHE == 1 )
            {
                if( ( usFlags & dnsNBNS_FLAGS_RESPONSE ) != 0 )
                {
                    /* If this is a response from another device,
                    add the name to the DNS cache */
                    prvProcessDNSCache( ( char * ) ucNBNSName, &ulIPAddress, pdFALSE );
                }
            }
            #else
            {
                /* Avoid compiler warnings. */
                ( void ) ulIPAddress;
            }
            #endif /* ipconfigUSE_DNS_CACHE */

            if( ( ( usFlags & dnsNBNS_FLAGS_RESPONSE ) == 0 ) &&
                ( usType == dnsNBNS_TYPE_NET_BIOS ) &&
                ( xApplicationDNSQueryHook( ( const char * ) ucNBNSName ) != pdFALSE ) )
            {
            uint16_t usLength;
            DNSMessage_t *pxMessage;
            NBNSAnswer_t *pxAnswer;

                /* Someone is looking for a device with ucNBNSName,
                prepare a positive reply. */
                NetworkBufferDescriptor_t *pxNetworkBuffer = pxUDPPayloadBuffer_to_NetworkBuffer( pucUDPPayloadBuffer );

                if( ( xBufferAllocFixedSize == pdFALSE ) && ( pxNetworkBuffer != NULL ) )
                {
                NetworkBufferDescriptor_t *pxNewBuffer;
                BaseType_t xDataLength = pxNetworkBuffer->xDataLength + sizeof( UDPHeader_t ) +

                    sizeof( EthernetHeader_t ) + sizeof( IPHeader_t );

                    /* The field xDataLength was set to the length of the UDP payload.
                    The answer (reply) will be longer than the request, so the packet
                    must be duplicated into a bigger buffer */
                    pxNetworkBuffer->xDataLength = xDataLength;
                    pxNewBuffer = pxDuplicateNetworkBufferWithDescriptor( pxNetworkBuffer, xDataLength + 16 );
                    if( pxNewBuffer != NULL )
                    {
                        pucUDPPayloadBuffer = pxNewBuffer->pucEthernetBuffer + sizeof( UDPPacket_t );
                        pxNetworkBuffer = pxNewBuffer;
                    }
                    else
                    {
                        /* Just prevent that a reply will be sent */
                        pxNetworkBuffer = NULL;
                    }
                }

                /* Should not occur: pucUDPPayloadBuffer is part of a xNetworkBufferDescriptor */
                if( pxNetworkBuffer != NULL )
                {
                    pxMessage = (DNSMessage_t *)pucUDPPayloadBuffer;

                    /* As the fields in the structures are not word-aligned, we have to
                    copy the values byte-by-byte using macro's vSetField16() and vSetField32() */
                    vSetField16( pxMessage, DNSMessage_t, usFlags, dnsNBNS_QUERY_RESPONSE_FLAGS ); /* 0x8500 */
                    vSetField16( pxMessage, DNSMessage_t, usQuestions, 0 );
                    vSetField16( pxMessage, DNSMessage_t, usAnswers, 1 );
                    vSetField16( pxMessage, DNSMessage_t, usAuthorityRRs, 0 );
                    vSetField16( pxMessage, DNSMessage_t, usAdditionalRRs, 0 );

                    pxAnswer = (NBNSAnswer_t *)( pucUDPPayloadBuffer + offsetof( NBNSRequest_t, usType ) );

                    vSetField16( pxAnswer, NBNSAnswer_t, usType, usType );  /* Type */
                    vSetField16( pxAnswer, NBNSAnswer_t, usClass, dnsNBNS_CLASS_IN );   /* Class */
                    vSetField32( pxAnswer, NBNSAnswer_t, ulTTL, dnsNBNS_TTL_VALUE );
                    vSetField16( pxAnswer, NBNSAnswer_t, usDataLength, 6 ); /* 6 bytes including the length field */
                    vSetField16( pxAnswer, NBNSAnswer_t, usNbFlags, dnsNBNS_NAME_FLAGS );
                    vSetField32( pxAnswer, NBNSAnswer_t, ulIPAddress, FreeRTOS_ntohl( *ipLOCAL_IP_ADDRESS_POINTER ) );

                    usLength = ( uint16_t ) ( offsetof( NBNSRequest_t, usType ) + sizeof( NBNSAnswer_t ) );

                    prvReplyDNSMessage( pxNetworkBuffer, usLength );
                }
            }
        }
    }

#endif  /* ipconfigUSE_NBNS */
/*-----------------------------------------------------------*/

static Socket_t prvCreateDNSSocket( void )
{
static Socket_t xSocket = NULL;
struct freertos_sockaddr xAddress;
BaseType_t xReturn;
TickType_t xTimeoutTime = pdMS_TO_TICKS( 200 );

    /*2016--12--02--15--42--41(ZJYC): 这一定是第一次调用此函数，创建套接字   */ 
    xSocket = FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_DGRAM, FREERTOS_IPPROTO_UDP );
    /*2016--12--02--15--41--59(ZJYC): 自动绑定端口   */ 
    xAddress.sin_port = 0u;
    xReturn = FreeRTOS_bind( xSocket, &xAddress, sizeof( xAddress ) );
    /*2016--12--02--15--42--17(ZJYC): 检查是否绑定成功，否则清了他们   */ 
    if( xReturn != 0 )
    {
        FreeRTOS_closesocket( xSocket );
        xSocket = NULL;
    }
    else
    {
        /*2016--12--02--15--43--07(ZJYC): 设置接收和发射超时时长   */ 
        FreeRTOS_setsockopt( xSocket, 0, FREERTOS_SO_RCVTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
        FreeRTOS_setsockopt( xSocket, 0, FREERTOS_SO_SNDTIMEO, ( void * ) &xTimeoutTime, sizeof( TickType_t ) );
    }
    return xSocket;
}
/*-----------------------------------------------------------*/

#if( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) )

    static void prvReplyDNSMessage( NetworkBufferDescriptor_t *pxNetworkBuffer, BaseType_t lNetLength )
    {
    UDPPacket_t *pxUDPPacket;
    IPHeader_t *pxIPHeader;
    UDPHeader_t *pxUDPHeader;

        pxUDPPacket = (UDPPacket_t *) pxNetworkBuffer->pucEthernetBuffer;
        pxIPHeader = &pxUDPPacket->xIPHeader;
        pxUDPHeader = &pxUDPPacket->xUDPHeader;
        /* HT: started using defines like 'ipSIZE_OF_xxx' */
        pxIPHeader->usLength               = FreeRTOS_htons( lNetLength + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_UDP_HEADER );
        /* HT:endian: should not be translated, copying from packet to packet */
        pxIPHeader->ulDestinationIPAddress = pxIPHeader->ulSourceIPAddress;
        pxIPHeader->ulSourceIPAddress      = *ipLOCAL_IP_ADDRESS_POINTER;
        pxIPHeader->ucTimeToLive           = ipconfigUDP_TIME_TO_LIVE;
        pxIPHeader->usIdentification       = FreeRTOS_htons( usPacketIdentifier );
        usPacketIdentifier++;
        pxUDPHeader->usLength              = FreeRTOS_htons( lNetLength + ipSIZE_OF_UDP_HEADER );
        vFlip_16( pxUDPPacket->xUDPHeader.usSourcePort, pxUDPPacket->xUDPHeader.usDestinationPort );

        #if( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
        {
            /*2016--12--02--15--44--59(ZJYC): 计算IP头校验和   */ 
            pxIPHeader->usHeaderChecksum       = 0x00;
            pxIPHeader->usHeaderChecksum       = usGenerateChecksum( 0UL, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
            pxIPHeader->usHeaderChecksum       = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
            /*2016--12--02--15--44--40(ZJYC): 计算包的检验和   */ 
            usGenerateProtocolChecksum( ( uint8_t* ) pxUDPPacket, pdTRUE );
        }
        #endif
        /*2016--12--02--15--43--46(ZJYC): 高速NIC驱动，多少个字节必须被发送   */ 
        pxNetworkBuffer->xDataLength = ( size_t ) ( lNetLength + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_UDP_HEADER + ipSIZE_OF_ETH_HEADER );
        /*2016--12--02--15--44--20(ZJYC): 函数将会填充以太网地址并发送他   */ 
        vReturnEthernetFrame( pxNetworkBuffer, pdFALSE );
    }

#endif /* ipconfigUSE_NBNS == 1 || ipconfigUSE_LLMNR == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_DNS_CACHE == 1 )

    static void prvProcessDNSCache( const char *pcName, uint32_t *pulIP, BaseType_t xLookUp )
    {
    BaseType_t x;
    BaseType_t xFound = pdFALSE;
    static BaseType_t xFreeEntry = 0;

        /*2016--12--02--15--45--32(ZJYC): 遍历DNS缓存   */ 
        for( x = 0; x < ipconfigDNS_CACHE_ENTRIES; x++ )
        {
            if( xDNSCache[ x ].pcName[ 0 ] == 0 )
            {
                break;
            }
            if( strncmp( xDNSCache[ x ].pcName, pcName, sizeof( xDNSCache[ x ].pcName ) ) == 0 )
            {
                /*2016--12--02--15--45--54(ZJYC): 查找或添加   */ 
                if( xLookUp != pdFALSE )
                {
                    *pulIP = xDNSCache[ x ].ulIPAddress;
                }
                else
                {
                    xDNSCache[ x ].ulIPAddress = *pulIP;
                }
                xFound = pdTRUE;
                break;
            }
        }

        if( xFound == pdFALSE )
        {
            if( xLookUp != pdFALSE )
            {
                *pulIP = 0;
            }
            else
            {
                /* Called to add or update an item */
                strncpy( xDNSCache[ xFreeEntry ].pcName, pcName, sizeof( xDNSCache[ xFreeEntry ].pcName ) );
                xDNSCache[ xFreeEntry ].ulIPAddress = *pulIP;

                xFreeEntry++;
                if( xFreeEntry == ipconfigDNS_CACHE_ENTRIES )
                {
                    xFreeEntry = 0;
                }
            }
        }

        if( ( xLookUp == 0 ) || ( *pulIP != 0 ) )
        {
            FreeRTOS_debug_printf( ( "prvProcessDNSCache: %s: '%s' @ %lxip\n", xLookUp ? "look-up" : "add", pcName, FreeRTOS_ntohl( *pulIP ) ) );
        }
    }

#endif /* ipconfigUSE_DNS_CACHE */

#endif /* ipconfigUSE_DNS != 0 */


