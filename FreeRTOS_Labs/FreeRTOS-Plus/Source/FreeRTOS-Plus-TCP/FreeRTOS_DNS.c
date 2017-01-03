
/*2016--12--02--09--44--48(ZJYC): ��׼ͷ�ļ�   */ 
#include <stdint.h>

/*2016--12--02--09--45--00(ZJYC): FREERTOSͷ�ļ�   */ 
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "list.h"
#include "semphr.h"

/*2016--12--02--09--45--12(ZJYC): FREERTOS+TCPͷ�ļ�   */ 
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DNS.h"
#include "NetworkBufferManagement.h"
#include "NetworkInterface.h"
#include "IPTraceMacroDefaults.h"

/*2016--12--02--09--45--28(ZJYC): ���DNS���������ų�����   */ 
#if( ipconfigUSE_DNS != 0 )

#if( ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN )
    #define dnsDNS_PORT                     0x3500
    #define dnsONE_QUESTION                 0x0100
    #define dnsOUTGOING_FLAGS               0x0001 /*2016--12--02--09--45--53(ZJYC): ��׼����   */ 
    #define dnsRX_FLAGS_MASK                0x0f80 /*2016--12--02--09--46--11(ZJYC): ��־λ����   */ 
    #define dnsEXPECTED_RX_FLAGS            0x0080 /*2016--12--02--09--46--37(ZJYC): DNS�ظ���־������û���κδ���   */ 
#else
    #define dnsDNS_PORT                     0x0035
    #define dnsONE_QUESTION                 0x0001
    #define dnsOUTGOING_FLAGS               0x0100 /*2016--12--02--09--45--53(ZJYC): ��׼����   */ 
    #define dnsRX_FLAGS_MASK                0x800f /*2016--12--02--09--46--11(ZJYC): ��־λ����   */ 
    #define dnsEXPECTED_RX_FLAGS            0x8000 /*2016--12--02--09--46--37(ZJYC): DNS�ظ���־������û���κδ���   */ 

#endif /* ipconfigBYTE_ORDER */

/*2016--12--02--09--47--55(ZJYC): ��δ����֮ǰ���ղ����ظ�������£��೤ʱ���ٴη�������   */ 
#ifndef ipconfigDNS_REQUEST_ATTEMPTS
    #define ipconfigDNS_REQUEST_ATTEMPTS        5
#endif

/*2016--12--02--09--49--12(ZJYC): ��������ĵ�һ�ֽڵĸ���λ����λ�������
��Ϊ�����ַ�����ƫ�ƶ���������ַ���   */ 
/*2016--12--02--10--31--37(ZJYC): ����һ��ѹ��DNS���ģ������ظ����ַ�ʹ��������ʾ   */ 
#define dnsNAME_IS_OFFSET                   ( ( uint8_t ) 0xc0 )

/*2016--12--02--09--50--46(ZJYC): NBNS��־   */ 
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

/*2016--12--02--10--54--00(ZJYC): ����������������������ƥ�䣬�ظ��н�����Ŵ˱�־   */ 
#define dnsNBNS_QUERY_RESPONSE_FLAGS    ( 0x8500 )

/*2016--12--02--10--54--40(ZJYC): �����׽��ֲ��󶨵���׼DNS�˿ڣ����ش������׽���
���ΪNULL�������򲻰�   */ 
static Socket_t prvCreateDNSSocket( void );

/*2016--12--02--10--55--41(ZJYC): �ڵ�һ���������ݵ��㸴�ƻ������д���DNS��Ϣ   */ 
static size_t prvCreateDNSMessage( uint8_t *pucUDPPayloadBuffer, const char *pcHostName, TickType_t xIdentifier );

/*2016--12--02--10--56--31(ZJYC): ������Դ��¼�е���������   */ 
static uint8_t *prvSkipNameField( uint8_t *pucByte );

/*2016--12--02--10--57--28(ZJYC): ��������DNS�������Ļظ�   */ 
static uint32_t prvParseDNSReply( uint8_t *pucUDPPayloadBuffer, TickType_t xIdentifier );

/*2016--12--02--10--57--55(ZJYC): ׼������DNS��Ϣ��DNS��������xReadTimeOut_msΪ0 �Է�
�û��ṩ�˻ص�����   */ 
static uint32_t prvGetHostByName( const char *pcHostName, TickType_t xIdentifier, TickType_t xReadTimeOut_ms );

/*2016--12--02--10--59--02(ZJYC): NBNSЭ���LLMNRЭ�鹲��ظ�����   */ 
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
        uint32_t ulIPAddress;       /*2016--12--02--11--00--00(ZJYC): ARP������ڵ�IP��ַ   */ 
        char pcName[ipconfigDNS_CACHE_NAME_LENGTH];  /*2016--12--02--11--00--30(ZJYC): ��������   */ 
        uint8_t ucAge;              /*2016--12--02--11--01--41(ZJYC): ���ڵݼ�����ֵ�����Ա���ͨˢ�£��������0��ARP������ж�Ӧ����ᱻ���   */ 
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

/*2016--12--02--11--02--53(ZJYC): DNS��ѯ����ͷ������xDNSMessage������������������1��������
ÿһ���������ƺ����ͺ�class   */ 
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
        uint8_t ucNameOffset;   /*2016--12--02--13--39--40(ZJYC): ���Ʋ����ظ����֣�ֻ�����һƫ����   */ 
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
        TickType_t xRemaningTime;       /*2016--12--02--13--40--31(ZJYC): ��ʱms��λ   */ 
        FOnDNSEvent pCallbackFunction;  /*2016--12--02--13--40--47(ZJYC): ����ʱ���߻�ȡһIP��ַ֮����õĺ���   */ 
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
    /*2016--12--02--13--41--48(ZJYC): ��ʼ���ص��ṹ   */ 
    void vDNSInitialise( void );
    void vDNSInitialise( void )
    {
        vListInitialise( &xCallbackList );
    }
    /*-----------------------------------------------------------*/
    /*2016--12--02--14--06--08(ZJYC): �����ص��ṹ�岢��ɾ���ɵĳ�ʱ��
    һ���б��Ϊ�գ�DNS��ʱ������ֹͣ���û�ȡ��DNS��������ṩpvSearchID
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
                /*2016--12--02--14--08--31(ZJYC): �ߵ���һ���б���Ϊ����Ҫɾ������б�   */ 
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
    /*2016--12--02--14--09--16(ZJYC): FreeRTOS_gethostbyname_a()�����Żص���������
    �洢֮�Ա����ʹ��*/ 
    static void vDNSSetCallBack( const char *pcHostName, void *pvSearchID, FOnDNSEvent pCallbackFunction, TickType_t xTimeout, TickType_t xIdentifier );
    static void vDNSSetCallBack( const char *pcHostName, void *pvSearchID, FOnDNSEvent pCallbackFunction, TickType_t xTimeout, TickType_t xIdentifier )
    {
        size_t lLength = strlen( pcHostName );
        DNSCallback_t *pxCallback = ( DNSCallback_t * )pvPortMalloc( sizeof( *pxCallback ) + lLength );
        /*2016--12--02--14--10--26(ZJYC): ��msת��Ϊʱ�ӵδ�   */ 
        xTimeout /= portTICK_PERIOD_MS;
        if( pxCallback != NULL )
        {
            if( listLIST_IS_EMPTY( &xCallbackList ) )
            {
                /*2016--12--02--14--10--54(ZJYC): ���ǵ�һ��������DNS��ʱ��������Ƿ�ʱ   */ 
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
    /*2016--12--02--14--11--25(ZJYC): DNS�ظ������գ������Ƿ���ƥ���
    ��ڲ����þ��*/ 
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
/*2016--12--02--14--12--15(ZJYC): ����һ��һ�ı�ʾ�������������ھֲ�����
��Ϊ gethostbyname() �ᱻ��ͬ���̵߳���   */ 
TickType_t xIdentifier = ( TickType_t )usIdentifier++;
    /*2016--12--02--14--13--22(ZJYC): ���ʹ��DNS���棬���Ȼ����Ƿ�������洢��   */ 
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
                /*2016--12--02--14--14--13(ZJYC): �û��ṩ�˻ص����������ԣ�������recvfrom()����   */ 
                xReadTimeOut_ms  = 0;
                vDNSSetCallBack( pcHostName, pvSearchID, pCallback, xTimeout, ( TickType_t ) xIdentifier );
            }
            else
            {
                /*2016--12--02--14--14--47(ZJYC): ���IP��ַ֪���ˣ�ִ�лص�����   */ 
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
    /*2016--12--02--14--15--41(ZJYC): ���LLMNR��ʹ�ã�Ȼ���ж��Ƿ�����������'.'��
    �������LLMNR���Ա���Ϊһ����������*/ 
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
    /*2016--12--02--14--19--21(ZJYC): ����Ǹ�2�ǽ�������   */ 
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
            /*2016--12--02--14--21--06(ZJYC): ��ȡһ���壬ʹ�������ӳ٣������ӳٻᱻ
            ������ipconfigUDP_MAX_SEND_BLOCK_TIME_TICKS���Է���ֵ��Ҫ�����*/ 
            pucUDPPayloadBuffer = ( uint8_t * ) FreeRTOS_GetUDPPayloadBuffer( xExpectedPayloadLength, portMAX_DELAY );
            if( pucUDPPayloadBuffer != NULL )
            {
                /*2016--12--02--14--22--11(ZJYC): �ڻ�ȡ�Ļ���������DNS��Ϣ   */ 
                xPayloadLength = prvCreateDNSMessage( pucUDPPayloadBuffer, pcHostName, xIdentifier );
                iptraceSENDING_DNS_REQUEST();
                /*2016--12--02--14--22--40(ZJYC): ��ȡDNS��������ַ   */ 
                FreeRTOS_GetAddressConfiguration( NULL, NULL, NULL, &ulIPAddress );
                /*2016--12--02--14--22--58(ZJYC): ����DNS��Ϣ   */ 
                /* Send the DNS message. */
#if( ipconfigUSE_LLMNR == 1 )
                if( bHasDot == pdFALSE )
                {
                    /*2016--12--02--14--23--13(ZJYC): ʹ��LLMNR��ַ   */ 
                    ( ( DNSMessage_t * ) pucUDPPayloadBuffer) -> usFlags = 0;
                    xAddress.sin_addr = ipLLMNR_IP_ADDR;    /* Is in network byte order. */
                    xAddress.sin_port = FreeRTOS_ntohs( ipLLMNR_PORT );
                }
                else
#endif
                {
                    /*2016--12--02--14--23--44(ZJYC): ʹ��DNS������   */ 
                    xAddress.sin_addr = ulIPAddress;
                    xAddress.sin_port = dnsDNS_PORT;
                }
                ulIPAddress = 0UL;
                if( FreeRTOS_sendto( xDNSSocket, pucUDPPayloadBuffer, xPayloadLength, FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) ) != 0 )
                {
                    /*2016--12--02--14--24--10(ZJYC): �ȴ��ظ�   */ 
                    lBytes = FreeRTOS_recvfrom( xDNSSocket, &pucUDPPayloadBuffer, 0, FREERTOS_ZERO_COPY, &xAddress, &ulAddressLength );
                    if( lBytes > 0 )
                    {
                        /*2016--12--02--14--31--16(ZJYC): �յ��ظ���������   */ 
                        ulIPAddress = prvParseDNSReply( pucUDPPayloadBuffer, xIdentifier );
                        /*2016--12--02--14--31--32(ZJYC): ������ϣ��㸴�ƽӿ��Ѿ���ʹ�ã����Ի�����Ա��ͷ���   */ 
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
                    /*2016--12--02--14--42--05(ZJYC): ��Ϣû�б����ͣ����Բ���ͨ���㸴���ͷţ������������ͷ�   */ 
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
    0,                  /*2016--12--02--14--44--07(ZJYC): ��ʾ���ᱻ��д   */ 
    dnsOUTGOING_FLAGS,  /*2016--12--02--14--45--33(ZJYC): ��׼����   */ 
    dnsONE_QUESTION,    /*2016--12--02--14--45--44(ZJYC): ֻ��һ������   */ 
    0,                  /*2016--12--02--14--45--55(ZJYC): û�лظ�   */ 
    0,                  /*2016--12--02--14--46--05(ZJYC): û��Ȩ��   */ 
    0                   /*2016--12--02--14--46--16(ZJYC): û�ж���   */ 
};

    /*2016--12--02--14--46--33(ZJYC): ����ͷ����������   */ 
    memcpy( ( void * ) pucUDPPayloadBuffer, ( void * ) &xDefaultPartDNSHeader, sizeof( xDefaultPartDNSHeader ) );
    /*2016--12--02--14--46--51(ZJYC): д��Ψһ��ʶ��   */ 
    pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;
    pxDNSMessageHeader->usIdentifier = ( uint16_t ) xIdentifier;
    /*2016--12--02--14--47--04(ZJYC): ��ͷ��ĩβ������Դ��¼�������ҵ�ͷ��β��   */ 
    pucStart = pucUDPPayloadBuffer + sizeof( xDefaultPartDNSHeader );
    /*2016--12--02--14--47--52(ZJYC): Ϊ�����ֽ������ռ�   */ 
    pucByte = pucStart + 1;
    /*2016--12--02--14--48--26(ZJYC): ����������   */ 
    strcpy( ( char * ) pucByte, pcHostName );
    /*2016--12--02--14--48--59(ZJYC): ����ַ�����λ   */ 
    pucByte += strlen( pcHostName );
    *pucByte = 0x00u;
    /*2016--12--02--14--49--15(ZJYC): �������滻'.'Ϊ����   */ 
    pucByte = pucStart;
    do
    {
        pucByte++;
        while( ( *pucByte != 0x00 ) && ( *pucByte != '.' ) )
        {
            pucByte++;
        }
        /*2016--12--02--14--49--40(ZJYC): ����ֽڼ���   */ 
        *pucStart = ( uint8_t ) ( ( uint32_t ) pucByte - ( uint32_t ) pucStart );
        ( *pucStart )--;
        pucStart = pucByte;
    } while( *pucByte != 0x00 );
    /*2016--12--02--14--50--14(ZJYC): ��ɼ�¼�����   */ 
    pxTail = (DNSTail_t *)( pucByte + 1 );
    vSetField16( pxTail, DNSTail_t, usType, dnsTYPE_A_HOST );   /* Type A: host */
    vSetField16( pxTail, DNSTail_t, usClass, dnsCLASS_IN ); /* 1: Class IN */
    /*2016--12--02--14--50--36(ZJYC): ������������Ϣ���ܳ��ȣ���ʼ�����һ����д����ֽ�
    �����ڻ���ͷ��*/ 
    return ( ( uint32_t ) pucByte - ( uint32_t ) pucUDPPayloadBuffer + 1 ) + sizeof( *pxTail );
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_DNS_CACHE == 1 )
    static uint8_t *prvReadNameField( uint8_t *pucByte, char *pcName, BaseType_t xLen )
    {
    BaseType_t xNameLen = 0;
        /*2016--12--02--14--51--57(ZJYC): �ж��Ƿ�����Ϊ��ȫ�������ƣ�������һ��ƫ��ָ�������ط�   */ 
        if( ( *pucByte & dnsNAME_IS_OFFSET ) == dnsNAME_IS_OFFSET )
        {
            /*2016--12--02--14--53--10(ZJYC): �������ֽ�ƫ��   */ 
            pucByte += sizeof( uint16_t );
        }
        else
        {
            /*2016--12--02--14--53--33(ZJYC): pucByteָ��ȫ�ַ����룬�����ַ���   */ 
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
    /*2016--12--02--14--54--10(ZJYC): �����Ƿ�Ϊȫ�ַ����֣�����һƫ��ָ�������ط�   */ 
    if( ( *pucByte & dnsNAME_IS_OFFSET ) == dnsNAME_IS_OFFSET )
    {
        /* Jump over the two byte offset. */
        pucByte += sizeof( uint16_t );
    }
    else
    {
        /*2016--12--02--14--55--01(ZJYC): ָ��ȫ�ַ����������ַ���   */ 
        while( *pucByte != 0x00 )
        {
            /*2016--12--02--14--55--28(ZJYC): �����ƶ��������ַ������ȣ�������������   */ 
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

    /*2016--12--02--15--24--46(ZJYC): ��û�б�����   */ 
    return pdFAIL;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_NBNS == 1 )

    uint32_t ulNBNSHandlePacket (NetworkBufferDescriptor_t *pxNetworkBuffer )
    {
    UDPPacket_t *pxUDPPacket = ( UDPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;
    uint8_t *pucUDPPayloadBuffer = pxNetworkBuffer->pucEthernetBuffer + sizeof( *pxUDPPacket );

        prvTreatNBNS( pucUDPPayloadBuffer, pxUDPPacket->xIPHeader.ulSourceIPAddress );

        /*2016--12--02--15--24--46(ZJYC): ��û�б�����   */ 
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
        /*2016--12--02--15--25--24(ZJYC): ��ͷ��֮��ĵ�һ���ֽڿ�ʼ   */ 
        pucByte = pucUDPPayloadBuffer + sizeof( DNSMessage_t );
        /*2016--12--02--15--25--42(ZJYC): �������������¼   */ 
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
                /*2016--12--02--15--26--20(ZJYC): ����������   */ 
                pucByte = prvSkipNameField( pucByte );
            }
            #if( ipconfigUSE_LLMNR == 1 )
            {
                /* usChar2u16 returns value in host endianness */
                usType = usChar2u16( pucByte );
                usClass = usChar2u16( pucByte + 2 );
            }
            #endif /* ipconfigUSE_LLMNR */

            /*2016--12--02--15--26--44(ZJYC): ����Type��Class����   */ 
            pucByte += sizeof( uint32_t );
        }
        /*2016--12--02--15--27--01(ZJYC): �ӻش��¼��ʼѰ��   */ 
        pxDNSMessageHeader->usAnswers = FreeRTOS_ntohs( pxDNSMessageHeader->usAnswers );
        if( ( pxDNSMessageHeader->usFlags & dnsRX_FLAGS_MASK ) == dnsEXPECTED_RX_FLAGS )
        {
            for( x = 0; x < pxDNSMessageHeader->usAnswers; x++ )
            {
                pucByte = prvSkipNameField( pucByte );

                /*2016--12--02--15--28--25(ZJYC): �Ƿ���A����   */ 
                if( usChar2u16( pucByte ) == dnsTYPE_A_HOST )
                {
                    /*2016--12--02--15--33--13(ZJYC): ����������Ҫ�ļ�¼���������ͣ�Class��TTL������
                    ��һ������*/ 
                    pucByte += ( sizeof( uint32_t ) + sizeof( uint32_t ) + sizeof( uint8_t ) );
                    /*2016--12--02--15--34--13(ZJYC): �����Լ�����ݳ���   */ 
                    if( ( size_t ) *pucByte == sizeof( uint32_t ) )
                    {
                        /*2016--12--02--15--34--28(ZJYC): �����ڶ�������   */ 
                        pucByte++;
                        /*2016--12--02--15--38--51(ZJYC): ����IP��ַ   */ 
                        memcpy( ( void * ) &ulIPAddress, ( void * ) pucByte, sizeof( uint32_t ) );
                        #if( ipconfigUSE_DNS_CACHE == 1 )
                        {
                            prvProcessDNSCache( pcName, &ulIPAddress, pdFALSE );
                        }
                        #endif /* ipconfigUSE_DNS_CACHE */
                        #if( ipconfigDNS_USE_CALLBACKS != 0 )
                        {
                            /*2016--12--02--15--39--04(ZJYC): �鿴�Ƿ�������FreeRTOS_gethostbyname_a�첽����   */ 
                            vDNSDoCallback( ( TickType_t ) pxDNSMessageHeader->usIdentifier, pcName, ulIPAddress );
                        }
                        #endif  /* ipconfigDNS_USE_CALLBACKS != 0 */
                    }
                    break;
                }
                else
                {
                    /*2016--12--02--15--39--48(ZJYC): ����type��class��TTL   */ 
                    pucByte += ( sizeof( uint32_t ) + sizeof( uint32_t ) );
                    /*2016--12--02--15--40--10(ZJYC): �������ݵĳ���   */ 
                    memcpy( ( void * ) &usDataLength, ( void * ) pucByte, sizeof( uint16_t ) );
                    usDataLength = FreeRTOS_ntohs( usDataLength );
                    /*2016--12--02--15--40--30(ZJYC): �������ݳ������ݱ���   */ 
                    pucByte += usDataLength + sizeof( uint16_t );
                }
            }
        }
#if( ipconfigUSE_LLMNR == 1 )
        else if( usQuestions && ( usType == dnsTYPE_A_HOST ) && ( usClass == dnsCLASS_IN ) )
        {
            /*2016--12--02--15--41--06(ZJYC): �ⲻ�Ƕ����ǵ�DNS��Ӧ���п�����LLMNR   */ 
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

    /*2016--12--02--15--42--41(ZJYC): ��һ���ǵ�һ�ε��ô˺����������׽���   */ 
    xSocket = FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_DGRAM, FREERTOS_IPPROTO_UDP );
    /*2016--12--02--15--41--59(ZJYC): �Զ��󶨶˿�   */ 
    xAddress.sin_port = 0u;
    xReturn = FreeRTOS_bind( xSocket, &xAddress, sizeof( xAddress ) );
    /*2016--12--02--15--42--17(ZJYC): ����Ƿ�󶨳ɹ���������������   */ 
    if( xReturn != 0 )
    {
        FreeRTOS_closesocket( xSocket );
        xSocket = NULL;
    }
    else
    {
        /*2016--12--02--15--43--07(ZJYC): ���ý��պͷ��䳬ʱʱ��   */ 
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
            /*2016--12--02--15--44--59(ZJYC): ����IPͷУ���   */ 
            pxIPHeader->usHeaderChecksum       = 0x00;
            pxIPHeader->usHeaderChecksum       = usGenerateChecksum( 0UL, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
            pxIPHeader->usHeaderChecksum       = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
            /*2016--12--02--15--44--40(ZJYC): ������ļ����   */ 
            usGenerateProtocolChecksum( ( uint8_t* ) pxUDPPacket, pdTRUE );
        }
        #endif
        /*2016--12--02--15--43--46(ZJYC): ����NIC���������ٸ��ֽڱ��뱻����   */ 
        pxNetworkBuffer->xDataLength = ( size_t ) ( lNetLength + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_UDP_HEADER + ipSIZE_OF_ETH_HEADER );
        /*2016--12--02--15--44--20(ZJYC): �������������̫����ַ��������   */ 
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

        /*2016--12--02--15--45--32(ZJYC): ����DNS����   */ 
        for( x = 0; x < ipconfigDNS_CACHE_ENTRIES; x++ )
        {
            if( xDNSCache[ x ].pcName[ 0 ] == 0 )
            {
                break;
            }
            if( strncmp( xDNSCache[ x ].pcName, pcName, sizeof( xDNSCache[ x ].pcName ) ) == 0 )
            {
                /*2016--12--02--15--45--54(ZJYC): ���һ����   */ 
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


