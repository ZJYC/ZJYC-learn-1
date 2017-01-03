/*
    ARP协议就是MAC地址到IP地址的一种映射管理，MAC作为网卡的唯一标示难以记忆和管理，
    相反就是IP地址十分方便，所以在与任何一个网卡进行通信前，都需要获取对方的MAC地址，
    即发送ARP请求：
    目的MAC+源MAC+帧类型+硬件类型+协议类型+硬件地址长度+协议地址长度+op+发送者MAC+发送者IP+接受者MAC+接受者MAC
    |以太网首部---------|arp首部-------------------------------------------|ARP字段-------------------------------|
    以太网首部的目的地址是FFFFFFFFFFFF，意思是发给所有在线的网卡，
    ARP字段中的接受者MAC为000000000000表示此MAC地址需要填充
    目标IP的网卡收到此ARP请求后会单独回复（单播）
    
    函数介绍：
    
    eFrameProcessingResult_t eARPProcessPacket( ARPPacket_t * const pxARPFrame );
        处理ARP请求包与ARP应答包
        pxARPFrame：ARP帧信息
    uint32_t ulARPRemoveCacheEntryByMac( const MACAddress_t * pxMACAddress )
        通过MAC地址来删除缓存项
        pxMACAddress：待删除MAC地址
    void vARPRefreshCacheEntry( const MACAddress_t * pxMACAddress, const uint32_t ulIPAddress )
        刷新缓存
        pxMACAddress：？？？
        ulIPAddress：？？？
    eARPLookupResult_t eARPGetCacheEntryByMac( MACAddress_t * const pxMACAddress, uint32_t *pulIPAddress )
        根据MAC获取IP地址
        pxMACAddress：待获取MAC地址
        pulIPAddress：返回的IP地址
    eARPLookupResult_t eARPGetCacheEntry( uint32_t *pulIPAddress, MACAddress_t * const pxMACAddress )
        根据IP地址获取MAC地址
        pulIPAddress：IP地址
        pxMACAddress：MAC地址
    static eARPLookupResult_t prvCacheLookup( uint32_t ulAddressToLookup, MACAddress_t * const pxMACAddress )
        缓存表搜索
    void vARPAgeCache( void )
        缓存表生命周期递减
    void vARPSendGratuitous( void )
        发送免费ARP
    void FreeRTOS_OutputARPRequest( uint32_t ulIPAddress )
        发送ARP请求
    void vARPGenerateRequestPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer )
        产生ARP请求包
    void FreeRTOS_ClearARP( void )
        清除ARP缓存
    void FreeRTOS_PrintARPCache( void )
        打印ARP缓存
*/
/* 标准头文件 */
#include <stdint.h>
#include <stdio.h>
/* 操作系统头文件 */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
/* 协议栈头文件 */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DHCP.h"
#if( ipconfigUSE_LLMNR == 1 )
    #include "FreeRTOS_DNS.h"
#endif /* ipconfigUSE_LLMNR */
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"
/* 当ARP缓存项到期时（到达此数值），会发送ARP请求包来刷新缓存 */
#define arpMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST       ( 3 )
/* 免费ARP周期（用于与定期检查是否存在IP冲突） */
#ifndef arpGRATUITOUS_ARP_PERIOD
    #define arpGRATUITOUS_ARP_PERIOD                    ( pdMS_TO_TICKS( 20000 ) )
#endif
/* 根据IP地址查询MAC地址 */
static eARPLookupResult_t prvCacheLookup( uint32_t ulAddressToLookup, MACAddress_t * const pxMACAddress );
/* ARP缓存 */
static ARPCacheRow_t xARPCache[ ipconfigARP_CACHE_ENTRIES ];
/* 上一个免费ARP发送的时间 */
static TickType_t xLastGratuitousARPTime = ( TickType_t ) 0;
/* IP冲突检测目前只是内部使用，当DHCP没有回应时，驱动会尝试一个随机的链路层地址（169.254.x.x）
他会发出一免费ARP消息，一段时间之后，检查下面的变量 */
#if( ipconfigARP_USE_CLASH_DETECTION != 0 )
    /* 如果其他设备回复了免费ARP，则数值为非零值 */
    BaseType_t xARPHadIPClash;
    /* 与本机冲突的设备的MAC地址 */
    MACAddress_t xARPClashMacAddress;
#endif /* ipconfigARP_USE_CLASH_DETECTION */
/* 以太网和ARP头 */
static const uint8_t xDefaultPartARPPacketHeader[] =
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* 目的地址 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* 源地址 */
    0x08, 0x06,                             /* 帧类型 */
    0x00, 0x01,                             /* 硬件类型 */
    0x08, 0x00,                             /* 协议类型 */
    ipMAC_ADDRESS_LENGTH_BYTES,             /* 硬件地址长度 */
    ipIP_ADDRESS_LENGTH_BYTES,              /* 协议地址长度 */
    0x00, 0x01,                             /* 操作类型 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* 发送者硬件地址 */
    0x00, 0x00, 0x00, 0x00,                 /* 发送者协议地址 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00      /* 目标硬件地址 */
};
/* ARP数据包处理 */
eFrameProcessingResult_t eARPProcessPacket( ARPPacket_t * const pxARPFrame )
{
eFrameProcessingResult_t eReturn = eReleaseBuffer;
ARPHeader_t *pxARPHeader;

    pxARPHeader = &( pxARPFrame->xARPHeader );
    traceARP_PACKET_RECEIVED();
    /* 如果本地地址为0则不作任何事情，这意味着DHCP请求还没有完成 */
    if( *ipLOCAL_IP_ADDRESS_POINTER != 0UL )
    {
        switch( pxARPHeader->usOperation )
        {
            /* ARP请求包 */
            case ipARP_REQUEST  :
                /* 请求本地地址 */
                if( pxARPHeader->ulTargetProtocolAddress == *ipLOCAL_IP_ADDRESS_POINTER )
                {
                    iptraceSENDING_ARP_REPLY( pxARPHeader->ulSenderProtocolAddress );
                    /* 加入ARP缓存 */
                    vARPRefreshCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), pxARPHeader->ulSenderProtocolAddress );
                    /* 产生ARP应答包 */
                    pxARPHeader->usOperation = ( uint16_t ) ipARP_REPLY;//类型为应答
                    if( pxARPHeader->ulTargetProtocolAddress == pxARPHeader->ulSenderProtocolAddress )
                    {
                        /* 以太网头部的MAC为广播地址 */
                        memcpy( pxARPFrame->xEthernetHeader.xSourceAddress.ucBytes, xBroadcastMACAddress.ucBytes, sizeof( xBroadcastMACAddress ) );
                        /* 目标硬件地址为0 */
                        memset( pxARPHeader->xTargetHardwareAddress.ucBytes, '\0', sizeof( MACAddress_t ) );
                        /* 目标协议地址为0 */
                        pxARPHeader->ulTargetProtocolAddress = 0UL;
                    }
                    else
                    {
                        //填充目标MAC地址
                        memcpy( pxARPHeader->xTargetHardwareAddress.ucBytes, pxARPHeader->xSenderHardwareAddress.ucBytes, sizeof( MACAddress_t ) );
                        //填充目标协议地址
                        pxARPHeader->ulTargetProtocolAddress = pxARPHeader->ulSenderProtocolAddress;
                    }
                    /* 发送者硬件地址填写本地地址 */
                    memcpy( pxARPHeader->xSenderHardwareAddress.ucBytes, ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) );
                    /* 填写发送者协议地址 */
                    pxARPHeader->ulSenderProtocolAddress = *ipLOCAL_IP_ADDRESS_POINTER;

                    eReturn = eReturnEthernetFrame;
                }
                break;
            /* ARP应答包 */
            case ipARP_REPLY :
                iptracePROCESSING_RECEIVED_ARP_REPLY( pxARPHeader->ulTargetProtocolAddress );
                /* 加入缓存表 */
                vARPRefreshCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), pxARPHeader->ulSenderProtocolAddress );
                /* Process received ARP frame to see if there is a clash. */
                #if( ipconfigARP_USE_CLASH_DETECTION != 0 )
                {
                    if( pxARPHeader->ulSenderProtocolAddress == *ipLOCAL_IP_ADDRESS_POINTER )
                    {
                        xARPHadIPClash = pdTRUE;
                        memcpy( xARPClashMacAddress.ucBytes, pxARPHeader->xSenderHardwareAddress.ucBytes, sizeof( xARPClashMacAddress.ucBytes ) );
                    }
                }
                #endif /* ipconfigARP_USE_CLASH_DETECTION */
                break;

            default :
                /* Invalid. */
                break;
        }
    }

    return eReturn;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_ARP_REMOVE_ENTRY != 0 )

    uint32_t ulARPRemoveCacheEntryByMac( const MACAddress_t * pxMACAddress )
    {
    BaseType_t x;
    uint32_t lResult = 0;

        /* For each entry in the ARP cache table. */
        for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
        {
            if( ( memcmp( xARPCache[ x ].xMACAddress.ucBytes, pxMACAddress->ucBytes, sizeof( pxMACAddress->ucBytes ) ) == 0 ) )
            {
                lResult = xARPCache[ x ].ulIPAddress;
                memset( &xARPCache[ x ], '\0', sizeof( xARPCache[ x ] ) );
                break;
            }
        }

        return lResult;
    }

#endif  /* ipconfigUSE_ARP_REMOVE_ENTRY != 0 */
/* 刷新ARP缓存 */
void vARPRefreshCacheEntry( const MACAddress_t * pxMACAddress, const uint32_t ulIPAddress )
{
BaseType_t x, xIpEntry = -1, xMacEntry = -1, xUseEntry = 0;
uint8_t ucMinAgeFound = 0U;
    /* 允许存储非局域网IP地址 */
    #if( ipconfigARP_STORES_REMOTE_ADDRESSES == 0 )
        /* 只处理局域网的IP地址 */
        if( ( ( ulIPAddress & xNetworkAddressing.ulNetMask ) == ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) ) ||
            ( *ipLOCAL_IP_ADDRESS_POINTER == 0ul ) )
    #else
        /* 若不允许处理非局域网IP地址，向网关求助是唯一的选择 */
        if( pdTRUE )
    #endif
    {
        /* 得到最大数值 */
        ucMinAgeFound--;
        /* 遍历缓存表 */
        for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
        {
            /* 判断IP地址 */
            if( xARPCache[ x ].ulIPAddress == ulIPAddress )
            {
                if( pxMACAddress == NULL )
                {
                    /* 可能，这个缓存项还没有完成 */
                    xIpEntry = x;
                    break;
                }
                /* 判断MAC地址 */
                if( memcmp( xARPCache[ x ].xMACAddress.ucBytes, pxMACAddress->ucBytes, sizeof( pxMACAddress->ucBytes ) ) == 0 )
                {
                    /* 刷新此缓存项并返回 */
                    xARPCache[ x ].ucAge = ( uint8_t ) ipconfigMAX_ARP_AGE;
                    xARPCache[ x ].ucValid = ( uint8_t ) pdTRUE;
                    return;
                }
                /* 可能，这个缓存项也没有完成 */
                xIpEntry = x;
            }
            else if( ( pxMACAddress != NULL ) && ( memcmp( xARPCache[ x ].xMACAddress.ucBytes, pxMACAddress->ucBytes, sizeof( pxMACAddress->ucBytes ) ) == 0 ) )
            {
                /* IP地址不匹配，但是MAC地址匹配 */
    #if( ipconfigARP_STORES_REMOTE_ADDRESSES != 0 )
                /* 如果允许存储非局域网地址，则网关的MAC地址不能被重写 */
                BaseType_t bIsLocal[ 2 ];
                /* 判断缓存项 与 本地地址 是否处于同一局域网 */
                bIsLocal[ 0 ] = ( ( xARPCache[ x ].ulIPAddress & xNetworkAddressing.ulNetMask ) == ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) );
                /* 判断目标地址 与 本地地址 是否处于同一局域网 */
                bIsLocal[ 1 ] = ( ( ulIPAddress & xNetworkAddressing.ulNetMask ) == ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) );
                if( bIsLocal[ 0 ] == bIsLocal[ 1 ] )
                {
                    xMacEntry = x;
                }
    #else
                xMacEntry = x;
    #endif
            }
            /* _HT_
            Shouldn't we test for xARPCache[ x ].ucValid == pdFALSE here ? */
            else if( xARPCache[ x ].ucAge < ucMinAgeFound )
            {
                /* 寻找最老的缓存项，不行就把他使用了 */
                ucMinAgeFound = xARPCache[ x ].ucAge;
                xUseEntry = x;
            }
        }
        if( xMacEntry >= 0 )
        {
            xUseEntry = xMacEntry;
            if( xIpEntry >= 0 )
            {
                /* MAC和IP都发现了，但是不在一个缓存项中，清除IP项 */
                memset( &xARPCache[ xIpEntry ], '\0', sizeof( xARPCache[ xIpEntry ] ) );
            }
        }
        else if( xIpEntry >= 0 )
        {
            /* 找到IP地址，但是MAC地址不匹配 */
            xUseEntry = xIpEntry;
        }
        /* 使用最老的缓存项 */
        xARPCache[ xUseEntry ].ulIPAddress = ulIPAddress;
        if( pxMACAddress != NULL )
        {
            memcpy( xARPCache[ xUseEntry ].xMACAddress.ucBytes, pxMACAddress->ucBytes, sizeof( pxMACAddress->ucBytes ) );
            iptraceARP_TABLE_ENTRY_CREATED( ulIPAddress, (*pxMACAddress) );
            /* And this entry does not need immediate attention */
            xARPCache[ xUseEntry ].ucAge = ( uint8_t ) ipconfigMAX_ARP_AGE;
            xARPCache[ xUseEntry ].ucValid = ( uint8_t ) pdTRUE;
        }
        else if( xIpEntry < 0 )
        {
            xARPCache[ xUseEntry ].ucAge = ( uint8_t ) ipconfigMAX_ARP_RETRANSMISSIONS;
            xARPCache[ xUseEntry ].ucValid = ( uint8_t ) pdFALSE;
        }
    }
}
/*-----------------------------------------------------------*/
/* 根据MAC地址获取IP地址 */
#if( ipconfigUSE_ARP_REVERSED_LOOKUP == 1 )
    eARPLookupResult_t eARPGetCacheEntryByMac( MACAddress_t * const pxMACAddress, uint32_t *pulIPAddress )
    {
    BaseType_t x;
    eARPLookupResult_t eReturn = eARPCacheMiss;

        /* 遍历缓存表 */
        for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
        {
            /* 判断MAC是否匹配 */
            if( memcmp( pxMACAddress->ucBytes, xARPCache[ x ].xMACAddress.ucBytes, sizeof( MACAddress_t ) ) == 0 )
            {
                *pulIPAddress = xARPCache[ x ].ulIPAddress;
                eReturn = eARPCacheHit;
                break;
            }
        }

        return eReturn;
    }
#endif /* ipconfigUSE_ARP_REVERSED_LOOKUP */

eARPLookupResult_t eARPGetCacheEntry( uint32_t *pulIPAddress, MACAddress_t * const pxMACAddress )
{
eARPLookupResult_t eReturn;
uint32_t ulAddressToLookup;

#if( ipconfigUSE_LLMNR == 1 )
    if( *pulIPAddress == ipLLMNR_IP_ADDR )
    {
        /* LLMNR 的IP地址有一个固定的虚拟IP地址 */
        memcpy( pxMACAddress->ucBytes, xLLMNR_MacAdress.ucBytes, sizeof( MACAddress_t ) );
        eReturn = eARPCacheHit;
    }
    else
#endif
    if( ( *pulIPAddress == ipBROADCAST_IP_ADDRESS ) ||  /* Is it the general broadcast address 255.255.255.255? */
        ( *pulIPAddress == xNetworkAddressing.ulBroadcastAddress ) )/* Or a local broadcast address, eg 192.168.1.255? */
    {
        /* 这是广播IP，所以返回其MAC */
        memcpy( pxMACAddress->ucBytes, xBroadcastMACAddress.ucBytes, sizeof( MACAddress_t ) );
        /* 找到缓存 */
        eReturn = eARPCacheHit;
    }
    else if( *ipLOCAL_IP_ADDRESS_POINTER == 0UL )
    {
        /* 本地地址为零，不做任何事情 */
        eReturn = eCantSendPacket;
    }
    else
    {
        /* 找不到缓存 */
        eReturn = eARPCacheMiss;

        if( ( *pulIPAddress & xNetworkAddressing.ulNetMask ) != ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) )
        {
            /* 不在同一个局域网下 */
#if( ipconfigARP_STORES_REMOTE_ADDRESSES == 1 )
            /* 搜索缓存表 */
            eReturn = prvCacheLookup( *pulIPAddress, pxMACAddress );

            if( eReturn == eARPCacheHit )
            {
                /* 找到缓存 */
            }
            else
#endif
            {
                /* 找不到缓存项，数据发向路由器 */
                ulAddressToLookup = xNetworkAddressing.ulGatewayAddress;
            }
        }
        else
        {
            /* IP在局域网中，我们直接搜索缓存表即可 */
            ulAddressToLookup = *pulIPAddress;
        }

        if( eReturn == eARPCacheMiss )
        {
            if( ulAddressToLookup == 0UL )
            {
                /* IP不在局域网内，并且不存在路由器 */
                eReturn = eCantSendPacket;
            }
            else
            {
                /* 搜索缓存表 */
                eReturn = prvCacheLookup( ulAddressToLookup, pxMACAddress );

                if( eReturn == eARPCacheMiss )
                {
                    /* It might be that the ARP has to go to the gateway. */
                    *pulIPAddress = ulAddressToLookup;
                }
            }
        }
    }

    return eReturn;
}

/* 搜索缓存表 */

static eARPLookupResult_t prvCacheLookup( uint32_t ulAddressToLookup, MACAddress_t * const pxMACAddress )
{
BaseType_t x;
eARPLookupResult_t eReturn = eARPCacheMiss;

    /* 遍历缓存表 */
    for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
    {
        /* 判断IP地址 */
        if( xARPCache[ x ].ulIPAddress == ulAddressToLookup )
        {
            /* 发现匹配项 */
            if( xARPCache[ x ].ucValid == ( uint8_t ) pdFALSE )
            {
                /* 此项正在等待ARP回复 */
                eReturn = eCantSendPacket;
            }
            else
            {
                /* 发现有效项 */
                memcpy( pxMACAddress->ucBytes, xARPCache[ x ].xMACAddress.ucBytes, sizeof( MACAddress_t ) );
                eReturn = eARPCacheHit;
            }
            break;
        }
    }

    return eReturn;
}
/*-----------------------------------------------------------*/

void vARPAgeCache( void )
{
BaseType_t x;
TickType_t xTimeNow;

    /* 遍历缓存表 */
    for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
    {
        /* 生命未到期 */
        if( xARPCache[ x ].ucAge > 0U )
        {
            /* 递减生命 */
            ( xARPCache[ x ].ucAge )--;

            /* 如若正在等待ARP回复，重发ARP请求 */
            if( xARPCache[ x ].ucValid == ( uint8_t ) pdFALSE )
            {
                FreeRTOS_OutputARPRequest( xARPCache[ x ].ulIPAddress );
            }
            else if( xARPCache[ x ].ucAge <= ( uint8_t ) arpMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST )
            {
                /* 如若生命小于阈值，也要发送ARP请求 */
                iptraceARP_TABLE_ENTRY_WILL_EXPIRE( xARPCache[ x ].ulIPAddress );
                FreeRTOS_OutputARPRequest( xARPCache[ x ].ulIPAddress );
            }
            else
            {
                /* The age has just ticked down, with nothing to do. */
            }

            if( xARPCache[ x ].ucAge == 0u )
            {
                /* 生命到期，清除掉 */
                iptraceARP_TABLE_ENTRY_EXPIRED( xARPCache[ x ].ulIPAddress );
                xARPCache[ x ].ulIPAddress = 0UL;
            }
        }
    }

    xTimeNow = xTaskGetTickCount ();
    /* 发送免费ARP请求 */
    if( ( xLastGratuitousARPTime == ( TickType_t ) 0 ) || ( ( xTimeNow - xLastGratuitousARPTime ) > ( TickType_t ) arpGRATUITOUS_ARP_PERIOD ) )
    {
        FreeRTOS_OutputARPRequest( *ipLOCAL_IP_ADDRESS_POINTER );
        xLastGratuitousARPTime = xTimeNow;
    }
}
void vARPSendGratuitous( void )
{
    /* 将计数器清零可以促使免费ARP的产生 */
    xLastGratuitousARPTime = ( TickType_t ) 0;
    /* 迫使IP任务调用vARPAgeCache().已完成免费ARP的发送 */
    xSendEventToIPTask( eARPTimerEvent );
}

/* 发送ARP请求 */
void FreeRTOS_OutputARPRequest( uint32_t ulIPAddress )
{
NetworkBufferDescriptor_t *pxNetworkBuffer;

    /* 获取一块内存 */
    pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( sizeof( ARPPacket_t ), ( TickType_t ) 0 );

    if( pxNetworkBuffer != NULL )
    {
        /* 填充ARP数据 */
        pxNetworkBuffer->ulIPAddress = ulIPAddress;
        vARPGenerateRequestPacket( pxNetworkBuffer );
        /* 如果定义了最小包大小，则进行数据的填充 */
        #if defined( ipconfigETHERNET_MINIMUM_PACKET_BYTES )
        {
            if( pxNetworkBuffer->xDataLength < ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES )
            {
            BaseType_t xIndex;

                FreeRTOS_printf( ( "OutputARPRequest: length %lu\n", pxNetworkBuffer->xDataLength ) );
                for( xIndex = ( BaseType_t ) pxNetworkBuffer->xDataLength; xIndex < ( BaseType_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES; xIndex++ )
                {
                    pxNetworkBuffer->pucEthernetBuffer[ xIndex ] = 0u;
                }
                pxNetworkBuffer->xDataLength = ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES;
            }
        }
        #endif
        /* 发送ARP请求随后释放内存 */
        xNetworkInterfaceOutput( pxNetworkBuffer, pdTRUE );
    }
}
/* 产生ARP请求包 */
void vARPGenerateRequestPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer )
{
ARPPacket_t *pxARPPacket;

    pxARPPacket = ( ARPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;

    /* memcpy the const part of the header information into the correct
    location in the packet.  This copies:
        xEthernetHeader.ulDestinationAddress
        xEthernetHeader.usFrameType;
        xARPHeader.usHardwareType;
        xARPHeader.usProtocolType;
        xARPHeader.ucHardwareAddressLength;
        xARPHeader.ucProtocolAddressLength;
        xARPHeader.usOperation;
        xARPHeader.xTargetHardwareAddress;
    */
    memcpy( ( void * ) &( pxARPPacket->xEthernetHeader ), ( void * ) xDefaultPartARPPacketHeader, sizeof( xDefaultPartARPPacketHeader ) );
    memcpy( ( void * ) pxARPPacket->xEthernetHeader.xSourceAddress.ucBytes , ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
    memcpy( ( void * ) pxARPPacket->xARPHeader.xSenderHardwareAddress.ucBytes, ( void * ) ipLOCAL_MAC_ADDRESS, ( size_t ) ipMAC_ADDRESS_LENGTH_BYTES );
    /* HT:endian: network to network */
    pxARPPacket->xARPHeader.ulSenderProtocolAddress = *ipLOCAL_IP_ADDRESS_POINTER;
    pxARPPacket->xARPHeader.ulTargetProtocolAddress = pxNetworkBuffer->ulIPAddress;

    pxNetworkBuffer->xDataLength = sizeof( ARPPacket_t );

    iptraceCREATING_ARP_REQUEST( pxNetworkBuffer->ulIPAddress );
}
/* 清除ARP缓存表 */

void FreeRTOS_ClearARP( void )
{
    memset( xARPCache, '\0', sizeof( xARPCache ) );
}
/* 打印ARP缓存表 */

#if( ipconfigHAS_PRINTF != 0 ) || ( ipconfigHAS_DEBUG_PRINTF != 0 )

    void FreeRTOS_PrintARPCache( void )
    {
    BaseType_t x, xCount = 0;

        /* Loop through each entry in the ARP cache. */
        for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
        {
            if( ( xARPCache[ x ].ulIPAddress != 0ul ) && ( xARPCache[ x ].ucAge > 0U ) )
            {
                /* See if the MAC-address also matches, and we're all happy */
                FreeRTOS_printf( ( "Arp %2ld: %3u - %16lxip : %02x:%02x:%02x : %02x:%02x:%02x\n",
                    x,
                    xARPCache[ x ].ucAge,
                    xARPCache[ x ].ulIPAddress,
                    xARPCache[ x ].xMACAddress.ucBytes[0],
                    xARPCache[ x ].xMACAddress.ucBytes[1],
                    xARPCache[ x ].xMACAddress.ucBytes[2],
                    xARPCache[ x ].xMACAddress.ucBytes[3],
                    xARPCache[ x ].xMACAddress.ucBytes[4],
                    xARPCache[ x ].xMACAddress.ucBytes[5] ) );
                xCount++;
            }
        }

        FreeRTOS_printf( ( "Arp has %ld entries\n", xCount ) );
    }

#endif /* ( ipconfigHAS_PRINTF != 0 ) || ( ipconfigHAS_DEBUG_PRINTF != 0 ) */
