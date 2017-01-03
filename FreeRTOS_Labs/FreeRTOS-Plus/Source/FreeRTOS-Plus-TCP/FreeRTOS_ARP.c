/*
    ARPЭ�����MAC��ַ��IP��ַ��һ��ӳ�����MAC��Ϊ������Ψһ��ʾ���Լ���͹���
    �෴����IP��ַʮ�ַ��㣬���������κ�һ����������ͨ��ǰ������Ҫ��ȡ�Է���MAC��ַ��
    ������ARP����
    Ŀ��MAC+ԴMAC+֡����+Ӳ������+Э������+Ӳ����ַ����+Э���ַ����+op+������MAC+������IP+������MAC+������MAC
    |��̫���ײ�---------|arp�ײ�-------------------------------------------|ARP�ֶ�-------------------------------|
    ��̫���ײ���Ŀ�ĵ�ַ��FFFFFFFFFFFF����˼�Ƿ����������ߵ�������
    ARP�ֶ��еĽ�����MACΪ000000000000��ʾ��MAC��ַ��Ҫ���
    Ŀ��IP�������յ���ARP�����ᵥ���ظ���������
    
    �������ܣ�
    
    eFrameProcessingResult_t eARPProcessPacket( ARPPacket_t * const pxARPFrame );
        ����ARP�������ARPӦ���
        pxARPFrame��ARP֡��Ϣ
    uint32_t ulARPRemoveCacheEntryByMac( const MACAddress_t * pxMACAddress )
        ͨ��MAC��ַ��ɾ��������
        pxMACAddress����ɾ��MAC��ַ
    void vARPRefreshCacheEntry( const MACAddress_t * pxMACAddress, const uint32_t ulIPAddress )
        ˢ�»���
        pxMACAddress��������
        ulIPAddress��������
    eARPLookupResult_t eARPGetCacheEntryByMac( MACAddress_t * const pxMACAddress, uint32_t *pulIPAddress )
        ����MAC��ȡIP��ַ
        pxMACAddress������ȡMAC��ַ
        pulIPAddress�����ص�IP��ַ
    eARPLookupResult_t eARPGetCacheEntry( uint32_t *pulIPAddress, MACAddress_t * const pxMACAddress )
        ����IP��ַ��ȡMAC��ַ
        pulIPAddress��IP��ַ
        pxMACAddress��MAC��ַ
    static eARPLookupResult_t prvCacheLookup( uint32_t ulAddressToLookup, MACAddress_t * const pxMACAddress )
        ���������
    void vARPAgeCache( void )
        ������������ڵݼ�
    void vARPSendGratuitous( void )
        �������ARP
    void FreeRTOS_OutputARPRequest( uint32_t ulIPAddress )
        ����ARP����
    void vARPGenerateRequestPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer )
        ����ARP�����
    void FreeRTOS_ClearARP( void )
        ���ARP����
    void FreeRTOS_PrintARPCache( void )
        ��ӡARP����
*/
/* ��׼ͷ�ļ� */
#include <stdint.h>
#include <stdio.h>
/* ����ϵͳͷ�ļ� */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
/* Э��ջͷ�ļ� */
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
/* ��ARP�������ʱ���������ֵ�����ᷢ��ARP�������ˢ�»��� */
#define arpMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST       ( 3 )
/* ���ARP���ڣ������붨�ڼ���Ƿ����IP��ͻ�� */
#ifndef arpGRATUITOUS_ARP_PERIOD
    #define arpGRATUITOUS_ARP_PERIOD                    ( pdMS_TO_TICKS( 20000 ) )
#endif
/* ����IP��ַ��ѯMAC��ַ */
static eARPLookupResult_t prvCacheLookup( uint32_t ulAddressToLookup, MACAddress_t * const pxMACAddress );
/* ARP���� */
static ARPCacheRow_t xARPCache[ ipconfigARP_CACHE_ENTRIES ];
/* ��һ�����ARP���͵�ʱ�� */
static TickType_t xLastGratuitousARPTime = ( TickType_t ) 0;
/* IP��ͻ���Ŀǰֻ���ڲ�ʹ�ã���DHCPû�л�Ӧʱ�������᳢��һ���������·���ַ��169.254.x.x��
���ᷢ��һ���ARP��Ϣ��һ��ʱ��֮�󣬼������ı��� */
#if( ipconfigARP_USE_CLASH_DETECTION != 0 )
    /* ��������豸�ظ������ARP������ֵΪ����ֵ */
    BaseType_t xARPHadIPClash;
    /* �뱾����ͻ���豸��MAC��ַ */
    MACAddress_t xARPClashMacAddress;
#endif /* ipconfigARP_USE_CLASH_DETECTION */
/* ��̫����ARPͷ */
static const uint8_t xDefaultPartARPPacketHeader[] =
{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     /* Ŀ�ĵ�ַ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* Դ��ַ */
    0x08, 0x06,                             /* ֡���� */
    0x00, 0x01,                             /* Ӳ������ */
    0x08, 0x00,                             /* Э������ */
    ipMAC_ADDRESS_LENGTH_BYTES,             /* Ӳ����ַ���� */
    ipIP_ADDRESS_LENGTH_BYTES,              /* Э���ַ���� */
    0x00, 0x01,                             /* �������� */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* ������Ӳ����ַ */
    0x00, 0x00, 0x00, 0x00,                 /* ������Э���ַ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00      /* Ŀ��Ӳ����ַ */
};
/* ARP���ݰ����� */
eFrameProcessingResult_t eARPProcessPacket( ARPPacket_t * const pxARPFrame )
{
eFrameProcessingResult_t eReturn = eReleaseBuffer;
ARPHeader_t *pxARPHeader;

    pxARPHeader = &( pxARPFrame->xARPHeader );
    traceARP_PACKET_RECEIVED();
    /* ������ص�ַΪ0�����κ����飬����ζ��DHCP����û����� */
    if( *ipLOCAL_IP_ADDRESS_POINTER != 0UL )
    {
        switch( pxARPHeader->usOperation )
        {
            /* ARP����� */
            case ipARP_REQUEST  :
                /* ���󱾵ص�ַ */
                if( pxARPHeader->ulTargetProtocolAddress == *ipLOCAL_IP_ADDRESS_POINTER )
                {
                    iptraceSENDING_ARP_REPLY( pxARPHeader->ulSenderProtocolAddress );
                    /* ����ARP���� */
                    vARPRefreshCacheEntry( &( pxARPHeader->xSenderHardwareAddress ), pxARPHeader->ulSenderProtocolAddress );
                    /* ����ARPӦ��� */
                    pxARPHeader->usOperation = ( uint16_t ) ipARP_REPLY;//����ΪӦ��
                    if( pxARPHeader->ulTargetProtocolAddress == pxARPHeader->ulSenderProtocolAddress )
                    {
                        /* ��̫��ͷ����MACΪ�㲥��ַ */
                        memcpy( pxARPFrame->xEthernetHeader.xSourceAddress.ucBytes, xBroadcastMACAddress.ucBytes, sizeof( xBroadcastMACAddress ) );
                        /* Ŀ��Ӳ����ַΪ0 */
                        memset( pxARPHeader->xTargetHardwareAddress.ucBytes, '\0', sizeof( MACAddress_t ) );
                        /* Ŀ��Э���ַΪ0 */
                        pxARPHeader->ulTargetProtocolAddress = 0UL;
                    }
                    else
                    {
                        //���Ŀ��MAC��ַ
                        memcpy( pxARPHeader->xTargetHardwareAddress.ucBytes, pxARPHeader->xSenderHardwareAddress.ucBytes, sizeof( MACAddress_t ) );
                        //���Ŀ��Э���ַ
                        pxARPHeader->ulTargetProtocolAddress = pxARPHeader->ulSenderProtocolAddress;
                    }
                    /* ������Ӳ����ַ��д���ص�ַ */
                    memcpy( pxARPHeader->xSenderHardwareAddress.ucBytes, ( void * ) ipLOCAL_MAC_ADDRESS, sizeof( MACAddress_t ) );
                    /* ��д������Э���ַ */
                    pxARPHeader->ulSenderProtocolAddress = *ipLOCAL_IP_ADDRESS_POINTER;

                    eReturn = eReturnEthernetFrame;
                }
                break;
            /* ARPӦ��� */
            case ipARP_REPLY :
                iptracePROCESSING_RECEIVED_ARP_REPLY( pxARPHeader->ulTargetProtocolAddress );
                /* ���뻺��� */
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
/* ˢ��ARP���� */
void vARPRefreshCacheEntry( const MACAddress_t * pxMACAddress, const uint32_t ulIPAddress )
{
BaseType_t x, xIpEntry = -1, xMacEntry = -1, xUseEntry = 0;
uint8_t ucMinAgeFound = 0U;
    /* ����洢�Ǿ�����IP��ַ */
    #if( ipconfigARP_STORES_REMOTE_ADDRESSES == 0 )
        /* ֻ�����������IP��ַ */
        if( ( ( ulIPAddress & xNetworkAddressing.ulNetMask ) == ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) ) ||
            ( *ipLOCAL_IP_ADDRESS_POINTER == 0ul ) )
    #else
        /* ����������Ǿ�����IP��ַ��������������Ψһ��ѡ�� */
        if( pdTRUE )
    #endif
    {
        /* �õ������ֵ */
        ucMinAgeFound--;
        /* ��������� */
        for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
        {
            /* �ж�IP��ַ */
            if( xARPCache[ x ].ulIPAddress == ulIPAddress )
            {
                if( pxMACAddress == NULL )
                {
                    /* ���ܣ���������û����� */
                    xIpEntry = x;
                    break;
                }
                /* �ж�MAC��ַ */
                if( memcmp( xARPCache[ x ].xMACAddress.ucBytes, pxMACAddress->ucBytes, sizeof( pxMACAddress->ucBytes ) ) == 0 )
                {
                    /* ˢ�´˻�������� */
                    xARPCache[ x ].ucAge = ( uint8_t ) ipconfigMAX_ARP_AGE;
                    xARPCache[ x ].ucValid = ( uint8_t ) pdTRUE;
                    return;
                }
                /* ���ܣ����������Ҳû����� */
                xIpEntry = x;
            }
            else if( ( pxMACAddress != NULL ) && ( memcmp( xARPCache[ x ].xMACAddress.ucBytes, pxMACAddress->ucBytes, sizeof( pxMACAddress->ucBytes ) ) == 0 ) )
            {
                /* IP��ַ��ƥ�䣬����MAC��ַƥ�� */
    #if( ipconfigARP_STORES_REMOTE_ADDRESSES != 0 )
                /* �������洢�Ǿ�������ַ�������ص�MAC��ַ���ܱ���д */
                BaseType_t bIsLocal[ 2 ];
                /* �жϻ����� �� ���ص�ַ �Ƿ���ͬһ������ */
                bIsLocal[ 0 ] = ( ( xARPCache[ x ].ulIPAddress & xNetworkAddressing.ulNetMask ) == ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) );
                /* �ж�Ŀ���ַ �� ���ص�ַ �Ƿ���ͬһ������ */
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
                /* Ѱ�����ϵĻ�������оͰ���ʹ���� */
                ucMinAgeFound = xARPCache[ x ].ucAge;
                xUseEntry = x;
            }
        }
        if( xMacEntry >= 0 )
        {
            xUseEntry = xMacEntry;
            if( xIpEntry >= 0 )
            {
                /* MAC��IP�������ˣ����ǲ���һ���������У����IP�� */
                memset( &xARPCache[ xIpEntry ], '\0', sizeof( xARPCache[ xIpEntry ] ) );
            }
        }
        else if( xIpEntry >= 0 )
        {
            /* �ҵ�IP��ַ������MAC��ַ��ƥ�� */
            xUseEntry = xIpEntry;
        }
        /* ʹ�����ϵĻ����� */
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
/* ����MAC��ַ��ȡIP��ַ */
#if( ipconfigUSE_ARP_REVERSED_LOOKUP == 1 )
    eARPLookupResult_t eARPGetCacheEntryByMac( MACAddress_t * const pxMACAddress, uint32_t *pulIPAddress )
    {
    BaseType_t x;
    eARPLookupResult_t eReturn = eARPCacheMiss;

        /* ��������� */
        for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
        {
            /* �ж�MAC�Ƿ�ƥ�� */
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
        /* LLMNR ��IP��ַ��һ���̶�������IP��ַ */
        memcpy( pxMACAddress->ucBytes, xLLMNR_MacAdress.ucBytes, sizeof( MACAddress_t ) );
        eReturn = eARPCacheHit;
    }
    else
#endif
    if( ( *pulIPAddress == ipBROADCAST_IP_ADDRESS ) ||  /* Is it the general broadcast address 255.255.255.255? */
        ( *pulIPAddress == xNetworkAddressing.ulBroadcastAddress ) )/* Or a local broadcast address, eg 192.168.1.255? */
    {
        /* ���ǹ㲥IP�����Է�����MAC */
        memcpy( pxMACAddress->ucBytes, xBroadcastMACAddress.ucBytes, sizeof( MACAddress_t ) );
        /* �ҵ����� */
        eReturn = eARPCacheHit;
    }
    else if( *ipLOCAL_IP_ADDRESS_POINTER == 0UL )
    {
        /* ���ص�ַΪ�㣬�����κ����� */
        eReturn = eCantSendPacket;
    }
    else
    {
        /* �Ҳ������� */
        eReturn = eARPCacheMiss;

        if( ( *pulIPAddress & xNetworkAddressing.ulNetMask ) != ( ( *ipLOCAL_IP_ADDRESS_POINTER ) & xNetworkAddressing.ulNetMask ) )
        {
            /* ����ͬһ���������� */
#if( ipconfigARP_STORES_REMOTE_ADDRESSES == 1 )
            /* ��������� */
            eReturn = prvCacheLookup( *pulIPAddress, pxMACAddress );

            if( eReturn == eARPCacheHit )
            {
                /* �ҵ����� */
            }
            else
#endif
            {
                /* �Ҳ�����������ݷ���·���� */
                ulAddressToLookup = xNetworkAddressing.ulGatewayAddress;
            }
        }
        else
        {
            /* IP�ھ������У�����ֱ������������� */
            ulAddressToLookup = *pulIPAddress;
        }

        if( eReturn == eARPCacheMiss )
        {
            if( ulAddressToLookup == 0UL )
            {
                /* IP���ھ������ڣ����Ҳ�����·���� */
                eReturn = eCantSendPacket;
            }
            else
            {
                /* ��������� */
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

/* ��������� */

static eARPLookupResult_t prvCacheLookup( uint32_t ulAddressToLookup, MACAddress_t * const pxMACAddress )
{
BaseType_t x;
eARPLookupResult_t eReturn = eARPCacheMiss;

    /* ��������� */
    for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
    {
        /* �ж�IP��ַ */
        if( xARPCache[ x ].ulIPAddress == ulAddressToLookup )
        {
            /* ����ƥ���� */
            if( xARPCache[ x ].ucValid == ( uint8_t ) pdFALSE )
            {
                /* �������ڵȴ�ARP�ظ� */
                eReturn = eCantSendPacket;
            }
            else
            {
                /* ������Ч�� */
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

    /* ��������� */
    for( x = 0; x < ipconfigARP_CACHE_ENTRIES; x++ )
    {
        /* ����δ���� */
        if( xARPCache[ x ].ucAge > 0U )
        {
            /* �ݼ����� */
            ( xARPCache[ x ].ucAge )--;

            /* �������ڵȴ�ARP�ظ����ط�ARP���� */
            if( xARPCache[ x ].ucValid == ( uint8_t ) pdFALSE )
            {
                FreeRTOS_OutputARPRequest( xARPCache[ x ].ulIPAddress );
            }
            else if( xARPCache[ x ].ucAge <= ( uint8_t ) arpMAX_ARP_AGE_BEFORE_NEW_ARP_REQUEST )
            {
                /* ��������С����ֵ��ҲҪ����ARP���� */
                iptraceARP_TABLE_ENTRY_WILL_EXPIRE( xARPCache[ x ].ulIPAddress );
                FreeRTOS_OutputARPRequest( xARPCache[ x ].ulIPAddress );
            }
            else
            {
                /* The age has just ticked down, with nothing to do. */
            }

            if( xARPCache[ x ].ucAge == 0u )
            {
                /* �������ڣ������ */
                iptraceARP_TABLE_ENTRY_EXPIRED( xARPCache[ x ].ulIPAddress );
                xARPCache[ x ].ulIPAddress = 0UL;
            }
        }
    }

    xTimeNow = xTaskGetTickCount ();
    /* �������ARP���� */
    if( ( xLastGratuitousARPTime == ( TickType_t ) 0 ) || ( ( xTimeNow - xLastGratuitousARPTime ) > ( TickType_t ) arpGRATUITOUS_ARP_PERIOD ) )
    {
        FreeRTOS_OutputARPRequest( *ipLOCAL_IP_ADDRESS_POINTER );
        xLastGratuitousARPTime = xTimeNow;
    }
}
void vARPSendGratuitous( void )
{
    /* ��������������Դ�ʹ���ARP�Ĳ��� */
    xLastGratuitousARPTime = ( TickType_t ) 0;
    /* ��ʹIP�������vARPAgeCache().��������ARP�ķ��� */
    xSendEventToIPTask( eARPTimerEvent );
}

/* ����ARP���� */
void FreeRTOS_OutputARPRequest( uint32_t ulIPAddress )
{
NetworkBufferDescriptor_t *pxNetworkBuffer;

    /* ��ȡһ���ڴ� */
    pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( sizeof( ARPPacket_t ), ( TickType_t ) 0 );

    if( pxNetworkBuffer != NULL )
    {
        /* ���ARP���� */
        pxNetworkBuffer->ulIPAddress = ulIPAddress;
        vARPGenerateRequestPacket( pxNetworkBuffer );
        /* �����������С����С����������ݵ���� */
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
        /* ����ARP��������ͷ��ڴ� */
        xNetworkInterfaceOutput( pxNetworkBuffer, pdTRUE );
    }
}
/* ����ARP����� */
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
/* ���ARP����� */

void FreeRTOS_ClearARP( void )
{
    memset( xARPCache, '\0', sizeof( xARPCache ) );
}
/* ��ӡARP����� */

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
