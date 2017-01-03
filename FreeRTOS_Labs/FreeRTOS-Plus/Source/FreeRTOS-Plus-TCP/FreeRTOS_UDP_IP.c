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
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"

#if( ipconfigUSE_DNS == 1 )
    #include "FreeRTOS_DNS.h"
#endif

/* The expected IP version and header length coded into the IP header itself. */
#define ipIP_VERSION_AND_HEADER_LENGTH_BYTE ( ( uint8_t ) 0x45 )

/* Part of the Ethernet and IP headers are always constant when sending an IPv4
UDP packet.  This array defines the constant parts, allowing this part of the
packet to be filled in using a simple memcpy() instead of individual writes. */
UDPPacketHeader_t xDefaultPartUDPPacketHeader =
{
    /* .ucBytes : */
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* Դ��ַMAC */
        0x08, 0x00,                             /* ֡���� */
        ipIP_VERSION_AND_HEADER_LENGTH_BYTE,    /* �汾��ͷ���� */
        0x00,                                   /* �������� */
        0x00, 0x00,                             /* ����ܳ��� */
        0x00, 0x00,                             /* �����ʶ */
        0x00, 0x00,                             /* Ƭ��ƫ�Ƶ�ַ */
        ipconfigUDP_TIME_TO_LIVE,               /* ���ʱ�� */
        ipPROTOCOL_UDP,                         /* Э������ */
        0x00, 0x00,                             /* ͷУ�� */
        0x00, 0x00, 0x00, 0x00                  /* Դ��ַIP */
    }
};
/*-----------------------------------------------------------*/
/* ����UDP�� */
void vProcessGeneratedUDPPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer )
{
UDPPacket_t *pxUDPPacket;
IPHeader_t *pxIPHeader;
eARPLookupResult_t eReturned;
uint32_t ulIPAddress = pxNetworkBuffer->ulIPAddress;
    pxUDPPacket = ( UDPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;
    /* ������û����ARP���� */
    eReturned = eARPGetCacheEntry( &( ulIPAddress ), &( pxUDPPacket->xEthernetHeader.xDestinationAddress ) );
    if( eReturned != eCantSendPacket )/* ���ص�ַ��0 */
    {
        if( eReturned == eARPCacheHit )/* �ҵ����ڱ��ص�ARP���� */
        {
            #if( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
                uint8_t ucSocketOptions;
            #endif
            iptraceSENDING_UDP_PACKET( pxNetworkBuffer->ulIPAddress );
            pxIPHeader = &( pxUDPPacket->xIPHeader );
        #if ( ipconfigSUPPORT_OUTGOING_PINGS == 1 )
            /* Ҳ�п�����ICMP���� */
            if( pxNetworkBuffer->usPort != ipPACKET_CONTAINS_ICMP_DATA )
        #endif /* ipconfigSUPPORT_OUTGOING_PINGS */
            {
                UDPHeader_t *pxUDPHeader;
                pxUDPHeader = &( pxUDPPacket->xUDPHeader );
                pxUDPHeader->usDestinationPort = pxNetworkBuffer->usPort;
                pxUDPHeader->usSourcePort = pxNetworkBuffer->usBoundPort;
                pxUDPHeader->usLength = ( uint16_t ) ( pxNetworkBuffer->xDataLength + sizeof( UDPHeader_t ) );
                pxUDPHeader->usLength = FreeRTOS_htons( pxUDPHeader->usLength );
                pxUDPHeader->usChecksum = 0u;
            }

            /* memcpy() the constant parts of the header information into
            the correct location within the packet.  This fills in:
                xEthernetHeader.xSourceAddress
                xEthernetHeader.usFrameType
                xIPHeader.ucVersionHeaderLength
                xIPHeader.ucDifferentiatedServicesCode
                xIPHeader.usLength
                xIPHeader.usIdentification
                xIPHeader.usFragmentOffset
                xIPHeader.ucTimeToLive
                xIPHeader.ucProtocol
            and
                xIPHeader.usHeaderChecksum
            */
            /* Save options now, as they will be overwritten by memcpy */
            #if( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
                ucSocketOptions = pxNetworkBuffer->pucEthernetBuffer[ ipSOCKET_OPTIONS_OFFSET ];
            #endif
            memcpy( ( void *) &( pxUDPPacket->xEthernetHeader.xSourceAddress ), ( void * ) xDefaultPartUDPPacketHeader.ucBytes, sizeof( xDefaultPartUDPPacketHeader ) );

        #if ipconfigSUPPORT_OUTGOING_PINGS == 1
            if( pxNetworkBuffer->usPort == ipPACKET_CONTAINS_ICMP_DATA )
            {
                pxIPHeader->ucProtocol = ipPROTOCOL_ICMP;
                pxIPHeader->usLength = ( uint16_t ) ( pxNetworkBuffer->xDataLength + sizeof( IPHeader_t ) );
            }
            else
        #endif /* ipconfigSUPPORT_OUTGOING_PINGS */
            {
                pxIPHeader->usLength = ( uint16_t ) ( pxNetworkBuffer->xDataLength + sizeof( IPHeader_t ) + sizeof( UDPHeader_t ) );
            }
            /* The total transmit size adds on the Ethernet header. */
            pxNetworkBuffer->xDataLength = pxIPHeader->usLength + sizeof( EthernetHeader_t );
            pxIPHeader->usLength = FreeRTOS_htons( pxIPHeader->usLength );
            /* HT:endian: changed back to network endian */
            pxIPHeader->ulDestinationIPAddress = pxNetworkBuffer->ulIPAddress;
            #if( ipconfigUSE_LLMNR == 1 )
            {
                /* LLMNR messages are typically used on a LAN and they're
                 * not supposed to cross routers */
                if( pxNetworkBuffer->ulIPAddress == ipLLMNR_IP_ADDR )
                {
                    pxIPHeader->ucTimeToLive = 0x01;
                }
            }
            #endif
            #if( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
            {
                pxIPHeader->usHeaderChecksum = 0u;
                pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0UL, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
                pxIPHeader->usHeaderChecksum = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
                if( ( ucSocketOptions & ( uint8_t ) FREERTOS_SO_UDPCKSUM_OUT ) != 0u )
                {
                    usGenerateProtocolChecksum( (uint8_t*)pxUDPPacket, pdTRUE );
                }
                else
                {
                    pxUDPPacket->xUDPHeader.usChecksum = 0u;
                }
            }
            #endif
        }
        else if( eReturned == eARPCacheMiss )/* �Ҳ������� */
        {
            /* Add an entry to the ARP table with a null hardware address.
            This allows the ARP timer to know that an ARP reply is
            outstanding, and perform retransmissions if necessary. */
            vARPRefreshCacheEntry( NULL, ulIPAddress );

            /* Generate an ARP for the required IP address. */
            iptracePACKET_DROPPED_TO_GENERATE_ARP( pxNetworkBuffer->ulIPAddress );
            pxNetworkBuffer->ulIPAddress = ulIPAddress;
            vARPGenerateRequestPacket( pxNetworkBuffer );
        }
        else
        {
            /* The lookup indicated that an ARP request has already been
            sent out for the queried IP address. */
            eReturned = eCantSendPacket;
        }
    }

    if( eReturned != eCantSendPacket )
    {
        #if defined( ipconfigETHERNET_MINIMUM_PACKET_BYTES )/* ������������С���͵�Ԫ�������������� */
        {
            if( pxNetworkBuffer->xDataLength < ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES )
            {
                BaseType_t xIndex;
                FreeRTOS_printf( ( "vProcessGeneratedUDPPacket: length %lu\n", pxNetworkBuffer->xDataLength ) );
                for( xIndex = ( BaseType_t ) pxNetworkBuffer->xDataLength; xIndex < ( BaseType_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES; xIndex++ )
                {
                    pxNetworkBuffer->pucEthernetBuffer[ xIndex ] = 0u;
                }
                pxNetworkBuffer->xDataLength = ( size_t ) ipconfigETHERNET_MINIMUM_PACKET_BYTES;
            }
        }
        #endif
        xNetworkInterfaceOutput( pxNetworkBuffer, pdTRUE );/* �����꼴�ͷ��ڴ� */
    }
    else/* �����ܱ����ͣ�DHCPΪ��ɣ������Ѱ��ͷŵ� */
    {
        vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
    }
}
/* ����UDP�� */
BaseType_t xProcessReceivedUDPPacket( NetworkBufferDescriptor_t *pxNetworkBuffer, uint16_t usPort )
{
BaseType_t xReturn = pdPASS;
FreeRTOS_Socket_t *pxSocket;

UDPPacket_t *pxUDPPacket = (UDPPacket_t *) pxNetworkBuffer->pucEthernetBuffer;
    /* ���ݶ˿ں��ҵ��׽��� */
    pxSocket = pxUDPSocketLookup( usPort );
    if( pxSocket )/* �׽��ִ��� */
    {
        /* ˢ��ARP����ҪС�ģ���ʱ�򣬻������ٸ��㲥���������ӻ��������ڲ� */
        vARPRefreshCacheEntry( &( pxUDPPacket->xEthernetHeader.xSourceAddress ), pxUDPPacket->xIPHeader.ulSourceIPAddress );
        #if( ipconfigUSE_CALLBACKS == 1 )/* �ص����� */
        {
            /* Did the owner of this socket register a reception handler ? */
            if( ipconfigIS_VALID_PROG_ADDRESS( pxSocket->u.xUDP.pxHandleReceive ) )
            {
                struct freertos_sockaddr xSourceAddress, destinationAddress;
                void *pcData = ( void * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipUDP_PAYLOAD_OFFSET_IPv4 ] );
                FOnUDPReceive_t xHandler = ( FOnUDPReceive_t ) pxSocket->u.xUDP.pxHandleReceive;
                xSourceAddress.sin_port = pxNetworkBuffer->usPort;
                xSourceAddress.sin_addr = pxNetworkBuffer->ulIPAddress;
                destinationAddress.sin_port = usPort;
                destinationAddress.sin_addr = pxUDPPacket->xIPHeader.ulDestinationIPAddress;
                if( xHandler( ( Socket_t * ) pxSocket, ( void* ) pcData, ( size_t ) pxNetworkBuffer->xDataLength,
                    &xSourceAddress, &destinationAddress ) )
                {
                    xReturn = pdFAIL; /* FAIL means that we did not consume or release the buffer */
                }
            }
        }
        #endif /* ipconfigUSE_CALLBACKS */
        #if( ipconfigUDP_MAX_RX_PACKETS > 0 )/* ���Ƕ����������հ����������� */
        {
            if( xReturn == pdPASS )
            {
                if ( listCURRENT_LIST_LENGTH( &( pxSocket->u.xUDP.xWaitingPacketsList ) ) >= pxSocket->u.xUDP.uxMaxPackets )
                {
                    FreeRTOS_debug_printf( ( "xProcessReceivedUDPPacket: buffer full %ld >= %ld port %u\n",
                        listCURRENT_LIST_LENGTH( &( pxSocket->u.xUDP.xWaitingPacketsList ) ),
                        pxSocket->u.xUDP.uxMaxPackets, pxSocket->usLocalPort ) );
                    xReturn = pdFAIL; /* we did not consume or release the buffer */
                }
            }
        }
        #endif
        if( xReturn == pdPASS )
        {
            vTaskSuspendAll();
            {
                if( xReturn == pdPASS )
                {
                    taskENTER_CRITICAL();
                    {
                        /* �����ݰ����ݸ��׽��� */
                        vListInsertEnd( &( pxSocket->u.xUDP.xWaitingPacketsList ), &( pxNetworkBuffer->xBufferListItem ) );
                    }
                    taskEXIT_CRITICAL();
                }
            }
            xTaskResumeAll();
            /* �����׽��ֵ��¼���ʶ */
            if( pxSocket->xEventGroup != NULL )
            {
                xEventGroupSetBits( pxSocket->xEventGroup, eSOCKET_RECEIVE );
            }
            #if( ipconfigSUPPORT_SELECT_FUNCTION == 1 )
            {
                if( ( pxSocket->pxSocketSet != NULL ) && ( ( pxSocket->xSelectBits & eSELECT_READ ) != 0 ) )
                {
                    xEventGroupSetBits( pxSocket->pxSocketSet->xSelectGroup, eSELECT_READ );
                }
            }
            #endif
            #if( ipconfigSOCKET_HAS_USER_SEMAPHORE == 1 )
            {
                if( pxSocket->pxUserSemaphore != NULL )
                {
                    xSemaphoreGive( pxSocket->pxUserSemaphore );
                }
            }
            #endif
            #if( ipconfigUSE_DHCP == 1 )/* �ǲ���DHCP�¼����� */
            {
                if( xIsDHCPSocket( pxSocket ) )
                {
                    xSendEventToIPTask( eDHCPEvent );
                }
            }
            #endif
        }
    }
    else/* �׽��ֲ����� */
    {
        /* �����ڼ����˶˿ڵ��׽��� */
        #if( ipconfigUSE_DNS == 1 )/* һ��DNSӦ�𣿣� */
            if( FreeRTOS_ntohs( pxUDPPacket->xUDPHeader.usSourcePort ) == ipDNS_PORT )
            {
                vARPRefreshCacheEntry( &( pxUDPPacket->xEthernetHeader.xSourceAddress ), pxUDPPacket->xIPHeader.ulSourceIPAddress );
                xReturn = ( BaseType_t )ulDNSHandlePacket( pxNetworkBuffer );
            }
            else
        #endif
        #if( ipconfigUSE_LLMNR == 1 )/* LLMNR���󣿣� */
            if( ( usPort == FreeRTOS_ntohs( ipLLMNR_PORT ) ) ||
                ( pxUDPPacket->xUDPHeader.usSourcePort == FreeRTOS_ntohs( ipLLMNR_PORT ) ) )
            {
                vARPRefreshCacheEntry( &( pxUDPPacket->xEthernetHeader.xSourceAddress ), pxUDPPacket->xIPHeader.ulSourceIPAddress );
                xReturn = ( BaseType_t )ulDNSHandlePacket( pxNetworkBuffer );
            }
            else
        #endif /* ipconfigUSE_LLMNR */
        #if( ipconfigUSE_NBNS == 1 )/* NBNS���󣿣� */
            if( ( usPort == FreeRTOS_ntohs( ipNBNS_PORT ) ) ||
                ( pxUDPPacket->xUDPHeader.usSourcePort == FreeRTOS_ntohs( ipNBNS_PORT ) ) )
            {
                vARPRefreshCacheEntry( &( pxUDPPacket->xEthernetHeader.xSourceAddress ), pxUDPPacket->xIPHeader.ulSourceIPAddress );
                xReturn = ( BaseType_t )ulNBNSHandlePacket( pxNetworkBuffer );
            }
            else
        #endif /* ipconfigUSE_NBNS */
        {
            xReturn = pdFAIL;
        }
    }

    return xReturn;
}
/*-----------------------------------------------------------*/
