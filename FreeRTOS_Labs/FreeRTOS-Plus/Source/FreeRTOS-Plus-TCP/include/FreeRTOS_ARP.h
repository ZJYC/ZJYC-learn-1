
#ifndef FREERTOS_ARP_H
#define FREERTOS_ARP_H

#ifdef __cplusplus
extern "C" {
#endif

/* �û�������ѡ�� */
#include "FreeRTOSIPConfig.h"
#include "FreeRTOSIPConfigDefaults.h"
#include "IPTraceMacroDefaults.h"

/*-----------------------------------------------------------*/
/* ����ṹ��Ͷ��� */
/*-----------------------------------------------------------*/
//ARP�����ṹ
typedef struct xARP_CACHE_TABLE_ROW
{
    uint32_t ulIPAddress;       /* IP��ַ */
    MACAddress_t xMACAddress;  /* MAC��ַ */
    uint8_t ucAge;              /* һ����ֵ���������Եݼ���������ˢ��  ���Ϊ0�����汻��� */
    uint8_t ucValid;            /* pdTRUE: MAC��ַ��Ч, pdFALSE: �ȴ�ARP�ظ� */
} ARPCacheRow_t;
//ARP��ѯ���
typedef enum
{
    eARPCacheMiss = 0,          /* 0 û�з�����Ч���� */
    eARPCacheHit,               /* 1 ������һ����Ч���� */
    eCantSendPacket             /* 2 û��IP��ַ��������ARP��Ȼ�ڴ����У����԰����ܱ����� */
} eARPLookupResult_t;

typedef enum
{
    eNotFragment = 0,           /* ���ڷ��͵�IP���ݰ�����Ƭ�ε�һ���֡� */
    eFirstFragment,             /* ���ڷ��͵�IP����һ��֧����������ݰ��еĵ�һ�� */
    eFollowingFragment          /* ���ڷ��͵�IP����һ��֧����������ݰ���һ���� */
} eIPFragmentStatus_t;

/*
 * If ulIPAddress is already in the ARP cache table then reset the age of the
 * entry back to its maximum value.  If ulIPAddress is not already in the ARP
 * cache table then add it - replacing the oldest current entry if there is not
 * a free space available.
 */
/*  */
void vARPRefreshCacheEntry( const MACAddress_t * pxMACAddress, const uint32_t ulIPAddress );

#if( ipconfigARP_USE_CLASH_DETECTION != 0 )
    /* Becomes non-zero if another device responded to a gratuitos ARP message. */
    extern BaseType_t xARPHadIPClash;
    /* MAC-address of the other device containing the same IP-address. */
    extern MACAddress_t xARPClashMacAddress;
#endif /* ipconfigARP_USE_CLASH_DETECTION */

#if( ipconfigUSE_ARP_REMOVE_ENTRY != 0 )

    /*
     * In some rare cases, it might be useful to remove a ARP cache entry of a
     * known MAC address to make sure it gets refreshed.
     */
    uint32_t ulARPRemoveCacheEntryByMac( const MACAddress_t * pxMACAddress );

#endif /* ipconfigUSE_ARP_REMOVE_ENTRY != 0 */

/*
 * Look for ulIPAddress in the ARP cache.  If the IP address exists, copy the
 * associated MAC address into pxMACAddress, refresh the ARP cache entry's
 * age, and return eARPCacheHit.  If the IP address does not exist in the ARP
 * cache return eARPCacheMiss.  If the packet cannot be sent for any reason
 * (maybe DHCP is still in process, or the addressing needs a gateway but there
 * isn't a gateway defined) then return eCantSendPacket.
 */
eARPLookupResult_t eARPGetCacheEntry( uint32_t *pulIPAddress, MACAddress_t * const pxMACAddress );

#if( ipconfigUSE_ARP_REVERSED_LOOKUP != 0 )

    /* Lookup an IP-address if only the MAC-address is known */
    eARPLookupResult_t eARPGetCacheEntryByMac( MACAddress_t * const pxMACAddress, uint32_t *pulIPAddress );

#endif
/*
 * Reduce the age count in each entry within the ARP cache.  An entry is no
 * longer considered valid and is deleted if its age reaches zero.
 */
void vARPAgeCache( void );

/*
 * Send out an ARP request for the IP address contained in pxNetworkBuffer, and
 * add an entry into the ARP table that indicates that an ARP reply is
 * outstanding so re-transmissions can be generated.
 */
void vARPGenerateRequestPacket( NetworkBufferDescriptor_t * const pxNetworkBuffer );

/*
 * After DHCP is ready and when changing IP address, force a quick send of our new IP
 * address
 */
void vARPSendGratuitous( void );

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* FREERTOS_ARP_H */













