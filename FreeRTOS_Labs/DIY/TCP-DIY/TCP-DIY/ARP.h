
/* 
	����API
	ARP��ʼ��		ARP_Init
	����MAC����IP	ARP_GetIP_ByMAC
	����IP����MAC	ARP_GetMAC_ByIP
	����ARP����		ARP_AddItem
	ARP��ʱ����		ARP_TickTask
*/

#include "DataTypeDef.h"

#define ARP_CACHE_CAPACITY	100
#define ARP_TTL_MAX			0xff
#define ARP_True			0xff
#define ARP_False			0x00

typedef struct ARP_Cache_
{

	uint8_t Used;
	uint8_t TTL;
	IP IP[4];
	MAC MAC[6];
}ARP_Cache;








