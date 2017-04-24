
/* 
	基本API
	ARP初始化		ARP_Init
	根据MAC查找IP	ARP_GetIP_ByMAC
	根据IP查找MAC	ARP_GetMAC_ByIP
	加入ARP缓存		ARP_AddItem
	ARP定时任务		ARP_TickTask
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








