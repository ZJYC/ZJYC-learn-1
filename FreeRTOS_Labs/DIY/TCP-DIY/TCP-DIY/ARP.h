
/* 
	基本API
	ARP初始化		ARP_Init
	根据MAC查找IP	ARP_GetIP_ByMAC
	根据IP查找MAC	ARP_GetMAC_ByIP
	加入ARP缓存		ARP_AddItem
	ARP定时任务		ARP_TickTask
*/

#ifndef __ARP_H__
#define __ARP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"

#define ARP_CACHE_CAPACITY	50
#define ARP_TTL_MAX			0xff
#define ARP_True			0xff
#define ARP_False			0x00

typedef struct ARP_Cache_
{
	uint8_t Used;
	uint8_t TTL;
	IP IP;
	MAC MAC;
}ARP_Cache;

#define ARP_HardwareType	0x0001
#define ARP_ProtocolType	0x0800
#define ARP_HardwareLen		6
#define ARP_ProtocolLen		4
#define ARP_OpcodeRequest	0x0001
#define ARP_OpcodeRespond	0x0002
#define ARP_HeaderLen		28

typedef struct ARP_Header_
{
	uint16_t HardwareType;
	uint16_t ProtocolType;
	uint8_t HardwareLen;
	uint8_t ProtocolLen;
	uint16_t Opcode;
	MAC SrcMAC;
	IP  SrcIP;
	MAC DstMAC;
	IP DstIP;
}ARP_Header;


void ARP_Init(void);
uint8_t ARP_GetIP_ByMAC(MAC * mac, IP * ip, uint8_t * IndexOfCache);
uint8_t ARP_GetMAC_ByIP(IP * ip, MAC * mac, uint8_t * IndexOfCache, uint8_t SendRequest);
void ARP_AddItem(IP * ip, MAC * mac);
void ARP_TickTask(void);
void ARP_ProcessPacket(NeteworkBuff * pNeteorkBuff);
void ARP_SendRequest(IP * TargetIP);

#ifdef __cplusplus
}
#endif

#endif

