
/* 
	����API
	ARP��ʼ��		ARP_Init
	����MAC����IP	ARP_GetIP_ByMAC
	����IP����MAC	ARP_GetMAC_ByIP
	����ARP����		ARP_AddItem
	ARP��ʱ����		ARP_TickTask
*/

#ifndef __ARP_H__
#define __ARP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "Ethernet.h"

#define ARP_CACHE_CAPACITY	100
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
	MAC DstIP;
}ARP_Header;


uint8_t ARP_Init(void);
uint8_t ARP_GetIP_ByMAC(MAC * mac, IP * ip, uint8_t * IndexOfCache);
uint8_t ARP_GetMAC_ByIP(IP * ip, MAC * mac, uint8_t * IndexOfCache);
uint8_t ARP_AddItem(IP * ip, MAC * mac);
uint8_t ARP_TickTask(void);
uint8_t ARP_ProcessPacket(NeteworkBuff * pNeteorkBuff);
uint8_t ARP_SendRequest(NeteworkBuff * pNeteorkBuff, IP * TargetIP);

#ifdef __cplusplus
}
#endif

#endif

