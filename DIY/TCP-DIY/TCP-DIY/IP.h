
#ifndef __IP_H__
#define __IP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "Socket.h"

#define IP_VersionIPV4	4
#define	IP_Flags_DF		2
#define	IP_Flags_MF		1

#define IP_PacketDelete 0
#define IP_PacketPass	1

#define IP_HeaderLen	20

#define IP_Protocol_ICMP	1
#define IP_Protocol_IGMP	2
#define IP_Protocol_TCP		6
#define IP_Protocol_UDP		17

#define IP_VersionOffset	0x000F
#define IP_HeaderLenOffset	0x00F0
#define IP_TOS_Offset		0xFF00
#define IP_FlagsOffset		0x0007
#define IP_Offset_Offset	0xFFF8
#define IP_TTL_Offset		0x00FF
#define IP_Protocol_Offset	0xFF00

#define IP_TTL_MAX			64

#pragma pack (1)
typedef struct IP_Header_
{
	union U_VL_
	{
		uint8_t U_VL_ALL;
		struct S_VL_ALL_
		{
			uint8_t Version : 4;
			uint8_t HeaderLen : 4;
		}S_VL_ALL;
	}U_VL;
	uint8_t TOS;
	uint16_t TotalLen;
	uint16_t Identify;
	union U_FO_
	{
		uint16_t U_FO_ALL;
		struct S_FO_ALL_
		{
			uint16_t Flags : 3;
			uint16_t Offset : 13;
		}S_FO_ALL;
	}U_FO;
	union U_TP_
	{
		uint16_t U_TP_ALL;
		struct S_TP_ALL_
		{
			uint16_t Protocol : 8;
			uint16_t TTL : 8;
		}S_TP_ALL;
	}U_TP;
	uint16_t CheckSum;
	IP SrcIP;
	IP DstIP;
	uint8_t Buff;
}IP_Header;
#pragma pack ()

extern MAC LocalMAC;
extern IP  LocalIP;
extern MAC BrocastMAC;
extern MAC ZeroMAC;

void IP_ProcessPacket(NeteworkBuff * pNeteorkBuff);
void prvIP_FillPacket(NeteworkBuff * pNeteworkBuff, IP * RemoteIP, uint8_t Protocol);
uint32_t IP_GetOptionSize(void);
#ifdef __cplusplus
}
#endif

#endif



