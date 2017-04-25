
#ifndef __IP_H__
#define __IP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"


#define IP_VersionIPV4	4
#define	IP_Flags_DF		2
#define	IP_Flags_MF		1

#define IP_PacketDelete 0
#define IP_PacketPass	1

#define IP_Protocol_ICMP	1
#define IP_Protocol_IGMP	2
#define IP_Protocol_TCP		6
#define IP_Protocol_UDP		17

#define IP_TTL_MAX			64

#pragma pack (1)
typedef struct IP_Header_
{
	uint16_t Version : 4;
	uint16_t HeaderLen : 4;
	uint16_t TOS : 8;
	uint16_t TotalLen;
	uint16_t Identify;
	uint16_t Flags : 3;
	uint16_t Offset : 13;
	uint16_t TTL : 8;
	uint16_t Protocol : 8;
	uint16_t CRC;
	IP SrcIP;
	IP DstIP;
	uint8_t Buff;
}IP_Header;
#pragma pack ()







extern MAC LocalMAC;
extern IP  LocalIP;
extern MAC BrocastMAC;
extern MAC ZeroMAC;

uint16_t IP_ProcessPacket(NeteworkBuff * pNeteworkBuff);

#ifdef __cplusplus
}
#endif

#endif



