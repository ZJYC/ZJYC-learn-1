
#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"

#define EthernetType_IP		0x0800
#define EthernetType_ARP	0x0806

#define EthernetHeaderLen	18

#define EthernetPacketPass		0x01
#define EthernetPacketDelete	0x00

typedef struct Ethernet_Header_
{
	MAC DstMAC;
	MAC SrcMAC;
	uint16_t Type;
	uint8_t Buff;
}Ethernet_Header;

typedef struct NeteworkBuff_
{
	uint16_t BuffLen;
	uint8_t Buff[2048];
}NeteworkBuff;


uint16_t EthernetSend(NeteworkBuff * pNeteorkBuff);
uint16_t EthernetRecv(NeteworkBuff * pNeteorkBuff);
uint16_t EthernetFilter(NeteworkBuff * pNeteorkBuff);











#ifdef __cplusplus
}
#endif


#endif
