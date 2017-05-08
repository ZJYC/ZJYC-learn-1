
#ifndef __UDP_H__
#define __UDP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "Socket.h"
#include "UDP.h"
#include "IP.h"

#define UDP_HEADE_LEN	8

#pragma pack (1)
typedef struct UDP_Header_
{
	uint32_t SrcPort : 16;
	uint32_t DstPort : 16;
	uint32_t DataLen : 16;
	uint32_t CheckSum : 16;
	uint8_t Buff;
}UDP_Header;
#pragma pack ()

void UDP_ProcessPacket(NeteworkBuff * pNeteorkBuff);
void prvUDP_FillPacket(NeteworkBuff * pNeteorkBuff, IP * RemoteIP, uint16_t DstPort, uint16_t SrcPort, uint8_t * Data, uint32_t Len);
uint32_t UDP_GetPacketSize(uint32_t DataLen);
#ifdef __cplusplus
}
#endif

#endif
