
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

RES UDP_ProcessPacket(UDP_Header * pUDP_Header);
uint16_t prvUDP_GetCheckSum(uint16_t*PseudoHeader, uint16_t PseudoLenBytes, uint16_t*Data, uint32_t DataLenBytes);
RES UDP_PreProcessPacket(IP_Header * pIP_Header);
RES prvUDP_FillPacket(Socket * pSocket, uint8_t * Data, uint32_t Len);

#ifdef __cplusplus
}
#endif

#endif
