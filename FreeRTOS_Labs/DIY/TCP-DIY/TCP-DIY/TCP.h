
#ifndef __TCP_H__
#define __TCP_H__

#include "DataTypeDef.h"
#include "IP.h"

#define TCP_FLAG_URG	(1<<5)
#define TCP_FLAG_ACK	(1<<4)
#define TCP_FLAG_PSH	(1<<3)
#define TCP_FLAG_RST	(1<<2)
#define TCP_FLAG_SYN	(1<<1)
#define TCP_FLAG_FIN	(1<<0)

#define TCP_HEADE_LEN_MIN	(5)	
#pragma pack (1)
typedef struct TCP_Header_
{
	uint32_t SrcPort : 16;
	uint32_t DstPort : 16;
	uint32_t SN;
	uint32_t AK;
	uint32_t HeaderLen : 4;
	uint32_t Reserve : 4;
	uint32_t Flags : 8;
	uint32_t WinSize : 8;
	uint32_t CheckSum : 16;
	uint32_t Urgent : 16;
	uint8_t OptionSegment;
}TCP_Header;
#pragma pack ()











#endif
