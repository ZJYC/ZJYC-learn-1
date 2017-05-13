

#ifndef __DATATYPEDEF_H__
#define __DATATYPEDEF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>

#define uint8_t unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int

#include "NetworkBuff.h"


#ifndef NULL
	#define NULL	0x00
#endif
#define True		0xff
#define PortStart	1024
#define PortEnd		65535

#pragma pack (1)

typedef union IP_
{
	uint8_t  U8[4];
	uint32_t U32;
}IP;

typedef struct MAC_ {uint8_t Byte[6];}MAC;

typedef struct ADDR_
{
	IP RemoteIP;
	IP LocalIP;
	MAC RemoteMAC;
	MAC LocalMAC;
	uint16_t RemotePort;
	uint16_t LocalPort;
}ADDR;

#pragma pack ()

typedef enum RES_
{
	RES_True = 0,
	RES_False,
	RES_ARPPacketPass,
	RES_ARPPacketDeny,
	RES_ARPHasRespond,
	RES_ARPPacketProcessed,
	RES_EthernetPacketPass,
	RES_EthernetPacketDeny,
	RES_IPPacketDeny,
	RES_IPPacketPass,
	RES_UDPPacketDeny,
	RES_UDPPacketPass,
	RES_TCPPacketDeny,
	RES_TCPPacketPass,
	RES_TCPPacketRespond
}RES;


#ifdef __cplusplus
}
#endif

#endif








