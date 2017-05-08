
#ifndef __TCP_H__
#define __TCP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "IP.h"
#include "Basic.h"
#include "TCP_WIN.h"

#define TCP_FLAG_CWR	(1<<7)
#define TCP_FLAG_ECE	(1<<6)
#define TCP_FLAG_URG	(1<<5)
#define TCP_FLAG_ACK	(1<<4)
#define TCP_FLAG_PSH	(1<<3)
#define TCP_FLAG_RST	(1<<2)
#define TCP_FLAG_SYN	(1<<1)
#define TCP_FLAG_FIN	(1<<0)

#define TCP_HEADE_LEN_MIN	(20)	

#pragma pack (1)

typedef enum TCP_Option_
{
	TOK_EOL = 0,
	TOK_NOP = 1,
	TOK_MSS = 2,
	TOK_WSOPT = 3,
	TOK_SACK_Per = 4,
	TOK_SACK = 5,
	TOK_TSOPT = 6,
}TCP_Option;

typedef enum TCP_State_
{
	TCP_STATE_CLOSED = 0,
	TCP_STATE_LISTEN,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECV,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_FIN_WAIT1,
	TCP_STATE_ClOSING,
	TCP_STATE_FIN_WAIT2,
	TCP_STATE_TIME_WAIT,
}TCP_State;
typedef struct TCP_Header_
{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t SN;
	uint32_t AK;
	uint8_t HeaderLen;
	uint8_t Flags;
	uint16_t WinSize;
	uint16_t CheckSum;
	uint16_t Urgent;
	uint8_t Option;
}TCP_Header;
typedef struct TCP_Control_
{
	TCP_State State;
	uint32_t RemoteMSS;
	uint32_t RemoteWinSize;
	uint8_t  RemoteWinScale;
	uint32_t LocalMSS;
	uint32_t LocalWinSize;
	uint8_t  LocalWinScale;
	uint32_t LocalSN;
	uint32_t AK_Except;
	uint32_t RemoteSN;
	uint32_t FIN_Sent : 1;
	uint32_t FIN_Recv : 1;
	uint32_t SYN_Sent : 1;
	uint32_t MSS_Send : 1;
	uint32_t WIN_Sent : 1;
	uint32_t WIN_Change : 1;
	uint32_t ActiveSYN : 1;
	uint32_t MSS_Change : 1;
	uint32_t TSOPT : 1;
	TCP_Win * pTCP_Win;
}TCP_Control;
#pragma pack ()

void TCP_Test(void);

#ifdef __cplusplus
}
#endif

#endif
