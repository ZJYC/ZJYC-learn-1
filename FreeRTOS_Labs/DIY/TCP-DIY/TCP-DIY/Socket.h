
#ifndef __SOCKET_H__
#define __SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"
#include "TCP.h"

#pragma pack (1)

typedef struct Socket_
{
	struct Socket_ * Next;
	uint8_t Procotol;
	ADDR addr;
	NeteworkBuff * pNeteworkBuff;
	TCP_Control * pTCP_Control;
}Socket;

#pragma pack ()

Socket * prvSocket_New(ADDR * pADDR, uint8_t Procotol);
void Socket_Send(Socket * pSocket, uint8_t * Data, uint32_t Len);
Socket * Socket_GetSocketByPort(uint16_t Port);

#ifdef __cplusplus
}
#endif


#endif

