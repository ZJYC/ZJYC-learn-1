
#ifndef __SOCKET_H__
#define __SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "DataTypeDef.h"

#pragma pack (1)

typedef struct Socket_
{
	struct Socket_ * Next;
	ADDR addr;
	uint8_t Procotol;
	NeteworkBuff * pNeteworkBuff;
}Socket;

#pragma pack ()

uint16_t prvSocket_GetRandomPortNum(void);
Socket * prvSocket_GetSocketByPort(uint16_t Port);







#ifdef __cplusplus
}
#endif


#endif

