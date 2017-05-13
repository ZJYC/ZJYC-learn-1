
#ifndef __NETWORKBUFF_H__
#define __NETWORKBUFF_H__

#include "DataTypeDef.h"

#define NetworkBuffDirRx	0
#define NetworkBuffDirTx	1
#pragma pack (1)
typedef struct NeteworkBuff_
{
	struct NeteworkBuff_ * Next;
	uint8_t Ready;
	uint32_t BuffLen;
	uint8_t Buff;
}NeteworkBuff;
#pragma pack ()
void Network_Init(void);
NeteworkBuff * Network_New(uint8_t Direction, uint32_t Len);
void Network_Del(NeteworkBuff * UselessBuff);
NeteworkBuff * Network_GetOne(uint8_t Direction);

#endif




















