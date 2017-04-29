
#include "heap_5.h"

uint8_t MemPool[1024 * 100] = { 0x00 };
NeteworkBuff pNeteworkBuffRxHead = { 0x00 };
NeteworkBuff pNeteworkBuffTxHead = { 0x00 };

HeapRegion_t xHeapRegions[] = 
{
	{ MemPool ,100*1024},
	{NULL,0},
};

void Network_Init(void)
{
	memset(MemPool, 0x00, 100 * 1024);
	MM_Ops.Init(&xHeapRegions);
}

static void prvNetwork_Insert(uint8_t Direction, NeteworkBuff * Newer)
{
	NeteworkBuff * Temp = 0;
	if (Direction == NetworkBuffDirRx)Temp = &pNeteworkBuffRxHead;
	if (Direction == NetworkBuffDirTx)Temp = &pNeteworkBuffTxHead;
	while (Temp->Next != NULL)Temp = Temp->Next;
	Temp->Next = Newer;
}

static void prvNetwork_Remove(NeteworkBuff * UselessBuff)
{
	uint8_t i = 0;
	NeteworkBuff * Prev = 0, * Next = 0, * Mine = UselessBuff;
	for (i = 0; i < 2; i++)
	{
		if (i % 2 == 0)Prev = &pNeteworkBuffRxHead;
		if (i % 2 == 1)Prev = &pNeteworkBuffTxHead;
		while (Prev->Next != NULL && Prev->Next != Mine)Prev = Prev->Next;
		if (Prev->Next == Mine)
		{
			Next = Mine->Next;
			Mine->Next = NULL;
			Prev->Next = Next;
		}
	}
}

NeteworkBuff * Network_New(uint8_t Direction,uint32_t Len)
{
	uint32_t ActuallLen = Len + sizeof(NeteworkBuff);
	NeteworkBuff * pNeteworkBuff = 0x00;
	uint8_t * MemHeader = MM_Ops.Malloc(ActuallLen);

	if (MemHeader != NULL)
	{
		pNeteworkBuff = (NeteworkBuff*)MemHeader;
		prvNetwork_Insert(Direction, pNeteworkBuff);
		pNeteworkBuff->Ready = NULL;
		pNeteworkBuff->BuffLen = Len;
		return pNeteworkBuff;
	}
	return NULL;
}

void Network_Del(NeteworkBuff * UselessBuff)
{
	if (UselessBuff == NULL)return;
	prvNetwork_Remove(UselessBuff);
	MM_Ops.Free((void*)UselessBuff);
}

NeteworkBuff * Network_GetOne(uint8_t Direction)
{
	NeteworkBuff * Header = 0;
	if (Direction == NetworkBuffDirRx)Header = &pNeteworkBuffRxHead;
	if (Direction == NetworkBuffDirTx)Header = &pNeteworkBuffTxHead;
	while (Header->Next != NULL)
	{
		if (Header->Next->Ready == True)return Header->Next;
		Header = Header->Next;
	}
	return NULL;
}



