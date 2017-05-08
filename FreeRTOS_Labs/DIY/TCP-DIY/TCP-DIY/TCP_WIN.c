
#include "DataTypeDef.h"
#include "TCP_WIN.h"
#include "heap_5.h"
#include "TCP.h"

static Segment * prvTCPWin_NewSegment(uint8_t * Buff, uint32_t Len,uint32_t SnStart)
{
	Segment * pSegment = (Segment*)MM_Ops.Malloc(sizeof(Segment));

	if (pSegment) 
	{
		memset((uint8_t*)pSegment,0x00,sizeof(Segment));
		pSegment->Buff = Buff;
		pSegment->Len = Len;
		pSegment->SnStart = SnStart;
		pSegment->SnEnd = SnStart + Len;
		return pSegment;
	}
	return NULL;
}

static uint32_t prvTCPWin_GetCount(Segment * pSegment)
{
	uint32_t Counter = 0;
	Segment * SegmentTemp = pSegment;
	while (SegmentTemp->Next)
	{
		Counter++;
		SegmentTemp = SegmentTemp->Next;
	}
	return Counter;
}

static void prvTCPWin_DelSegmentFrom(Segment * pSegmentHead, Segment * pSegment)
{
	while (pSegmentHead->Next != pSegment && pSegmentHead->Next)pSegmentHead = pSegmentHead->Next;
	if (pSegmentHead->Next)
	{
		pSegmentHead->Next = pSegment->Next;
		pSegment->Next = 0;
	}
}

static void prvTCPWin_DelSegment(Segment * pSegment)
{
	MM_Ops.Free((uint8_t*)pSegment);
}

static void prvTCPWin_AddSegmentToEnd(Segment * pSegmentHead, Segment * pSegment)
{
	while (pSegmentHead->Next)pSegmentHead = pSegmentHead->Next;
	if (!pSegmentHead->Next)pSegmentHead->Next = pSegment;
}

TCP_Win * prvTCPWin_NewWindows(uint32_t WinSizeRx, uint32_t WinSizeTx)
{

	TCP_Win * pTCP_Win = (TCP_Win*)MM_Ops.Malloc(sizeof(TCP_Win));
	if (pTCP_Win)
	{
		memset((uint8_t*)pTCP_Win,0x00, sizeof(TCP_Win));
		pTCP_Win->TxBuff = MM_Ops.Malloc(WinSizeTx);
		pTCP_Win->RxBuff = MM_Ops.Malloc(WinSizeRx);
		if (pTCP_Win->TxBuff && pTCP_Win->TxBuff)
		{
			memset(pTCP_Win->TxBuff, 0x00, WinSizeTx);
			memset(pTCP_Win->RxBuff, 0x00, WinSizeRx);

			pTCP_Win->TxCapacity = WinSizeTx;
			pTCP_Win->RxCapacity = WinSizeRx;
		}
	}


}

static Segment * prvTCPWin_FindSnEnd(Segment * pSegment,uint32_t Sn)
{
	while (pSegment->Next)
	{
		if (pSegment->SnEnd == Sn)return pSegment;
		pSegment = pSegment->Next;
	}
	return NULL;
}

void TCPWin_AckNormal(TCP_Win * pTCP_Win,uint32_t Sn)
{
	Segment * pSegment_Wait = prvTCPWin_FindSnEnd(pTCP_Win->pSegment_Wait, Sn);
	if (pSegment_Wait)
	{
		prvTCPWin_DelSegmentFrom(pTCP_Win->pSegment_Wait, pSegment_Wait);
		prvTCPWin_DelSegment(pSegment_Wait);
	}
}

void TCPWin_AddTxData(TCP_Win * pTCP_Win, uint8_t * Data, uint32_t Len)
{
	uint8_t * Buff = 0;
	Segment * pSegment = 0;
	uint32_t SegmentLen = 0;
	memcpy((uint8_t*)pTCP_Win->TxBuff, (uint8_t*)Data,Len);
	pTCP_Win->TxBuffLen = Len;
	Buff = pTCP_Win->TxBuff;

	while (pTCP_Win->TxBuffLen)
	{
		if (pTCP_Win->TxBuffLen >= pTCP_Win->MSS){SegmentLen = pTCP_Win->MSS;}
		else { SegmentLen = pTCP_Win->TxBuffLen; }
		pTCP_Win->TxBuffLen -= SegmentLen;
		pSegment = prvTCPWin_NewSegment(Buff, SegmentLen, pTCP_Win->Sn);
		prvTCPWin_AddSegmentToEnd(pTCP_Win->pSegment_Tx, pSegment);
	}
}

void TCPWin_SendData(Socket * pSocket)
{
	TCP_Win * pTCP_Win = pSocket->pTCP_Control->pTCP_Win;
	uint32_t SegmentWaitCounter = prvTCPWin_GetCount(pSocket->pTCP_Control->pSegment_Wait);
	uint32_t SegmentWin = pTCP_Win->TxCapacity / pTCP_Win->MSS;

	if (SegmentWin > SegmentWaitCounter)
	{
		prvTCP_GeneratePacket();
	}
}








