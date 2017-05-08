#ifndef __TCP_WIN_H__
#define __TCP_WIN_H__
#ifdef __cplusplus
extern "C" {
#endif
/*
	窗口的API
	接收应答号
	创建
	删除
	添加数据
*/
#include "DataTypeDef.h"

	typedef struct Segment_
	{
		struct Segment_ * Next;
		uint8_t * Buff;
		uint32_t Len;
		uint32_t SnStart;
		uint32_t SnEnd;
	}Segment;

	typedef struct TCP_Win_
	{
		Segment * pSegment_Tx;
		Segment * pSegment_Rx;
		Segment * pSegment_Pri;
		Segment * pSegment_Wait;

		uint32_t MSS;
		uint32_t Sn;

		uint8_t * TxBuff;
		uint32_t TxBuffLen;
		uint32_t TxCapacity;
		uint8_t * RxBuff;
		uint32_t RxCapacity;
		uint32_t RxBuffLen;
	}TCP_Win;


#ifdef __cplusplus
}
#endif
#endif
