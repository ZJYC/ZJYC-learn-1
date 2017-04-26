
#include "ARP.h"
#include "Ethernet.h"
#include "Basic.h"

IP ip[2] = { { 12, 12, 12, 12 }, { 13, 13, 13, 13 } };
MAC mac[2] = { { 12, 12, 12, 12, 12, 12 }, {13,13,13,13,13,13} };

typedef union X_
{
	uint8_t Byte[4];
	uint32_t U32;
	struct U8_ 
	{
		uint32_t A : 4;
		uint32_t B : 4;
		uint32_t C : 8;
		uint32_t D : 16;
	}U8;
}X;

int main(void)
{
	X x = { 0x12,0x34,0x56,0x78 };
	x.U32 = DIY_ntohl(x.U32);

	ARP_Init();
	EthernetRecv(&NeteorkBuffTemp);
	while (1);
}

















