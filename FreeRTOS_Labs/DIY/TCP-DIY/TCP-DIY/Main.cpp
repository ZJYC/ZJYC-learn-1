
#include "ARP.h"
#include "Ethernet.h"
#include "Basic.h"
#include "Socket.h"
#include "IP.h"
#include "UDP.h"

IP ip[2] = { { 12, 12, 12, 12 }, { 13, 13, 13, 13 } };
MAC mac[2] = { { 12, 12, 12, 12, 12, 12 }, {13,13,13,13,13,13} };
Socket Socket_UDP1234 = { 0x00 };
ADDR Socket_UDP1234_ADDR = {0x00};
void APP_Prepare(void)
{
	Socket_UDP1234_ADDR.LocalIP.U32 = LocalIP.U32;
	Socket_UDP1234_ADDR.LocalMAC = LocalMAC;
	Socket_UDP1234_ADDR.RemoteIP.U8[0] = 1;
	Socket_UDP1234_ADDR.RemoteIP.U8[1] = 2;
	Socket_UDP1234_ADDR.RemoteIP.U8[2] = 3;
	Socket_UDP1234_ADDR.RemoteIP.U8[3] = 4;
	Socket_UDP1234_ADDR.LocalPort = 5678;
	Socket_UDP1234_ADDR.RemotePort = 1234;
	prvSocket_Socket(&Socket_UDP1234,&Socket_UDP1234_ADDR,IP_Protocol_UDP);
}

int main(void)
{
	uint8_t Data[3] = { '1','2','3' };

	APP_Prepare();
	ARP_Init();
	//EthernetRecv(&NeteorkBuffTemp);
	prvUDP_FillPacket(&Socket_UDP1234, (uint8_t*)&Data, 3);
	while (1);
}

















