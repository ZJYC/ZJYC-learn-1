
#include "ARP.h"
#include "Ethernet.h"
#include "Basic.h"
#include "Socket.h"
#include "IP.h"
#include "UDP.h"
#include "TCP_Task.h"
#include "TCP.h"

ADDR Address = 
{
	{ 7,8,9,0 }, {1,2,3,4},
	{ 7, 8, 9, 10, 11, 12 }, {1,2,3,4,5,6},
	{ 7890 }, {1234},
};

void Init(void)
{
	Network_Init();
	ARP_Init();
	ARP_AddItem(&Address.RemoteIP, &Address.RemoteMAC);
}

int main(void)
{
	//uint8_t Data[] = "1234567890";
	//Init();
	//Socket * pSocket = prvSocket_New(&Address, IP_Protocol_UDP);
	//Socket_Send(pSocket,Data, 10);
	//while (1)MainLoop();
	TCP_Test();
}

















