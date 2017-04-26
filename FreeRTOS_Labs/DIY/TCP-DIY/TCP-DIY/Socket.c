
#include "Socket.h"
#include "UDP.h"
#include "Ethernet.h"
#include "IP.h"

Socket Socket_Header = { NULL };

uint16_t prvSocket_GetRandomPortNum(void)
{
	uint16_t i;

	for (i = PortStart; i < PortEnd; i++)
	{
		if (prvSocket_GetSocketByPort(i) == NULL)return i;
	}
}

Socket * prvSocket_GetSocketByPort(uint16_t Port)
{
	Socket * pSocket = &Socket_Header;

	while (True)
	{
		if (pSocket->addr.LocalPort == Port)return pSocket;
		if (pSocket->Next != NULL)pSocket = pSocket->Next;
		else return NULL;
	}
}

void * prvSocket_Socket(Socket * Socket_New,ADDR * pADDR,uint8_t Procotol)
{
	Socket * pSocket = &Socket_Header;

	if (pADDR->RemoteIP.U32 == 0 || pADDR->RemotePort == 0)return NULL;
	if (pADDR->LocalPort == NULL)pADDR->LocalPort = prvSocket_GetRandomPortNum();
	pADDR->LocalIP.U32 = LocalIP.U32;
	Socket_New->addr = *pADDR;
	Socket_New->Next = NULL;
	Socket_New->Procotol = Procotol;
	Socket_New->pNeteworkBuff = &NeteorkBuffTemp;
	while (True)if (pSocket->Next != NULL)pSocket = pSocket->Next;
	pSocket->Next = Socket_New;
}

RES prvSocketSend(Socket * pSocket, uint8_t * Data, uint32_t Len)
{
	if (pSocket->Procotol == IP_Protocol_UDP)
	{
		prvUDP_GeneratePacket(pSocket, Data, Len);
	}

}














