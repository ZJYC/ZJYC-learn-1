
#include "Socket.h"
#include "UDP.h"
#include "Ethernet.h"
#include "IP.h"
#include "heap_5.h"

Socket Socket_Header = { NULL };

Socket * Socket_GetSocketByPort(uint16_t Port)
{
	Socket * pSocket = &Socket_Header;

	while (True)
	{
		if (pSocket->addr.LocalPort == Port)return pSocket;
		if (pSocket->Next != NULL)pSocket = pSocket->Next;
		else return NULL;
	}
}

uint16_t prvSocket_GetRandomPortNum(void)
{
	uint16_t i;

	for (i = PortStart; i < PortEnd; i++)
	{
		if (Socket_GetSocketByPort(i) == NULL)return i;
	}

	return 0;
}

Socket * prvSocket_New(ADDR * pADDR,uint8_t Procotol)
{
	Socket * pSocketHeader = &Socket_Header;
	Socket * pSocketNew = 0;

	if (pADDR == NULL)return NULL;
	if (pADDR->RemoteIP.U32 == 0 || pADDR->RemotePort == 0)return NULL;
	if (pADDR->LocalPort == NULL)pADDR->LocalPort = prvSocket_GetRandomPortNum();
	pADDR->LocalIP.U32 = LocalIP.U32;

	pSocketNew = (Socket*)MM_Ops.Malloc(sizeof(Socket));
	if (pSocketNew == NULL)return NULL;

	pSocketNew->addr = *pADDR;
	pSocketNew->Next = NULL;
	pSocketNew->Procotol = Procotol;
	pSocketNew->pNeteworkBuff = NULL;
	while (True)
	{
		if (pSocketHeader->Next != NULL)pSocketHeader = pSocketHeader->Next;
		else break;
	}
	pSocketHeader->Next = pSocketNew;
	return pSocketNew;
}

void Socket_Send(Socket * pSocket, uint8_t * Data, uint32_t Len)
{
	if (pSocket == NULL)return;

	if (pSocket->Procotol == IP_Protocol_UDP)
	{
		NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirTx, EthernetHeaderLen + IP_HeaderLen + UDP_HEADE_LEN + Len);
		prvUDP_FillPacket(pNeteworkBuff, &pSocket->addr.RemoteIP, pSocket->addr.RemotePort, pSocket->addr.LocalPort, Data, Len);
		Ethernet_TransmitPacket(pNeteworkBuff);
	}

}














