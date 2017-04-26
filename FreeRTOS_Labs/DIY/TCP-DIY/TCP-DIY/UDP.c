
#include "Ethernet.h"
#include "Basic.h"
#include "Socket.h"
#include "IP.h"
#include "Basic.h"
#include "UDP.h"

RES UDP_Send(Socket * pSocket, uint8_t * Data, uint32_t Len)
{
	return RES_True;
}

RES prvUDP_GeneratePacket(Socket * pSocket, uint8_t * Data, uint32_t Len)
{
	NeteworkBuff * pNeteworkBuff = pSocket->pNeteworkBuff;
	Ethernet_Header * pEthernet_Header = (Ethernet_Header *)pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint8_t * pUDP_Payload = (uint8_t*)&pUDP_Header->Buff;

	if (pSocket->Procotol != IP_Protocol_UDP)return RES_False;
	pUDP_Header->DataLen = Len;
	pUDP_Header->DstPort = pSocket->addr.RemotePort;
	pUDP_Header->SrcPort = pSocket->addr.LocalPort;
	//pIP_Header->Protocol = IP_Protocol_UDP;
	memset(pUDP_Payload, 0x00, prvAlign(Len, 16));
	memcpy(pUDP_Payload, Data, Len);
	pUDP_Header->CheckSum = prvUDP_GenerateCheckSum(pUDP_Header);
	/* 到现在为止UDP填充完毕 */
	IP_FillPacket(pSocket);
	return RES_True;
}

RES UDP_ProcessPacket(UDP_Header * pUDP_Header)
{
	Socket * pSocket;
	uint16_t CheckSum = DIY_ntohs(pUDP_Header->CheckSum);

	if (CheckSum != prvUDP_GenerateCheckSum(pUDP_Header))return RES_UDPPacketDeny;
	pSocket = prvSocket_GetSocketByPort(DIY_ntohs(pUDP_Header->SrcPort));
	if (pSocket == NULL)return RES_UDPPacketDeny;
	switch (0)
	{
		default:break;
	}

}

RES UDP_PreProcessPacket(IP_Header * pIP_Header)
{
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	Socket * pSocket = prvSocket_GetSocketByPort(DIY_ntohs(pUDP_Header->SrcPort));
	if (pSocket == NULL)return RES_UDPPacketDeny;
	PayloadLen = pUDP_Header->DataLen + UDP_HEADE_LEN;
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = 0x00 << 24 + IP_Protocol_UDP << 16 + PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);

}

uint16_t prvUDP_GenerateCheckSum(UDP_Header * pUDP_Header)
{
	uint16_t TempDebug = 0;
	uint16_t * Buff = (uint16_t*)pUDP_Header;
	uint32_t Len = prvAlign(DIY_ntohs(pUDP_Header->DataLen), 16) + UDP_HEADE_LEN;
	pUDP_Header->CheckSum = 0;
	TempDebug = prvGetCheckSum(Buff, Len / 2);
	pUDP_Header->CheckSum = TempDebug;
}

uint16_t prvUDP_GetCheckSum(uint16_t*PseudoHeader, uint16_t PseudoHeaderLen, uint16_t*Data, uint32_t DataLen)
{

}






