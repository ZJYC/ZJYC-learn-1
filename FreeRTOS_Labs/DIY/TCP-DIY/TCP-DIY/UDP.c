
#include "Ethernet.h"
#include "Basic.h"
#include "Socket.h"
#include "IP.h"
#include "Basic.h"
#include "UDP.h"

static uint16_t prvUDP_GetCheckSum(uint16_t*PseudoHeader, uint16_t PseudoLenBytes, uint16_t*Data, uint32_t DataLenBytes)
{
	uint32_t cksum = 0;
	uint16_t TempDebug = 0;
	while (PseudoLenBytes)
	{
		TempDebug = *PseudoHeader++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		PseudoLenBytes -= 2;
	}
	while (DataLenBytes > 1)
	{
		TempDebug = *Data++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		DataLenBytes -= 2;
	}
	if (DataLenBytes)
	{
		TempDebug = (*(uint8_t *)Data); TempDebug <<= 8;
		cksum += TempDebug;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	return (uint16_t)(~cksum);
}

static RES UDP_PreProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs(pUDP_Header->DstPort));
	if (pSocket == NULL)return RES_UDPPacketDeny;

	CheckSum = DIY_ntohs(pUDP_Header->CheckSum);
	pUDP_Header->CheckSum = 0;
	PayloadLen = DIY_ntohs(pUDP_Header->DataLen);
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_UDP << 16 | PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);
	CheckTemp = prvUDP_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pUDP_Header, PayloadLen);
	if (CheckTemp == CheckSum)return RES_UDPPacketPass;
	else return RES_UDPPacketDeny;
}

void prvUDP_FillPacket(NeteworkBuff * pNeteorkBuff, IP * RemoteIP,uint16_t DstPort, uint16_t SrcPort,uint8_t * Data, uint32_t Len)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint8_t * pUDP_Payload = (uint8_t*)&pUDP_Header->Buff;
	uint16_t LenTemp = 0, PayloadLen;

	pUDP_Header->DataLen = DIY_htons(Len + UDP_HEADE_LEN);
	pUDP_Header->DstPort = DIY_htons(DstPort);
	pUDP_Header->SrcPort = DIY_htons(SrcPort);
	memcpy(pUDP_Payload, Data, Len);
	PayloadLen = DIY_ntohs(pUDP_Header->DataLen);
	PseudoHeader[0] = LocalIP.U32;
	PseudoHeader[1] = RemoteIP->U32;
	PseudoHeader[2] = IP_Protocol_UDP << 16 | PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);
	pUDP_Header->CheckSum = 0;
	pUDP_Header->CheckSum = prvUDP_GetCheckSum((uint16_t*)PseudoHeader,12,(uint16_t*)pUDP_Header, PayloadLen);
	pUDP_Header->CheckSum = DIY_htons(pUDP_Header->CheckSum);
	/* IP */
	pIP_Header->TotalLen = IP_HeaderLen + DIY_htons(pUDP_Header->DataLen);
	pIP_Header->TotalLen = DIY_htons(pIP_Header->TotalLen);
	prvIP_FillPacket(pNeteorkBuff, RemoteIP,IP_Protocol_UDP);
}

void UDP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;

	if (UDP_PreProcessPacket(pNeteorkBuff) != RES_UDPPacketPass)return;

	switch (0)
	{
		default:break;
	}

}

uint32_t UDP_GetPacketSize(uint32_t DataLen)
{
	return EthernetHeaderLen + IP_HeaderLen + IP_GetOptionSize() + UDP_HEADE_LEN + DataLen;
}






