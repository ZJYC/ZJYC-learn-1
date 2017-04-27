
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

/*
****************************************************
*  Function       : prvUDP_FillPacket
*  Description    : Normally,A upper layer wants to send data,this function will be called to fill most attributes of protocol UDP 
*  Params         : 
					pSocket:pointer of socket
					Data:pointer of data
					Len:data's length
*  Return         : Reserved
*  Author         : -5A4A5943-
*  History        :
*****************************************************
*/
RES prvUDP_FillPacket(Socket * pSocket, uint8_t * Data, uint32_t Len)
{
	uint32_t PseudoHeader[3] = { 0x00 };
	NeteworkBuff * pNeteworkBuff = pSocket->pNeteworkBuff;
	Ethernet_Header * pEthernet_Header = (Ethernet_Header *)pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	uint8_t * pUDP_Payload = (uint8_t*)&pUDP_Header->Buff;
	uint16_t LenTemp = 0, PayloadLen;

	if (pSocket->Procotol != IP_Protocol_UDP)return RES_False;
	pUDP_Header->DataLen = DIY_htons(Len + UDP_HEADE_LEN);
	pUDP_Header->DstPort = DIY_htons(pSocket->addr.RemotePort);
	pUDP_Header->SrcPort = DIY_htons(pSocket->addr.LocalPort);
	pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	pIP_Header->U_TP.S_TP_ALL.Protocol = IP_Protocol_UDP;
	pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	memcpy(pUDP_Payload, Data, Len);

	PayloadLen = DIY_ntohs(pUDP_Header->DataLen);
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_UDP << 16 | PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);

	pUDP_Header->CheckSum = 0;

	pUDP_Header->CheckSum = prvUDP_GetCheckSum((uint16_t*)PseudoHeader,12,(uint16_t*)pUDP_Header, PayloadLen);
	pUDP_Header->CheckSum = DIY_htons(pUDP_Header->CheckSum);
	//pUDP_Header->CheckSum = prvUDP_GenerateCheckSum(pUDP_Header);
	/* 到现在为止UDP填充完毕 */
	prvIP_FillPacket(pSocket);
	return RES_True;
}

RES UDP_ProcessPacket(UDP_Header * pUDP_Header)
{
	switch (0)
	{
		default:break;
	}

}
/*
****************************************************
*  Function       : UDP_PreProcessPacket
*  Description    : pre process incoming UDP packet,Include Checksum and port searching
*  Params         : pIP_Header:The IP header which contians this UDP packet
*  Return         : 
					RES_UDPPacketDeny:The packet need not further process,Just ignore it.
					RES_UDPPacketPass:We need to process.
*  Author         : -5A4A5943-
*  History        :
					2017--04--27--11--20--17
					Available now,Will add features in later
*****************************************************
*/
RES UDP_PreProcessPacket(IP_Header * pIP_Header)
{
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0,CheckTemp = 0;
	UDP_Header * pUDP_Header = (UDP_Header*)&pIP_Header->Buff;
	Socket * pSocket = prvSocket_GetSocketByPort(DIY_ntohs(pUDP_Header->DstPort));
	if (pSocket == NULL)return RES_UDPPacketDeny;
	CheckSum = DIY_ntohs(pUDP_Header->CheckSum);
	pUDP_Header->CheckSum = 0;
	PayloadLen = DIY_ntohs(pUDP_Header->DataLen);
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_UDP << 16 | PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);
	CheckTemp = prvUDP_GetCheckSum((uint16_t*)PseudoHeader,12,(uint16_t*)pUDP_Header, PayloadLen);
	if (CheckTemp == CheckSum)return RES_UDPPacketPass;
	else return RES_UDPPacketDeny;
}

/*
****************************************************
*  Function       :prvUDP_GetCheckSum
*  Description    :Generate UDP's checkSum
*  Params         :
					PseudoHeader:
					PseudoLenBytes:
					Data:
					DataLenBytes:
*  Return         : CheckSum
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--11--16--09
					Available now
*****************************************************
*/
uint16_t prvUDP_GetCheckSum(uint16_t*PseudoHeader, uint16_t PseudoLenBytes, uint16_t*Data, uint32_t DataLenBytes)
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
		TempDebug = *Data++;TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		DataLenBytes -= 2;
	}
	if (DataLenBytes)
	{
		TempDebug = (*(uint8_t *)Data);TempDebug <<= 8;
		cksum += TempDebug;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	return (uint16_t)(~cksum);
}







