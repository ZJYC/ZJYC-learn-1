
#include "DataTypeDef.h"
#include "IP.h"
#include "Ethernet.h"
#include "UDP.h"
#include "TCP.h"
#include "Socket.h"
#include "Basic.h"

/* 
	关于数据的加入方式
	我们只使用一个缓存<NeteorkBuffTemp>,所有的数据都在其中进行填充，数据由TCP或者是UDP层加入数据，
	每一层只负责他们自己的属性并加入到<NeteorkBuffTemp>中
*/

MAC LocalMAC = { 0x90,0x2b,0x34,0xce,0xc9,0x02 };
IP  LocalIP = {192,168,120,65};
MAC BrocastMAC = {0xFF,0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
MAC ZeroMAC = {0x00,0x00, 0x00, 0x00, 0x00, 0x00};
IP  BrocastIP = {192,168,120,255};

/*
****************************************************
*  Function       : prvIP_GetCheckSum
*  Description    : Generate IP header checksum
*  Params         : pIP_Header:IP header
*  Return         : The checksum
*  Author         : -5A4A5943-
*  History        :
					2017--04--27--14--46--43
					Available now
*****************************************************
*/
uint16_t prvIP_GetCheckSum(IP_Header * pIP_Header)
{
	uint16_t Checksum = DIY_ntohs(pIP_Header->CheckSum);
	uint16_t HeaderLen = 0, TempDebug = 0;
	uint16_t * pHeader = (uint16_t *)pIP_Header;
	uint32_t cksum = 0;
	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	HeaderLen = pIP_Header->U_VL.S_VL_ALL.HeaderLen * 4;
	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	pIP_Header->CheckSum = 0;

	while (HeaderLen > 1)
	{
		TempDebug = *pHeader++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		HeaderLen -= 2;
	}
	if (HeaderLen)
	{
		TempDebug = (*(uint8_t *)pHeader); TempDebug <<= 8;
		cksum += TempDebug;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	cksum = (uint16_t)(~cksum);

	return cksum;
}

/*
****************************************************
*  Function       : IP_AllowPacket
*  Description    : Pre process the packet ,including checksum and Version and DstIP
*  Params         : pIP_Header:IP header pointer
*  Return         : 
					IP_PacketPass:The packet need to further process
					IP_PacketDelete:Just ignore this packet
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--14--51--17
					in the future I will add some new feature.This is just a simple framework.
*****************************************************
*/
uint16_t prvIP_PreProcessPacket(IP_Header * pIP_Header)
{
	uint16_t Checksum = DIY_ntohs(pIP_Header->CheckSum);
	if (Checksum != prvIP_GetCheckSum(pIP_Header))return IP_PacketDelete;
	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	if (pIP_Header->U_VL.S_VL_ALL.Version != IP_VersionIPV4)return IP_PacketDelete;
	if (pIP_Header->DstIP.U32 == LocalIP.U32)return IP_PacketPass;
	if (pIP_Header->DstIP.U32 == BrocastIP.U32)return IP_PacketPass;
	return IP_PacketDelete;
}

/*
****************************************************
*  Function       : IP_ProcessPacket
*  Description    : Recv a network frame with IP protocol,This function will first check it,then give it to Upper layer.
*  Params         : pIP_Header:pointer of IP Header
*  Return         : Reserved
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--14--56--37
					Add a tunnel to UDP procotol
*****************************************************
*/
uint16_t IP_ProcessPacket(IP_Header * pIP_Header)
{
	if (prvIP_PreProcessPacket(pIP_Header) == IP_PacketPass)
	{
		switch (pIP_Header->U_TP.S_TP_ALL.Protocol)
		{
			case IP_Protocol_ICMP:/*ICMP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_IGMP:/*IGMP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_TCP:/*TCP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_UDP:
			{
				if (UDP_PreProcessPacket(pIP_Header) == RES_UDPPacketDeny)return RES_False;
				UDP_ProcessPacket((UDP_Header *)&pIP_Header->Buff); break; 
			}
			default:break;
		}
	}
	return 0;
}

/*
****************************************************
*  Function       : prvIP_FillPacket
*  Description    : Normally,A upper layer wants to send data,This function will be called to fill most attributes of IP protocol
*  Params         : pSocket:pointer of Socket
*  Return         : Reserved
*  Author         : -5A4A5943-
*  History        : 
					2017--04--27--15--01--46
					Just a simple successful implement,Will add new feature in the future.
*****************************************************
*/
uint16_t prvIP_FillPacket(Socket * pSocket)
{
	NeteworkBuff * pNeteworkBuff = pSocket->pNeteworkBuff;
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;

	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	pIP_Header->U_FO.U_FO_ALL = DIY_ntohs(pIP_Header->U_FO.U_FO_ALL);

	pIP_Header->U_VL.S_VL_ALL.Version = IP_VersionIPV4;
	pIP_Header->U_VL.S_VL_ALL.HeaderLen = IP_HeaderLen/4;
	pIP_Header->TOS = 0;
	pIP_Header->Identify = DIY_ntohs(8511);
	pIP_Header->U_FO.S_FO_ALL.Flags = 0;
	pIP_Header->U_FO.S_FO_ALL.Offset = 0;
	pIP_Header->U_TP.S_TP_ALL.TTL = IP_TTL_MAX;
	pIP_Header->DstIP.U32 = pSocket->addr.RemoteIP.U32;
	pIP_Header->SrcIP.U32 = pSocket->addr.LocalIP.U32;

	pIP_Header->U_VL.U_VL_ALL = DIY_ntohc(pIP_Header->U_VL.U_VL_ALL);
	pIP_Header->U_TP.U_TP_ALL = DIY_ntohs(pIP_Header->U_TP.U_TP_ALL);
	pIP_Header->U_FO.U_FO_ALL = DIY_ntohs(pIP_Header->U_FO.U_FO_ALL);

	pIP_Header->CheckSum = prvIP_GetCheckSum(pIP_Header);
	pIP_Header->CheckSum = DIY_htons(pIP_Header->CheckSum);
	return 0;
}

uint32_t DIY_GetIPAddress(void)
{
	return LocalIP.U32;
}

void DIY_SetIPAddress(uint32_t NewIP)
{
	LocalIP.U32 = NewIP;
}


