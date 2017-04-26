
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

MAC LocalMAC = { 0x0c,0x12,0x62,0xb8,0x5a,0x98 };
IP  LocalIP = {1,2,3,4};
MAC BrocastMAC = {0xFF,0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
MAC ZeroMAC = {0x00,0x00, 0x00, 0x00, 0x00, 0x00};
IP  BrocastIP = {192,168,0,255};

uint16_t IP_CheckSum(IP_Header * pIP_Header)
{
	return IP_PacketPass;
}

uint16_t IP_AllowPacket(IP_Header * pIP_Header)
{
	if (IP_CheckSum(pIP_Header) == IP_PacketDelete)return IP_PacketDelete;

	pIP_Header->VLT.U16 = DIY_ntohs(pIP_Header->VLT.U16);
	pIP_Header->TP.U16 = DIY_ntohs(pIP_Header->TP.U16);
	if (pIP_Header->VLT.Version != IP_VersionIPV4)return IP_PacketDelete;
	if (pIP_Header->DstIP.U32 == LocalIP.U32)return IP_PacketPass;
	if (pIP_Header->DstIP.U32 == BrocastIP.U32)return IP_PacketPass;
	return IP_PacketDelete;
}

uint16_t IP_ProcessPacket(IP_Header * pIP_Header)
{
	if (IP_AllowPacket(pIP_Header) == IP_PacketPass)
	{
		switch (pIP_Header->TP.Protocol)
		{
			case IP_Protocol_ICMP:/*ICMP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_IGMP:/*IGMP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_TCP:/*TCP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_UDP:UDP_ProcessPacket((UDP_Header *)&pIP_Header->Buff); break;
			default:break;
		}
	}
}

uint16_t IP_FillPacket(Socket * pSocket)
{
	NeteworkBuff * pNeteworkBuff = pSocket->pNeteworkBuff;
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)pEthernet_Header->Buff;
	UDP_Header * pUDP_Header;
	TCP_Header * pTCP_Header;

	//pIP_Header->Version = IP_VersionIPV4;
	//pIP_Header->HeaderLen = IP_HeaderLen/4;
	//pIP_Header->TOS = 0;
	//pIP_Header->Identify = 0;
	//pIP_Header->Flags = 0;
	//pIP_Header->Offset = 0;
	//pIP_Header->TTL = IP_TTL_MAX;
	pIP_Header->DstIP.U32 = pSocket->addr.RemoteIP.U32;
	pIP_Header->SrcIP.U32 = pSocket->addr.LocalIP.U32;
	//switch (pIP_Header->Protocol)
	//{
	//	case IP_Protocol_UDP:
	//	{
	//		pUDP_Header = (UDP_Header*)pIP_Header->Buff;
	//		pIP_Header->TotalLen = pUDP_Header->DataLen + IP_HeaderLen + UDP_HEADE_LEN;
	//		prvIP_GenerateCheckSum(pIP_Header);
	//		break;
	//	}
	//}
}

uint16_t prvIP_GenerateCheckSum(IP_Header * pIP_Header)
{
	pIP_Header->CheckSum = 0;
	//pIP_Header->CheckSum = prvGetCheckSum((uint16_t*)pIP_Header, pIP_Header->HeaderLen / 2);
}

uint32_t DIY_GetIPAddress(void)
{
	return LocalIP.U32;
}

void DIY_SetIPAddress(uint32_t NewIP)
{
	LocalIP.U32 = NewIP;
}


