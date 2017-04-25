
#include "DataTypeDef.h"
#include "IP.h"
#include "Ethernet.h"

MAC LocalMAC = {0x12,0x34,0x56,0x78,0x90,0xAB};
IP  LocalIP = {192,168,0,123};
MAC BrocastMAC = {0xFF,0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
MAC ZeroMAC = {0x00,0x00, 0x00, 0x00, 0x00, 0x00};
IP  BrocastIP = {192,168,0,255};

uint16_t IP_CheckSum(IP_Header * pIP_Header)
{
	return IP_PacketPass;
}

uint16_t IP_AllowPacket(IP_Header * pIP_Header)
{
	if(IP_CheckSum(pIP_Header) == IP_PacketDelete)return IP_PacketDelete;
	if (pIP_Header->Version != IP_VersionIPV4)return IP_PacketDelete;
	if (memcmp((uint8_t*)&pIP_Header->DstIP, (uint8_t*)&LocalIP, sizeof(IP) == 0))return IP_PacketPass;
	if (memcmp((uint8_t*)&pIP_Header->DstIP, (uint8_t*)&BrocastIP, sizeof(IP) == 0))return IP_PacketPass;
	return IP_PacketDelete;
}

uint16_t IP_ProcessPacket(NeteworkBuff * pNeteworkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)pEthernet_Header->Buff;

	if (IP_AllowPacket(pIP_Header) == IP_PacketPass)
	{
		switch (pIP_Header->Protocol)
		{
			case IP_Protocol_ICMP:/*ICMP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_IGMP:/*IGMP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_TCP:/*TCP_ProcessPacket(pNeteworkBuff); */break;
			case IP_Protocol_UDP:/*UDP_ProcessPacket(pNeteworkBuff); */break;
			default:break;
		}
	}
}

uint16_t IP_GeneratePacket(NeteworkBuff * pNeteworkBuff,uint8_t Protocol,uint32_t SrcIP,uint32_t DstIP)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)pNeteworkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)pEthernet_Header->Buff;

	pIP_Header->Version = IP_VersionIPV4;
	pIP_Header->HeaderLen = 5;
	pIP_Header->TOS = 0;
	pIP_Header->TotalLen = 0;
	//need to calculate,Need to know the upper protocol
	pIP_Header->Identify = 0;
	pIP_Header->Flags = 0;
	pIP_Header->Offset = 0;
	pIP_Header->TTL = IP_TTL_MAX;
	pIP_Header->Protocol = Protocol;
	pIP_Header->CRC = 0;//Need to calculate
	pIP_Header->DstIP.U32 = DstIP;
	pIP_Header->SrcIP.U32 = SrcIP;
}

uint32_t DIY_GetIPAddress(void)
{
	return LocalIP.U32;
}

void DIY_SetIPAddress(uint32_t NewIP)
{
	LocalIP.U32 = NewIP;
}


