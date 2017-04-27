

#include "ARP.h"
#include "IP.h"
#include "Ethernet.h"

ARP_FCB ARP_FCB_MAIN = { 0x00 };

uint8_t ARP_Buff[24] = { 0x00 };

NeteworkBuff * pNeteworkBuffOnly4ARP = (NeteworkBuff*)ARP_Buff;

uint8_t ARP_Init(void)
{
	uint8_t i;
	memset((uint8_t*)&ARP_FCB_MAIN, NULL, sizeof(ARP_FCB_MAIN));
}

uint8_t ARP_GetIP_ByMAC(MAC * mac,IP * ip, uint8_t * IndexOfCache)
{
	uint8_t i,*Buf1,*Buf2;

	Buf2 = (uint8_t*)mac;

	for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&ARP_FCB_MAIN.Cache[i].MAC;

		if (ARP_FCB_MAIN.Cache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(MAC)) == 0)
		{
			if (ip != NULL)*ip = ARP_FCB_MAIN.Cache[i].IP;
			if (IndexOfCache != NULL)*IndexOfCache = i;
			return ARP_True;
		}
	}
	return ARP_False;
}

uint8_t ARP_GetMAC_ByIP(IP * ip,MAC * mac,uint8_t * IndexOfCache)
{
	uint8_t i, *Buf1, *Buf2;

	Buf2 = (uint8_t*)ip;

	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&ARP_FCB_MAIN.Cache[i].IP;

		if (ARP_FCB_MAIN.Cache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(IP)) == 0)
		{
			if (mac != NULL)*mac = ARP_FCB_MAIN.Cache[i].MAC;
			if (IndexOfCache != NULL)*IndexOfCache = i;
			return ARP_True;
		}
	}
	return ARP_False;
}

uint8_t ARP_AddItem(IP * ip, MAC * mac)
{
	uint8_t IndexOfCache = 0,i;

	if (ARP_GetMAC_ByIP(mac, NULL, &IndexOfCache) == ARP_True)
	{
		ARP_FCB_MAIN.Cache[IndexOfCache].TTL = ARP_TTL_MAX;
		return ARP_True;
	}
	else
	{
		for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
		{
			if (ARP_FCB_MAIN.Cache[i].Used == ARP_False)
			{
				ARP_FCB_MAIN.Cache[i].Used = ARP_True;
				memcpy((uint8_t*)&ARP_FCB_MAIN.Cache[i].IP, ip, sizeof(IP));
				memcpy((uint8_t*)&ARP_FCB_MAIN.Cache[i].MAC, mac, sizeof(MAC));
				ARP_FCB_MAIN.Cache[i].TTL = ARP_TTL_MAX;
				return ARP_True;
			}
		}
	}
	return ARP_False;
}

uint8_t ARP_TickTask(void)
{
	uint8_t i;
	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		if (ARP_FCB_MAIN.Cache[i].Used == ARP_True)
		{
			ARP_FCB_MAIN.Cache[i].TTL -= 1;
			if (ARP_FCB_MAIN.Cache[i].TTL <= 0)
			{
				ARP_FCB_MAIN.Cache[i].Used = ARP_False;
			}
		}
	}
}

uint16_t ARP_PreProcesspacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header*pEthernet_Header = (Ethernet_Header*)pNeteorkBuff->Buff;
	ARP_Header * pARP_Header = (ARP_Header*)&pEthernet_Header->Buff;

	ARP_FCB_MAIN.EthDst = pEthernet_Header->DstMAC;
	ARP_FCB_MAIN.EthSrc = pEthernet_Header->SrcMAC;

	if (pARP_Header->HardwareType == ARP_HardwareType && pARP_Header->HardwareLen == ARP_HardwareLen &&
		pARP_Header->ProtocolType == ARP_ProtocolType && pARP_Header->ProtocolLen == ARP_ProtocolLen)
	{
		return RES_ARPPacketPass;
	}
	return RES_ARPPacketDeny;
}

RES ARP_ProcessPacket(ARP_Header * pARP_Header)
{
	if (pARP_Header->HardwareType == ARP_HardwareType && pARP_Header->HardwareLen == ARP_HardwareLen &&
		pARP_Header->ProtocolType == ARP_ProtocolType && pARP_Header->ProtocolLen == ARP_ProtocolLen)
	{
		if (pARP_Header->Opcode == ARP_OpcodeRequest)
		{
			ARP_AddItem(&pARP_Header->SrcIP, &pARP_Header->SrcMAC);
			ARP_FillRespond(pARP_Header);
			return RES_ARPHasRespond;
		}
		if (pARP_Header->Opcode == ARP_OpcodeRespond)
		{
			ARP_AddItem(&pARP_Header->SrcIP, &pARP_Header->SrcMAC);
			return RES_ARPPacketProcessed;
		}
	}
	return RES_False;
}

uint8_t ARP_FillRespond(ARP_Header * pARP_Header)
{
	//Ethernet_Header * pEthernet_Header = (Ethernet_Header*)pNeteorkBuff->Buff;
	//ARP_Header * pARP_Header = (ARP_Header*)&pEthernet_Header->Buff;
	MAC TargetMac = { 0 };
	ARP_GetMAC_ByIP(&pARP_Header->SrcIP,&TargetMac,NULL);
	pARP_Header->DstIP.U32 = pARP_Header->SrcIP.U32;
	pARP_Header->DstMAC = TargetMac;
	pARP_Header->SrcIP.U32 = LocalIP.U32;
	pARP_Header->SrcMAC = LocalMAC;
	pARP_Header->HardwareLen = ARP_HardwareLen;
	pARP_Header->HardwareType = ARP_HardwareType;
	pARP_Header->Opcode = ARP_OpcodeRespond;
	pARP_Header->ProtocolLen = ARP_ProtocolLen;
	pARP_Header->ProtocolType = ARP_ProtocolType;
}

uint8_t ARP_SendRequest(NeteworkBuff * pNeteorkBuff,IP * TargetIP)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)pNeteorkBuff->Buff;
	ARP_Header * pARP_Header = (ARP_Header*)&pEth_Header->Buff;
	/* ETH »áÔÚµ×²ã½»»»*/
	memcpy((uint8_t*)&pEth_Header->SrcMAC, (uint8_t*)&BrocastMAC, sizeof(MAC));
	memcpy((uint8_t*)&pEth_Header->DstMAC, (uint8_t*)&LocalMAC, sizeof(MAC));
	/* ARP */
	memcpy((uint8_t*)&pARP_Header->DstIP, (uint8_t*)TargetIP, sizeof(IP));
	memcpy((uint8_t*)&pARP_Header->DstMAC, (uint8_t*)&ZeroMAC, sizeof(MAC));
	memcpy((uint8_t*)&pARP_Header->SrcIP, (uint8_t*)&LocalIP, sizeof(IP));
	memcpy((uint8_t*)&pARP_Header->SrcMAC, (uint8_t*)&LocalMAC, sizeof(MAC));
	pARP_Header->HardwareLen = ARP_HardwareLen;
	pARP_Header->HardwareType = ARP_HardwareType;
	pARP_Header->Opcode = ARP_OpcodeRequest;
	pARP_Header->ProtocolLen = ARP_ProtocolLen;
	pARP_Header->ProtocolType = ARP_ProtocolType;
	EthernetSend(pNeteorkBuff);
}


