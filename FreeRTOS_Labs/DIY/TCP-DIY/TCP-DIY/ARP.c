

#include "ARP.h"
#include "IP.h"
#include "Ethernet.h"

ARP_Cache ArpCache[ARP_CACHE_CAPACITY] = { 0x00 };

uint8_t ARP_Init(void)
{
	uint8_t i;
	memset((uint8_t*)&ArpCache, NULL, sizeof(ArpCache));
}

uint8_t ARP_GetIP_ByMAC(MAC * mac,IP * ip, uint8_t * IndexOfCache)
{
	uint8_t i,*Buf1,*Buf2;

	Buf2 = (uint8_t*)mac;

	for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&ArpCache[i].MAC;

		if (ArpCache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(MAC)) == 0)
		{
			if (ip != NULL)*ip = ArpCache[i].IP;
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
		Buf1 = (uint8_t*)&ArpCache[i].IP;

		if (ArpCache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(IP)) == 0)
		{
			if (mac != NULL)*mac = ArpCache[i].MAC;
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
		ArpCache[IndexOfCache].TTL = ARP_TTL_MAX;
		return ARP_True;
	}
	else
	{
		for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
		{
			if (ArpCache[i].Used == ARP_False)
			{
				ArpCache[i].Used = ARP_True;
				memcpy((uint8_t*)&ArpCache[i].IP, ip, sizeof(IP));
				memcpy((uint8_t*)&ArpCache[i].MAC, mac, sizeof(MAC));
				ArpCache[i].TTL = ARP_TTL_MAX;
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
		if (ArpCache[i].Used == ARP_True)
		{
			ArpCache[i].TTL -= 1;
			if (ArpCache[i].TTL <= 0)
			{
				ArpCache[i].Used = ARP_False;
			}
		}
	}
}

uint8_t ARP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	ARP_Header * pARP_Header = (ARP_Header *)pNeteorkBuff->Buff;

	if (pARP_Header->HardwareType == ARP_HardwareType && pARP_Header->HardwareLen == ARP_HardwareLen &&
		pARP_Header->ProtocolType == ARP_ProtocolType && pARP_Header->ProtocolLen == ARP_ProtocolLen)
	{
		if (pARP_Header->Opcode == ARP_OpcodeRequest)
		{
			memcpy((uint8_t*)&pARP_Header->DstIP, (uint8_t*)&pARP_Header->SrcIP,sizeof(IP));
			memcpy((uint8_t*)&pARP_Header->DstMAC, (uint8_t*)&pARP_Header->SrcMAC, sizeof(MAC));
			memcpy((uint8_t*)&pARP_Header->SrcIP, (uint8_t*)&LocalIP, sizeof(IP));
			memcpy((uint8_t*)&pARP_Header->SrcMAC, (uint8_t*)&LocalMAC, sizeof(MAC));
			pARP_Header->Opcode = ARP_OpcodeRespond;
			pNeteorkBuff->BuffLen = ARP_HeaderLen;
			EthernetSend(pNeteorkBuff);
		}
		if (pARP_Header->Opcode == ARP_OpcodeRespond)
		{
			ARP_AddItem(&pARP_Header->SrcIP, &pARP_Header->SrcMAC);
		}
	}
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


