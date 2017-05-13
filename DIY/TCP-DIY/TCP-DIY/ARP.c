

#include "ARP.h"
#include "IP.h"
#include "Ethernet.h"
#include "heap_5.h"

ARP_Cache * pARP_Cache = 0x00;

void ARP_Init(void)
{
	uint8_t i;
	pARP_Cache = (ARP_Cache*)MM_Ops.Malloc(sizeof(ARP_Cache) * ARP_CACHE_CAPACITY);
	if (pARP_Cache != NULL)memset((uint8_t*)pARP_Cache,0x00, sizeof(ARP_Cache) * ARP_CACHE_CAPACITY);
}

uint8_t ARP_GetIP_ByMAC(MAC * mac,IP * ip, uint8_t * IndexOfCache)
{
	uint8_t i,*Buf1,*Buf2;

	Buf2 = (uint8_t*)mac;

	for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&pARP_Cache[i].MAC;

		if (pARP_Cache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(MAC)) == 0)
		{
			if (ip != NULL)*ip = pARP_Cache[i].IP;
			if (IndexOfCache != NULL)*IndexOfCache = i;
			return ARP_True;
		}
	}
	return ARP_False;
}

uint8_t ARP_GetMAC_ByIP(IP * ip, MAC * mac, uint8_t * IndexOfCache, uint8_t SendRequest)
{
	uint8_t i, *Buf1, *Buf2;

	Buf2 = (uint8_t*)ip;

	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&pARP_Cache[i].IP;

		if (pARP_Cache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(IP)) == 0)
		{
			if (mac != NULL)*mac = pARP_Cache[i].MAC;
			if (IndexOfCache != NULL)*IndexOfCache = i;
			return ARP_True;
		}
	}
	if (SendRequest != NULL)ARP_SendRequest(ip);
	return ARP_False;
}

void ARP_AddItem(IP * ip, MAC * mac)
{
	uint8_t IndexOfCache = 0,i;

	if (ARP_GetMAC_ByIP(mac, NULL, &IndexOfCache,NULL) == ARP_True)
	{
		pARP_Cache[IndexOfCache].TTL = ARP_TTL_MAX;
	}
	else
	{
		for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
		{
			if (pARP_Cache[i].Used == ARP_False)
			{
				pARP_Cache[i].Used = ARP_True;
				memcpy((uint8_t*)&pARP_Cache[i].IP, ip, sizeof(IP));
				memcpy((uint8_t*)&pARP_Cache[i].MAC, mac, sizeof(MAC));
				pARP_Cache[i].TTL = ARP_TTL_MAX;
				return;
			}
		}
	}
}

void ARP_TickTask(void)
{
	uint8_t i;
	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		if (pARP_Cache[i].Used == ARP_True)
		{
			pARP_Cache[i].TTL -= 1;
			if (pARP_Cache[i].TTL <= 0)
			{
				pARP_Cache[i].Used = ARP_False;
			}
			if (pARP_Cache[i].TTL <= ARP_TTL_MAX / 2)
			{
				ARP_SendRequest(&pARP_Cache[i].IP);
			}
		}
	}
}

static RES prvARP_PreProcesspacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header*pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	ARP_Header * pARP_Header = (ARP_Header*)&pEthernet_Header->Buff;

	if (pARP_Header->HardwareType == ARP_HardwareType && pARP_Header->HardwareLen == ARP_HardwareLen &&
		pARP_Header->ProtocolType == ARP_ProtocolType && pARP_Header->ProtocolLen == ARP_ProtocolLen)
	{
		return RES_ARPPacketPass;
	}
	return RES_ARPPacketDeny;
}

static void ARP_SendRespon(NeteworkBuff * pOldNeteorkBuff)
{
	Ethernet_Header * pOldEthernet_Header = (Ethernet_Header*)&pOldNeteorkBuff->Buff;
	ARP_Header * pOldARP_Header = (ARP_Header*)&pOldEthernet_Header->Buff;

	NeteworkBuff * pNewNeteworkBuff = Network_New(NetworkBuffDirTx, EthernetHeaderLen + ARP_HeaderLen);

	Ethernet_Header * pNewEthernet_Header = (Ethernet_Header*)&pNewNeteworkBuff->Buff;
	ARP_Header * pNewARP_Header = (ARP_Header*)&pNewEthernet_Header->Buff;
	/* ETH */
	pNewEthernet_Header->DstMAC = pOldEthernet_Header->SrcMAC;
	pNewEthernet_Header->SrcMAC = pOldEthernet_Header->DstMAC;
	pNewEthernet_Header->Type = EthernetType_ARP;
	/* ARP */
	pNewARP_Header->DstIP.U32 = pOldARP_Header->SrcIP.U32;
	pNewARP_Header->DstMAC = pOldARP_Header->SrcMAC;
	pNewARP_Header->SrcIP.U32 = LocalIP.U32;
	pNewARP_Header->SrcMAC = LocalMAC;
	pNewARP_Header->HardwareLen = ARP_HardwareLen;
	pNewARP_Header->HardwareType = ARP_HardwareType;
	pNewARP_Header->Opcode = ARP_OpcodeRespond;
	pNewARP_Header->ProtocolLen = ARP_ProtocolLen;
	pNewARP_Header->ProtocolType = ARP_ProtocolType;
	/* TX */
	Ethernet_TransmitPacket(pNewNeteworkBuff);
}

void ARP_SendRequest(IP * TargetIP)
{
	NeteworkBuff * pNewNeteworkBuff = Network_New(NetworkBuffDirTx, EthernetHeaderLen + ARP_HeaderLen);
	Ethernet_Header * pNewEthernet_Header = (Ethernet_Header*)&pNewNeteworkBuff->Buff;
	ARP_Header * pNewARP_Header = (ARP_Header*)&pNewEthernet_Header->Buff;
	/* ETH */
	pNewEthernet_Header->DstMAC = BrocastMAC;
	pNewEthernet_Header->SrcMAC = LocalMAC;
	pNewEthernet_Header->Type = EthernetType_ARP;
	/* ARP */
	pNewARP_Header->DstIP.U32 = TargetIP->U32;
	pNewARP_Header->DstMAC = ZeroMAC;
	pNewARP_Header->SrcIP.U32 = LocalIP.U32;
	pNewARP_Header->SrcMAC = LocalMAC;
	pNewARP_Header->HardwareLen = ARP_HardwareLen;
	pNewARP_Header->HardwareType = ARP_HardwareType;
	pNewARP_Header->Opcode = ARP_OpcodeRequest;
	pNewARP_Header->ProtocolLen = ARP_ProtocolLen;
	pNewARP_Header->ProtocolType = ARP_ProtocolType;
	/* TX */
	Ethernet_TransmitPacket(pNewNeteworkBuff);
}

void ARP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header*pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	ARP_Header * pARP_Header = (ARP_Header*)&pEthernet_Header->Buff;

	if (prvARP_PreProcesspacket(pNeteorkBuff) != RES_ARPPacketPass)return;

	if (pARP_Header->Opcode == ARP_OpcodeRequest)
	{
		ARP_AddItem(&pARP_Header->SrcIP, &pARP_Header->SrcMAC);
		ARP_SendRespon(pNeteorkBuff);
	}
	if (pARP_Header->Opcode == ARP_OpcodeRespond)
	{
		ARP_AddItem(&pARP_Header->SrcIP, &pARP_Header->SrcMAC);
	}
}

