
#include "Ethernet.h"
#include "IP.h"
#include "ARP.h"

/* 
	�������绺���е�Len����
	�ݶ�������ʱ�����ӡ�����ʱ�𼶼���

*/

NeteworkBuff NeteorkBuffTemp ={100,{0}};

uint16_t EthernetSend(NeteworkBuff * pNeteorkBuff)
{
	/* �˴�Ӧ����MAC��ַ�������¼���CRC */
	pNeteorkBuff->BuffLen += EthernetHeaderLen;
	pNeteorkBuff = pNeteorkBuff;
}

uint16_t EthernetRecv(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)pNeteorkBuff->Buff;

	if (EthernetFilter(pNeteorkBuff) == EthernetPacketPass)
	{
		if (pEth_Header->Type == EthernetType_ARP)
		{
			ARP_ProcessPacket(pNeteorkBuff);
		}
		if (pEth_Header->Type == EthernetType_IP)
		{
			IP_ProcessPacket(pNeteorkBuff);
		}
	}
}

uint16_t EthernetFilter(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)pNeteorkBuff->Buff;

	if (memcmp((uint8_t*)&pEth_Header->DstMAC,(uint8_t*)&LocalMAC,sizeof(MAC)) == 0)
	{
		return EthernetPacketPass;
	}
	else
	if (memcmp((uint8_t*)&pEth_Header->DstMAC, (uint8_t*)&BrocastMAC, sizeof(MAC)) == 0)
	{
		return EthernetPacketPass;
	}
	else
	{
		return EthernetPacketDelete;
	}
	return EthernetPacketDelete;
}












