
#include "Ethernet.h"
#include "IP.h"
#include "ARP.h"
#include "Basic.h"
#include "TCP_Task.h"

/*
关于网络缓存中的Len属性
暂定：发送时逐级增加。接收时逐级减少
我们假设硬件自动计算以太网的CRC以及前导字段
何时动用字序（数据类型转换，非原子操作）
*/

uint8_t DebugBuff[2048] = { 0x00 };

/*
****************************************************
*  Function       : EthernetDeriverSend
*  Description    : ethernet lowest layer send data
*  Params         : pointer of pNeteorkBuff
*  Return         : Reserved
*  Author         : -5A4A5943-
*  History        :
*****************************************************
*/
static void PHY_Ethernet_DriverSend(uint8_t * Data,uint32_t Len)
{
	//memset(DebugBuff, 0x00, Len);
	//memcpy(DebugBuff, Data, Len);
	uint16_t i = 0;
	for (i = 0; i < Len; i++)
	{
		if (i % 8 == 0)printf("\r\n");
		printf("%02X ", Data[i]);
	}
}

static void PHY_Ethernet_DriverRecv(uint8_t * Data,uint32_t Len)
{
	NeteworkBuff * pNeteworkBuff = Network_New(NetworkBuffDirRx, Len);
	memcpy((uint8_t*)&pNeteworkBuff->Buff, Data, Len);
	pNeteworkBuff->Ready = True;
	tcb.Ethernet_Rx_Packet += 1;
}

void Ethernet_SendNetworkBuff(NeteworkBuff * pNeteorkBuff)
{
	if (pNeteorkBuff == NULL)return;
	PHY_Ethernet_DriverSend((uint8_t*)&pNeteorkBuff->Buff, pNeteorkBuff->BuffLen);
}

void Ethernet_TransmitPacket(NeteworkBuff * pNeteorkBuff)
{
	/* Has already add to header TX,But the ready flag is not true,Now set it to true */
	if (pNeteorkBuff == NULL)return;
	pNeteorkBuff->Ready = True;
	tcb.Ethernet_Tx_Packet += 1;
}

void Ethernet_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = 0x00; 
	RES res = RES_True;

	if (pNeteorkBuff == NULL)return RES_False;

	pEth_Header = (Ethernet_Header*)pNeteorkBuff->Buff;;
	/* 硬件自动计算CRC */
	if (prvEthernetFilter(pNeteorkBuff) == RES_EthernetPacketPass)
	{
		if (pEth_Header->Type == DIY_ntohs(EthernetType_ARP))
		{
			ARP_ProcessPacket(pNeteorkBuff);
		}
		if (pEth_Header->Type == DIY_ntohs(EthernetType_IP))
		{
			IP_ProcessPacket(pNeteorkBuff);
		}
	}
}

static RES prvEthernetFilter(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEth_Header = (Ethernet_Header*)pNeteorkBuff->Buff;

	if (memcmp((uint8_t*)&pEth_Header->DstMAC,(uint8_t*)&LocalMAC,sizeof(MAC)) == 0)
	{
		return RES_EthernetPacketPass;
	}
	else
	if (memcmp((uint8_t*)&pEth_Header->DstMAC, (uint8_t*)&BrocastMAC, sizeof(MAC)) == 0)
	{
		return RES_EthernetPacketPass;
	}
	else
	{
		return RES_EthernetPacketDeny;
	}
	return RES_EthernetPacketDeny;
}

void Ethernet_FillPacket(NeteworkBuff * pNeteorkBuff, uint32_t Protocol, IP * RemoteIP)
{
	MAC DstMAC = { 0x00 };
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;

	ARP_GetMAC_ByIP(RemoteIP, &DstMAC, NULL,NULL);
	pEthernet_Header->SrcMAC = LocalMAC;
	pEthernet_Header->DstMAC = DstMAC;
	pEthernet_Header->Type = DIY_htons(Protocol);
}










