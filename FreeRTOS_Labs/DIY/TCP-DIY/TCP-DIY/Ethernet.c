
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
/*
NeteworkBuff NeteorkBuffOnly4Eth ={ 
	0x2d,
	{ 0x0c,0x12,0x62,0xb8,0x5a,0x98,0x90,0x2b,0x34,0xce,0xc9,0x02,0x08,0x00,0x45,0x00,0x00,0x1f,0x21,0x3f,0x00,0x00,0x40,0x11,0x1c,0xa0,0xc0,0xa8,0x78,0x41,0x01,0x02,0x03,0x04,0x16,0x2e,0x04,0xd2,0x00,0x0b,0x43,0xb6,0x31,0x32,0x33, }
};
*/
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
	Data = Data;
	Len = Len;
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
	ARP_Header * pARP_Header;
	IP_Header * pIP_Header;
	RES res = RES_True;

	if (pNeteorkBuff == NULL)return RES_False;

	pEth_Header = (Ethernet_Header*)pNeteorkBuff->Buff;;
	/* 硬件自动计算CRC */
	if (prvEthernetFilter(pNeteorkBuff) == RES_EthernetPacketPass)
	{
		if (pEth_Header->Type == DIY_ntohs(EthernetType_ARP))
		{
			pARP_Header = (ARP_Header*)&pEth_Header->Buff;
			ARP_ProcessPacket(pARP_Header);
		}
		if (pEth_Header->Type == DIY_ntohs(EthernetType_IP))
		{
			pIP_Header = (IP_Header*)&pEth_Header->Buff;
			IP_ProcessPacket(pIP_Header);
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












