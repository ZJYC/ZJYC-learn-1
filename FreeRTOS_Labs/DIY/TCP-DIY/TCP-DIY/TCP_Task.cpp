
#include "TCP_Task.h"
#include "NetworkBuff.h"
#include "Ethernet.h"
TCB tcb = { 0x00 };

void MainLoop(void)
{
	while (True)
	{
		if (tcb.Ethernet_Rx_Packet)
		{
			NeteworkBuff * pNeteworkBuff = Network_GetOne(NetworkBuffDirRx);
			Ethernet_ProcessPacket(pNeteworkBuff);
			Network_Del(pNeteworkBuff);
			tcb.Ethernet_Rx_Packet -= 1;
		}
		if (tcb.Ethernet_Tx_Packet)
		{
			NeteworkBuff * pNeteworkBuff = Network_GetOne(NetworkBuffDirTx);
			Ethernet_SendNetworkBuff(pNeteworkBuff);
			Network_Del(pNeteworkBuff);
			tcb.Ethernet_Tx_Packet -= 1;
		}
	}
}




















