
#include "IP.h"
#include "Ethernet.h"
#include "TCP.h"
#include "TCP_WIN.h"

/* 
	API应包括以下功能
	选项字段X
	校验X
	找到数据头X

	检查选项字段
	自身状态机制

*/

uint8_t TCP_OptionBuff[32] = { 0x00 };

uint8_t DebugBuffXX[] ={
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x08, 0x00, 0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x66, 0xb8, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x1e, 0xd2, 0x04, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x4e, 0x22, 0x00, 0x00, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
};
NeteworkBuff * DebugNeteworkBuff = (NeteworkBuff*)DebugBuffXX;

static uint32_t prvTCP_GetRandom(void)
{
	return 0;
}

static uint16_t prvTCP_GetCheckSum(uint16_t * PseudoHeader, uint16_t PseudoLenBytes, uint16_t*Data, uint32_t DataLenBytes)
{
	uint32_t cksum = 0;
	uint16_t TempDebug = 0;
	while (PseudoLenBytes)
	{
		TempDebug = *PseudoHeader++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		PseudoLenBytes -= 2;
	}
	while (DataLenBytes > 1)
	{
		TempDebug = *Data++; TempDebug = DIY_ntohs(TempDebug);
		cksum += TempDebug;
		DataLenBytes -= 2;
	}
	if (DataLenBytes)
	{
		TempDebug = (*(uint8_t *)Data); TempDebug <<= 8;
		cksum += TempDebug;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	return (uint16_t)(~cksum);
}

static RES TCP_PreProcessPacket(NeteworkBuff * pNeteorkBuff, Socket ** pSocket, TCP_Header ** pTCP_Header)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	*pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	uint32_t PseudoHeader[3] = { 0x00 };
	uint16_t PayloadLen = 0, CheckSum = 0, CheckTemp = 0;
	*pSocket = Socket_GetSocketByPort(DIY_ntohs((*pTCP_Header)->DstPort));
	if (*pSocket == NULL)return RES_TCPPacketDeny;

	CheckSum = DIY_ntohs((*pTCP_Header)->CheckSum);
	(*pTCP_Header)->CheckSum = 0;
	PayloadLen = DIY_ntohs(pIP_Header->TotalLen) - IP_HeaderLen;
	PseudoHeader[0] = pIP_Header->SrcIP.U32;
	PseudoHeader[1] = pIP_Header->DstIP.U32;
	PseudoHeader[2] = IP_Protocol_TCP << 16 | PayloadLen;
	PseudoHeader[2] = DIY_ntohl(PseudoHeader[2]);
	CheckTemp = prvTCP_GetCheckSum((uint16_t*)PseudoHeader, 12, (uint16_t*)pTCP_Header, PayloadLen);
	if (CheckTemp != CheckSum)return RES_TCPPacketDeny;
	if ((*pSocket)->pTCP_Control->ActiveSYN)
	{
		if ((*pTCP_Header)->AK != (*pSocket)->pTCP_Control->AK_Except)return RES_TCPPacketDeny;
	}
	return RES_TCPPacketPass;
}

static void prvGetDataBuff(NeteworkBuff * pNeteorkBuff,uint8_t ** Buff,uint16_t * Len)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint16_t IP_TotalLen = DIY_ntohs(pIP_Header->TotalLen);
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF)/4;
	if(Len)*Len = IP_TotalLen - TCP_HeaderLen - IP_HeaderLen;
	if(Buff)*Buff = (uint8_t*)((uint32_t)pTCP_Header + TCP_HeaderLen);
}

static void prvGetOptionBuff(NeteworkBuff * pNeteorkBuff, uint8_t ** Buff, uint16_t * Len)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint16_t IP_TotalLen = DIY_ntohs(pIP_Header->TotalLen);
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF)/4;
	if(Len)*Len = TCP_HeaderLen - TCP_HEADE_LEN_MIN;
	*Buff = (uint8_t*)((uint32_t)pTCP_Header + TCP_HEADE_LEN_MIN);
}

static void prvTCP_ProcessOption(TCP_Control * pTCP_Control, uint8_t * Option, uint16_t Len)
{
	uint16_t i = 0,LenTemp = 0;
	uint32_t Value = 0;
	for (i = 0; i < Len;)
	{
		if (*Option == TOK_MSS)
		{
			LenTemp = *(Option + 1);
			Value = *(Option + 2) << 8 + *(Option + 3);
			pTCP_Control->RemoteMSS = Value;
			Option += LenTemp;
			i += LenTemp;
		}
		if (*Option == TOK_WSOPT)
		{
			LenTemp = *(Option + 1);
			Value = *(Option + 2);
			pTCP_Control->RemoteWinScale = Value;
			Option += LenTemp;
			i += LenTemp;
		}
		if (*Option == TOK_NOP)
		{
			Option += 1;
			i += LenTemp;
		}
		if (*Option == TOK_NOP)
		{
			break;
		}
	}
}

static void prvTCP_Handle_Established(TCP_Control * pTCP_Control)
{

	if (pTCP_Control->pTCP_Win == 0)
	{
		pTCP_Control->pTCP_Win = prvTCPWin_NewWindows(pTCP_Control->LocalWinSize, pTCP_Control->RemoteWinSize);
		pTCP_Control->pTCP_Win->MSS = pTCP_Control->RemoteMSS;
		pTCP_Control->pTCP_Win->Sn = pTCP_Control->LocalSN;
	}
	else
	{

	}
}

static void prvTCP_Handle_SYN_Recv(TCP_Control * pTCP_Control, NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint8_t * Option = 0;
	uint16_t OptionLen = 0;
	pTCP_Control->RemoteSN = pTCP_Header->SN;
	pTCP_Control->RemoteWinSize = pTCP_Header->WinSize;

	prvGetOptionBuff(pNeteorkBuff, &Option, &OptionLen);
	prvTCP_ProcessOption(pTCP_Control, Option, OptionLen);
	//send SYN+ACK
	prvTCP_FillPacket(pTCP_Control, 0, 0);
}

static uint32_t prvTCP_ProcessSN_ACK_Num(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->DstPort));
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;

	if (pTCP_Control->State >= TCP_STATE_ESTABLISHED)
	{
		if (pTCP_Control->LocalSN != pTCP_Header->AK)
		{
			if (pTCP_Control->LocalSN + 1 != pTCP_Header->AK)return;
		}
		pTCP_Control->RemoteSN = pTCP_Header->SN;
	}
	else
	{

	}
}

uint32_t TCP_GetOptionSize(TCP_Control * pTCP_Control)
{
	uint32_t OptionSize = 0;

	if (pTCP_Control->MSS_Send == 0 || pTCP_Control->MSS_Change)
	{
		//pTCP_Control->MSS_Send = 1;
		//pTCP_Control->MSS_Change = 0;
		OptionSize += 4;
	}
	if (pTCP_Control->WIN_Sent == 0 || pTCP_Control->WIN_Change)
	{
		//pTCP_Control->WIN_Sent = 1;
		//pTCP_Control->WIN_Change = 0;
		OptionSize += 4;
	}
	if (pTCP_Control->TSOPT)OptionSize += 10;

}

uint32_t TCP_GetPacketSize(TCP_Control * pTCP_Control,uint32_t DataLen)
{
	uint32_t Len = TCP_GetOptionSize(pTCP_Control);
	Len += EthernetHeaderLen + IP_HeaderLen + IP_GetOptionSize() + DataLen;
	return Len;
}

static void prvTCP_FillEtc(NeteworkBuff * pNeteorkBuff)
{
	/* 包括窗口大小，标志，ACK号，SN号 */
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->SrcPort));
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;

	pTCP_Header->AK = pTCP_Control->RemoteSN;
	pTCP_Header->SN = pTCP_Control->LocalSN;
	pTCP_Header->Urgent = 0;
	pTCP_Header->WinSize = pTCP_Control->LocalWinSize;

	switch (pTCP_Control->State)
	{
		case TCP_STATE_CLOSED:
		{
			if (pTCP_Control->ActiveSYN)
			{
				 pTCP_Header->Flags |= TCP_FLAG_SYN;
			}
			break;
		}
		case TCP_STATE_SYN_RECV:
		{
			pTCP_Header->Flags |= TCP_FLAG_SYN | TCP_FLAG_ACK;
			break;
		}
		case TCP_STATE_SYN_SENT:
		{
			if (pTCP_Control->ActiveSYN)pTCP_Header->Flags |= TCP_FLAG_ACK;
			break;
		}
		case TCP_STATE_ESTABLISHED:
		{
			uint32_t DataLen = 0;
			pTCP_Header->Flags |= TCP_FLAG_ACK;
			prvGetDataBuff(pNeteorkBuff, 0, &DataLen);
			if(DataLen)pTCP_Header->Flags |= TCP_FLAG_PSH;
			break;
		}
		default:break;
	}

	//pTCP_Header->Flags |= Flags;
	//pTCP_Header->AK = RemoteSN;
}

static void prvTCP_FillOption(NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	Socket * pSocket = Socket_GetSocketByPort(DIY_ntohs((pTCP_Header)->SrcPort));
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;
	uint8_t * pOption = 0, OptionLen = 0;

	prvGetOptionBuff(pNeteorkBuff, &pOption, 0);
	if (pTCP_Control->MSS_Send == NULL || pTCP_Control->MSS_Change)
	{
		pTCP_Control->MSS_Send = 1;
		pTCP_Control->MSS_Change = 0;
		pOption[OptionLen + 0] = (uint8_t)TOK_MSS;
		pOption[OptionLen + 1] = 4;
		pOption[OptionLen + 2] = pTCP_Control->LocalMSS / 256;
		pOption[OptionLen + 3] = pTCP_Control->LocalMSS % 256;
		OptionLen += 4;
	}
	if (pTCP_Control->WIN_Sent == NULL || pTCP_Control->WIN_Change)
	{
		pTCP_Control->WIN_Sent = 1;
		pTCP_Control->WIN_Change = 0;
		pOption[OptionLen + 0] = (uint8_t)TOK_WSOPT;
		pOption[OptionLen + 1] = 3;
		pOption[OptionLen + 2] = pTCP_Control->LocalWinScale;
		pOption[OptionLen + 3] = TOK_NOP;
		OptionLen += 4;
	}
	/* 以后再加吧 */
}

static void prvTCP_FillData(NeteworkBuff * pNeteorkBuff,uint8_t * Data,uint32_t Len)
{
	uint8_t * Buff = 0;
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	prvGetDataBuff(pNeteorkBuff, &Buff, 0);
	memcpy(Buff, Data, Len);
	if (Len)pTCP_Header->Flags |= TCP_FLAG_PSH;
}

void TCP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Socket * pSocket = 0;
	TCP_Header * pTCP_Header = 0;
	TCP_Control * pTCP_Control = 0;
	if (pNeteorkBuff == NULL)return;
	if (TCP_PreProcessPacket(pNeteorkBuff, &pSocket, &pTCP_Header) != RES_TCPPacketPass)return;
	pTCP_Control = pSocket->pTCP_Control;
	uint8_t Flags = pTCP_Header->Flags;

	switch (pTCP_Control->State)
	{
		case TCP_STATE_LISTEN:
		{
			if (Flags & TCP_FLAG_SYN)
			{
				 prvTCP_Handle_SYN_Recv(pSocket, pNeteorkBuff);
				 pTCP_Control->State = TCP_STATE_SYN_SENT;
			}
			break;
		}
		case TCP_STATE_SYN_SENT:
		{
			if (pTCP_Control->ActiveSYN && Flags & TCP_FLAG_ACK && Flags & TCP_FLAG_SYN)
			{
			   //Handle_SYN_ACK()
			}
			if (!pTCP_Control->ActiveSYN && Flags & TCP_FLAG_ACK)
			{
			   pTCP_Control->State = TCP_STATE_ESTABLISHED;
			}
			break;
		};
		case TCP_STATE_ESTABLISHED:
		{
			prvTCP_Handle_Established(pSocket);
			break;
		}
		default:break;
	};
}

void prvTCP_FillPacket(TCP_Control * pTCP_Control, uint8_t * Data, uint32_t DataLen)
{
	NeteworkBuff * pNeteorkBuff = Network_New(NetworkBuffDirTx, TCP_GetPacketSize(pTCP_Control, DataLen));
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	pTCP_Header->SrcPort = pTCP_Control->LocalPort;
	pTCP_Header->DstPort = pTCP_Control->RemotePort;
	pTCP_Header->HeaderLen = TCP_GetOptionSize(pTCP_Control) + DataLen + TCP_HEADE_LEN_MIN;

	/* 如下需要保证顺序可靠 */
	prvTCP_FillOption(pNeteorkBuff);
	prvTCP_FillData(pNeteorkBuff, Data, DataLen);
	prvTCP_FillHeader(pNeteorkBuff);
	/* IP */
	prvIP_FillPacket(pNeteorkBuff, &pTCP_Control->RemoteIP, IP_Protocol_TCP);
	Ethernet_TransmitPacket(pNeteorkBuff);
}

void TCP_Connect(TCP_Control * pTCP_Control)
{
	pTCP_Control->ActiveSYN = 1;
	prvTCP_FillPacket(pTCP_Control,0,0);
	pTCP_Control->State = TCP_STATE_SYN_SENT;
}

