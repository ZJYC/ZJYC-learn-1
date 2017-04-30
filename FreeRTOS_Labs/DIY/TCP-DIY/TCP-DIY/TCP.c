
#include "IP.h"
#include "Ethernet.h"
#include "TCP.h"
/* 
	API应包括以下功能
	选项字段X
	校验X
	找到数据头X

	检查选项字段
	自身状态机制

*/

uint8_t TCP_OptionBuff[32] = { 0x00 };

uint8_t DebugBuffXX[] =
{
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

void prvTCP_GeneratePacket(Socket * pSocket,uint8_t * Data, uint32_t DataLen)
{
	uint16_t OptionLen = 0;
	NeteworkBuff * pNeteorkBuff;
	Ethernet_Header * pEthernet_Header;
	IP_Header * pIP_Header;
	TCP_Header * pTCP_Header;

	prvTCP_GenerateOption(pSocket, &OptionLen);
	pNeteorkBuff = Network_New(NetworkBuffDirTx, EthernetHeaderLen + IP_HeaderLen + TCP_HEADE_LEN_MIN + OptionLen + DataLen);
	pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	pSocket->pNeteworkBuff = pNeteorkBuff;

	pTCP_Header->SrcPort = pSocket->addr.LocalPort;
	pTCP_Header->DstPort = pSocket->addr.RemotePort;
	pTCP_Header->HeaderLen = OptionLen + DataLen + TCP_HEADE_LEN_MIN;
	memcpy((uint8_t*)&pTCP_Header->Option, TCP_OptionBuff, OptionLen);
	pTCP_Header->WinSize = pSocket->pTCP_Control->LocalWinSize;
	pTCP_Header->Flags = 0;
	memcpy((uint8_t*)((uint32_t)pTCP_Header->Option + OptionLen), Data, DataLen);
	pTCP_Header->SN = pSocket->pTCP_Control->LocalSN;
	if (DataLen == 0)pSocket->pTCP_Control->AK_Except = pTCP_Header->SN + 1;
	else pSocket->pTCP_Control->AK_Except = pTCP_Header->SN + DataLen;
	if (DataLen != 0)pTCP_Header->Flags |= TCP_FLAG_PSH;
}

static void prvGetDataBuff(NeteworkBuff * pNeteorkBuff,uint8_t ** Buff,uint16_t * Len)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint16_t IP_TotalLen = DIY_ntohs(pIP_Header->TotalLen);
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF)/4;
	*Len = IP_TotalLen - TCP_HeaderLen - IP_HeaderLen;
	*Buff = (uint8_t*)((uint32_t)pTCP_Header + TCP_HeaderLen);
}

static void prvGetOptionBuff(NeteworkBuff * pNeteorkBuff, uint8_t ** Buff, uint16_t * Len)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	uint16_t IP_TotalLen = DIY_ntohs(pIP_Header->TotalLen);
	uint16_t TCP_HeaderLen = (pTCP_Header->HeaderLen & 0x00FF)/4;
	*Len = TCP_HeaderLen - TCP_HEADE_LEN_MIN;
	*Buff = (uint8_t*)((uint32_t)pTCP_Header + TCP_HEADE_LEN_MIN);
}

void TCP_Test(void)
{
	uint8_t * Data, *Option;
	uint16_t DataLen, OptionLen;
	prvGetDataBuff(DebugNeteworkBuff,&Data,&DataLen);
	prvGetOptionBuff(DebugNeteworkBuff,&Option,&OptionLen);
	//TCP_PreProcessPacket(DebugNeteworkBuff);
}

static void prvTCP_ProcessOption(Socket * pSocket,uint8_t * Option, uint16_t Len)
{
	uint16_t i = 0,LenTemp = 0;
	uint32_t Value = 0;
	for (i = 0; i < Len;)
	{
		if (*Option == TOK_MSS)
		{
			LenTemp = *(Option + 1);
			Value = *(Option + 2) << 8 + *(Option + 3);
			pSocket->pTCP_Control->RemoteMSS = Value;
			Option += LenTemp;
			i += LenTemp;
		}
		if (*Option == TOK_WSOPT)
		{
			LenTemp = *(Option + 1);
			Value = *(Option + 2);
			pSocket->pTCP_Control->RemoteWinScale = Value;
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

void TCP_ProcessPacket(NeteworkBuff * pNeteorkBuff)
{
	Socket * pSocket = 0;
	TCP_Header * pTCP_Header = 0;
	TCP_Control * pTCP_Control = 0;
	if (pNeteorkBuff == NULL)return;
	if (TCP_PreProcessPacket(pNeteorkBuff, &pSocket, &pTCP_Header) != RES_TCPPacketPass)return;
	pTCP_Control = pSocket->pTCP_Control;
	if (pTCP_Control->State == TCP_STATE_LISTEN)
	{
		uint8_t Flags = pTCP_Header->Flags;
		if (Flags & TCP_FLAG_SYN)
		{
			prvTCP_Handle_SYN_Recv(pSocket, pNeteorkBuff);
		}
		if (Flags & TCP_FLAG_ACK)
		{

		}
	}
}

static void prvTCP_Handle_ACK_Recv(Socket * pSocket)
{
	if (pSocket->pTCP_Control->State == TCP_STATE_SYN_RECV)
	{
		pSocket->pTCP_Control->State = TCP_STATE_ESTABLISHED;
		return;
	}
	if (pSocket->pTCP_Control->State == TCP_STATE_ESTABLISHED)
	{

	}
}

static void prvTCP_Handle_SYN_Recv(Socket * pSocket, NeteworkBuff * pNeteorkBuff)
{
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;

	uint8_t * Option = 0;
	uint16_t OptionLen = 0;
	pTCP_Control->State = TCP_STATE_SYN_RECV;
	pTCP_Control->RemoteSN = pTCP_Header->SN;
	pTCP_Control->RemoteWinSize = pTCP_Header->WinSize;

	prvGetOptionBuff(pNeteorkBuff, &Option, &OptionLen);
	prvTCP_ProcessOption(pSocket, Option, OptionLen);
	//send SYN+ACK
	prvTCP_GeneratePacket(pSocket,0,0);
	prvTCP_SetFlag_SN(pSocket,TCP_FLAG_SYN + TCP_FLAG_ACK, pTCP_Control->RemoteSN + 1);
	prvIP_FillPacket(pNeteorkBuff, &pSocket->addr.RemoteIP, IP_Protocol_TCP);
	Ethernet_TransmitPacket(pNeteorkBuff);
}

static void prvTCP_SetFlag_SN(Socket * pSocket,uint8_t Flags, uint32_t RemoteSN)
{
	NeteworkBuff * pNeteorkBuff = pSocket->pNeteworkBuff;
	Ethernet_Header * pEthernet_Header = (Ethernet_Header*)&pNeteorkBuff->Buff;
	IP_Header * pIP_Header = (IP_Header*)&pEthernet_Header->Buff;
	TCP_Header * pTCP_Header = (TCP_Header*)&pIP_Header->Buff;

	pTCP_Header->Flags |= Flags;
	pTCP_Header->AK = RemoteSN;
}

static void prvTCP_GenerateOption(Socket * pSocket, uint16_t * Len)
{
	TCP_Control * pTCP_Control = pSocket->pTCP_Control;
	uint8_t OptionLen = 0, *pOption = TCP_OptionBuff;

	if (pTCP_Control->MSS_Send == NULL)
	{
		pOption[OptionLen + 0] = (uint8_t)TOK_MSS;
		pOption[OptionLen + 1] = 4;
		pOption[OptionLen + 2] = pTCP_Control->LocalMSS / 256;
		pOption[OptionLen + 3] = pTCP_Control->LocalMSS % 256;
		OptionLen += 4;
	}
	if (pTCP_Control->WIN_Sent == NULL || pTCP_Control->WIN_Change != NULL)
	{
		pOption[OptionLen + 0] = (uint8_t)TOK_WSOPT;
		pOption[OptionLen + 1] = 3;
		pOption[OptionLen + 2] = pTCP_Control->LocalWinScale;
		pOption[OptionLen + 3] = TOK_NOP;
		OptionLen += 4;
	}
	/* 以后再加吧 */
	*Len = OptionLen;
}


