
#include "ARP.h"
#include "Ethernet.h"
#include "Basic.h"

IP ip[2] = { { 12, 12, 12, 12 }, { 13, 13, 13, 13 } };
MAC mac[2] = { { 12, 12, 12, 12, 12, 12 }, {13,13,13,13,13,13} };


int main(void)
{
	ARP_Init();
	EthernetRecv(&NeteorkBuffTemp);
	while (1);
}

















