
#include "ARP.h"

IP ip[2] = { { 12, 12, 12, 12 }, { 13, 13, 13, 13 } };
MAC mac[2] = { { 12, 12, 12, 12, 12, 12 }, {13,13,13,13,13,13} };


int main(void)
{
	ARP_Init();
	ARP_AddItem(&ip[0],&mac[0]);
	ARP_AddItem(&ip[1], &mac[1]);
	ARP_GetIP_ByMAC(&mac[0],&ip[0],NULL);
	ARP_GetMAC_ByIP(&ip[1], &mac[0], NULL);
	while (1);
}

















