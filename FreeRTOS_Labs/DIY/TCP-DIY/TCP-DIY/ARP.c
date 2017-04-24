

#include "ARP.h"

ARP_Cache ArpCache[ARP_CACHE_CAPACITY] = { 0x00 };

uint8_t ARP_Init(void)
{
	uint8_t i;
	memset((uint8_t*)&ArpCache, NULL, sizeof(ArpCache));
}

uint8_t ARP_GetIP_ByMAC(MAC * mac,IP * ip, uint8_t * IndexOfCache)
{
	uint8_t i,*Buf1,*Buf2;

	Buf2 = (uint8_t*)&mac;

	for ( i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&ArpCache[i].MAC;

		if (ArpCache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(MAC)) == 0)
		{
			if (ip != NULL)*ip = *ArpCache[i].IP;
			*IndexOfCache = i;
			return ARP_True;
		}
	}
	return ARP_False;
}

uint8_t ARP_GetMAC_ByIP(IP * ip,MAC * mac,uint8_t * IndexOfCache)
{
	uint8_t i, *Buf1, *Buf2;

	Buf2 = (uint8_t*)&ip;

	for (i = 0; i < ARP_CACHE_CAPACITY; i++)
	{
		Buf1 = (uint8_t*)&ArpCache[i].IP;

		if (ArpCache[i].Used == ARP_True && memcmp(Buf1, Buf2, sizeof(IP)) == 0)
		{
			if (mac != NULL)*mac = *ArpCache[i].MAC;
			*IndexOfCache = i;
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
				memcpy((uint8_t*)&ArpCache[i].MAC, ip, sizeof(MAC));
				return ARP_True;
			}
		}
	}
	return ARP_False;
}




