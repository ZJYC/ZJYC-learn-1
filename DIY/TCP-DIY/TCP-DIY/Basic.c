
#include "Basic.h"




/*
uint16_t prvGetCheckSum(uint16_t *data, uint32_t nums)
{
	uint32_t index = 0;
	uint32_t sum = 0;
	uint16_t checkSum;

	for (index = 0; index < nums; index++)
	{
		sum += DIY_ntohs(data[index]);
	}

	checkSum = (uint16_t)(sum & 0xffff) + (uint16_t)(sum >> 16);

	return ~checkSum;
}
*/
uint16_t prvGetCheckSum(uint16_t *data, uint32_t LenBytes)
{
	uint32_t cksum = 0;
	while (LenBytes > 1)
	{
		cksum += *data++;
		LenBytes -= 2;
	}
	if (LenBytes)
	{
		cksum += *(uint8_t *)data;
	}
	while (cksum >> 16)cksum = (cksum >> 16) + (cksum & 0xffff);

	return (uint16_t)(~cksum);
}






















