
#include "Basic.h"





uint16_t prvGetCheckSum(uint16_t *data, uint32_t nums)
{
	uint32_t index = 0;
	uint32_t sum = 0;
	uint16_t checkSum;

	for (index = 0; index < nums; index++)
	{
		sum += data[index];
	}

	checkSum = (unsigned short int)(sum & 0xffff) + (unsigned short int)(sum >> 16);

	return ~checkSum;
}
























