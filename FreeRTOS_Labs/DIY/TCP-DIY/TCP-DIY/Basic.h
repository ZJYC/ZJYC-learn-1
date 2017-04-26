
#ifndef __BASIC_H__
#define __BASIC_H__

#include "DataTypeDef.h"

#define prvAlign(x,y)	((x) % (y) == 0 ? (x) : ((x)/(y)+1)*(y))
/* 以太网是大端模式 */
#define DIY_htonl(x)	(((x) & 0x000000FF) << 24 |((x) & 0x0000FF00) << 8 |((x) & 0x00FF0000) >> 8 |((x) & 0xFF000000) >> 24)
#define DIY_ntohl(x)	(((x) & 0x000000FF) << 24 |((x) & 0x0000FF00) << 8 |((x) & 0x00FF0000) >> 8 |((x) & 0xFF000000) >> 24)

#define DIY_htons(x)	(((x) & 0x00FF) << 8 | ((x) & 0xFF00) >> 8)
#define DIY_ntohs(x)	(((x) & 0x00FF) << 8 | ((x) & 0xFF00) >> 8)

#define DIY_htonc(x)	(((x) & 0xF0) >> 4 | ((x) & 0x0F) << 4)
#define DIY_ntohc(x)	(((x) & 0xF0) >> 4 | ((x) & 0x0F) << 4)





uint16_t prvGetCheckSum(uint16_t *data, uint32_t nums);



#endif


