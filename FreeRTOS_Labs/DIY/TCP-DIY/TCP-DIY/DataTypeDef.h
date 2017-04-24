

#ifndef __DATATYPEDEF_H__
#define __DATATYPEDEF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdio.h>

#define uint8_t unsigned char
#ifndef NULL
	#define NULL	0x00
#endif
#pragma pack (1)
typedef struct IP_
{
	uint8_t Byte[4];
}IP;

typedef struct MAC_
{
	uint8_t Byte[6];
}MAC;

#pragma pack ()
#ifdef __cplusplus
}
#endif

#endif








