
#ifndef __BT_BDE_H__
#define __BT_BDE_H__

/*
****************************************************
*  文件名             : BT_BDE.h
*  作者               : --
*  版本               : V1.0
*  编写日期           : 2016--12--14--14--39--54
*  简介               : ！！C99标准！！
*  函数列表           : 
                        BT_BDE_OpsTypedef
                        BT_BDE_PriDataTypedef
                        BT_BDE_DriverTypedef
*  历史版本           : 
*****************************************************
*/

/* 常用宏定义 */
#if 1

#define BT_True                 (0xff)
#define BT_False                (0x00)

#define BT_CHK_PARAM(x)         {if((uint32_t)x == 0)return BT_False;}
#define BT_CHK_BIT(val,bit)     ((val) & (1 << (bit)))
#define BT_SET_BIT(val,bit)     {(val) |= (1 << (bit));}
#define BT_CLR_BIT(val,bit)     {(val) &= ~(1 << (bit));}
#define BT_ABS(x)               ((x) > 0 ? (x):(-(x)))
#define BT_CHK_LEN(pxStr,Len)   {if(strlen((const char *)(pxStr)) > (Len))return BT_False;}

#define BT_FLAG_RxLock          (0x01)

#endif

/* 蓝牙数据 */
typedef struct BT_BDE_PriDataTypedef_
{
    /* 当前角色 */
    uint8_t CurRole;
    /* 字符分解输出 */
    uint8_t ParamSplit[6][16];
    /* 标志组 */
    uint16_t FlagGroup;
    /* 指令生成在此缓冲区中 */
    uint8_t InstructionBuff[60];
    
    uint8_t CSQ_Signal[4];
    uint8_t CSQ_Ber[4];
    
    uint32_t Counter;
    
}BT_BDE_PriDataTypedef;
/* 串口驱动 */
typedef struct BT_UartTypedef_
{
    
    (uint16_t)(*Init)(uint16_t Baud);
    (uint16_t)(*Send)(uint8_t * Data,uint16_t ExpectLen,uint16_t Timeout);
    (uint16_t)(*Recv)(uint8_t * Data,uint16_t ExpectLen,uint16_t Timeout);
    
}BT_UartTypedef;
/* 蓝牙驱动 */
typedef struct BT_BDE_DriverTypedef_
{
    BT_UartTypedef          Uart;
    BT_BDE_PriDataTypedef   PriData;

    (uint8_t)(*TimingProcess)(uint16_t Period);
    
}BT_BDE_DriverTypedef;


extern BT_BDE_DriverTypedef BT_BDE_Driver;

#endif


