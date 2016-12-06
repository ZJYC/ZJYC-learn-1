
#ifndef __ARP_H__
#define __ARP_H__

#define U8  uint8_t
#define U16 uint16_t
#define ARP_FRAME_TYPE  (0x0806)    /* 帧类型 */
#define ARP_HARD_TYPE   (0x0001)    /* 硬件类型 */
#define ARP_Pro_TYPE    (0x0800)    /* ARP协议类型IP */
#define ARP_REQUEST     (0x0001)
#define ARP_REPLY       (0x0002)
#define ARP_HARD_LEN    (0x06)
#define ARP_IP_LEN      (0x04)
typedef struct MAC_Typedef_
{
    U8 Addr[ARP_HARD_LEN];
}MAC_Src,MAC_Dst,MAC;

typdef struct IP_Typedef_
{
    U8 Add[ARP_IP_LEN];
}IP_Src,IP_Dst,IP;

typedef struct ARP_FRAME_Typedef_
{
    MAC_Dst Dst;
    MAC_Src Src;
    U16 FrameType;
    U16 HardType;
    U16 ProType;
    U8 HardAddrLen;
    U8 ProAddrLen;
    U8 OpType;
    MAC SenderAddr;
    IP  SenderIP;
    MAC DstAddr;
    IP  DstIP;
}ARP_FRAME_Typedef;

typedef struct ARP_CACHE_Item_
{
    MAC MacAddr;
    IP  IpAddr;
}ARP_CACHE_Item;

typedef struct ARP_CACHE_Typedef_
{
    MAC MacAddr;
    IP  IpAddr;
};









#endif














