
/*
 *  FreeRTOS_TCP_WIN.c
 *  Module which handles the TCP windowing schemes for FreeRTOS-PLUS-TCP
 */

#ifndef FREERTOS_TCP_WIN_H
#define FREERTOS_TCP_WIN_H

#ifdef __cplusplus
extern "C" {
#endif

extern BaseType_t xTCPWindowLoggingLevel;

typedef struct xTCPTimer
{
    uint32_t ulBorn;
} TCPTimer_t;

typedef struct xTCP_SEGMENT
{
    uint32_t ulSequenceNumber;      /* 本包中第一字节的序列号 */
    int32_t lMaxLength;             /* 最大空间, 能被存储在本段的字节数 */
    int32_t lDataLength;            /* 实际的字节数 */
    int32_t lStreamPos;             /* 套接字发送/接收流的索引 */
    TCPTimer_t xTransmitTimer;      /* 本段被发送时存储一下时间 (TX only) */
    union
    {
        struct
        {
            uint32_t
                ucTransmitCount : 8,/* 本段被发送了多少次（重传）,用于计算RTT*/
                ucDupAckCount : 8,  /* 记录一个比本段更高的序列号被应答的次数，3次之后会发送快速重传 */
                bOutstanding : 1,   /* 等待对方应答 */
                bAcked : 1,         /* 本段已被确认 */
                bIsForRx : 1;       /* pdTRUE 如果段用来接收 */
        } bits;
        uint32_t ulFlags;
    } u;
#if( ipconfigUSE_TCP_WIN != 0 )
    struct xLIST_ITEM xQueueItem;  /* 只用于发送，段可以被连接到三种链表中：xPriorityQueue, xTxQueue, and xWaitQueue */ 
    struct xLIST_ITEM xListItem;    /* With this item the segment can be connected to a list, depending on who is owning it */
#endif
} TCPSegment_t;

typedef struct xTCP_WINSIZE
{
    uint32_t ulRxWindowLength;
    uint32_t ulTxWindowLength;
} TCPWinSize_t;

/*
 * If TCP time-stamps are being used, they will occupy 12 bytes in
 * each packet, and thus the message space will become smaller
 */
/* Keep this as a multiple of 4 */
#if( ipconfigUSE_TCP_WIN == 1 )
    #if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
        #define ipSIZE_TCP_OPTIONS  ( 16u + 12u )
    #else
        #define ipSIZE_TCP_OPTIONS  16u
    #endif
#else
    #if ipconfigUSE_TCP_TIMESTAMPS == 1
        #define ipSIZE_TCP_OPTIONS   ( 12u + 12u )
    #else
        #define ipSIZE_TCP_OPTIONS   12u
    #endif
#endif

/*
 *  Every TCP connection owns a TCP window for the administration of all packets
 *  It owns two sets of segment descriptors, incoming and outgoing
 */
typedef struct xTCP_WINDOW
{
    union
    {
        struct
        {
            uint32_t
                bHasInit : 1,       /* 窗口结构体已被初始化 */
                bSendFullSize : 1,  /* 只发送大小为MSS的段 */
                bTimeStamps : 1;    /* 套接字使用时间戳 */
        } bits;                     /* party which opens the connection */
        uint32_t ulFlags;
    } u;
    TCPWinSize_t xSize;
    struct
    {
        uint32_t ulFirstSequenceNumber;  /* Logging & debug: the first segment received/sent in this connection
                                          * for Tx: 初始序列号 (ISS)
                                          * for Rx: 初始接收序列号 (IRS) */
        uint32_t ulCurrentSequenceNumber;/* Tx/Rx: 滑动窗口的左边值 */
        uint32_t ulFINSequenceNumber;    /* 带有FIN标志的序列号 */
        uint32_t ulHighestSequenceNumber;/* 最右边的字节加一的序列号 */
#if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
        uint32_t ulTimeStamp;            /* 时间戳 */
#endif
    } rx, tx;
    uint32_t ulOurSequenceNumber;       /* 我们发送的序列号 */
    uint32_t ulUserDataLength;          /* Number of bytes in Rx buffer which may be passed to the user, after having received a 'missing packet' */
    uint32_t ulNextTxSequenceNumber;    /* 下一次要发送的序列号 */
    int32_t lSRTT;                      /* 滑动拥塞控制 */
    uint8_t ucOptionLength;             /* 选项字段长度*/
#if( ipconfigUSE_TCP_WIN == 1 )
    List_t xPriorityQueue;              /* 优先组: 必须被立即发送的段 */
    List_t xTxQueue;                    /* 发送段: 传输的段 */
    List_t xWaitQueue;                  /* 等待段: 等待确认的段 */
    TCPSegment_t *pxHeadSegment;        /* 指向一个段，没有被发送但是大小在增长(用户增加了数据) */
    uint32_t ulOptionsData[ipSIZE_TCP_OPTIONS/sizeof(uint32_t)];    /* 包含了我们发出的选项字段 */
    List_t xTxSegments;                 /*2016--12--02--18--36--48(ZJYC): 所有发送段的链表，通过序列号排列   */ 
    List_t xRxSegments;                 /* 所有发送段的链表，通过序列号排列 */
#else
    /* 对于微型TCP，只有一个等待确认的段 */
    TCPSegment_t xTxSegment;            /* 优先组 */
#endif
    uint16_t usOurPortNumber;           /* 为了调试和日志:我们自己的端口 */
    uint16_t usPeerPortNumber;          /* 调试和日志: 对方的TCP端口号 */
    uint16_t usMSS;                     /* 当前接受的 MSS */
    uint16_t usMSSInit;                 /* 套接字拥有者设置的MSS值 */
} TCPWindow_t;


/*=============================================================================
 *
 * 创建和摧毁
 *
 *=============================================================================*/

/* 创建并初始化一个窗口 */
void vTCPWindowCreate( TCPWindow_t *pxWindow, uint32_t ulRxWindowLength,
    uint32_t ulTxWindowLength, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS );

/* Destroy a window (always returns NULL)
 * It will free some resources: a collection of segments */
void vTCPWindowDestroy( TCPWindow_t *pxWindow );

/* Initialize a window */
void vTCPWindowInit( TCPWindow_t *pxWindow, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS );

/*=============================================================================
 *
 * Rx functions
 *
 *=============================================================================*/

/* if true may be passed directly to user (segment expected and window is empty)
 * But pxWindow->ackno should always be used to set "BUF->ackno" */
int32_t lTCPWindowRxCheck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength, uint32_t ulSpace );

/* When lTCPWindowRxCheck returned false, please call store for this unexpected data */
BaseType_t xTCPWindowRxStore( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength );

/* This function will be called as soon as a FIN is received. It will return true
 * if there are no 'open' reception segments */
BaseType_t xTCPWindowRxEmpty( TCPWindow_t *pxWindow );

/* _HT_ Temporary function for testing/debugging
 * Not used at this moment */
void vTCPWinShowSegments( TCPWindow_t *pxWindow, BaseType_t bForRx );

/*=============================================================================
 *
 * Tx functions
 *
 *=============================================================================*/

/* Adds data to the Tx-window */
int32_t lTCPWindowTxAdd( TCPWindow_t *pxWindow, uint32_t ulLength, int32_t lPosition, int32_t lMax );

/* Check data to be sent and calculate the time period we may sleep */
BaseType_t xTCPWindowTxHasData( TCPWindow_t *pxWindow, uint32_t ulWindowSize, TickType_t *pulDelay );

/* See if anything is left to be sent
 * Function will be called when a FIN has been received. Only when the TX window is clean,
 * it will return pdTRUE */
BaseType_t xTCPWindowTxDone( TCPWindow_t *pxWindow );

/* Fetches data to be sent.
 * apPos will point to a location with the circular data buffer: txStream */
uint32_t ulTCPWindowTxGet( TCPWindow_t *pxWindow, uint32_t ulWindowSize, int32_t *plPosition );

/* Receive a normal ACK */
uint32_t ulTCPWindowTxAck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber );

/* Receive a SACK option */
uint32_t ulTCPWindowTxSack( TCPWindow_t *pxWindow, uint32_t ulFirst, uint32_t ulLast );


#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* FREERTOS_TCP_WIN_H */
