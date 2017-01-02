
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
    struct xLIST_ITEM xListItem;   /* 通过这个所有的段连接到内存池 */
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
/*
****************************************************
*  函数名         : vTCPWindowCreate
*  函数描述       : 创建并初始化一个窗口
*  参数           : 
                    pxWindow：窗口指针
                    ulRxWindowLength：接收窗口长度
                    ulTxWindowLength：发送窗口长度
                    ulAckNumber：应答号
                    ulSequenceNumber：序列号
                    ulMSS：MSS
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
void vTCPWindowCreate( TCPWindow_t *pxWindow, uint32_t ulRxWindowLength,uint32_t ulTxWindowLength, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS );
/*
****************************************************
*  函数名         : vTCPWindowDestroy
*  函数描述       : 摧毁一个窗口，将会回收一系列的段
*  参数           : pxWindow：待摧毁窗口
*  返回值         : NULL
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
void vTCPWindowDestroy( TCPWindow_t *pxWindow );
/*
****************************************************
*  函数名         : vTCPWindowInit
*  函数描述       : 初始化一个窗口
*  参数           : 
                    pxWindow：窗口
                    ulAckNumber：应答号
                    ulSequenceNumber：序列号
                    ulMSS：MSS
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
void vTCPWindowInit( TCPWindow_t *pxWindow, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS );

/*=============================================================================
 *
 * Rx functions
 *
 *=============================================================================*/

/* if true may be passed directly to user (segment expected and window is empty)
 * But pxWindow->ackno should always be used to set "BUF->ackno" */
/*
****************************************************
*  函数名         : lTCPWindowRxCheck
*  函数描述       : 
                    返回0,ulCurrentSequenceNumber增加了ulLength
*  参数           : 
                    pxWindow：窗口
                    ulSequenceNumber：接收到的序列号
                    ulLength：接收到的数据长度
                    ulSpace：接收缓冲区可用空间
*  返回值         : 
                    -1：序列号非期望或者是存储空间不足
                    0：序号好正常并且空间充足
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
int32_t lTCPWindowRxCheck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength, uint32_t ulLength );

/* When lTCPWindowRxCheck returned false, please call store for this unexpected data */
/*
****************************************************
*  函数名         : xTCPWindowRxStore
*  函数描述       : 用以存储非顺序的数据
*  参数           : 
                    pxWindow：窗口
                    ulSequenceNumber：序列号
                    ulLength：数据长度
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
BaseType_t xTCPWindowRxStore( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength );

/* This function will be called as soon as a FIN is received. It will return true
 * if there are no 'open' reception segments */
/*
****************************************************
*  函数名         : xTCPWindowRxEmpty
*  函数描述       : 查看接收窗口是否为空
*  参数           : pxWindow：窗口
*  返回值         : 
                    pdFALSE：不为空
                    pdTRUE：为空
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
BaseType_t xTCPWindowRxEmpty( TCPWindow_t *pxWindow );

/* _HT_ Temporary function for testing/debugging
 * Not used at this moment */
void vTCPWinShowSegments( TCPWindow_t *pxWindow, BaseType_t bForRx );

/*=============================================================================
 *
 * Tx functions
 *
 *=============================================================================*/
/*
****************************************************
*  函数名         : lTCPWindowTxAdd
*  函数描述       : 我们有ulLength数据要发送，把数据防盗窗口
*  参数           : 
                    pxWindow：窗口
                    ulLength：需要发送的数据长度
                    lPosition：缓冲区位置
                    lMax：缓冲区长度
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
int32_t lTCPWindowTxAdd( TCPWindow_t *pxWindow, uint32_t ulLength, int32_t lPosition, int32_t lMax );
/*
****************************************************
*  函数名         : xTCPWindowTxHasData
*  函数描述       : 确认是否有数据要发送，并计算发送延迟时间Check data to be sent and calculate the time period we may sleep
*  参数           : 
                    pxWindow：窗口
                    ulWindowSize：窗口大小
                    pulDelay：等待时间
*  返回值         : 
                    pdTRUE：有数据需要发送
                    pdFALSE：没有数据需要发送
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
BaseType_t xTCPWindowTxHasData( TCPWindow_t *pxWindow, uint32_t ulWindowSize, TickType_t *pulDelay );

/* See if anything is left to be sent
 * Function will be called when a FIN has been received. Only when the TX window is clean,
 * it will return pdTRUE */
/*
****************************************************
*  函数名         : 
*  函数描述       : 查看是否存在没有被发送的
                    函数在接收到FIN之后被调用，只有TX 窗口被清空的情况下才会返回pdTRUE
*  参数           : 
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
BaseType_t xTCPWindowTxDone( TCPWindow_t *pxWindow );

/* Fetches data to be sent.
 * apPos will point to a location with the circular data buffer: txStream */
/*
****************************************************
*  函数名         : ulTCPWindowTxGet
*  函数描述       : 
*  参数           : 
                    pxWindow：窗口
                    ulWindowSize：窗口大小
                    plPosition：数据所在位置
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
uint32_t ulTCPWindowTxGet( TCPWindow_t *pxWindow, uint32_t ulWindowSize, int32_t *plPosition );
/*
****************************************************
*  函数名         : ulTCPWindowTxAck
*  函数描述       : 收到一个常规应答
*  参数           : 
                    pxWindow：窗口
                    ulSequenceNumber：收到的序列号
*  返回值         : 
                    0：
                    被应答的字节数
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
uint32_t ulTCPWindowTxAck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber );
/*
****************************************************
*  函数名         : ulTCPWindowTxSack
*  函数描述       : 收到一选择性应答
*  参数           : 
                    pxWindow：窗口
                    ulFirst：起始序列号
                    ulLast：结束序列号
*  返回值         : 被应答的字节数
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
uint32_t ulTCPWindowTxSack( TCPWindow_t *pxWindow, uint32_t ulFirst, uint32_t ulLast );


#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* FREERTOS_TCP_WIN_H */
