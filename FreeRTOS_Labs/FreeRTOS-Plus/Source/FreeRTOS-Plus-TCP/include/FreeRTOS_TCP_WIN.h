
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
                ucDupAckCount : 8,  /* Counts the number of times that a higher segment was ACK'd. After 3 times a Fast Retransmission takes place */
                bOutstanding : 1,   /* 等待对方应答 */
                bAcked : 1,         /* 本段已被确认 */
                bIsForRx : 1;       /* pdTRUE if segment is used for reception */
        } bits;
        uint32_t ulFlags;
    } u;
#if( ipconfigUSE_TCP_WIN != 0 )
    struct xLIST_ITEM xQueueItem;   /* TX only: segments can be linked in one of three queues: xPriorityQueue, xTxQueue, and xWaitQueue */
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
                bHasInit : 1,       /* The window structure has been initialised */
                bSendFullSize : 1,  /* May only send packets with a size equal to MSS (for optimisation) */
                bTimeStamps : 1;    /* Socket is supposed to use TCP time-stamps. This depends on the */
        } bits;                     /* party which opens the connection */
        uint32_t ulFlags;
    } u;
    TCPWinSize_t xSize;
    struct
    {
        uint32_t ulFirstSequenceNumber;  /* Logging & debug: the first segment received/sent in this connection
                                          * for Tx: initial send sequence number (ISS)
                                          * for Rx: initial receive sequence number (IRS) */
        uint32_t ulCurrentSequenceNumber;/* Tx/Rx: the oldest sequence number not yet confirmed, also SND.UNA / RCV.NXT
                                          * In other words: the sequence number of the left side of the sliding window */
        uint32_t ulFINSequenceNumber;    /* The sequence number which carried the FIN flag */
        uint32_t ulHighestSequenceNumber;/* Sequence number of the right-most byte + 1 */
#if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
        uint32_t ulTimeStamp;            /* The value of the TCP timestamp, transmitted or received */
#endif
    } rx, tx;
    uint32_t ulOurSequenceNumber;       /* The SEQ number we're sending out */
    uint32_t ulUserDataLength;          /* Number of bytes in Rx buffer which may be passed to the user, after having received a 'missing packet' */
    uint32_t ulNextTxSequenceNumber;    /* The sequence number given to the next byte to be added for transmission */
    int32_t lSRTT;                      /* Smoothed Round Trip Time, it may increment quickly and it decrements slower */
    uint8_t ucOptionLength;             /* Number of valid bytes in ulOptionsData[] */
#if( ipconfigUSE_TCP_WIN == 1 )
    List_t xPriorityQueue;              /* Priority queue: segments which must be sent immediately */
    List_t xTxQueue;                    /* Transmit queue: segments queued for transmission */
    List_t xWaitQueue;                  /* Waiting queue:  outstanding segments */
    TCPSegment_t *pxHeadSegment;        /* points to a segment which has not been transmitted and it's size is still growing (user data being added) */
    uint32_t ulOptionsData[ipSIZE_TCP_OPTIONS/sizeof(uint32_t)];    /* Contains the options we send out */
    List_t xTxSegments;                 /*2016--12--02--18--36--48(ZJYC): 所有发送段的链表，通过序列号排列   */ 
    List_t xRxSegments;                 /* A linked list of reception segments, order depends on sequence of arrival */
#else
    /* For tiny TCP, there is only 1 outstanding TX segment */
    TCPSegment_t xTxSegment;            /* Priority queue */
#endif
    uint16_t usOurPortNumber;           /* Mostly for debugging/logging: our TCP port number */
    uint16_t usPeerPortNumber;          /* debugging/logging: the peer's TCP port number */
    uint16_t usMSS;                     /* Current accepted MSS */
    uint16_t usMSSInit;                 /* MSS as configured by the socket owner */
} TCPWindow_t;


/*=============================================================================
 *
 * Creation and destruction
 *
 *=============================================================================*/

/* Create and initialize a window */
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
