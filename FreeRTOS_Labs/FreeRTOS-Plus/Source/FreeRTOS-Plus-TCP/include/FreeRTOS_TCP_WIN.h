
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
    uint32_t ulSequenceNumber;      /* �����е�һ�ֽڵ����к� */
    int32_t lMaxLength;             /* ���ռ�, �ܱ��洢�ڱ��ε��ֽ��� */
    int32_t lDataLength;            /* ʵ�ʵ��ֽ��� */
    int32_t lStreamPos;             /* �׽��ַ���/������������ */
    TCPTimer_t xTransmitTimer;      /* ���α�����ʱ�洢һ��ʱ�� (TX only) */
    union
    {
        struct
        {
            uint32_t
                ucTransmitCount : 8,/* ���α������˶��ٴΣ��ش���,���ڼ���RTT*/
                ucDupAckCount : 8,  /* ��¼һ���ȱ��θ��ߵ����кű�Ӧ��Ĵ�����3��֮��ᷢ�Ϳ����ش� */
                bOutstanding : 1,   /* �ȴ��Է�Ӧ�� */
                bAcked : 1,         /* �����ѱ�ȷ�� */
                bIsForRx : 1;       /* pdTRUE ������������� */
        } bits;
        uint32_t ulFlags;
    } u;
#if( ipconfigUSE_TCP_WIN != 0 )
    struct xLIST_ITEM xQueueItem;  /* ֻ���ڷ��ͣ��ο��Ա����ӵ����������У�xPriorityQueue, xTxQueue, and xWaitQueue */ 
    struct xLIST_ITEM xListItem;   /* ͨ��������еĶ����ӵ��ڴ�� */
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
                bHasInit : 1,       /* ���ڽṹ���ѱ���ʼ�� */
                bSendFullSize : 1,  /* ֻ���ʹ�СΪMSS�Ķ� */
                bTimeStamps : 1;    /* �׽���ʹ��ʱ��� */
        } bits;                     /* party which opens the connection */
        uint32_t ulFlags;
    } u;
    TCPWinSize_t xSize;
    struct
    {
        uint32_t ulFirstSequenceNumber;  /* Logging & debug: the first segment received/sent in this connection
                                          * for Tx: ��ʼ���к� (ISS)
                                          * for Rx: ��ʼ�������к� (IRS) */
        uint32_t ulCurrentSequenceNumber;/* Tx/Rx: �������ڵ����ֵ */
        uint32_t ulFINSequenceNumber;    /* ����FIN��־�����к� */
        uint32_t ulHighestSequenceNumber;/* ���ұߵ��ֽڼ�һ�����к� */
#if( ipconfigUSE_TCP_TIMESTAMPS == 1 )
        uint32_t ulTimeStamp;            /* ʱ��� */
#endif
    } rx, tx;
    uint32_t ulOurSequenceNumber;       /* ���Ƿ��͵����к� */
    uint32_t ulUserDataLength;          /* Number of bytes in Rx buffer which may be passed to the user, after having received a 'missing packet' */
    uint32_t ulNextTxSequenceNumber;    /* ��һ��Ҫ���͵����к� */
    int32_t lSRTT;                      /* ����ӵ������ */
    uint8_t ucOptionLength;             /* ѡ���ֶγ���*/
#if( ipconfigUSE_TCP_WIN == 1 )
    List_t xPriorityQueue;              /* ������: ���뱻�������͵Ķ� */
    List_t xTxQueue;                    /* ���Ͷ�: ����Ķ� */
    List_t xWaitQueue;                  /* �ȴ���: �ȴ�ȷ�ϵĶ� */
    TCPSegment_t *pxHeadSegment;        /* ָ��һ���Σ�û�б����͵��Ǵ�С������(�û�����������) */
    uint32_t ulOptionsData[ipSIZE_TCP_OPTIONS/sizeof(uint32_t)];    /* ���������Ƿ�����ѡ���ֶ� */
    List_t xTxSegments;                 /*2016--12--02--18--36--48(ZJYC): ���з��Ͷε�����ͨ�����к�����   */ 
    List_t xRxSegments;                 /* ���з��Ͷε�����ͨ�����к����� */
#else
    /* ����΢��TCP��ֻ��һ���ȴ�ȷ�ϵĶ� */
    TCPSegment_t xTxSegment;            /* ������ */
#endif
    uint16_t usOurPortNumber;           /* Ϊ�˵��Ժ���־:�����Լ��Ķ˿� */
    uint16_t usPeerPortNumber;          /* ���Ժ���־: �Է���TCP�˿ں� */
    uint16_t usMSS;                     /* ��ǰ���ܵ� MSS */
    uint16_t usMSSInit;                 /* �׽���ӵ�������õ�MSSֵ */
} TCPWindow_t;


/*=============================================================================
 *
 * �����ʹݻ�
 *
 *=============================================================================*/
/*
****************************************************
*  ������         : vTCPWindowCreate
*  ��������       : ��������ʼ��һ������
*  ����           : 
                    pxWindow������ָ��
                    ulRxWindowLength�����մ��ڳ���
                    ulTxWindowLength�����ʹ��ڳ���
                    ulAckNumber��Ӧ���
                    ulSequenceNumber�����к�
                    ulMSS��MSS
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
void vTCPWindowCreate( TCPWindow_t *pxWindow, uint32_t ulRxWindowLength,uint32_t ulTxWindowLength, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS );
/*
****************************************************
*  ������         : vTCPWindowDestroy
*  ��������       : �ݻ�һ�����ڣ��������һϵ�еĶ�
*  ����           : pxWindow�����ݻٴ���
*  ����ֵ         : NULL
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
void vTCPWindowDestroy( TCPWindow_t *pxWindow );
/*
****************************************************
*  ������         : vTCPWindowInit
*  ��������       : ��ʼ��һ������
*  ����           : 
                    pxWindow������
                    ulAckNumber��Ӧ���
                    ulSequenceNumber�����к�
                    ulMSS��MSS
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
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
*  ������         : lTCPWindowRxCheck
*  ��������       : 
                    ����0,ulCurrentSequenceNumber������ulLength
*  ����           : 
                    pxWindow������
                    ulSequenceNumber�����յ������к�
                    ulLength�����յ������ݳ���
                    ulSpace�����ջ��������ÿռ�
*  ����ֵ         : 
                    -1�����кŷ����������Ǵ洢�ռ䲻��
                    0����ź��������ҿռ����
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
int32_t lTCPWindowRxCheck(TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength, uint32_t ulSpace);

/* When lTCPWindowRxCheck returned false, please call store for this unexpected data */
/*
****************************************************
*  ������         : xTCPWindowRxStore
*  ��������       : ���Դ洢��˳�������
*  ����           : 
                    pxWindow������
                    ulSequenceNumber�����к�
                    ulLength�����ݳ���
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
BaseType_t xTCPWindowRxStore( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength );

/* This function will be called as soon as a FIN is received. It will return true
 * if there are no 'open' reception segments */
/*
****************************************************
*  ������         : xTCPWindowRxEmpty
*  ��������       : �鿴���մ����Ƿ�Ϊ��
*  ����           : pxWindow������
*  ����ֵ         : 
                    pdFALSE����Ϊ��
                    pdTRUE��Ϊ��
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
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
*  ������         : lTCPWindowTxAdd
*  ��������       : ������ulLength����Ҫ���ͣ������ݷ�������
*  ����           : 
                    pxWindow������
                    ulLength����Ҫ���͵����ݳ���
                    lPosition��������λ��
                    lMax������������
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
int32_t lTCPWindowTxAdd( TCPWindow_t *pxWindow, uint32_t ulLength, int32_t lPosition, int32_t lMax );
/*
****************************************************
*  ������         : xTCPWindowTxHasData
*  ��������       : ȷ���Ƿ�������Ҫ���ͣ������㷢���ӳ�ʱ��Check data to be sent and calculate the time period we may sleep
*  ����           : 
                    pxWindow������
                    ulWindowSize�����ڴ�С
                    pulDelay���ȴ�ʱ��
*  ����ֵ         : 
                    pdTRUE����������Ҫ����
                    pdFALSE��û��������Ҫ����
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
BaseType_t xTCPWindowTxHasData( TCPWindow_t *pxWindow, uint32_t ulWindowSize, TickType_t *pulDelay );

/* See if anything is left to be sent
 * Function will be called when a FIN has been received. Only when the TX window is clean,
 * it will return pdTRUE */
/*
****************************************************
*  ������         : 
*  ��������       : �鿴�Ƿ����û�б����͵�
                    �����ڽ��յ�FIN֮�󱻵��ã�ֻ��TX ���ڱ���յ�����²Ż᷵��pdTRUE
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
BaseType_t xTCPWindowTxDone( TCPWindow_t *pxWindow );

/* Fetches data to be sent.
 * apPos will point to a location with the circular data buffer: txStream */
/*
****************************************************
*  ������         : ulTCPWindowTxGet
*  ��������       : 
*  ����           : 
                    pxWindow������
                    ulWindowSize�����ڴ�С
                    plPosition����������λ��
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
uint32_t ulTCPWindowTxGet( TCPWindow_t *pxWindow, uint32_t ulWindowSize, int32_t *plPosition );
/*
****************************************************
*  ������         : ulTCPWindowTxAck
*  ��������       : �յ�һ������Ӧ��
*  ����           : 
                    pxWindow������
                    ulSequenceNumber���յ������к�
*  ����ֵ         : 
                    0��
                    ��Ӧ����ֽ���
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
uint32_t ulTCPWindowTxAck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber );
/*
****************************************************
*  ������         : ulTCPWindowTxSack
*  ��������       : �յ�һѡ����Ӧ��
*  ����           : 
                    pxWindow������
                    ulFirst����ʼ���к�
                    ulLast���������к�
*  ����ֵ         : ��Ӧ����ֽ���
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
uint32_t ulTCPWindowTxSack( TCPWindow_t *pxWindow, uint32_t ulFirst, uint32_t ulLast );


#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* FREERTOS_TCP_WIN_H */
