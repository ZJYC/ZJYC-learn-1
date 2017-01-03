/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_TCP_WIN.h"

/* Constants used for Smoothed Round Trip Time (SRTT). */
#define winSRTT_INCREMENT_NEW       2
#define winSRTT_INCREMENT_CURRENT   6
#define winSRTT_DECREMENT_NEW       1
#define winSRTT_DECREMENT_CURRENT   7
#define winSRTT_CAP_mS              50

#if( ipconfigUSE_TCP_WIN == 1 )

    #define xTCPWindowRxNew( pxWindow, ulSequenceNumber, lCount ) xTCPWindowNew( pxWindow, ulSequenceNumber, lCount, pdTRUE )

    #define xTCPWindowTxNew( pxWindow, ulSequenceNumber, lCount ) xTCPWindowNew( pxWindow, ulSequenceNumber, lCount, pdFALSE )

    /* The code to send a single Selective ACK (SACK):
     * NOP (0x01), NOP (0x01), SACK (0x05), LEN (0x0a),
     * followed by a lower and a higher sequence number,
     * where LEN is 2 + 2*4 = 10 bytes. */
    #if( ipconfigBYTE_ORDER == pdFREERTOS_BIG_ENDIAN )
        #define OPTION_CODE_SINGLE_SACK     ( 0x0101050aUL )
    #else
        #define OPTION_CODE_SINGLE_SACK     ( 0x0a050101UL )
    #endif

    /* Normal retransmission:
     * A packet will be retransmitted after a Retransmit Time-Out (RTO).
     * Fast retransmission:
     * When 3 packets with a higher sequence number have been acknowledged
     * by the peer, it is very unlikely a current packet will ever arrive.
     * It will be retransmitted far before the RTO.
     */
    #define DUPLICATE_ACKS_BEFORE_FAST_RETRANSMIT       ( 3u )

    /* If there have been several retransmissions (4), decrease the
     * size of the transmission window to at most 2 times MSS.
     */
    #define MAX_TRANSMIT_COUNT_USING_LARGE_WINDOW       ( 4u )

#endif /* configUSE_TCP_WIN */
/*-----------------------------------------------------------*/

extern void vListInsertGeneric( List_t * const pxList, ListItem_t * const pxNewListItem, MiniListItem_t * const pxWhere );

/*
 * All TCP sockets share a pool of segment descriptors (TCPSegment_t)
 * Available descriptors are stored in the 'xSegmentList'
 * When a socket owns a descriptor, it will either be stored in
 * 'xTxSegments' or 'xRxSegments'
 * As soon as a package has been confirmed, the descriptor will be returned
 * to the segment pool
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static BaseType_t prvCreateSectors( void );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * Find a segment with a given sequence number in the list of received
 * segments: 'pxWindow->xRxSegments'.
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static TCPSegment_t *xTCPWindowRxFind( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * Allocate a new segment
 * The socket will borrow all segments from a common pool: 'xSegmentList',
 * which is a list of 'TCPSegment_t'
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static TCPSegment_t *xTCPWindowNew( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, int32_t lCount, BaseType_t xIsForRx );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/* When the peer has a close request (FIN flag), the driver will check if
 * there are missing packets in the Rx-queue
 * It will accept the closure of the connection if both conditions are true:
 * - the Rx-queue is empty
 * - we've ACK'd the highest Rx sequence number seen
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    BaseType_t xTCPWindowRxEmpty( TCPWindow_t *pxWindow );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * Detaches and returns the head of a queue
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static TCPSegment_t *xTCPWindowGetHead( List_t *pxList );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * Returns the head of a queue but it won't be detached
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static TCPSegment_t *xTCPWindowPeekHead( List_t *pxList );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 *  Free entry pxSegment because it's not used anymore
 *  The ownership will be passed back to the segment pool
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static void vTCPWindowFree( TCPSegment_t *pxSegment );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
****************************************************
*  函数名         : xTCPWindowRxConfirm
*  函数描述       :     一个序列号为ulSequenceNumber的段已被接收，如果ulCurrentSequenceNumber == 
                        ulSequenceNumber表示这正是我们所期望的，我们查看在ulSequenceNumber和
                        (ulSequenceNumber+xLength)之间是否存在另一个段的序列号，通常没有。

*  参数           : 
                    pxWindow：
                    ulSequenceNumber：
                    ulLength：接收数据长度
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
#if( ipconfigUSE_TCP_WIN == 1 )
    static TCPSegment_t *xTCPWindowRxConfirm( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
****************************************************
*  函数名         : lTCPIncrementTxPosition
*  函数描述       : 
*  参数           : 
                    lPosition：当前位置
                    lMax：缓冲区最大长度
                    lCount：存储字节数
*  返回值         : 存储完之后的位置
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
#if( ipconfigUSE_TCP_WIN == 1 )
    static int32_t lTCPIncrementTxPosition( int32_t lPosition, int32_t lMax, int32_t lCount );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * This function will look if there is new transmission data.  It will return
 * true if there is data to be sent.
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static BaseType_t prvTCPWindowTxHasSpace( TCPWindow_t *pxWindow, uint32_t ulWindowSize );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * An acknowledge was received.  See if some outstanding data may be removed
 * from the transmission queue(s).
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static uint32_t prvTCPWindowTxCheckAck( TCPWindow_t *pxWindow, uint32_t ulFirst, uint32_t ulLast );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*
 * A higher Tx block has been acknowledged.  Now iterate through the xWaitQueue
 * to find a possible condition for a FAST retransmission.
 */
#if( ipconfigUSE_TCP_WIN == 1 )
    static uint32_t prvTCPWindowFastRetransmit( TCPWindow_t *pxWindow, uint32_t ulFirst );
#endif /* ipconfigUSE_TCP_WIN == 1 */

/*-----------------------------------------------------------*/

/* TCP segement pool. */
#if( ipconfigUSE_TCP_WIN == 1 )
    static TCPSegment_t *xTCPSegments = NULL;
#endif /* ipconfigUSE_TCP_WIN == 1 */

/* List of free TCP segments. */
#if( ipconfigUSE_TCP_WIN == 1 )
    static List_t xSegmentList;
#endif

/* Logging verbosity level. */
BaseType_t xTCPWindowLoggingLevel = 0;

#if( ipconfigUSE_TCP_WIN == 1 )
    /* Some 32-bit arithmetic: comparing sequence numbers */
    static portINLINE BaseType_t xSequenceLessThanOrEqual( uint32_t a, uint32_t b );
    static portINLINE BaseType_t xSequenceLessThanOrEqual( uint32_t a, uint32_t b )
    {
        /* Test if a <= b
        Return true if the unsigned subtraction of (b-a) doesn't generate an
        arithmetic overflow. */
        return ( ( b - a ) & 0x80000000UL ) == 0UL;
    }
#endif /* ipconfigUSE_TCP_WIN */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
    static portINLINE BaseType_t xSequenceLessThan( uint32_t a, uint32_t b );
    static portINLINE BaseType_t xSequenceLessThan( uint32_t a, uint32_t b )
    {
        /* Test if a < b */
        return ( ( b - a - 1UL ) & 0x80000000UL ) == 0UL;
    }
#endif /* ipconfigUSE_TCP_WIN */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
    static portINLINE BaseType_t xSequenceGreaterThan( uint32_t a, uint32_t b );
    static portINLINE BaseType_t xSequenceGreaterThan( uint32_t a, uint32_t b )
    {
        /* Test if a > b */
        return ( ( a - b - 1UL ) & 0x80000000UL ) == 0UL;
    }
#endif /* ipconfigUSE_TCP_WIN */

/*-----------------------------------------------------------*/
static portINLINE BaseType_t xSequenceGreaterThanOrEqual( uint32_t a, uint32_t b );
static portINLINE BaseType_t xSequenceGreaterThanOrEqual( uint32_t a, uint32_t b )
{
    /* Test if a >= b */
    return ( ( a - b ) & 0x80000000UL ) == 0UL;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
    static portINLINE void vListInsertFifo( List_t * const pxList, ListItem_t * const pxNewListItem );
    static portINLINE void vListInsertFifo( List_t * const pxList, ListItem_t * const pxNewListItem )
    {
        vListInsertGeneric( pxList, pxNewListItem, &pxList->xListEnd );
    }
#endif
/*-----------------------------------------------------------*/

static portINLINE void vTCPTimerSet( TCPTimer_t *pxTimer );
static portINLINE void vTCPTimerSet( TCPTimer_t *pxTimer )
{
    pxTimer->ulBorn = xTaskGetTickCount ( );
}
/*-----------------------------------------------------------*/

static portINLINE uint32_t ulTimerGetAge( TCPTimer_t *pxTimer );
static portINLINE uint32_t ulTimerGetAge( TCPTimer_t *pxTimer )
{
    return ( ( xTaskGetTickCount() - pxTimer->ulBorn ) * portTICK_PERIOD_MS );
}
/*-----------------------------------------------------------*/

/* _HT_ GCC (using the settings that I'm using) checks for every public function if it is
preceded by a prototype. Later this prototype will be located in list.h? */

extern void vListInsertGeneric( List_t * const pxList, ListItem_t * const pxNewListItem, MiniListItem_t * const pxWhere );

void vListInsertGeneric( List_t * const pxList, ListItem_t * const pxNewListItem, MiniListItem_t * const pxWhere )
{
    /*2016--12--03--18--16--54(ZJYC): 向pxList插入一新的成员，这不会对列表排序，
    他吧成员放在xListEnd之前，所以他会是最后一个被listGET_HEAD_ENTRY()返回的元素*/ 
    pxNewListItem->pxNext = (struct xLIST_ITEM * configLIST_VOLATILE)pxWhere;
    pxNewListItem->pxPrevious = pxWhere->pxPrevious;
    pxWhere->pxPrevious->pxNext = pxNewListItem;
    pxWhere->pxPrevious = pxNewListItem;
    /*2016--12--03--18--18--53(ZJYC): 记住这一个成员在哪一个列表中   */ 
    pxNewListItem->pvContainer = ( void * ) pxList;
    ( pxList->uxNumberOfItems )++;
}
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )

    static BaseType_t prvCreateSectors( void )
    {
    BaseType_t xIndex, xReturn;
        /*2016--12--03--18--19--31(ZJYC): 为xTCPSegments创建空间，并保存在xSegmentList   */ 
        vListInitialise( &xSegmentList );
        xTCPSegments = ( TCPSegment_t * ) pvPortMallocLarge( ipconfigTCP_WIN_SEG_COUNT * sizeof(    xTCPSegments[ 0 ] ) );
        if( xTCPSegments == NULL )
        {
            FreeRTOS_debug_printf( ( "prvCreateSectors: malloc %lu failed\n",
                ipconfigTCP_WIN_SEG_COUNT * sizeof( xTCPSegments[ 0 ] ) ) );

            xReturn = pdFAIL;
        }
        else
        {
            /*2016--12--03--18--20--15(ZJYC): 清空已申请的空间   */ 
            memset( xTCPSegments, '\0', ipconfigTCP_WIN_SEG_COUNT * sizeof( xTCPSegments[ 0 ] ) );
            for( xIndex = 0; xIndex < ipconfigTCP_WIN_SEG_COUNT; xIndex++ )
            {
                /* Could call vListInitialiseItem here but all data has been
                nulled already.  Set the owner to a segment descriptor. */
                listSET_LIST_ITEM_OWNER( &( xTCPSegments[ xIndex ].xListItem ), ( void* ) &( xTCPSegments[ xIndex ] ) );
                listSET_LIST_ITEM_OWNER( &( xTCPSegments[ xIndex ].xQueueItem ), ( void* ) &( xTCPSegments[ xIndex ] ) );

                /* And add it to the pool of available segments */
                vListInsertFifo( &xSegmentList, &( xTCPSegments[xIndex].xListItem ) );
            }
            xReturn = pdPASS;
        }
        return xReturn;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : xTCPWindowRxFind
*  函数描述       : 找到接收断机和中对应于序列号ulSequenceNumber的段
*  参数           : ulSequenceNumber序列号
*  返回值         : 
                    找到：返回对应的短
                    否则：返回NULL
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static TCPSegment_t *xTCPWindowRxFind( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber )
    {
    const ListItem_t *pxIterator;
    const MiniListItem_t* pxEnd;
    TCPSegment_t *pxSegment, *pxReturn = NULL;
        /*2016--12--03--18--21--18(ZJYC): 在接收段集合中找到给定序列号的段   */ 
        pxEnd = ( const MiniListItem_t* )listGET_END_MARKER( &pxWindow->xRxSegments );
        for( pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxEnd );
             pxIterator != ( const ListItem_t * ) pxEnd;
             pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
        {
            pxSegment = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxIterator );
            if( pxSegment->ulSequenceNumber == ulSequenceNumber )
            {
                pxReturn = pxSegment;
                break;
            }
        }
        return pxReturn;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : xTCPWindowNew
*  函数描述       : (Rx/Tx)创建新的段，
*  参数           : 
                    pxWindow：窗口
                    ulSequenceNumber：本包中第一字节的序列号
                    lCount：存储在本段的字节数
                    xIsForRx：是不是接受缓冲还是发送缓冲
*  返回值         : 
                    成功：返回新创建的段
                    失败：返回NULL
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static TCPSegment_t *xTCPWindowNew( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, int32_t lCount, BaseType_t xIsForRx )
    {
    TCPSegment_t *pxSegment;
    ListItem_t * pxItem;
        /*2016--12--03--18--22--27(ZJYC): 申请一新的段，套接字将会从一共同的内存池中借段，
        xSegmentList*/ 
        if( listLIST_IS_EMPTY( &xSegmentList ) != pdFALSE )
        {
            /* If the TCP-stack runs out of segments, you might consider
            increasing 'ipconfigTCP_WIN_SEG_COUNT'. */
            FreeRTOS_debug_printf( ( "xTCPWindow%cxNew: Error: all segments occupied\n", xIsForRx ? 'R' : 'T' ) );
            pxSegment = NULL;
        }
        else
        {
            /*2016--12--03--18--24--32(ZJYC): 从列表中弹出成员，同步保护不需要，
            因为只存在一个任务调用他们*/ 
            pxItem = ( ListItem_t * ) listGET_HEAD_ENTRY( &xSegmentList );
            pxSegment = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxItem );
            configASSERT( pxItem != NULL );
            configASSERT( pxSegment != NULL );
            /*2016--12--03--18--25--57(ZJYC): 从xSegmentList删除成员   */ 
            uxListRemove( pxItem );
            /*2016--12--03--18--26--42(ZJYC): 把它放到另一个连接Rx或者Tx中   */ 
            vListInsertFifo( xIsForRx ? &pxWindow->xRxSegments : &pxWindow->xTxSegments, pxItem );
            /*2016--12--03--18--27--18(ZJYC): 并且设置本段的定时器为0   */ 
            vTCPTimerSet( &pxSegment->xTransmitTimer );
            pxSegment->u.ulFlags = 0;
            pxSegment->u.bits.bIsForRx = ( xIsForRx != 0 );
            pxSegment->lMaxLength = lCount;
            pxSegment->lDataLength = lCount;
            pxSegment->ulSequenceNumber = ulSequenceNumber;
            #if( ipconfigHAS_DEBUG_PRINTF != 0 )
            {
            static UBaseType_t xLowestLength = ipconfigTCP_WIN_SEG_COUNT;
            UBaseType_t xLength = listCURRENT_LIST_LENGTH( &xSegmentList );
                if( xLowestLength > xLength )
                {
                    xLowestLength = xLength;
                }
            }
            #endif /* ipconfigHAS_DEBUG_PRINTF */
        }
        return pxSegment;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
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
    BaseType_t xTCPWindowRxEmpty( TCPWindow_t *pxWindow )
    {
    BaseType_t xReturn;
        /*2016--12--03--18--28--01(ZJYC): 当对方有关闭请求时（FIN），驱动会检查接受队列是否存在
        丢失的包，如果接受队列为空或者最高接收序列号已被应答，则会接收关闭请求*/ 
        if( listLIST_IS_EMPTY( ( &pxWindow->xRxSegments ) ) == pdFALSE )
        {
            /*2016--12--03--18--30--01(ZJYC): 数据已存储但是早些的数据丢失了   */ 
            xReturn = pdFALSE;
        }
        else if( xSequenceGreaterThanOrEqual( pxWindow->rx.ulCurrentSequenceNumber, pxWindow->rx.ulHighestSequenceNumber ) != pdFALSE )
        {
            /*2016--12--03--18--30--31(ZJYC): 没有接收包被存储，并且最高序列号已经被应答   */ 
            xReturn = pdTRUE;
        }
        else
        {
            FreeRTOS_debug_printf( ( "xTCPWindowRxEmpty: cur %lu highest %lu (empty)\n",
                ( pxWindow->rx.ulCurrentSequenceNumber - pxWindow->rx.ulFirstSequenceNumber ),
                ( pxWindow->rx.ulHighestSequenceNumber - pxWindow->rx.ulFirstSequenceNumber ) ) );
            xReturn = pdFALSE;
        }

        return xReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : xTCPWindowGetHead
*  函数描述       : 从pxList拿走一个段，并将其返回，
*  参数           : pxList：列表
*  返回值         : 
                    成功：返回拿到的段
                    失败：返回NULL
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static TCPSegment_t *xTCPWindowGetHead( List_t *pxList )
    {
    TCPSegment_t *pxSegment;
    ListItem_t * pxItem;

        /* Detaches and returns the head of a queue. */
        if( listLIST_IS_EMPTY( pxList ) != pdFALSE )
        {
            pxSegment = NULL;
        }
        else
        {
            pxItem = ( ListItem_t * ) listGET_HEAD_ENTRY( pxList );
            pxSegment = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxItem );
            uxListRemove( pxItem );
        }
        return pxSegment;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : xTCPWindowPeekHead
*  函数描述       : 看一看pxList的首部，并不真正的拿走
*  参数           : pxList：列表
*  返回值         : 
                    成功：返回拿到的段
                    失败：返回NULL
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static TCPSegment_t *xTCPWindowPeekHead( List_t *pxList )
    {
    ListItem_t *pxItem;
    TCPSegment_t *pxReturn;

        /* Returns the head of a queue but it won't be detached. */
        if( listLIST_IS_EMPTY( pxList ) != pdFALSE )
        {
            pxReturn = NULL;
        }
        else
        {
            pxItem = ( ListItem_t * ) listGET_HEAD_ENTRY( pxList );
            pxReturn = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxItem );
        }

        return pxReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : vTCPWindowFree
*  函数描述       : 
*  参数           : 
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static void vTCPWindowFree( TCPSegment_t *pxSegment )
    {
        /*2016--12--02--17--30--37(ZJYC): 将内存返回到segment pool中   */ 
        if( listLIST_ITEM_CONTAINER( &( pxSegment->xQueueItem ) ) != NULL )
        {
            uxListRemove( &( pxSegment->xQueueItem ) );
        }
        pxSegment->ulSequenceNumber = 0u;
        pxSegment->lDataLength = 0l;
        pxSegment->u.ulFlags = 0u;
        /*2016--12--03--18--38--34(ZJYC): 从xRxSegments/xTxSegments中取出   */ 
        if( listLIST_ITEM_CONTAINER( &( pxSegment->xListItem ) ) != NULL )
        {
            uxListRemove( &( pxSegment->xListItem ) );
        }
        /*2016--12--03--18--38--54(ZJYC): 返回到xSegmentList   */ 
        vListInsertFifo( &xSegmentList, &( pxSegment->xListItem ) );
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )

    void vTCPWindowDestroy( TCPWindow_t *pxWindow )
    {
    List_t * pxSegments;
    BaseType_t xRound;
    TCPSegment_t *pxSegment;
        /*2016--12--02--17--31--32(ZJYC): 由于TCP窗口不再使用，删除之，分别RX和TX   */ 
        for( xRound = 0; xRound < 2; xRound++ )
        {
            if( xRound != 0 )
            {
                pxSegments = &( pxWindow->xRxSegments );
            }
            else
            {
                pxSegments = &( pxWindow->xTxSegments );
            }
            if( listLIST_IS_INITIALISED( pxSegments ) != pdFALSE )
            {
                while( listCURRENT_LIST_LENGTH( pxSegments ) > 0U )
                {
                    pxSegment = ( TCPSegment_t * ) listGET_OWNER_OF_HEAD_ENTRY( pxSegments );
                    vTCPWindowFree( pxSegment );
                }
            }
        }
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

void vTCPWindowCreate( TCPWindow_t *pxWindow, uint32_t ulRxWindowLength,
    uint32_t ulTxWindowLength, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS )
{
    /*2016--12--02--17--32--29(ZJYC): 创建并初始化一窗口   */ 
    #if( ipconfigUSE_TCP_WIN == 1 )
    {
        if( xTCPSegments == NULL )
        {
            prvCreateSectors();
        }
        vListInitialise( &pxWindow->xTxSegments );      /*2016--12--02--17--33--02(ZJYC): 需发送组   */ 
        vListInitialise( &pxWindow->xRxSegments );      /*2016--12--02--17--33--11(ZJYC): 需接收组   */ 
        vListInitialise( &pxWindow->xPriorityQueue );   /*2016--12--02--17--33--26(ZJYC): 优先组（必须被马上发送）   */ 
        vListInitialise( &pxWindow->xTxQueue   );       /*2016--12--02--17--37--14(ZJYC): 排队等待发送   */ 
        vListInitialise( &pxWindow->xWaitQueue );       /*2016--12--02--17--37--44(ZJYC): 等待确认组   */ 
    }
    #endif /* ipconfigUSE_TCP_WIN == 1 */
    if( xTCPWindowLoggingLevel != 0 )
    {
        FreeRTOS_debug_printf( ( "vTCPWindowCreate: for WinLen = Rx/Tx: %lu/%lu\n",ulRxWindowLength, ulTxWindowLength ) );
    }
    pxWindow->xSize.ulRxWindowLength = ulRxWindowLength;
    pxWindow->xSize.ulTxWindowLength = ulTxWindowLength;
    vTCPWindowInit( pxWindow, ulAckNumber, ulSequenceNumber, ulMSS );
}
/*-----------------------------------------------------------*/

void vTCPWindowInit( TCPWindow_t *pxWindow, uint32_t ulAckNumber, uint32_t ulSequenceNumber, uint32_t ulMSS )
{
const int32_t l500ms = 500;

    pxWindow->u.ulFlags = 0ul;
    pxWindow->u.bits.bHasInit = pdTRUE_UNSIGNED;

    if( ulMSS != 0ul )
    {
        if( pxWindow->usMSSInit != 0u )
        {
            pxWindow->usMSSInit = ( uint16_t ) ulMSS;
        }

        if( ( ulMSS < ( uint32_t ) pxWindow->usMSS ) || ( pxWindow->usMSS == 0u ) )
        {
            pxWindow->xSize.ulRxWindowLength = ( pxWindow->xSize.ulRxWindowLength / ulMSS ) * ulMSS;
            pxWindow->usMSS = ( uint16_t ) ulMSS;
        }
    }

    #if( ipconfigUSE_TCP_WIN == 0 )
    {
        pxWindow->xTxSegment.lMaxLength = ( int32_t ) pxWindow->usMSS;
    }
    #endif /* ipconfigUSE_TCP_WIN == 1 */

    /*Start with a timeout of 2 * 500 ms (1 sec). */
    pxWindow->lSRTT = l500ms;

    /* Just for logging, to print relative sequence numbers. */
    pxWindow->rx.ulFirstSequenceNumber = ulAckNumber;

    /* The segment asked for in the next transmission. */
    pxWindow->rx.ulCurrentSequenceNumber = ulAckNumber;

    /* The right-hand side of the receive window. */
    pxWindow->rx.ulHighestSequenceNumber = ulAckNumber;

    pxWindow->tx.ulFirstSequenceNumber = ulSequenceNumber;

    /* The segment asked for in next transmission. */
    pxWindow->tx.ulCurrentSequenceNumber = ulSequenceNumber;

    /* The sequence number given to the next outgoing byte to be added is
    maintained by lTCPWindowTxAdd(). */
    pxWindow->ulNextTxSequenceNumber = ulSequenceNumber;

    /* The right-hand side of the transmit window. */
    pxWindow->tx.ulHighestSequenceNumber = ulSequenceNumber;
    pxWindow->ulOurSequenceNumber = ulSequenceNumber;
}
/*-----------------------------------------------------------*/

/*=============================================================================
 *
 *                ######        #    #
 *                 #    #       #    #
 *                 #    #       #    #
 *                 #    #        ####
 *                 ######         ##
 *                 #  ##         ####
 *                 #   #        #    #
 *                 #    #       #    #
 *                ###  ##       #    #
 * Rx functions
 *
 *=============================================================================*/

#if( ipconfigUSE_TCP_WIN == 1 )
    /*2016--12--02--18--41--19(ZJYC): 收到一个带着ulSequenceNumber的段，当ulCurrentSequenceNumber =  ulSequenceNumber表示这确实是我们所期望的。本函数用于检查是否存在序列号介于ulSequenceNumber和(ulSequenceNumber+ulLength)的包，一般情况下是没有的，下一个应该接受的段的序列号应等于(ulSequenceNumber+ulLength)*/ 
    static TCPSegment_t *xTCPWindowRxConfirm( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength )
    {
    TCPSegment_t *pxBest = NULL;
    const ListItem_t *pxIterator;
    uint32_t ulNextSequenceNumber = ulSequenceNumber + ulLength;
    const MiniListItem_t* pxEnd = ( const MiniListItem_t* ) listGET_END_MARKER( &pxWindow->xRxSegments );
    TCPSegment_t *pxSegment;

        /* A segment has been received with sequence number 'ulSequenceNumber',
        where 'ulCurrentSequenceNumber == ulSequenceNumber', which means that
        exactly this segment was expected.  xTCPWindowRxConfirm() will check if
        there is already another segment with a sequence number between (ulSequenceNumber)
        and (ulSequenceNumber+ulLength).  Normally none will be found, because
        the next RX segment should have a sequence number equal to
        '(ulSequenceNumber+ulLength)'. */

        /* Iterate through all RX segments that are stored: */
        for( pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxEnd );
             pxIterator != ( const ListItem_t * ) pxEnd;
             pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
        {
            pxSegment = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxIterator );
            /* And see if there is a segment for which:
            'ulSequenceNumber' <= 'pxSegment->ulSequenceNumber' < 'ulNextSequenceNumber'
            If there are more matching segments, the one with the lowest sequence number
            shall be taken */
            if( ( xSequenceGreaterThanOrEqual( pxSegment->ulSequenceNumber, ulSequenceNumber ) != 0 ) &&
                ( xSequenceLessThan( pxSegment->ulSequenceNumber, ulNextSequenceNumber ) != 0 ) )
            {
                if( ( pxBest == NULL ) || ( xSequenceLessThan( pxSegment->ulSequenceNumber, pxBest->ulSequenceNumber ) != 0 ) )
                {
                    pxBest = pxSegment;
                }
            }
        }

        if( ( pxBest != NULL ) &&
            ( ( pxBest->ulSequenceNumber != ulSequenceNumber ) || ( pxBest->lDataLength != ( int32_t ) ulLength ) ) )
        {
            FreeRTOS_flush_logging();
            FreeRTOS_debug_printf( ( "xTCPWindowRxConfirm[%u]: search %lu (+%ld=%lu) found %lu (+%ld=%lu)\n",
                pxWindow->usPeerPortNumber,
                ulSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                ulLength,
                ulSequenceNumber + ulLength - pxWindow->rx.ulFirstSequenceNumber,
                pxBest->ulSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                pxBest->lDataLength,
                pxBest->ulSequenceNumber + ( ( uint32_t ) pxBest->lDataLength ) - pxWindow->rx.ulFirstSequenceNumber ) );
        }

        return pxBest;
    }

#endif /* ipconfgiUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
    /*2016--12--02--18--45--44(ZJYC): 如果lTCPWindowRxCheck返回0，包会直接传递给用户，如果返回正数，一个之前的报丢失了
    但是这个包会被保存，如果是负数，包早就被保存了，后者，这是一非顺序包或没有足够的内存了。*/ 
    int32_t lTCPWindowRxCheck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength, uint32_t ulSpace )
    {
    uint32_t ulCurrentSequenceNumber, ulLast, ulSavedSequenceNumber;
    int32_t lReturn, lDistance;
    TCPSegment_t *pxFound;

        /* If lTCPWindowRxCheck( ) returns == 0, the packet will be passed
        directly to user (segment is expected).  If it returns a positive
        number, an earlier packet is missing, but this packet may be stored.
        If negative, the packet has already been stored, or it is out-of-order,
        or there is not enough space.

        As a side-effect, pxWindow->ulUserDataLength will get set to non-zero,
        if more Rx data may be passed to the user after this packet. */

        ulCurrentSequenceNumber = pxWindow->rx.ulCurrentSequenceNumber;

        /* For Selective Ack (SACK), used when out-of-sequence data come in. */
        pxWindow->ucOptionLength = 0u;

        /* Non-zero if TCP-windows contains data which must be popped. */
        pxWindow->ulUserDataLength = 0ul;

        if( ulCurrentSequenceNumber == ulSequenceNumber )
        {
            /* This is the packet with the lowest sequence number we're waiting
            for.  It can be passed directly to the rx stream. */
            if( ulLength > ulSpace )
            {
                FreeRTOS_debug_printf( ( "lTCPWindowRxCheck: Refuse %lu bytes, due to lack of space (%lu)\n", ulLength, ulSpace ) );
                lReturn = -1;
            }
            else
            {
                ulCurrentSequenceNumber += ulLength;

                if( listCURRENT_LIST_LENGTH( &( pxWindow->xRxSegments ) ) != 0 )
                {
                    ulSavedSequenceNumber = ulCurrentSequenceNumber;

                    /* See if (part of) this segment has been stored already,
                    but this rarely happens. */
                    pxFound = xTCPWindowRxConfirm( pxWindow, ulSequenceNumber, ulLength );
                    if( pxFound != NULL )
                    {
                        ulCurrentSequenceNumber = pxFound->ulSequenceNumber + ( ( uint32_t ) pxFound->lDataLength );

                        /* Remove it because it will be passed to user directly. */
                        vTCPWindowFree( pxFound );
                    }

                    /*  Check for following segments that are already in the
                    queue and increment ulCurrentSequenceNumber. */
                    while( ( pxFound = xTCPWindowRxFind( pxWindow, ulCurrentSequenceNumber ) ) != NULL )
                    {
                        ulCurrentSequenceNumber += ( uint32_t ) pxFound->lDataLength;

                        /* As all packet below this one have been passed to the
                        user it can be discarded. */
                        vTCPWindowFree( pxFound );
                    }

                    if( ulSavedSequenceNumber != ulCurrentSequenceNumber )
                    {
                        /*  After the current data-package, there is more data
                        to be popped. */
                        pxWindow->ulUserDataLength = ulCurrentSequenceNumber - ulSavedSequenceNumber;

                        if( xTCPWindowLoggingLevel >= 1 )
                        {
                            FreeRTOS_debug_printf( ( "lTCPWindowRxCheck[%d,%d]: retran %lu (Found %lu bytes at %lu cnt %ld)\n",
                                pxWindow->usPeerPortNumber, pxWindow->usOurPortNumber,
                                ulSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                                pxWindow->ulUserDataLength,
                                ulSavedSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                                listCURRENT_LIST_LENGTH( &pxWindow->xRxSegments ) ) );
                        }
                    }
                }

                pxWindow->rx.ulCurrentSequenceNumber = ulCurrentSequenceNumber;

                /* Packet was expected, may be passed directly to the socket
                buffer or application.  Store the packet at offset 0. */
                lReturn = 0;
            }
        }
        else if( ulCurrentSequenceNumber == ( ulSequenceNumber + 1UL ) )
        {
            /* Looks like a TCP keep-alive message.  Do not accept/store Rx data
            ulUserDataLength = 0. Not packet out-of-sync.  Just reply to it. */
            lReturn = -1;
        }
        else
        {
            /* The packet is not the one expected.  See if it falls within the Rx
            window so it can be stored. */

            /*  An "out-of-sequence" segment was received, must have missed one.
            Prepare a SACK (Selective ACK). */
            ulLast = ulSequenceNumber + ulLength;
            lDistance = ( int32_t ) ( ulLast - ulCurrentSequenceNumber );

            if( lDistance <= 0 )
            {
                /* An earlier has been received, must be a retransmission of a
                packet that has been accepted already.  No need to send out a
                Selective ACK (SACK). */
                lReturn = -1;
            }
            else if( lDistance > ( int32_t ) ulSpace )
            {
                /* The new segment is ahead of rx.ulCurrentSequenceNumber.  The
                sequence number of this packet is too far ahead, ignore it. */
                FreeRTOS_debug_printf( ( "lTCPWindowRxCheck: Refuse %lu+%lu bytes, due to lack of space (%lu)\n", lDistance, ulLength, ulSpace ) );
                lReturn = -1;
            }
            else
            {
                /* See if there is more data in a contiguous block to make the
                SACK describe a longer range of data. */

                /* TODO: SACK's may also be delayed for a short period
                 * This is useful because subsequent packets will be SACK'd with
                 * single one message
                 */
                while( ( pxFound = xTCPWindowRxFind( pxWindow, ulLast ) ) != NULL )
                {
                    ulLast += ( uint32_t ) pxFound->lDataLength;
                }

                if( xTCPWindowLoggingLevel >= 1 )
                {
                    FreeRTOS_debug_printf( ( "lTCPWindowRxCheck[%d,%d]: seqnr %lu exp %lu (dist %ld) SACK to %lu\n",
                        pxWindow->usPeerPortNumber, pxWindow->usOurPortNumber,
                        ulSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                        ulCurrentSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                        ( BaseType_t ) ( ulSequenceNumber - ulCurrentSequenceNumber ),  /* want this signed */
                        ulLast - pxWindow->rx.ulFirstSequenceNumber ) );
                }

                /* Now prepare the SACK message.
                Code OPTION_CODE_SINGLE_SACK already in network byte order. */
                pxWindow->ulOptionsData[0] = OPTION_CODE_SINGLE_SACK;

                /* First sequence number that we received. */
                pxWindow->ulOptionsData[1] = FreeRTOS_htonl( ulSequenceNumber );

                /* Last + 1 */
                pxWindow->ulOptionsData[2] = FreeRTOS_htonl( ulLast );

                /* Which make 12 (3*4) option bytes. */
                pxWindow->ucOptionLength = 3 * sizeof( pxWindow->ulOptionsData[ 0 ] );

                pxFound = xTCPWindowRxFind( pxWindow, ulSequenceNumber );

                if( pxFound != NULL )
                {
                    /* This out-of-sequence packet has been received for a
                    second time.  It is already stored but do send a SACK
                    again. */
                    lReturn = -1;
                }
                else
                {
                    pxFound = xTCPWindowRxNew( pxWindow, ulSequenceNumber, ( int32_t ) ulLength );

                    if( pxFound == NULL )
                    {
                        /* Can not send a SACK, because the segment cannot be
                        stored. */
                        pxWindow->ucOptionLength = 0u;

                        /* Needs to be stored but there is no segment
                        available. */
                        lReturn = -1;
                    }
                    else
                    {
                        if( xTCPWindowLoggingLevel != 0 )
                        {
                            FreeRTOS_debug_printf( ( "lTCPWindowRxCheck[%u,%u]: seqnr %lu (cnt %lu)\n",
                                pxWindow->usPeerPortNumber, pxWindow->usOurPortNumber, ulSequenceNumber - pxWindow->rx.ulFirstSequenceNumber,
                                listCURRENT_LIST_LENGTH( &pxWindow->xRxSegments ) ) );
                            FreeRTOS_flush_logging( );
                        }

                        /* Return a positive value.  The packet may be accepted
                        and stored but an earlier packet is still missing. */
                        lReturn = ( int32_t ) ( ulSequenceNumber - ulCurrentSequenceNumber );
                    }
                }
            }
        }

        return lReturn;
    }

#endif /* ipconfgiUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

/*=============================================================================
 *
 *                    #########   #    #
 *                    #   #   #   #    #
 *                        #       #    #
 *                        #        ####
 *                        #         ##
 *                        #        ####
 *                        #       #    #
 *                        #       #    #
 *                      #####     #    #
 *
 * Tx functions
 *
 *=============================================================================*/

#if( ipconfigUSE_TCP_WIN == 1 )

    static int32_t lTCPIncrementTxPosition( int32_t lPosition, int32_t lMax, int32_t lCount )
    {
        /* +TCP stores data in circular buffers.  Calculate the next position to
        store. */
        lPosition += lCount;
        if( lPosition >= lMax )
        {
            lPosition -= lMax;
        }
        return lPosition;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : lTCPWindowTxAdd
*  函数描述       : 我们有ulLength数据要发送，
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
    int32_t lTCPWindowTxAdd( TCPWindow_t *pxWindow, uint32_t ulLength, int32_t lPosition, int32_t lMax )
    {
    int32_t lBytesLeft = ( int32_t ) ulLength, lToWrite;
    int32_t lDone = 0;
    TCPSegment_t *pxSegment = pxWindow->pxHeadSegment;

        /* Puts a message in the Tx-window (after buffer size has been
        verified). */
        if( pxSegment != NULL )
        {
            /* 此段还有空闲空间 */
            if( pxSegment->lDataLength < pxSegment->lMaxLength )
            {
                /* 此段没有等待应答 && 此段数据非空 */
                if( ( pxSegment->u.bits.bOutstanding == pdFALSE_UNSIGNED ) && ( pxSegment->lDataLength != 0 ) )
                {
                    /*2016--12--02--18--50--21(ZJYC): 把数据添加到TX队列，将会被调整到MSS   */ 
                    /*2016--12--02--18--54--13(ZJYC): 寻找待发送数据和pool空闲值之中的最小值   */ 
                    /* 计算此段可以存储多少字节 */
                    lToWrite = FreeRTOS_min_int32( lBytesLeft, pxSegment->lMaxLength - pxSegment->lDataLength );
                    pxSegment->lDataLength += lToWrite;
                    if( pxSegment->lDataLength >= pxSegment->lMaxLength )
                    {
                        /* 本段已经填满了 */
                        pxWindow->pxHeadSegment = NULL;
                    }
                    /* 总字节数减少lToWrite */
                    lBytesLeft -= lToWrite;
                    /* 计算下一次发送的序列号 */
                    pxWindow->ulNextTxSequenceNumber += ( uint32_t ) lToWrite;
                    /* 我们填入了多少字节 */
                    lDone += lToWrite;

                    /* Some detailed logging, for those who're interested. */
                    if( ( xTCPWindowLoggingLevel >= 2 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != 0 ) )
                    {
                        FreeRTOS_debug_printf( ( "lTCPWindowTxAdd: Add %4lu bytes for seqNr %lu len %4lu (nxt %lu) pos %lu\n",
                            ulLength,
                            pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                            pxSegment->lDataLength,
                            pxWindow->ulNextTxSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                            pxSegment->lStreamPos ) );
                        FreeRTOS_flush_logging( );
                    }

                    /* 在已知最大为lMax的情况下计算下一次需要写入的位置 */
                    lPosition = lTCPIncrementTxPosition( lPosition, lMax, lToWrite );
                }
            }
        }
        /* 还有数据需要发送 */
        while( lBytesLeft > 0 )
        {
            /*2016--12--02--18--54--45(ZJYC): Pool并没有城下所有的待发送数据，需要新建   */ 
            pxSegment = xTCPWindowTxNew( pxWindow, pxWindow->ulNextTxSequenceNumber, pxWindow->usMSS );
            if( pxSegment != NULL )
            {
                /* Store as many as needed, but no more than the maximum
                (MSS). */
                lToWrite = FreeRTOS_min_int32( lBytesLeft, pxSegment->lMaxLength );
                pxSegment->lDataLength = lToWrite;
                pxSegment->lStreamPos = lPosition;
                lBytesLeft -= lToWrite;
                lPosition = lTCPIncrementTxPosition( lPosition, lMax, lToWrite );
                pxWindow->ulNextTxSequenceNumber += ( uint32_t ) lToWrite;
                lDone += lToWrite;
                /*2016--12--02--18--53--04(ZJYC): 加入发送队列   */ 
                vListInsertFifo( &( pxWindow->xTxQueue ), &( pxSegment->xQueueItem ) );
                /* Let 'pxHeadSegment' point to this segment if there is still
                space. */
                if( pxSegment->lDataLength < pxSegment->lMaxLength )
                {
                    pxWindow->pxHeadSegment = pxSegment;
                }
                else
                {
                    pxWindow->pxHeadSegment = NULL;
                }

                if( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != 0 )
                {
                    if( ( xTCPWindowLoggingLevel >= 3 ) ||
                        ( ( xTCPWindowLoggingLevel >= 2 ) && ( pxWindow->pxHeadSegment != NULL ) ) )
                    {
                        FreeRTOS_debug_printf( ( "lTCPWindowTxAdd: New %4ld bytes for seqNr %lu len %4lu (nxt %lu) pos %lu\n",
                            ulLength,
                            pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                            pxSegment->lDataLength,
                            pxWindow->ulNextTxSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                            pxSegment->lStreamPos ) );
                        FreeRTOS_flush_logging( );
                    }
                }
            }
            else
            {
                /* A sever situation: running out of segments for transmission.
                No more data can be sent at the moment. */
                if( lDone != 0 )
                {
                    FreeRTOS_debug_printf( ( "lTCPWindowTxAdd: Sorry all buffers full (cancel %ld bytes)\n", lBytesLeft ) );
                }
                break;
            }
        }

        return lDone;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )

    BaseType_t xTCPWindowTxDone( TCPWindow_t *pxWindow )
    {
        return listLIST_IS_EMPTY( ( &pxWindow->xTxSegments) );
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
    /*2016--12--02--18--56--30(ZJYC): 看看是否还有数据需要发送，是返回true   */ 
    /* 看看滑动窗口是否还有发送的空间 */
    static BaseType_t prvTCPWindowTxHasSpace( TCPWindow_t *pxWindow, uint32_t ulWindowSize )
    {
    uint32_t ulTxOutstanding;
    BaseType_t xHasSpace;
    TCPSegment_t *pxSegment;
        pxSegment = xTCPWindowPeekHead( &( pxWindow->xTxQueue ) );
        if( pxSegment == NULL )
        {
            xHasSpace = pdFALSE;
        }
        else
        {
            /*2016--12--02--18--57--11(ZJYC): 有多少数据在等待应答   */ 
            if( pxWindow->tx.ulHighestSequenceNumber >= pxWindow->tx.ulCurrentSequenceNumber )
            {
                ulTxOutstanding = pxWindow->tx.ulHighestSequenceNumber - pxWindow->tx.ulCurrentSequenceNumber;
            }
            else
            {
                ulTxOutstanding = 0UL;
            }

            /* Subtract this from the peer's space. */
            ulWindowSize -= FreeRTOS_min_uint32( ulWindowSize, ulTxOutstanding );

            /* See if the next segment may be sent. */
            if( ulWindowSize >= ( uint32_t ) pxSegment->lDataLength )
            {
                xHasSpace = pdTRUE;
            }
            else
            {
                xHasSpace = pdFALSE;
            }

            /* If 'xHasSpace', it looks like the peer has at least space for 1
            more new segment of size MSS.  xSize.ulTxWindowLength is the self-imposed
            limitation of the transmission window (in case of many resends it
            may be decreased). */
            if( ( ulTxOutstanding != 0UL ) && ( pxWindow->xSize.ulTxWindowLength < ulTxOutstanding + ( ( uint32_t ) pxSegment->lDataLength ) ) )
            {
                xHasSpace = pdFALSE;
            }
        }

        return xHasSpace;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : xTCPWindowTxHasData
*  函数描述       : 确认是否有数据要发送，并计算发送延迟时间
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
    BaseType_t xTCPWindowTxHasData( TCPWindow_t *pxWindow, uint32_t ulWindowSize, TickType_t *pulDelay )
    {
    TCPSegment_t *pxSegment;
    BaseType_t xReturn;
    TickType_t ulAge, ulMaxAge;
        *pulDelay = 0u;
        if( listLIST_IS_EMPTY( &pxWindow->xPriorityQueue ) == pdFALSE )
        {
            /*2016--12--02--18--58--49(ZJYC): 如果优先组存在，就没有必要重传
            pulDelay为0 表示必须立即发送*/ 
            xReturn = pdTRUE;
        }
        else
        {
            pxSegment = xTCPWindowPeekHead( &( pxWindow->xWaitQueue ) );
            if( pxSegment != NULL )
            {
                /*2016--12--02--19--00--40(ZJYC): 存在等待应答组，看看是否需要超时重传   */ 
                ulAge = ulTimerGetAge( &pxSegment->xTransmitTimer );
                ulMaxAge = ( 1u << pxSegment->u.bits.ucTransmitCount ) * ( ( uint32_t ) pxWindow->lSRTT );
                if( ulMaxAge > ulAge )
                {
                    /*2016--12--02--19--01--24(ZJYC): 这些时间后发送   */ 
                    *pulDelay = ulMaxAge - ulAge;
                }
                xReturn = pdTRUE;
            }
            else
            {
                /*2016--12--02--19--01--51(ZJYC): 不存在优先组，不存在等待应答，看看是否有数据要发送   */ 
                pxSegment = xTCPWindowPeekHead( &pxWindow->xTxQueue );
                /*2016--12--02--19--02--31(ZJYC): 是否与对方的接收窗口相匹配   */ 
                if( pxSegment == NULL )
                {
                    xReturn = pdFALSE;
                }
                else if( prvTCPWindowTxHasSpace( pxWindow, ulWindowSize ) == pdFALSE )
                {
                    /*2016--12--02--19--03--36(ZJYC): 等待应答的太多了   */ 
                    xReturn = pdFALSE;
                }
                else if( ( pxWindow->u.bits.bSendFullSize != pdFALSE_UNSIGNED ) && ( pxSegment->lDataLength < pxSegment->lMaxLength ) )
                {
                    /* 'bSendFullSize' is a special optimisation.  If true, the
                    driver will only sent completely filled packets (of MSS
                    bytes). */
                    xReturn = pdFALSE;
                }
                else
                {
                    xReturn = pdTRUE;
                }
            }
        }
        return xReturn;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : ulTCPWindowTxGet
*  函数描述       : 得到现在需要发送的数据
*  参数           : 
                    ulTCPWindowTxGet：
                    ulWindowSize：
                    plPosition：
*  返回值         : 
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    uint32_t ulTCPWindowTxGet( TCPWindow_t *pxWindow, uint32_t ulWindowSize, int32_t *plPosition )
    {
    TCPSegment_t *pxSegment;
    uint32_t ulMaxTime;
    uint32_t ulReturn  = ~0UL;
        /*2016--12--02--19--04--31(ZJYC): 得到现在需要发送的数据，优先组不需要检查窗口大小   */ 
        pxSegment = xTCPWindowGetHead( &( pxWindow->xPriorityQueue ) );
        pxWindow->ulOurSequenceNumber = pxWindow->tx.ulHighestSequenceNumber;
        if( pxSegment == NULL )
        {
            /*2016--12--02--19--06--15(ZJYC): 等待应答组：这也不需要检查窗口大小
            因为他们早就被发送了*/ 
            pxSegment = xTCPWindowPeekHead( &( pxWindow->xWaitQueue ) );
            if( pxSegment != NULL )
            {
                /*2016--12--02--19--07--13(ZJYC): 检查时间   */ 
                ulMaxTime = ( 1u << pxSegment->u.bits.ucTransmitCount ) * ( ( uint32_t ) pxWindow->lSRTT );
                if( ulTimerGetAge( &pxSegment->xTransmitTimer ) > ulMaxTime )
                {
                    /*2016--12--02--19--09--00(ZJYC): 普通重传，从等待列表删除   */ 
                    pxSegment = xTCPWindowGetHead( &( pxWindow->xWaitQueue ) );
                    pxSegment->u.bits.ucDupAckCount = pdFALSE_UNSIGNED;
                    /* Some detailed logging. */
                    if( ( xTCPWindowLoggingLevel != 0 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != 0 ) )
                    {
                        FreeRTOS_debug_printf( ( "ulTCPWindowTxGet[%u,%u]: WaitQueue %ld bytes for sequence number %lu (%lX)\n",
                            pxWindow->usPeerPortNumber,
                            pxWindow->usOurPortNumber,
                            pxSegment->lDataLength,
                            pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                            pxSegment->ulSequenceNumber ) );
                        FreeRTOS_flush_logging( );
                    }
                }
                else
                {
                    pxSegment = NULL;
                }
            }
            if( pxSegment == NULL )
            {
                /*2016--12--02--19--09--53(ZJYC): 新的要发送的数据，检查窗口   */ 
                pxSegment = xTCPWindowPeekHead( &( pxWindow->xTxQueue ) );
                if( pxSegment == NULL )
                {
                    /*2016--12--02--19--10--17(ZJYC): 没有要发送的数据   */ 
                    ulReturn = 0UL;
                }
                else if( ( pxWindow->u.bits.bSendFullSize != pdFALSE_UNSIGNED ) && ( pxSegment->lDataLength < pxSegment->lMaxLength ) )
                {
                    /*2016--12--02--19--10--43(ZJYC): 有数据要发送，但是驱动需要某一大小的数据   */ 
                    ulReturn = 0;
                }
                else if( prvTCPWindowTxHasSpace( pxWindow, ulWindowSize ) == pdFALSE )
                {
                    /*2016--12--02--19--11--19(ZJYC): 对方没有空间了   */ 
                    ulReturn = 0;
                }
                else
                {
                    /*2016--12--02--19--11--40(ZJYC): 从Tx队列删除，   */ 
                    pxSegment = xTCPWindowGetHead( &( pxWindow->xTxQueue ) );
                    if( pxWindow->pxHeadSegment == pxSegment )
                    {
                        pxWindow->pxHeadSegment = NULL;
                    }

                    /* pxWindow->tx.highest registers the highest sequence
                    number in our transmission window. */
                    pxWindow->tx.ulHighestSequenceNumber = pxSegment->ulSequenceNumber + ( ( uint32_t ) pxSegment->lDataLength );

                    /* ...and more detailed logging */
                    if( ( xTCPWindowLoggingLevel >= 2 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE ) )
                    {
                        FreeRTOS_debug_printf( ( "ulTCPWindowTxGet[%u,%u]: XmitQueue %ld bytes for sequence number %lu (ws %lu)\n",
                            pxWindow->usPeerPortNumber,
                            pxWindow->usOurPortNumber,
                            pxSegment->lDataLength,
                            pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                            ulWindowSize ) );
                        FreeRTOS_flush_logging( );
                    }
                }
            }
        }
        else
        {
            /*2016--12--02--19--12--41(ZJYC): 存在优先组不做超时检查和空间检查   */ 
            if( xTCPWindowLoggingLevel != 0 )
            {
                FreeRTOS_debug_printf( ( "ulTCPWindowTxGet[%u,%u]: PrioQueue %ld bytes for sequence number %lu (ws %lu)\n",
                    pxWindow->usPeerPortNumber,
                    pxWindow->usOurPortNumber,
                    pxSegment->lDataLength,
                    pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                    ulWindowSize ) );
                FreeRTOS_flush_logging( );
            }
        }

        /* See if it has already been determined to return 0. */
        if( ulReturn != 0UL )
        {
            configASSERT( listLIST_ITEM_CONTAINER( &(pxSegment->xQueueItem ) ) == NULL );

            /* Now that the segment will be transmitted, add it to the tail of
            the waiting queue. */
            vListInsertFifo( &pxWindow->xWaitQueue, &pxSegment->xQueueItem );

            /* And mark it as outstanding. */
            pxSegment->u.bits.bOutstanding = pdTRUE_UNSIGNED;

            /* Administer the transmit count, needed for fast
            retransmissions. */
            ( pxSegment->u.bits.ucTransmitCount )++;

            /* If there have been several retransmissions (4), decrease the
            size of the transmission window to at most 2 times MSS. */
            if( pxSegment->u.bits.ucTransmitCount == MAX_TRANSMIT_COUNT_USING_LARGE_WINDOW )
            {
                if( pxWindow->xSize.ulTxWindowLength > ( 2U * pxWindow->usMSS ) )
                {
                    FreeRTOS_debug_printf( ( "ulTCPWindowTxGet[%u - %d]: Change Tx window: %lu -> %u\n",
                        pxWindow->usPeerPortNumber, pxWindow->usOurPortNumber,
                        pxWindow->xSize.ulTxWindowLength, 2 * pxWindow->usMSS ) );
                    pxWindow->xSize.ulTxWindowLength = ( 2UL * pxWindow->usMSS );
                }
            }

            /* Clear the transmit timer. */
            vTCPTimerSet( &( pxSegment->xTransmitTimer ) );

            pxWindow->ulOurSequenceNumber = pxSegment->ulSequenceNumber;

            /* Inform the caller where to find the data within the queue. */
            *plPosition = pxSegment->lStreamPos;

            /* And return the length of the data segment */
            ulReturn = ( uint32_t ) pxSegment->lDataLength;
        }

        return ulReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
    /*2016--12--05--14--00--46(ZJYC): ulFirst和ulLast指明了确认的范围，在此范围内的数据被确认   */ 
/*
****************************************************
*  函数名         : prvTCPWindowTxCheckAck
*  函数描述       : 收到一SACK，处理之
*  参数           : 
*  返回值         : 被应答的数据长度
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static uint32_t prvTCPWindowTxCheckAck( TCPWindow_t *pxWindow, uint32_t ulFirst, uint32_t ulLast )
    {
    uint32_t ulBytesConfirmed = 0u;
    uint32_t ulSequenceNumber = ulFirst, ulDataLength;
    const ListItem_t *pxIterator;
    const MiniListItem_t *pxEnd = ( const MiniListItem_t* )listGET_END_MARKER( &pxWindow->xTxSegments );
    BaseType_t xDoUnlink;
    TCPSegment_t *pxSegment;
    /*2016--12--02--19--18--20(ZJYC): 收到了应答或者是选择性应答，看看那些等待应答的数据包可以从发送对流清除   */ 
        for(
                pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxEnd );
                ( pxIterator != ( const ListItem_t * ) pxEnd ) && ( xSequenceLessThan( ulSequenceNumber, ulLast ) != 0 );
            )
        {
            xDoUnlink = pdFALSE;
            pxSegment = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxIterator );
            /* Move to the next item because the current item might get
            removed. */
            pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator );
            /*2016--12--05--13--56--33(ZJYC): 如果段不在ACK范围之内则跳过   */ 
            if( xSequenceGreaterThan( ulSequenceNumber, pxSegment->ulSequenceNumber ) != pdFALSE )
            {
                continue;
            }
            /* Is it ready? */
            if( ulSequenceNumber != pxSegment->ulSequenceNumber )
            {
                break;
            }
            ulDataLength = ( uint32_t ) pxSegment->lDataLength;
            if( pxSegment->u.bits.bAcked == pdFALSE_UNSIGNED )
            {
                if( xSequenceGreaterThan( pxSegment->ulSequenceNumber + ( uint32_t )ulDataLength, ulLast ) != pdFALSE )
                {
                    /* 后边的数据我们还没发送，却应答了 */
                    /* What happens?  Only part of this segment was accepted,
                    probably due to WND limits

                      AAAAAAA BBBBBBB << acked
                      aaaaaaa aaaa    << sent */
                    #if( ipconfigHAS_DEBUG_PRINTF != 0 )
                    {
                        uint32_t ulFirstSeq = pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber;
                        FreeRTOS_debug_printf( ( "prvTCPWindowTxCheckAck[%u.%u]: %lu - %lu Partial sequence number %lu - %lu\n",
                            pxWindow->usPeerPortNumber,
                            pxWindow->usOurPortNumber,
                            ulFirstSeq - pxWindow->tx.ulFirstSequenceNumber,
                            ulLast - pxWindow->tx.ulFirstSequenceNumber,
                            ulFirstSeq, ulFirstSeq + ulDataLength ) );
                    }
                    #endif /* ipconfigHAS_DEBUG_PRINTF */
                    break;
                }
                /* This segment is fully ACK'd, set the flag. */
                pxSegment->u.bits.bAcked = pdTRUE_UNSIGNED;
                /* Calculate the RTT only if the segment was sent-out for the
                first time and if this is the last ACK'd segment in a range. */
                if( ( pxSegment->u.bits.ucTransmitCount == 1 ) && ( ( pxSegment->ulSequenceNumber + ulDataLength ) == ulLast ) )
                {
                    int32_t mS = ( int32_t ) ulTimerGetAge( &( pxSegment->xTransmitTimer ) );
                    if( pxWindow->lSRTT >= mS )
                    {
                        /* RTT becomes smaller: adapt slowly. */
                        pxWindow->lSRTT = ( ( winSRTT_DECREMENT_NEW * mS ) + ( winSRTT_DECREMENT_CURRENT * pxWindow->lSRTT ) ) / ( winSRTT_DECREMENT_NEW + winSRTT_DECREMENT_CURRENT );
                    }
                    else
                    {
                        /* RTT becomes larger: adapt quicker */
                        pxWindow->lSRTT = ( ( winSRTT_INCREMENT_NEW * mS ) + ( winSRTT_INCREMENT_CURRENT * pxWindow->lSRTT ) ) / ( winSRTT_INCREMENT_NEW + winSRTT_INCREMENT_CURRENT );
                    }
                    /* Cap to the minimum of 50ms. */
                    if( pxWindow->lSRTT < winSRTT_CAP_mS )
                    {
                        pxWindow->lSRTT = winSRTT_CAP_mS;
                    }
                }
                /* Unlink it from the 3 queues, but do not destroy it (yet). */
                xDoUnlink = pdTRUE;
            }
            /* pxSegment->u.bits.bAcked is now true.  Is it located at the left
            side of the transmission queue?  If so, it may be freed. */
            if( ulSequenceNumber == pxWindow->tx.ulCurrentSequenceNumber )
            {
                if( ( xTCPWindowLoggingLevel >= 2 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE ) )
                {
                    FreeRTOS_debug_printf( ( "prvTCPWindowTxCheckAck: %lu - %lu Ready sequence number %lu\n",
                        ulFirst - pxWindow->tx.ulFirstSequenceNumber,
                        ulLast - pxWindow->tx.ulFirstSequenceNumber,
                        pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber ) );
                }
                /* Increase the left-hand value of the transmission window. */
                pxWindow->tx.ulCurrentSequenceNumber += ulDataLength;
                /* This function will return the number of bytes that the tail
                of txStream may be advanced. */
                ulBytesConfirmed += ulDataLength;
                /* All segments below tx.ulCurrentSequenceNumber may be freed. */
                vTCPWindowFree( pxSegment );
                /* No need to unlink it any more. */
                xDoUnlink = pdFALSE;
            }
            if( ( xDoUnlink != pdFALSE ) && ( listLIST_ITEM_CONTAINER( &( pxSegment->xQueueItem ) ) != NULL ) )
            {
                /* Remove item from its queues. */
                uxListRemove( &pxSegment->xQueueItem );
            }
            ulSequenceNumber += ulDataLength;
        }

        return ulBytesConfirmed;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
/*
****************************************************
*  函数名         : prvTCPWindowFastRetransmit
*  函数描述       : 从xWaitQueue寻找需要重传的段
*  参数           : 
*  返回值         : 需要重传的段的个数
*  作者           : -5A4A5943-
*  历史版本       : 
*****************************************************
*/
    static uint32_t prvTCPWindowFastRetransmit( TCPWindow_t *pxWindow, uint32_t ulFirst )
    {
    const ListItem_t *pxIterator;
    const MiniListItem_t* pxEnd;
    TCPSegment_t *pxSegment;
    uint32_t ulCount = 0UL;

        /* A higher Tx block has been acknowledged.  Now iterate through the
         xWaitQueue to find a possible condition for a FAST retransmission. */

        pxEnd = ( const MiniListItem_t* ) listGET_END_MARKER( &( pxWindow->xWaitQueue ) );

        for( pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxEnd );
             pxIterator != ( const ListItem_t * ) pxEnd; )
        {
            /* Get the owner, which is a TCP segment. */
            pxSegment = ( TCPSegment_t * ) listGET_LIST_ITEM_OWNER( pxIterator );

            /* Hop to the next item before the current gets unlinked. */
            pxIterator  = ( const ListItem_t * ) listGET_NEXT( pxIterator );

            /* Fast retransmission:
            When 3 packets with a higher sequence number have been acknowledged
            by the peer, it is very unlikely a current packet will ever arrive.
            It will be retransmitted far before the RTO. */
            if( ( pxSegment->u.bits.bAcked == pdFALSE_UNSIGNED ) &&
                ( xSequenceLessThan( pxSegment->ulSequenceNumber, ulFirst ) != pdFALSE ) &&
                ( ++( pxSegment->u.bits.ucDupAckCount ) == DUPLICATE_ACKS_BEFORE_FAST_RETRANSMIT ) )
            {
                pxSegment->u.bits.ucTransmitCount = pdFALSE_UNSIGNED;

                /* Not clearing 'ucDupAckCount' yet as more SACK's might come in
                which might lead to a second fast rexmit. */
                if( ( xTCPWindowLoggingLevel >= 0 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE ) )
                {
                    FreeRTOS_debug_printf( ( "prvTCPWindowFastRetransmit: Requeue sequence number %lu < %lu\n",
                        pxSegment->ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                        ulFirst - pxWindow->tx.ulFirstSequenceNumber ) );
                    FreeRTOS_flush_logging( );
                }

                /* Remove it from xWaitQueue. */
                uxListRemove( &pxSegment->xQueueItem );

                /* Add this segment to the priority queue so it gets
                retransmitted immediately. */
                vListInsertFifo( &( pxWindow->xPriorityQueue ), &( pxSegment->xQueueItem ) );
                ulCount++;
            }
        }

        return ulCount;
    }
#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
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
    uint32_t ulTCPWindowTxAck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber )
    {
    uint32_t ulFirstSequence, ulReturn;

        /* Receive a normal ACK. */

        ulFirstSequence = pxWindow->tx.ulCurrentSequenceNumber;

        if( xSequenceLessThanOrEqual( ulSequenceNumber, ulFirstSequence ) != pdFALSE )
        {
            ulReturn = 0UL;
        }
        else
        {
            ulReturn = prvTCPWindowTxCheckAck( pxWindow, ulFirstSequence, ulSequenceNumber );
        }

        return ulReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 1 )
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
    uint32_t ulTCPWindowTxSack( TCPWindow_t *pxWindow, uint32_t ulFirst, uint32_t ulLast )
    {
    uint32_t ulAckCount = 0UL;
    uint32_t ulCurrentSequenceNumber = pxWindow->tx.ulCurrentSequenceNumber;

        /* Receive a SACK option. */
        ulAckCount = prvTCPWindowTxCheckAck( pxWindow, ulFirst, ulLast );
        prvTCPWindowFastRetransmit( pxWindow, ulFirst );

        if( ( xTCPWindowLoggingLevel >= 1 ) && ( xSequenceGreaterThan( ulFirst, ulCurrentSequenceNumber ) != pdFALSE ) )
        {
            FreeRTOS_debug_printf( ( "ulTCPWindowTxSack[%u,%u]: from %lu to %lu (ack = %lu)\n",
                pxWindow->usPeerPortNumber,
                pxWindow->usOurPortNumber,
                ulFirst - pxWindow->tx.ulFirstSequenceNumber,
                ulLast - pxWindow->tx.ulFirstSequenceNumber,
                pxWindow->tx.ulCurrentSequenceNumber - pxWindow->tx.ulFirstSequenceNumber ) );
            FreeRTOS_flush_logging( );
        }

        return ulAckCount;
    }

#endif /* ipconfigUSE_TCP_WIN == 1 */
/*-----------------------------------------------------------*/

/*
#####   #                      #####   ####  ######
# # #   #                      # # #  #    #  #    #
  #                              #   #     #  #    #
  #   ###   #####  #    #        #   #        #    #
  #     #   #    # #    #        #   #        #####
  #     #   #    # #    # ####   #   #        #
  #     #   #    # #    #        #   #     #  #
  #     #   #    #  ####         #    #    #  #
 #### ##### #    #     #        ####   ####  ####
                      #
                   ###
*/
/*
****************************************************
*  函数名         : lTCPWindowRxCheck
*  函数描述       : 根据接收尝试着增加pxWindow->rx.ulCurrentSequenceNumber
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
#if( ipconfigUSE_TCP_WIN == 0 )

    int32_t lTCPWindowRxCheck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength, uint32_t ulSpace )
    {
    int32_t iReturn;

        /* Data was received at 'ulSequenceNumber'.  See if it was expected
        and if there is enough space to store the new data. */
        if( ( pxWindow->rx.ulCurrentSequenceNumber != ulSequenceNumber ) || ( ulSpace < ulLength ) )
        {
            iReturn = -1;
        }
        else
        {
            pxWindow->rx.ulCurrentSequenceNumber += ( uint32_t ) ulLength;
            iReturn = 0;
        }

        return iReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    int32_t lTCPWindowTxAdd( TCPWindow_t *pxWindow, uint32_t ulLength, int32_t lPosition, int32_t lMax )
    {
    TCPSegment_t *pxSegment = &( pxWindow->xTxSegment );
    int32_t lResult;

        /* Data is being scheduled for transmission. */

        /* lMax would indicate the size of the txStream. */
        ( void ) lMax;
        /* This is tiny TCP: there is only 1 segment for outgoing data.
        As long as 'lDataLength' is unequal to zero, the segment is still occupied. */
        if( pxSegment->lDataLength > 0 )
        {
            lResult = 0L;
        }
        else
        {
            if( ulLength > ( uint32_t ) pxSegment->lMaxLength )
            {
                if( ( xTCPWindowLoggingLevel != 0 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE ) )
                {
                    FreeRTOS_debug_printf( ( "lTCPWindowTxAdd: can only store %ld / %ld bytes\n", ulLength, pxSegment->lMaxLength ) );
                }

                ulLength = ( uint32_t ) pxSegment->lMaxLength;
            }

            if( ( xTCPWindowLoggingLevel != 0 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE ) )
            {
                FreeRTOS_debug_printf( ( "lTCPWindowTxAdd: SeqNr %ld (%ld) Len %ld\n",
                    pxWindow->ulNextTxSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                    pxWindow->tx.ulCurrentSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                    ulLength ) );
            }

            /* The sequence number of the first byte in this packet. */
            pxSegment->ulSequenceNumber = pxWindow->ulNextTxSequenceNumber;
            pxSegment->lDataLength = ( int32_t ) ulLength;
            pxSegment->lStreamPos = lPosition;
            pxSegment->u.ulFlags = 0UL;
            vTCPTimerSet( &( pxSegment->xTransmitTimer ) );

            /* Increase the sequence number of the next data to be stored for
            transmission. */
            pxWindow->ulNextTxSequenceNumber += ulLength;
            lResult = ( int32_t )ulLength;
        }

        return lResult;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    uint32_t ulTCPWindowTxGet( TCPWindow_t *pxWindow, uint32_t ulWindowSize, int32_t *plPosition )
    {
    TCPSegment_t *pxSegment = &( pxWindow->xTxSegment );
    uint32_t ulLength = ( uint32_t ) pxSegment->lDataLength;
    uint32_t ulMaxTime;

        if( ulLength != 0UL )
        {
            /* _HT_ Still under investigation */
            ( void ) ulWindowSize;

            if( pxSegment->u.bits.bOutstanding != pdFALSE_UNSIGNED )
            {
                /* As 'ucTransmitCount' has a minimum of 1, take 2 * RTT */
                ulMaxTime = ( ( uint32_t ) 1u << pxSegment->u.bits.ucTransmitCount ) * ( ( uint32_t ) pxWindow->lSRTT );

                if( ulTimerGetAge( &( pxSegment->xTransmitTimer ) ) < ulMaxTime )
                {
                    ulLength = 0ul;
                }
            }

            if( ulLength != 0ul )
            {
                pxSegment->u.bits.bOutstanding = pdTRUE_UNSIGNED;
                pxSegment->u.bits.ucTransmitCount++;
                vTCPTimerSet (&pxSegment->xTransmitTimer);
                pxWindow->ulOurSequenceNumber = pxSegment->ulSequenceNumber;
                *plPosition = pxSegment->lStreamPos;
            }
        }

        return ulLength;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    BaseType_t xTCPWindowTxDone( TCPWindow_t *pxWindow )
    {
    BaseType_t xReturn;

        /* Has the outstanding data been sent because user wants to shutdown? */
        if( pxWindow->xTxSegment.lDataLength == 0 )
        {
            xReturn = pdTRUE;
        }
        else
        {
            xReturn = pdFALSE;
        }

        return xReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    static BaseType_t prvTCPWindowTxHasSpace( TCPWindow_t *pxWindow, uint32_t ulWindowSize );
    static BaseType_t prvTCPWindowTxHasSpace( TCPWindow_t *pxWindow, uint32_t ulWindowSize )
    {
    BaseType_t xReturn;

        if( ulWindowSize >= pxWindow->usMSSInit )
        {
            xReturn = pdTRUE;
        }
        else
        {
            xReturn = pdFALSE;
        }

        return xReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    BaseType_t xTCPWindowTxHasData( TCPWindow_t *pxWindow, uint32_t ulWindowSize, TickType_t *pulDelay )
    {
    TCPSegment_t *pxSegment = &( pxWindow->xTxSegment );
    BaseType_t xReturn;
    TickType_t ulAge, ulMaxAge;

        /* Check data to be sent. */
        *pulDelay = ( TickType_t ) 0;
        if( pxSegment->lDataLength == 0 )
        {
            /* Got nothing to send right now. */
            xReturn = pdFALSE;
        }
        else
        {
            if( pxSegment->u.bits.bOutstanding != pdFALSE_UNSIGNED )
            {
                ulAge = ulTimerGetAge ( &pxSegment->xTransmitTimer );
                ulMaxAge = ( ( TickType_t ) 1u << pxSegment->u.bits.ucTransmitCount ) * ( ( uint32_t ) pxWindow->lSRTT );

                if( ulMaxAge > ulAge )
                {
                    *pulDelay = ulMaxAge - ulAge;
                }

                xReturn = pdTRUE;
            }
            else if( prvTCPWindowTxHasSpace( pxWindow, ulWindowSize ) == pdFALSE )
            {
                /* Too many outstanding messages. */
                xReturn = pdFALSE;
            }
            else
            {
                xReturn = pdTRUE;
            }
        }

        return xReturn;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    uint32_t ulTCPWindowTxAck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber )
    {
    TCPSegment_t *pxSegment = &( pxWindow->xTxSegment );
    uint32_t ulDataLength = ( uint32_t ) pxSegment->lDataLength;

        /* Receive a normal ACK */

        if( ulDataLength != 0ul )
        {
            if( ulSequenceNumber < ( pxWindow->tx.ulCurrentSequenceNumber + ulDataLength ) )
            {
                if( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE )
                {
                    FreeRTOS_debug_printf( ( "win_tx_ack: acked %ld expc %ld len %ld\n",
                        ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                        pxWindow->tx.ulCurrentSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                        ulDataLength ) );
                }

                /* Nothing to send right now. */
                ulDataLength = 0ul;
            }
            else
            {
                pxWindow->tx.ulCurrentSequenceNumber += ulDataLength;

                if( ( xTCPWindowLoggingLevel != 0 ) && ( ipconfigTCP_MAY_LOG_PORT( pxWindow->usOurPortNumber ) != pdFALSE ) )
                {
                    FreeRTOS_debug_printf( ( "win_tx_ack: acked seqnr %ld len %ld\n",
                        ulSequenceNumber - pxWindow->tx.ulFirstSequenceNumber,
                        ulDataLength ) );
                }

                pxSegment->lDataLength = 0;
            }
        }

        return ulDataLength;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    BaseType_t xTCPWindowRxEmpty( TCPWindow_t *pxWindow )
    {
        /* Return true if 'ulCurrentSequenceNumber >= ulHighestSequenceNumber'
        'ulCurrentSequenceNumber' is the highest sequence number stored,
        'ulHighestSequenceNumber' is the highest sequence number seen. */
        return xSequenceGreaterThanOrEqual( pxWindow->rx.ulCurrentSequenceNumber, pxWindow->rx.ulHighestSequenceNumber );
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/

#if( ipconfigUSE_TCP_WIN == 0 )

    /* Destroy a window (always returns NULL) */
    void vTCPWindowDestroy( TCPWindow_t *pxWindow )
    {
        /* As in tiny TCP there are no shared segments descriptors, there is
        nothing to release. */
        ( void ) pxWindow;
    }

#endif /* ipconfigUSE_TCP_WIN == 0 */
/*-----------------------------------------------------------*/


