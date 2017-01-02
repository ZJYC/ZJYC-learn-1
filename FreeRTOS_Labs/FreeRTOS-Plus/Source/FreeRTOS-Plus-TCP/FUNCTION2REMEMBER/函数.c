

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
