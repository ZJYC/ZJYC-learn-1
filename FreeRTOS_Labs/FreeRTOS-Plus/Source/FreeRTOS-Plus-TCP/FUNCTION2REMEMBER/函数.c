

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
int32_t lTCPWindowRxCheck( TCPWindow_t *pxWindow, uint32_t ulSequenceNumber, uint32_t ulLength, uint32_t ulLength );

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
