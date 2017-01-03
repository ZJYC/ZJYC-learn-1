
#ifndef FREERTOS_TCP_IP_H
#define FREERTOS_TCP_IP_H

#ifdef __cplusplus
extern "C" {
#endif

BaseType_t xProcessReceivedTCPPacket( NetworkBufferDescriptor_t *pxNetworkBuffer );

typedef enum eTCP_STATE {
    /* Comments about the TCP states are borrowed from the very useful
     * Wiki page:
     * http://en.wikipedia.org/wiki/Transmission_Control_Protocol */
    eCLOSED = 0u,   /* 0 (server + client) û������״̬ */
    eTCP_LISTEN,    /* 1 (server) �ȴ��������� */
    eCONNECT_SYN,   /* 2 (client) �ڲ�״̬: �׽����뷢������ */
    eSYN_FIRST,     /* 3 (server) �ոմ���, ����Ӧ��SYN���� */
    eSYN_RECEIVED,  /* 4 (server) ��Ҫ���������Ӧ�����Ѿ����յ���������������֮�� */
    eESTABLISHED,   /* 5 (server + client) �����ӣ����ݿ��Դ��䣬���ݴ���׶ε�����״̬ */
    eFIN_WAIT_1,    /* 6 (server+client)�ȴ�Զ��TCP���ͽ�����������Ѿ�ȷ����Զ��TCP�Ľ�������*/
    eFIN_WAIT_2,    /* 7 (server + client) �ȴ�Զ��TCP���ͽ������� */
    eCLOSE_WAIT,    /* 8 (server + client) �ȴ������û��Ľ������� */
    eCLOSING,       /*   (server + client) �ȴ�Զ�̶Խ��������ȷ�� */
    eLAST_ACK,      /* 9 (server + client) �ȴ�Զ�̵Ľ�������ȷ��(Ҳ�����˶��������������ȷ��). */
    eTIME_WAIT,     /* 10 (either server or client) �ȴ��㹻��ʱ����ȷ��Զ�̵ĵ��˽�������  */
} eIPTCPState_t;


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* FREERTOS_TCP_IP_H */













