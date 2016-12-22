/*
****************************************************
*  �ļ���             : 
*  ����               : -5A4A5943-
*  �汾               : 
*  ��д����           : 
*  ���               : 
*  �����б�           : 
*  ��ʷ�汾           : 
*****************************************************
*/


/*ͷ�ļ�  */





/*�궨��  */





/*��������*/





/*��������*/





/*��������*/


/*
In:ָ������
Len:ָ���
Out:��ָ��ֽ��������ά�ַ�����

���룺��SPP: ok idle\r\n\0��
�����Out[0] = "SPP",Out[1] = "ok",Out[2] = "idle"
*/
static uint8_t prvSplitString(uint8_t * In,uint16_t Len,uint8_t ** Out)
{
    //CharUseless������һ�������ַ�
    uint8_t i = 0,tIndex = 0,CharUseless = 0;
    
    BT_CHK_PARAM(In);
    BT_CHK_PARAM(Out);
    BT_CHK_PARAM(Len);  /* ������ô����0�أ��ǲ��� */
    //���ַ����ĳ�����һ���޶�
    while(In[i] && i < Len)
    {
        //������4�������ַ�
        if(In[i] == '\r' || In[i] == '\n' || In[i] == ':' || In[i] == " " || In[i] == "+" || In[i] == ",")
        {
            In[i] = '\0';
            i ++;
            CharUseless = 0xff;
            continue;
        }
        //�洢���ֶεĵ�ַ
        if(CharUseless == 0xff){Out[tIndex++] = &In[i];CharUseless = 0x00;}
        if(tIndex > 6)return BT_Res_TooManyParams;
        i ++;
    }
    
    return BT_True;
}
/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint8_t * prvGenerateInstruction1(uint8_t * Param1,uint16_t * Len)
{
    uint8_t * Buff = BT_BDE_Driver.PriData.InstructionBuff;
    uint16_t i = 0;
    
    /* Param1�ĺϷ���Ӧ����һ�������м�� */
    
    /* ���һ�»��� */
    for(i = 0;i < 60;i ++)Buff[i] = 0x00;
    /* �ַ������� */
    strcpy(Buff,"SPP:");
    strcat(Buff,Param1);
    strcat(Buff,"/r/n");
    /* strcat ִ�к��*�Զ�*��dest�������'\0' */
    *Len = strlen(Buff) + 1;
    /* strlen ������������������ָ����Ҫ'/r/n/0'��Ϊ������־���ʼ�һ */
    return Buff;
}
/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint8_t * prvGenerateInstruction2(uint8_t * Param1,uint8_t * Param2,uint16_t * Len)
{
    uint8_t * Buff = BT_BDE_Driver.PriData.InstructionBuff;
    uint16_t i = 0;
    
    /* Param1�ĺϷ���Ӧ����һ�������м�� */
    
    /* ���һ�»��� */
    for(i = 0;i < 60;i ++)Buff[i] = 0x00;
    /* �ַ������� */
    strcpy(Buff,"SPP:");
    strcat(Buff,Param1);
    strcat(Buff," ");
    strcat(Buff,Param2);
    strcat(Buff,"/r/n");
    /* strcat ִ�к��*�Զ�*��dest�������'\0' */
    *Len = strlen(Buff) + 1;
    /* strlen ������������������ָ����Ҫ'/r/n/0'��Ϊ������־���ʼ�һ */
    return Buff;
}
/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint8_t * prvGenerateInstruction3(uint8_t * Param1,uint8_t * Param2,uint8_t * Param3,uint16_t * Len)
{
    uint8_t * Buff = BT_BDE_Driver.PriData.InstructionBuff;
    uint16_t i = 0;
    
    /* Param1�ĺϷ���Ӧ����һ�������м�� */
    
    /* ���һ�»��� */
    for(i = 0;i < 60;i ++)Buff[i] = 0x00;
    /* �ַ������� */
    strcpy(Buff,"SPP:");
    strcat(Buff,Param1);
    strcat(Buff," ");
    strcat(Buff,Param2);
    strcat(Buff," ");
    strcat(Buff,Param3);
    strcat(Buff,"/r/n");
    /* strcat ִ�к��*�Զ�*��dest�������'\0' */
    *Len = strlen(Buff) + 1;
    /* strlen ������������������ָ����Ҫ'/r/n/0'��Ϊ������־���ʼ�һ */
    return Buff;
}
/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint8_t * prvGenerateInstruction5(uint8_t * Param1,uint8_t * Param2,uint8_t * Param3,uint8_t * Param4,uint8_t * Param5,uint16_t * Len)
{
    uint8_t * Buff = BT_BDE_Driver.PriData.InstructionBuff;
    uint16_t i = 0;
    
    /* Param1�ĺϷ���Ӧ����һ�������м�� */
    
    /* ���һ�»��� */
    for(i = 0;i < 60;i ++)Buff[i] = 0x00;
    /* �ַ������� */
    strcpy(Buff,"SPP:");
    strcat(Buff,Param1);
    strcat(Buff," ");
    strcat(Buff,Param2);
    strcat(Buff," ");
    strcat(Buff,Param3);
    strcat(Buff," ");
    strcat(Buff,Param4);
    strcat(Buff," ");
    strcat(Buff,Param5);
    strcat(Buff,"/r/n");
    /* strcat ִ�к��*�Զ�*��dest�������'\0' */
    *Len = strlen(Buff) + 1;
    /* strlen ������������������ָ����Ҫ'/r/n/0'��Ϊ������־���ʼ�һ */
    return Buff;
}
/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
                        Instruction:ָ��
                        RetryCnt:�ش�����
                        Timeout:��ʱ
                        MatchIndex:ƥ������
                        Match:ƥ����
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint8_t prvSendInstruction(uint8_t * Instruction,uint8_t RetryCnt,uint16_t Timeout,uint8_t MatchIndex,uint8_t * Match)
{
    uint32_t CurCounter = BT_BDE_Driver.PriData.Counter;
    /* ����ٶ�ָ��Ȳ����ܳ���100�ֽ� */
    uint8_t Retry = 0,Buf[100] = {0x00},**ParamSplitTemp = BT_BDE_Driver.PriData.ParamSplit;;
    uint16_t LenRecv = 0;
    
    BT_BDE_Driver.Ops.Send(Instruction,strlen(Len));
    
    for(;;)
    {
        /* �յ�һ֡��Ϣ ֱ���ж��Ƿ�ƥ��Match */
        LenRecv = BT_BDE_Driver.Ops.Recv(Buf,0,Timeout);
        /* ����յ����� */
        if(LenRecv)
        {
            prvSplitString(Buf,LenRecv,ParamSplitTemp);
            /* ����ƥ������Ƿ���true */
            if(strcmp(ParamSplitTemp[MatchIndex],Match) == 0 )
            {
                return BT_True
            }
        }
        /* ����û���յ����� */
        else
        {
            /* �ش� */
            if(++Retry < RetryCnt)
            {
                CurCounter = BT_BDE_Driver.PriData.Counter;
                BT_BDE_Driver.Ops.Send(Instruction,strlen(Len));
            }
            else
            {
                return BT_False;
            }
        }
        if(Retry >= RetryCnt)return BT_False;
    }
}

/*
****************************************************
*  ������         : 
*  ��������       : ���SIM���Ƿ����
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
uint8_t AppDetectCCID(void)
{
    uint8_t Res = prvSendInstruction("AT+CCID\r\n",2,400,2,"OK");
    return Res;
}

uint8_t AppATE0(void)
{
    uint8_t Res = prvSendInstruction("ATE0\r\n",10,500,0,"OK");
    return Res;
}

uint8_t AppCAPS(void)
{
    uint8_t Res = prvSendInstruction("AT+CPAS\r\n",2,500,1,"0");
    return Res;
}

uint8_t AppCREG(void)
{
    uint8_t Res = prvSendInstruction("AT+CREG?\r\n",2,500,2,"1");
    if(Res == BT_False)Res = prvSendInstruction("AT+CREG?\r\n",2,500,2,"5");
    return Res;
}

uint8_t AppCGREG(void)
{
    uint8_t Res = prvSendInstruction("AT+CGREG?\r\n",2,500,2,"1");
    //if(Res == BT_False)Res = prvSendInstruction("AT+CREG?\r\n",2,500,2,"5");
    return Res;
}

uint8_t AppCSQ(void)
{
    uint8_t Res = prvSendInstruction("AT+CSQ\r\n",2,500,3,"OK");
    if(Res == BT_True)
    {
        strcpy(BT_BDE_Driver.PriData.CSQ_Signal,ParamSplitTemp[1]);
        strcpy(BT_BDE_Driver.PriData.CSQ_Ber,ParamSplitTemp[3]);
    }
}

uint8_t AppSetIP_Port(uint8_t * IP,uint8_t * Port)
{
    uint8_t * Buff = BT_BDE_Driver.PriData.InstructionBuff;
    uint8_t Res = prvSendInstruction("AT$MYNETACT=0,1\r\n",4,1000,0,"OK");
    if(Res == BT_True)
    {
        strcpy(Buff,"AT$MYNETSRV=0,0,0,0,");
        strcat(Buff,"\"");
        strcat(Buff,IP);
        strcat(Buff,":");
        strcat(Buff,Port);
        strcat(Buff,"\"");
        strcat(Buff,"\r\n");
        Res = prvSendInstruction(Buff,2,500,0,"OK");
    }
    return res;
}

uint8_t AppConnect(void)
{
    Res = prvSendInstruction("AT$MYNETOPEN=0\r\n",2,10000,0,"CONNECT");
    return Res;
}

uint16_t AppSend(uint8_t * Data,uint16_t Len)
{
    uint8_t * Buff = BT_BDE_Driver.PriData.InstructionBuff;
    sprintf(Buff,"AT$MYNETWRITE=0,%d\r\n",Len);
    Res = prvSendInstruction(Buff,4,300,0,"$MYNETWRITE");
    /* ���Ƿ������� */
    if(Res == BT_True)
    {
        BT_BDE_Driver.Ops.Send(Data,Len);
        BT_BDE_Driver.Ops.Send("\r\n",2);
        LenRecv = BT_BDE_Driver.Ops.Recv(Buf,0,Timeout);
        if(LenRecv)
        {
            prvSplitString(Buf,LenRecv,ParamSplitTemp);
            /* ����ƥ������Ƿ���true */
            if(strcmp(ParamSplitTemp[0],"OK") == 0 )
            {
                return BT_True
            }
        }
    }
}

uint16_t AppRecv(uint8_t * Data,uint16_t Len)
{
    uint8_t * LenStr = 0,*pData = 0;
    uint16_t ValLen = 0,i = 0;
    BT_BDE_Driver.Ops.Send("AT$MYNETREAD=0,2048",strlen("AT$MYNETREAD=0,2048"));
    if(Res == BT_True)
    {
        LenRecv = BT_BDE_Driver.Ops.Recv(Buf,0,Timeout);
        if(LenRecv)
        {
            while((Buf[i ++] != ',') && i < 2048);
            LenStr = &Buf[i];
            while(1)
            {
                if(Buf[i] == '\r' && Buf[i+1] == '\n')
                {
                    Buf[i] = 0;
                    Buf[i + 1] = 0;
                    pData = &Buf[i + 2];
                }
                i++;
            }
            ValLen = atoi(LenStr);
            for(i = 0;i < ValLen;i ++)
            {
                Data[i] = pData[i];
            }
            return ValLen;
        }
    }
    return 0;
}

uint16_t AppClose()
{
    uint8_t Res = prvSendInstruction("AT$MYNETCLOSE=0\r\n",4,300,0,"$MYNETCLOSE");
    return Res;
}

uint16_t AppInit()
{
    
}

/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint16_t prvSendData(uint8_t * Data,uint16_t Len)
{
    
}
/*
****************************************************
*  ������         : 
*  ��������       : 
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint8_t BT_BDE_TimingProcess(uint16_t Period)
{
    BT_CHK_PARAM(Period);
    
    BT_BDE_Driver.PriData.Counter += Period;
    if(BT_BDE_Driver.PriData.Counter > 100000)BT_BDE_Driver.PriData.Counter = 0;
    /* �ޤ�10������ ��Ҫ���ʤ󣿣� */
    if(BT_BDE_Driver.PriData.Counter % (Period * 10) == 0)
    {
        /* �յ�һ֡���� */
        /******************************************************
            ��������£��˴�ȫΪ͸�����ݣ���һ�˴���ָ������
        ���ǿ�ѡ��Ҫ�������ų���
        ******************************************************/
        if(BT_BDE_Driver.Ops.Recv(Buf,&LenRecv) != 0)
        {
            /* ��������Ҫ�ж�����͸�����ݻ������� */
            if(Buf[0] == 'S' && Buf[0] == 'P' &&Buf[0] == 'P' &&Buf[0] == ':')
            {
                
            }
        }
    }
}
/*
****************************************************
*  ������         : 
*  ��������       : �����б�Ҫ֪�����ǵȴ��˶೤ʱ��
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
static uint32_t GetDelayed(uint32_t ConstCounter)
{
    if(ConstCounter <= BT_BDE_Driver.PriData.Counter)return (BT_BDE_Driver.PriData.Counter - ConstCounter)
    return 100000 - ConstCounter + BT_BDE_Driver.PriData.Counter;
}


static uint8_t BT_UartInit(uint16_t Baud)
{
    
}
static uint8_t BT_UartSend(uint8_t * Data,uint16_t Len)
{
    
}
static uint16_t BT_UartRecv(uint8_t * Data,uint16_t ExpectLen,uint16_t Timeout)
{
    /* ����������������BT_False */
    if(BT_CHK_BIT(BT_BDE_Driver.PriData.FlagGroup,BT_FLAG_RxLock))return BT_False;
    /* ���� �� �̰߳�ȫ */
    BT_SET_BIT(BT_BDE_Driver.PriData.FlagGroup,BT_FLAG_RxLock);
    /* 

    if(RxFinished != 0)
    {
        for(i = 0;i < RxBufLen;i ++)
        {
            Data[i] = ComBuff[i];
        }
        *Len = RxBufLen;
        return BT_True;
    }

    */
    /* ������� */
    BT_CLR_BIT(BT_BDE_Driver.PriData.FlagGroup,BT_FLAG_RxLock);
}

BT_BDE_DriverTypedef BT_BDE_Driver = 
{
    {
        BT_UartInit,
        BT_UartSend,
        BT_UartRecv
    },
    {
        0x00
    },
    BT_BDE_TimingProcess,
};








