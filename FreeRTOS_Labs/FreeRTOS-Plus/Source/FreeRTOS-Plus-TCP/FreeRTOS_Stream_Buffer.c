
/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"

/*
****************************************************
*  ������         : uxStreamBufferAdd
*  ��������       : ������ݵ������������uxOffset>0�����ݻᱻд��uxHead+uxOffset��λ��
                    Ȼ��uxHead�����ƶ�������TCP�յ���˳������ʱʮ������
*  ����           : 
                    pxBuffer��������
                    uxOffset��ƫ����
                    pucData�����ݵ�ַ
                    uxCount�����ݸ���
*  ����ֵ         : ��д��ĸ���
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
size_t uxStreamBufferAdd( StreamBuffer_t *pxBuffer, size_t uxOffset, const uint8_t *pucData, size_t uxCount )
{
size_t uxSpace, uxNextHead, uxFirst;

    uxSpace = uxStreamBufferGetSpace( pxBuffer );

    /* If uxOffset > 0, items can be placed in front of uxHead */
    if( uxSpace > uxOffset )
    {
        uxSpace -= uxOffset;
    }
    else
    {
        uxSpace = 0u;
    }

    /* The number of bytes that can be written is the minimum of the number of
    bytes requested and the number available. */
    uxCount = FreeRTOS_min_uint32( uxSpace, uxCount );

    if( uxCount != 0u )
    {
        uxNextHead = pxBuffer->uxHead;

        if( uxOffset != 0u )
        {
            /* ( uxOffset > 0 ) means: write in front if the uxHead marker */
            uxNextHead += uxOffset;
            if( uxNextHead >= pxBuffer->LENGTH )
            {
                uxNextHead -= pxBuffer->LENGTH;
            }
        }

        if( pucData != NULL )
        {
            /* Calculate the number of bytes that can be added in the first
            write - which may be less than the total number of bytes that need
            to be added if the buffer will wrap back to the beginning. */
            uxFirst = FreeRTOS_min_uint32( pxBuffer->LENGTH - uxNextHead, uxCount );

            /* Write as many bytes as can be written in the first write. */
            memcpy( ( void* ) ( pxBuffer->ucArray + uxNextHead ), pucData, uxFirst );

            /* If the number of bytes written was less than the number that
            could be written in the first write... */
            if( uxCount > uxFirst )
            {
                /* ...then write the remaining bytes to the start of the
                buffer. */
                memcpy( ( void * )pxBuffer->ucArray, pucData + uxFirst, uxCount - uxFirst );
            }
        }

        if( uxOffset == 0u )
        {
            /* ( uxOffset == 0 ) means: write at uxHead position */
            uxNextHead += uxCount;
            if( uxNextHead >= pxBuffer->LENGTH )
            {
                uxNextHead -= pxBuffer->LENGTH;
            }
            pxBuffer->uxHead = uxNextHead;
        }

        if( xStreamBufferLessThenEqual( pxBuffer, pxBuffer->uxFront, uxNextHead ) != pdFALSE )
        {
            /* Advance the front pointer */
            pxBuffer->uxFront = uxNextHead;
        }
    }

    return uxCount;
}

/*
****************************************************
*  ������         : uxStreamBufferGet
*  ��������       : ����ͬuxStreamBufferAdd
*  ����           : 
*  ����ֵ         : 
*  ����           : -5A4A5943-
*  ��ʷ�汾       : 
*****************************************************
*/
size_t uxStreamBufferGet( StreamBuffer_t *pxBuffer, size_t uxOffset, uint8_t *pucData, size_t uxMaxCount, BaseType_t xPeek )
{
size_t uxSize, uxCount, uxFirst, uxNextTail;

    /* How much data is available? */
    uxSize = uxStreamBufferGetSize( pxBuffer );

    if( uxSize > uxOffset )
    {
        uxSize -= uxOffset;
    }
    else
    {
        uxSize = 0u;
    }

    /* Use the minimum of the wanted bytes and the available bytes. */
    uxCount = FreeRTOS_min_uint32( uxSize, uxMaxCount );

    if( uxCount > 0u )
    {
        uxNextTail = pxBuffer->uxTail;

        if( uxOffset != 0u )
        {
            uxNextTail += uxOffset;
            if( uxNextTail >= pxBuffer->LENGTH )
            {
                uxNextTail -= pxBuffer->LENGTH;
            }
        }

        if( pucData != NULL )
        {
            /* Calculate the number of bytes that can be read - which may be
            less than the number wanted if the data wraps around to the start of
            the buffer. */
            uxFirst = FreeRTOS_min_uint32( pxBuffer->LENGTH - uxNextTail, uxCount );

            /* Obtain the number of bytes it is possible to obtain in the first
            read. */
            memcpy( pucData, pxBuffer->ucArray + uxNextTail, uxFirst );

            /* If the total number of wanted bytes is greater than the number
            that could be read in the first read... */
            if( uxCount > uxFirst )
            {
                /*...then read the remaining bytes from the start of the buffer. */
                memcpy( pucData + uxFirst, pxBuffer->ucArray, uxCount - uxFirst );
            }
        }

        if( ( xPeek == pdFALSE ) && ( uxOffset == 0UL ) )
        {
            /* Move the tail pointer to effecively remove the data read from
            the buffer. */
            uxNextTail += uxCount;

            if( uxNextTail >= pxBuffer->LENGTH )
            {
                uxNextTail -= pxBuffer->LENGTH;
            }

            pxBuffer->uxTail = uxNextTail;
        }
    }

    return uxCount;
}

