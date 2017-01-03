
#ifndef NETWORK_BUFFER_MANAGEMENT_H
#define NETWORK_BUFFER_MANAGEMENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* 公开API */
BaseType_t xNetworkBuffersInitialise( void );
NetworkBufferDescriptor_t *pxGetNetworkBufferWithDescriptor( size_t xRequestedSizeBytes, TickType_t xBlockTimeTicks );
NetworkBufferDescriptor_t *pxNetworkBufferGetFromISR( size_t xRequestedSizeBytes );
void vReleaseNetworkBufferAndDescriptor( NetworkBufferDescriptor_t * const pxNetworkBuffer );
BaseType_t vNetworkBufferReleaseFromISR( NetworkBufferDescriptor_t * const pxNetworkBuffer );
uint8_t *pucGetNetworkBuffer( size_t *pxRequestedSizeBytes );
void vReleaseNetworkBuffer( uint8_t *pucEthernetBuffer );

/* 获取当前空闲网络缓存数 */
UBaseType_t uxGetNumberOfFreeNetworkBuffers( void );

/* 获取最小空闲网络缓存数. */
UBaseType_t uxGetMinimumFreeNetworkBuffers( void );

/* 把一个缓存复制到一个更大的缓存 */
NetworkBufferDescriptor_t *pxDuplicateNetworkBufferWithDescriptor( NetworkBufferDescriptor_t * const pxNetworkBuffer,
	BaseType_t xNewLength);

/* Increase the size of a Network Buffer.
In case BufferAllocation_2.c is used, the new space must be allocated. */
NetworkBufferDescriptor_t *pxResizeNetworkBufferWithDescriptor( NetworkBufferDescriptor_t * pxNetworkBuffer,
	size_t xNewSizeBytes );

#if ipconfigTCP_IP_SANITY
	/*
	 * Check if an address is a valid pointer to a network descriptor
	 * by looking it up in the array of network descriptors
	 */
	UBaseType_t bIsValidNetworkDescriptor (const NetworkBufferDescriptor_t * pxDesc);
	BaseType_t prvIsFreeBuffer( const NetworkBufferDescriptor_t *pxDescr );
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* NETWORK_BUFFER_MANAGEMENT_H */
