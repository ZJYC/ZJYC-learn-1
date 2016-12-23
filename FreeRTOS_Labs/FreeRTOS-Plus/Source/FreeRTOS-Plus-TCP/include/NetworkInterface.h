
#ifndef NETWORK_INTERFACE_H
#define NETWORK_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/* NOTE PUBLIC API FUNCTIONS. */
BaseType_t xNetworkInterfaceInitialise( void );
BaseType_t xNetworkInterfaceOutput( NetworkBufferDescriptor_t * const pxNetworkBuffer, BaseType_t xReleaseAfterSend );
void vNetworkInterfaceAllocateRAMToBuffers( NetworkBufferDescriptor_t pxNetworkBuffers[ ipconfigNUM_NETWORK_BUFFER_DESCRIPTORS ] );
BaseType_t xGetPhyLinkStatus( void );

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* NETWORK_INTERFACE_H */

