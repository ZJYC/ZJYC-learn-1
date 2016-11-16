/*
    FreeRTOS V9.0.0 - Copyright (C) 2016 Real Time Engineers Ltd.
    All rights reserved

    VISIT http://www.FreeRTOS.org TO ENSURE YOU ARE USING THE LATEST VERSION.

    This file is part of the FreeRTOS distribution.

    FreeRTOS is free software; you can redistribute it and/or modify it under
    the terms of the GNU General Public License (version 2) as published by the
    Free Software Foundation >>!AND MODIFIED BY!<< the FreeRTOS exception.

    ***************************************************************************
    >>!   NOTE: The modification to the GPL is included to allow you to     !<<
    >>!   distribute a combined work that includes FreeRTOS without being   !<<
    >>!   obliged to provide the source code for proprietary components     !<<
    >>!   outside of the FreeRTOS kernel.                                   !<<
    ***************************************************************************

    FreeRTOS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE.  Full license text is available on the following
    link: http://www.freertos.org/a00114.html

    ***************************************************************************
     *                                                                       *
     *    FreeRTOS provides completely free yet professionally developed,    *
     *    robust, strictly quality controlled, supported, and cross          *
     *    platform software that is more than just the market leader, it     *
     *    is the industry's de facto standard.                               *
     *                                                                       *
     *    Help yourself get started quickly while simultaneously helping     *
     *    to support the FreeRTOS project by purchasing a FreeRTOS           *
     *    tutorial book, reference manual, or both:                          *
     *    http://www.FreeRTOS.org/Documentation                              *
     *                                                                       *
    ***************************************************************************

    http://www.FreeRTOS.org/FAQHelp.html - Having a problem?  Start by reading
    the FAQ page "My application does not run, what could be wrong?".  Have you
    defined configASSERT()?

    http://www.FreeRTOS.org/support - In return for receiving this top quality
    embedded software for free we request you assist our global community by
    participating in the support forum.

    http://www.FreeRTOS.org/training - Investing in training allows your team to
    be as productive as possible as early as possible.  Now you can receive
    FreeRTOS training directly from Richard Barry, CEO of Real Time Engineers
    Ltd, and the world's leading authority on the world's leading RTOS.

    http://www.FreeRTOS.org/plus - A selection of FreeRTOS ecosystem products,
    including FreeRTOS+Trace - an indispensable productivity tool, a DOS
    compatible FAT file system, and our tiny thread aware UDP/IP stack.

    http://www.FreeRTOS.org/labs - Where new FreeRTOS products go to incubate.
    Come and try FreeRTOS+TCP, our new open source TCP/IP stack for FreeRTOS.

    http://www.OpenRTOS.com - Real Time Engineers ltd. license FreeRTOS to High
    Integrity Systems ltd. to sell under the OpenRTOS brand.  Low cost OpenRTOS
    licenses offer ticketed support, indemnification and commercial middleware.

    http://www.SafeRTOS.com - High Integrity Systems also provide a safety
    engineered and independently SIL3 certified version for use in safety and
    mission critical applications that require provable dependability.

    1 tab == 4 spaces!
*/

/*
 * Instructions for using this project are provided on:
 * http://www.FreeRTOS.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCPIP_FAT_Examples_Atmel_SAM4E.html
 */


/* Standard includes. */
#include <stdio.h>
#include <ctype.h>

/* FreeRTOS includes. */
#include <FreeRTOS.h>
#include "task.h"
#include "timers.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_tcp_server.h"
#include "FreeRTOS_DHCP.h"

/* FreeRTOS+FAT includes. */
#include "ff_stdio.h"
#include "ff_ramdisk.h"
#include "ff_sddisk.h"

/* Demo application includes. */
#include "TCPEchoClient_SingleTasks.h"
#include "SimpleTCPEchoServer.h"
#include "hr_gettime.h"
#include "UDPLoggingPrintf.h"

/* Atmel includes. */
#include "board.h"
#include "conf_board.h"
#include <asf.h>


/* Set the following constants to 1 or 0 to define which tasks to include and
exclude.  A WIDER RANGE OF EXAMPLES ARE AVAILABLE IN THE WIN32 DEMO:
http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/examples_FreeRTOS_simulator.html

mainCREATE_FTP_SERVER:  When set to 1 the TCP server task will include an FTP
server.
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/FTP_Server.html

mainCREATE_HTTP_SERVER:  When set to 1 the TCP server task will include a basic
HTTP server.
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/HTTP_web_Server.html

mainCREATE_UDP_CLI_TASKS:  When set to 1 a command console that uses a UDP port
for input and output is created using FreeRTOS+CLI.  The port number used is set
by the mainUDP_CLI_PORT_NUMBER constant above.  A dumb UDP terminal such as YAT
can be used to connect.
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/UDP_CLI.html

mainCREATE_TCP_ECHO_TASKS_SINGLE:  When set to 1 a set of tasks are created that
send TCP echo requests to the standard echo port (port 7), then wait for and
verify the echo reply, from within the same task (Tx and Rx are performed in the
same RTOS task).  The IP address of the echo server must be configured using the
configECHO_SERVER_ADDR0 to configECHO_SERVER_ADDR3 constants in
FreeRTOSConfig.h.
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCP_Echo_Clients.html

mainCREATE_SIMPLE_TCP_ECHO_SERVER:  When set to 1 FreeRTOS tasks are used with
FreeRTOS+TCP to create a TCP echo server.  Echo requests can be sent to the
FreeRTOS+TCP using a tool such as EchoTool https://github.com/PavelBansky/EchoTool
(a pre-built binary is available).
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCP_Echo_Server.html
*/
#define mainCREATE_FTP_SERVER					1
#define mainCREATE_HTTP_SERVER 					1
#define mainCREATE_UDP_CLI_TASKS				1
#define mainCREATE_TCP_ECHO_CLIENT_TASKS_SINGLE	1
#define mainCREATE_SIMPLE_TCP_ECHO_SERVER		1
#define mainCREATE_UDP_LOGGING_TASK 			1

/* FTP and HTTP servers execute in the TCP server work task. */
#define mainTCP_SERVER_TASK_PRIORITY	( tskIDLE_PRIORITY + 1 )
#define	mainTCP_SERVER_STACK_SIZE		( configMINIMAL_STACK_SIZE * 8 )

/* UDP CLI task parameters --------------------------------------------------
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/UDP_CLI.html */
#define mainUDP_CLI_TASK_PRIORITY		( tskIDLE_PRIORITY )
#define mainUDP_CLI_PORT_NUMBER			( 5001UL )
#define mainUDP_CLI_TASK_STACK_SIZE		( configMINIMAL_STACK_SIZE * 6 )

/* Simple echo client task parameters ---------------------------------------
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCP_Echo_Clients.html */
#define mainECHO_CLIENT_TASK_STACK_SIZE ( configMINIMAL_STACK_SIZE * 4 )
#define mainECHO_CLIENT_TASK_PRIORITY	( tskIDLE_PRIORITY + 1 )

/* Simple echo server task parameters ---------------------------------------
See http://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCP_Echo_Server.html */
#define mainECHO_SERVER_TASK_PRIORITY	( tskIDLE_PRIORITY + 1 )
#define	mainECHO_SERVER_STACK_SIZE		( configMINIMAL_STACK_SIZE * 4 )

/* Other configuration parameters -------------------------------------------*/

/* The SD card is mounted in the root of the file system. */
#define mainHAS_SDCARD					1
#define mainSD_CARD_DISK_NAME			"/"
#define mainSD_CARD_TESTING_DIRECTORY	"/fattest"

/* Configuration sanity check. */
#if ( ( mainHAS_SDCARD == 0 ) && ( mainCREATE_FTP_SERVER == 1 ) )
	#error The FTP server can only be created if mainHAS_SDCARD is 1.
#endif

/* Configuration sanity check. */
#if ( ( mainHAS_SDCARD == 0 ) && ( mainCREATE_HTTP_SERVER == 1 ) )
	#error The HTTP server can only be created if mainHAS_SDCARD is 1.
#endif

/* Define names that will be used for DNS, LLMNR and NBNS searches.  This allows
mainHOST_NAME to be used when the IP address is not known.  For example
"ping RTOSDemo" to resolve RTOSDemo to an IP address then send a ping request. */
#define mainHOST_NAME					"RTOSDemo"
#define mainDEVICE_NICK_NAME			"sam4expro"

/* The LED to toggle and the rate at which the LED will be toggled. */
#define mainLED_TOGGLE_PERIOD			pdMS_TO_TICKS( 250 )


#if( BOARD == SAM4E_XPLAINED_PRO )
	/* Used to place the heap. */
	#define mainHEAP_START		_estack
	#define mainRAM_LENGTH		0x00020000	/* 128 KB of internal SRAM. */
	#define mainRAM_START		0x20000000	/* at 0x20000000 */
	/* The SAM4E Xplained board has 2 banks of external SRAM, each one 512KB. */
	#define mainEXTERNAL_SRAM_SIZE		( 512ul * 1024ul )
#else
	#error Define memory regions here.
#endif /* SAM4E_XPLAINED_PRO */

/*-----------------------------------------------------------*/

/*
 * Just seeds the simple pseudo random number generator.
 */
static void prvSRand( UBaseType_t ulSeed );

/*
 * Miscellaneous initialisation including preparing the logging and seeding the
 * random number generator.
 */
static void prvMiscInitialisation( void );

/*
 * Creates files on the SD card disk.  The files can then be viewed via the FTP
 * server and the command line interface.
 */
#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )
	static void prvCreateExampleFiles( void );
#endif

/*
 * The Xplained Pro hardware does not have a pin for detecting the removal of
 * the SD card, so periodically check for the cards presence in software.
 */
#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )
	static void prvSDCardDetect( void );
#endif

/*
 * The task that runs the FTP and HTTP servers.
 */
#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )
	static void prvServerWorkTask( void *pvParameters );
#endif

/*
 * Heap_5.c is being used, so place the heap in the available memory.  See
 * http://www.freertos.org/a00111.html.
 */
static void prvInitialiseHeap( void );

/*
 * Callback function for the timer that toggles an LED.
 */
static void prvLEDTimerCallback( TimerHandle_t xTimer );

/*
 * Register a set of example CLI commands that interact with the file system.
 * These are very basic.
 */
extern void vRegisterFileSystemCLICommands( void );

/*
 * Register a set of example CLI commands that interact with the TCP/IP stack.
 */
extern void vRegisterTCPCLICommands( void );

/*
 * Register the standard CLI examples, which will include the taskstats command
 * if configUSE_STATS_FORMATTING_FUNCTIONS is set to 1 in FreeRTOSConfig.h.
 */
extern void vRegisterSampleCLICommands( void );

/*
 * Starts an interface to FreeRTOS+CLI that uses a UDP port for input and
 * output.
 */
extern void vStartUDPCommandInterpreterTask( uint16_t usStackSize, uint32_t ulPort, UBaseType_t uxPriority );

/*-----------------------------------------------------------*/

/* The default IP and MAC address used by the demo.  The address configuration
defined here will be used if ipconfigUSE_DHCP is 0, or if ipconfigUSE_DHCP is
1 but a DHCP server could not be contacted.  See the online documentation for
more information.  http://www.FreeRTOS.org/tcp */
static const uint8_t ucIPAddress[ 4 ] = { configIP_ADDR0, configIP_ADDR1, configIP_ADDR2, configIP_ADDR3 };
static const uint8_t ucNetMask[ 4 ] = { configNET_MASK0, configNET_MASK1, configNET_MASK2, configNET_MASK3 };
static const uint8_t ucGatewayAddress[ 4 ] = { configGATEWAY_ADDR0, configGATEWAY_ADDR1, configGATEWAY_ADDR2, configGATEWAY_ADDR3 };
static const uint8_t ucDNSServerAddress[ 4 ] = { configDNS_SERVER_ADDR0, configDNS_SERVER_ADDR1, configDNS_SERVER_ADDR2, configDNS_SERVER_ADDR3 };

/* Default MAC address configuration. */
const uint8_t ucMACAddress[ 6 ] = { configMAC_ADDR0, configMAC_ADDR1, configMAC_ADDR2, configMAC_ADDR3, configMAC_ADDR4, configMAC_ADDR5 };

/* Use by the pseudo random number generator. */
static UBaseType_t ulNextRand;

#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )

	/* Handle of the task that runs the FTP and HTTP servers. */
	static TaskHandle_t xServerWorkTaskHandle = NULL;

	/* The SD card disk. */
	static FF_Disk_t *pxDisk = NULL;

#endif

/* Used to place the heap. */
extern char _estack;

/*-----------------------------------------------------------*/

/* See http://www.FreeRTOS.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/TCPIP_FAT_Examples_Atmel_SAM4E.html */
int main(void)
{
TimerHandle_t xLEDTimer;

	/* Miscellaneous initialisation including preparing the logging and seeding
	the random number generator. */
	prvMiscInitialisation();

	/* Initialise the network interface.

	***NOTE*** Tasks that use the network are created in the network event hook
	when the network is connected and ready for use (see the definition of
	vApplicationIPNetworkEventHook() below).  The address values passed in here
	are used if ipconfigUSE_DHCP is set to 0, or if ipconfigUSE_DHCP is set to 1
	but a DHCP server cannot be	contacted. */
	FreeRTOS_printf( ( "FreeRTOS_IPInit\n" ) );
	FreeRTOS_IPInit( ucIPAddress, ucNetMask, ucGatewayAddress, ucDNSServerAddress, ucMACAddress );

	#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )
	{
		/* Create the task that handles the FTP and HTTP servers.  This will
		initialise the file system then wait for a notification from the network
		event hook before creating the servers.  The task is created at the idle
		priority, and sets itself to mainTCP_SERVER_TASK_PRIORITY after the file
		system has initialised. */
		xTaskCreate( prvServerWorkTask, "SvrWork", mainTCP_SERVER_STACK_SIZE, NULL, tskIDLE_PRIORITY, &xServerWorkTaskHandle );
	}
	#endif

	/* Create a timer that just toggles an LED to show something is alive. */
	xLEDTimer = xTimerCreate( "LED", mainLED_TOGGLE_PERIOD, pdTRUE, NULL, prvLEDTimerCallback );
	configASSERT( xLEDTimer );
	xTimerStart( xLEDTimer, 0 );

	/* Start the RTOS scheduler. */
	FreeRTOS_debug_printf( ("vTaskStartScheduler\n") );
	vTaskStartScheduler();

	/* If all is well, the scheduler will now be running, and the following
	line will never be reached.  If the following line does execute, then
	there was insufficient FreeRTOS heap memory available for the idle and/or
	timer tasks	to be created.  See the memory management section on the
	FreeRTOS web site for more details.  http://www.freertos.org/a00111.html */
	for( ;; )
	{
	}
}
/*-----------------------------------------------------------*/

#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )

	static void prvCreateExampleFiles( void )
	{
	extern void vCreateAndVerifyExampleFiles( char *pcMountPath );
	extern void vStdioWithCWDTest( const char *pcMountPath );
	extern void vMultiTaskStdioWithCWDTest( const char *const pcMountPath, uint16_t usStackSizeWords );

		FreeRTOS_printf( ( "Mount SD-card\n" ) );

		if( pxDisk != NULL )
		{
			/* Remove the base directory again, ready for another boot. */
			ff_deltree( mainSD_CARD_TESTING_DIRECTORY );

			/* Make sure that the testing directory exists. */
			ff_mkdir( mainSD_CARD_TESTING_DIRECTORY );

			/* Create a few example files on the disk.  These are not deleted again. */
			vCreateAndVerifyExampleFiles( mainSD_CARD_TESTING_DIRECTORY );
		}
	}

#endif /* ( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) ) */
/*-----------------------------------------------------------*/

#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )

	static void prvServerWorkTask( void *pvParameters )
	{
	TCPServer_t *pxTCPServer = NULL;
	const TickType_t xInitialBlockTime = pdMS_TO_TICKS( 5000UL );
	const TickType_t xSDCardInsertDelay = pdMS_TO_TICKS( 1000UL );

	/* A structure that defines the servers to be created.  Which servers are
	included in the structure depends on the mainCREATE_HTTP_SERVER and
	mainCREATE_FTP_SERVER settings at the top of this file. */
	static const struct xSERVER_CONFIG xServerConfiguration[] =
	{
		#if( mainCREATE_HTTP_SERVER == 1 )
				/* Server type,		port number,	backlog, 	root dir. */
				{ eSERVER_HTTP, 	80, 			12, 		configHTTP_ROOT },
		#endif

		#if( mainCREATE_FTP_SERVER == 1 )
				/* Server type,		port number,	backlog, 	root dir. */
				{ eSERVER_FTP,  	21, 			12, 		"" }
		#endif
	};


		/* Remove compiler warning about unused parameter. */
		( void ) pvParameters;

		/* Can't serve web pages or start an FTP session until the card is
		inserted.  The Xplained Pro hardware cannot generate an interrupt when
		the card is inserted - so periodically look for the card until it is
		inserted. */
		while( ( pxDisk = FF_SDDiskInit( mainSD_CARD_DISK_NAME ) ) == NULL )
		{
			vTaskDelay( xSDCardInsertDelay );
		}

		FreeRTOS_printf( ( "SD card detected, creating example files." ) );
		prvCreateExampleFiles();
		FreeRTOS_printf( ( "Example files created." ) );

		/* A disk is going to be created, so register the example file CLI
		commands (which are very basic). */
		vRegisterFileSystemCLICommands();

		/* The priority of this task can be raised now the disk has been
		initialised. */
		vTaskPrioritySet( NULL, mainTCP_SERVER_TASK_PRIORITY );

		/* Wait until the network is up before creating the servers.  The
		notification is given from the network event hook. */
		ulTaskNotifyTake( pdTRUE, portMAX_DELAY );

		/* Create the servers defined by the xServerConfiguration array above. */
		pxTCPServer = FreeRTOS_CreateTCPServer( xServerConfiguration, sizeof( xServerConfiguration ) / sizeof( xServerConfiguration[ 0 ] ) );
		configASSERT( pxTCPServer );

		for( ;; )
		{
			/* The Xplained pro board does not define a pin for detecting the
			removal of the SD card, so periodically check for the cards
			presence. */
			prvSDCardDetect();

			/* Run the HTTP and/or FTP servers, as configured above. */
			FreeRTOS_TCPServerWork( pxTCPServer, xInitialBlockTime );
		}
	}

#endif /* ( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) ) */
/*-----------------------------------------------------------*/

#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )

	static void prvSDCardDetect( void )
	{
	static BaseType_t xWasPresent = pdTRUE, xIsPresent;
	FF_IOManager_t *pxIOManager;
	BaseType_t xResult;

		/* The Xplained Pro board does not define a pin for detecting the remove of
		the SD card, so check for the card periodically in software. */
		xIsPresent = FF_SDDiskDetect( pxDisk );
		if( xWasPresent != xIsPresent )
		{
			if( xIsPresent == pdFALSE )
			{
				FreeRTOS_printf( ( "SD-card now removed (%ld -> %ld)\n", xWasPresent, xIsPresent ) );

				/* _RB_ Preferably the IO manager would not be exposed to the
				application here, but instead FF_SDDiskUnmount() would, which takes
				the disk as its parameter rather than the IO manager, would itself
				invalidate any open files before unmounting the disk. */
				pxIOManager = sddisk_ioman( pxDisk );

				if( pxIOManager != NULL )
				{
					/* Invalidate all open file handles so they will get closed by
					the application. */
					FF_Invalidate( pxIOManager );
					FF_SDDiskUnmount( pxDisk );
				}
			}
			else
			{
				FreeRTOS_printf( ( "SD-card now present (%ld -> %ld)\n", xWasPresent, xIsPresent ) );
				configASSERT( pxDisk );

				xResult = FF_SDDiskMount( pxDisk );

				if( xResult > 0 )
				{
					FF_PRINTF( "FF_SDDiskMount: SD-card OK\n" );
					FF_SDDiskShowPartition( pxDisk );
				}
				else
				{
					FF_PRINTF( "FF_SDDiskMount: SD-card FAILED\n" );
				}
			}

			xWasPresent = xIsPresent;
		}
	}

#endif /*( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )*/
/*-----------------------------------------------------------*/

void vAssertCalled( const char *pcFile, uint32_t ulLine )
{
volatile uint32_t ulBlockVariable = 0UL;
volatile const char *pcAssertedFileName;
volatile int iAssertedErrno;
volatile uint32_t ulAssertedLine;
volatile FF_Error_t xAssertedFF_Error;

	ulAssertedLine = ulLine;
	iAssertedErrno = stdioGET_ERRNO();
	xAssertedFF_Error = stdioGET_FF_ERROR( );
	pcAssertedFileName = strrchr( pcFile, '/' );

	/* These variables are set so they can be viewed in the debugger, but are
	not used in the code - the following lines just remove the compiler warning
	about this. */
	( void ) ulAssertedLine;
	( void ) iAssertedErrno;
	( void ) xAssertedFF_Error;

	if( pcAssertedFileName == 0 )
	{
		pcAssertedFileName = strrchr( pcFile, '\\' );
	}
	if( pcAssertedFileName != NULL )
	{
		pcAssertedFileName++;
	}
	else
	{
		pcAssertedFileName = pcFile;
	}
	FreeRTOS_printf( ( "vAssertCalled( %s, %ld\n", pcFile, ulLine ) );

	/* Setting ulBlockVariable to a non-zero value in the debugger will allow
	this function to be exited. */
	taskDISABLE_INTERRUPTS();
	{
		while( ulBlockVariable == 0UL )
		{
			__asm volatile( "NOP" );
		}
	}
	taskENABLE_INTERRUPTS();
}
/*-----------------------------------------------------------*/

/* Called by FreeRTOS+TCP when the network connects or disconnects.  Disconnect
events are only received if implemented in the MAC driver. */
void vApplicationIPNetworkEventHook( eIPCallbackEvent_t eNetworkEvent )
{
uint32_t ulIPAddress, ulNetMask, ulGatewayAddress, ulDNSServerAddress;
char cBuffer[ 16 ];
static BaseType_t xTasksAlreadyCreated = pdFALSE;

	FreeRTOS_printf( ( "vApplicationIPNetworkEventHook: event %ld\n", eNetworkEvent ) );

	/* If the network has just come up...*/
	if( eNetworkEvent == eNetworkUp )
	{
		/* Create the tasks that use the IP stack if they have not already been
		created. */
		if( xTasksAlreadyCreated == pdFALSE )
		{
			/* Tasks that use the TCP/IP stack can be created here. */

			/* Start a new task to fetch logging lines and send them out. */
			#if( mainCREATE_UDP_LOGGING_TASK == 1 )
			{
				vUDPLoggingTaskCreate();
			}
			#endif

			#if( ( mainCREATE_FTP_SERVER == 1 ) || ( mainCREATE_HTTP_SERVER == 1 ) )
			{
				/* Let the server work task now it can now create the servers. */
				xTaskNotifyGive( xServerWorkTaskHandle );
			}
			#endif

			#if( mainCREATE_TCP_ECHO_CLIENT_TASKS_SINGLE == 1 )
			{
				vStartTCPEchoClientTasks_SingleTasks( mainECHO_CLIENT_TASK_STACK_SIZE, mainECHO_CLIENT_TASK_PRIORITY );
			}
			#endif

			#if( mainCREATE_SIMPLE_TCP_ECHO_SERVER == 1 )
			{
				vStartSimpleTCPServerTasks( mainECHO_SERVER_STACK_SIZE, mainECHO_SERVER_TASK_PRIORITY );
			}
			#endif

			/* Register example commands with the FreeRTOS+CLI command
			interpreter via the UDP port specified by the
			mainUDP_CLI_PORT_NUMBER constant.  If the HTTP or FTP servers are
			being created then file system related commands will also be
			registered from the TCP server task. */
			#if( mainCREATE_UDP_CLI_TASKS == 1 )
			{
				vRegisterSampleCLICommands();
				vRegisterTCPCLICommands();
				vStartUDPCommandInterpreterTask( mainUDP_CLI_TASK_STACK_SIZE, mainUDP_CLI_PORT_NUMBER, mainUDP_CLI_TASK_PRIORITY );
			}
			#endif

			xTasksAlreadyCreated = pdTRUE;
		}

		/* Print out the network configuration, which may have come from a DHCP
		server. */
		FreeRTOS_GetAddressConfiguration( &ulIPAddress, &ulNetMask, &ulGatewayAddress, &ulDNSServerAddress );
		FreeRTOS_inet_ntoa( ulIPAddress, cBuffer );
		FreeRTOS_printf( ( "IP Address: %s\n", cBuffer ) );

		FreeRTOS_inet_ntoa( ulNetMask, cBuffer );
		FreeRTOS_printf( ( "Subnet Mask: %s\n", cBuffer ) );

		FreeRTOS_inet_ntoa( ulGatewayAddress, cBuffer );
		FreeRTOS_printf( ( "Gateway Address: %s\n", cBuffer ) );

		FreeRTOS_inet_ntoa( ulDNSServerAddress, cBuffer );
		FreeRTOS_printf( ( "DNS Server Address: %s\n", cBuffer ) );
	}
}
/*-----------------------------------------------------------*/

void vApplicationMallocFailedHook( void )
{
	/* Called if a call to pvPortMalloc() fails because there is insufficient
	free memory available in the FreeRTOS heap.  pvPortMalloc() is called
	internally by FreeRTOS API functions that create tasks, queues, software
	timers, and semaphores.  The size of the FreeRTOS heap is set by the
	configTOTAL_HEAP_SIZE configuration constant in FreeRTOSConfig.h. */
	vAssertCalled( __FILE__, __LINE__ );
}
/*-----------------------------------------------------------*/

void vApplicationStackOverflowHook( TaskHandle_t pxTask, char *pcTaskName )
{
	( void ) pcTaskName;
	( void ) pxTask;

	/* Run time stack overflow checking is performed if
	configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2.  This hook
	function is called if a stack overflow is detected. */
	taskDISABLE_INTERRUPTS();
	for( ;; );
}
/*-----------------------------------------------------------*/

UBaseType_t uxRand( void )
{
const uint32_t ulMultiplier = 0x015a4e35UL, ulIncrement = 1UL;

	/* Utility function to generate a pseudo random number. */

	ulNextRand = ( ulMultiplier * ulNextRand ) + ulIncrement;
	return( ( int ) ( ulNextRand >> 16UL ) & 0x7fffUL );
}
/*-----------------------------------------------------------*/

static void prvSRand( UBaseType_t ulSeed )
{
	/* Utility function to seed the pseudo random number generator. */
	ulNextRand = ulSeed;
}
/*-----------------------------------------------------------*/


const char *pcApplicationHostnameHook( void )
{
	/* Assign the name "rtosdemo" to this network node.  This function will be
	called during the DHCP: the machine will be registered with an IP address
	plus this name. */
	return mainHOST_NAME;
}
/*-----------------------------------------------------------*/

int Basic_stricmp( const char *pc1, const char *pc2 )
{
int iReturn = 0;

	while( *pc1 != 0x00 )
	{
		if( tolower( ( int ) *pc1 ) != tolower( ( int ) *pc2 ) )
		{
			iReturn = 1;
			break;
		}
		else
		{
			pc1++;
			pc2++;
		}
	}

	return iReturn;
}
/*-----------------------------------------------------------*/

BaseType_t xApplicationDNSQueryHook( const char *pcName )
{
BaseType_t xReturn;

	/* Determine if a name lookup is for this node.  Two names are given
	to this node: that returned by pcApplicationHostnameHook() and that set
	by mainDEVICE_NICK_NAME. */
	if( Basic_stricmp( pcName, pcApplicationHostnameHook() ) == 0 )
	{
		xReturn = pdPASS;
	}
	else if( Basic_stricmp( pcName, mainDEVICE_NICK_NAME ) == 0 )
	{
		xReturn = pdPASS;
	}
	else
	{
		xReturn = pdFAIL;
	}

	return xReturn;
}
/*-----------------------------------------------------------*/

uint32_t xGetRunTimeCounterValue( void )
{
static uint64_t ullHiresTime = 0; /* Is always 0? */

	return ( uint32_t ) ( ullGetHighResolutionTime() - ullHiresTime );
}
/*-----------------------------------------------------------*/

time_t FreeRTOS_time( time_t *pxTime )
{
	( void ) pxTime;
	return xTaskGetTickCount() / 1000 + 1425522441ul;
}
/*-----------------------------------------------------------*/

static void prvInitialiseHeap( )
{
uint32_t ulHeapSize;
uint8_t *pucHeapStart, *pucHeapEnd;

	pucHeapStart = ( uint8_t * ) ( ( ( ( uint32_t ) &mainHEAP_START ) + 7 ) & ~0x07ul );
	pucHeapEnd = ( uint8_t * ) ( mainRAM_START + mainRAM_LENGTH );

	ulHeapSize = ( uint32_t ) ( ( uint32_t ) pucHeapEnd - ( uint32_t ) &mainHEAP_START );
	ulHeapSize &= ~0x07ul;
	ulHeapSize -= 1024;

	HeapRegion_t xHeapRegions[] = {
		{ ( unsigned char *) pucHeapStart, ulHeapSize },
		{ ( unsigned char *) SRAM_BASE_ADDRESS, mainEXTERNAL_SRAM_SIZE },
		{ ( unsigned char *) SRAM_BASE_ADDRESS_2ND, mainEXTERNAL_SRAM_SIZE },
		{ NULL, 0 }
 	};

	vPortDefineHeapRegions( xHeapRegions );
}
/*-----------------------------------------------------------*/

static void prvMiscInitialisation( void )
{
	/* Initilise the SAM system */
	sysclk_init();
	board_init();
	prvInitialiseHeap();
	pmc_enable_periph_clk(ID_GMAC);
	pmc_enable_periph_clk(ID_TC0);
	pmc_enable_periph_clk(ID_TC3);
	pmc_enable_periph_clk(ID_SMC);

	#ifdef CONF_BOARD_TWI0
	{
		pmc_enable_periph_clk(ID_TWI0);
	}
	#endif

	#ifdef CONF_BOARD_TWI1
	{
		pmc_enable_periph_clk(ID_TWI1);
	}
	#endif

	pmc_enable_periph_clk(ID_PIOA);
	pmc_enable_periph_clk(ID_PIOB);

	/* Start a TC timer to get a hi-precision time. */
	vStartHighResolutionTimer();

	/* Seed the pseudo random number generator. */
	prvSRand( ( uint32_t ) prvMiscInitialisation );
}
/*-----------------------------------------------------------*/

static void prvLEDTimerCallback( TimerHandle_t xTimer )
{
	/* Prevent compiler warnings about the unused parameter. */
	( void ) xTimer;

	/* An LED is toggle to show that something is alive. */
	ioport_toggle_pin_level( LED0_GPIO );
}
/*-----------------------------------------------------------*/

/* Keep the linker happy. */
int _write( int fd, char* buf, int nbytes )
{
	( void ) fd;
	( void ) buf;
	( void ) nbytes;

	return 0;
}
/*-----------------------------------------------------------*/

/* Keep the linker happy. */
int _read( int fd, char* buf, int nbytes )
{
	( void ) fd;
	( void ) buf;
	( void ) nbytes;

	return 0;
}
/*-----------------------------------------------------------*/

void HardFault_Handler( void )
{
	while (1)
	{
	}
}
