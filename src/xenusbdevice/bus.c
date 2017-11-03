/*++

Copyright (c) 2017. Assured Information Security. Chris Patterson <pattersonc@ainfosec.com>

Copyright (c) Microsoft Corporation All Rights Reserved

Module: bus
Description: Responsible for 'devices/vusb' under xenbus.  Monitors xenbus and creates
child PDOs as devices come online.  Initiates cleanup when children are removed.

<xenbus> FDO

<xenbus> PDO
 |
<bus> FDO
 |
<bus-usbroothub-port> PDO
 |
<usbroothub> RAW PDO

--*/

#pragma warning(push, 0)
#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <debug_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <range_set_interface.h>
#include <store_interface.h>
#include <suspend_interface.h>
#include <unplug_interface.h>
#pragma warning(pop)

#include "bus.h"

#define BUS_TAG         'Xusb'

#define MAX_INSTANCE_ID_LEN 80

typedef struct _PDO_IDENTIFICATION_DESCRIPTION
{
	WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
	ULONG DeviceId;
} PDO_IDENTIFICATION_DESCRIPTION, *PPDO_IDENTIFICATION_DESCRIPTION;

typedef struct _PDO_DEVICE_CONTEXT
{
	ULONG DeviceId;
} PDO_DEVICE_CONTEXT, *PPDO_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PDO_DEVICE_CONTEXT, BusPdoGetContext)

typedef struct _FDO_DEVICE_CONTEXT
{
	WDFDEVICE					Device;

	XENBUS_DEBUG_INTERFACE      DebugInterface;
	XENBUS_SUSPEND_INTERFACE    SuspendInterface;
	XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
	XENBUS_STORE_INTERFACE      StoreInterface;
	XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
	XENBUS_CACHE_INTERFACE      CacheInterface;
	XENBUS_GNTTAB_INTERFACE     GnttabInterface;
	XENBUS_UNPLUG_INTERFACE     UnplugInterface;

	PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;

	HANDLE						XenstoreWatchThreadHandle;
	KEVENT                      XenstoreWatchThreadEvent;
	PXENBUS_STORE_WATCH         XenstoreWatchThreadWatch;
	BOOLEAN						XenstoreWatchThreadAlert;

	WDFSPINLOCK					XenstoreWatchLock;

} FDO_DEVICE_CONTEXT, *PFDO_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FDO_DEVICE_CONTEXT, BusFdoGetContext)

//
// Forward declarations
//

NTSTATUS
BusCreatePdo(
	_In_ WDFDEVICE       Device,
	_In_ PWDFDEVICE_INIT DeviceInit,
	_In_ ULONG           DeviceId
);

//EVT_WDF_DEVICE_PREPARE_HARDWARE  BusEvtDevicePrepareHardware;
//EVT_WDF_DEVICE_RELEASE_HARDWARE  BusEvtDeviceReleaseHardware;

EVT_WDF_DEVICE_D0_ENTRY BusEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED BusEvtDeviceD0ExitPreInterruptsDisabled;

#if 0
static BOOLEAN
BusAcquireXenbusInterfaces(
	IN  PFDO_DEVICE_CONTEXT     Fdo
)
{
	NTSTATUS status;

	// DEBUG_INTERFACE

	status = WdfFdoQueryForInterface(Fdo->Device,
		&GUID_XENBUS_DEBUG_INTERFACE,
		(PINTERFACE)&Fdo->DebugInterface,
		sizeof(Fdo->DebugInterface),
		XENBUS_DEBUG_INTERFACE_VERSION_MAX,
		NULL);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus debug interface: 0x%x\n", status);
		goto fail;
	}

	status = XENBUS_DEBUG(Acquire, &Fdo->DebugInterface);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus debug interface: 0x%x\n", status);
		goto fail;
	}

	Trace("successfully acquired xenbus debug interface\n");

	// EVTCHN_INTERFACE

	status = WdfFdoQueryForInterface(Fdo->Device,
		&GUID_XENBUS_EVTCHN_INTERFACE,
		(PINTERFACE)&Fdo->EvtchnInterface,
		sizeof(Fdo->EvtchnInterface),
		XENBUS_EVTCHN_INTERFACE_VERSION_MAX,
		NULL);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus evtchn interface: 0x%x\n", status);
		goto fail;
	}

	status = XENBUS_EVTCHN(Acquire, &Fdo->EvtchnInterface);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus evtchn interface: 0x%x\n", status);
		goto fail;
	}

	Trace("successfully acquired xenbus evtchn interface\n");

	// GNTTAB_INTERFACE

	status = WdfFdoQueryForInterface(Fdo->Device,
		&GUID_XENBUS_GNTTAB_INTERFACE,
		&Fdo->GnttabInterface.Interface,
		sizeof(Fdo->GnttabInterface),
		XENBUS_GNTTAB_INTERFACE_VERSION_MAX,
		NULL);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus gnttab interface: 0x%x\n", status);
		return NULL;
	}

	status = XENBUS_GNTTAB(Acquire, &Fdo->GnttabInterface);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to acquire xenbus gnttab interface: 0x%x\n", status);
		goto fail;
	}

	Trace("successfully acquired xenbus gnttab interface\n");

	// STORE_INTERFACE

	status = WdfFdoQueryForInterface(Fdo->Device,
		&GUID_XENBUS_STORE_INTERFACE,
		&Fdo->StoreInterface.Interface,
		sizeof(Fdo->StoreInterface),
		XENBUS_STORE_INTERFACE_VERSION_MAX,
		NULL);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus store interface: 0x%x\n", status);
		return NULL;
	}

	status = XENBUS_STORE(Acquire, &Fdo->StoreInterface);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to acquire xenbus store interface: 0x%x\n", status);
		goto fail;
	}

	Trace("successfully acquired xenbus store interface\n");

	// SUSPEND_INTERFACE

	status = WdfFdoQueryForInterface(Fdo->Device,
		&GUID_XENBUS_SUSPEND_INTERFACE,
		&Fdo->SuspendInterface.Interface,
		sizeof(Fdo->SuspendInterface),
		XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
		NULL);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to query xenbus suspend interface: 0x%x\n", status);
		return NULL;
	}

	status = XENBUS_SUSPEND(Acquire, &Fdo->SuspendInterface);

	if (!NT_SUCCESS(status))
	{
		TraceError("Failed to acquire xenbus suspend interface: 0x%x\n", status);
		return FALSE;
	}

	Trace("successfully acquired xenbus suspend interface\n");

	return TRUE;
fail:
	return FALSE;
}

static VOID
FdoReleaseInterfaces(
	PFDO_DEVICE_CONTEXT Fdo)
{
	NTSTATUS status;

	// DEBUG_INTERFACE

	XENBUS_DEBUG(Release, &Fdo->DebugInterface);

	Trace("successfully released xenbus debug interface\n");

	// EVTCHN_INTERFACE

	XENBUS_EVTCHN(Release, &Fdo->EvtchnInterface);

	Trace("successfully released xenbus evtchn interface\n");

	// GNTTAB_INTERFACE

	XENBUS_GNTTAB(Release, &Fdo->GnttabInterface);

	Trace("successfully released xenbus gnttab interface\n");

	// STORE_INTERFACE

	XENBUS_STORE(Release, &Fdo->StoreInterface);

	Trace("successfully released xenbus store interface\n");

	// SUSPEND_INTERFACE

	XENBUS_SUSPEND(Release, &Fdo->SuspendInterface);

	Trace("successfully released xenbus suspend interface\n");
}
#endif

VOID
BusEvtIoDeviceControl(
	_In_ WDFQUEUE   Queue,
	_In_ WDFREQUEST Request,
	_In_ size_t     OutputBufferLength,
	_In_ size_t     InputBufferLength,
	_In_ ULONG      IoControlCode
)
{
	UNREFERENCED_PARAMETER(Queue);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(IoControlCode);

	PAGED_CODE();

	Trace("====>\n");

	WdfRequestCompleteWithInformation(Request, STATUS_INVALID_PARAMETER, 0);

	Trace("<===>\n");
}

VOID
BusXenstoreWatchThread(IN WDFDEVICE Device)
{
	NTSTATUS					status;
	PFDO_DEVICE_CONTEXT			Fdo;

	Trace("====>\n");

	Fdo = BusFdoGetContext(Device);

	if (!Fdo)
	{
		Error("Failed to retrieve FDO context\n");
		return;
	}

	status = XENBUS_STORE(WatchAdd,
		&Fdo->StoreInterface,
		"device",
		"vusb",
		&Fdo->XenstoreWatchThreadEvent,
		&Fdo->XenstoreWatchThreadWatch);

	while (!Fdo->XenstoreWatchThreadAlert)
	{
		//LARGE_INTEGER Timeout;

		Trace(".\n");

		status = KeWaitForSingleObject(&Fdo->XenstoreWatchThreadEvent,
			Executive,
			KernelMode,
			TRUE,
			NULL);

		if (status != STATUS_TIMEOUT)
		{
			Warning("Timeout on wait?\n");
		}
		else if (!NT_SUCCESS(status))
		{
			Warning("KeWaitForSingleObject failure: 0x%x", status);
		}

		WDFCHILDLIST ChildList = WdfFdoGetDefaultChildList(Device);
		if (!ChildList)
		{
			Error("Failed to retrieve default child list.\n");
			break;
		}

		BusEvtChildListScanForChildren(ChildList);

		KeClearEvent(&Fdo->XenstoreWatchThreadEvent);
	}

	(VOID)XENBUS_STORE(WatchRemove,
		&Fdo->StoreInterface,
		Fdo->XenstoreWatchThreadWatch);
	Fdo->XenstoreWatchThreadWatch = NULL;

	Trace("<====\n");

	PsTerminateSystemThread(status);
}

VOID
BusDestroyXenstoreWatchThread(IN WDFDEVICE Device)
{
	PFDO_DEVICE_CONTEXT			Fdo;

	Trace("====>\n");

	Fdo = BusFdoGetContext(Device);

	if (!Fdo)
	{
		Error("Failed to retrieve FDO context\n");
		return;
	}

	if (Fdo->XenstoreWatchThreadHandle != NULL)
	{
		LARGE_INTEGER Timeout;

		Timeout.QuadPart = 1000;

		// alert thread to exit
		Fdo->XenstoreWatchThreadAlert = TRUE;
		KeSetEvent(&Fdo->XenstoreWatchThreadEvent, IO_NO_INCREMENT, FALSE);

		// wait for thread to exit
		(VOID)KeWaitForSingleObject(Fdo->XenstoreWatchThreadHandle,
			Executive,
			KernelMode,
			FALSE,
			NULL);

		ObDereferenceObject(Fdo->XenstoreWatchThreadHandle);
		Fdo->XenstoreWatchThreadHandle = NULL;
	}

	Trace("<====\n");
}

NTSTATUS
BusCreateXenstoreWatchThread(IN WDFDEVICE Device)
{
	NTSTATUS					status;
	PFDO_DEVICE_CONTEXT			Fdo;
	OBJECT_ATTRIBUTES   ObjectAttributes;
	HANDLE              ThreadHandle = 0;

	Trace("====>\n");

	Fdo = BusFdoGetContext(Device);

	if (!Fdo)
	{
		Error("Failed to retrieve FDO context\n");
		return STATUS_UNSUCCESSFUL;
	}

	InitializeObjectAttributes(&ObjectAttributes, NULL,
		OBJ_KERNEL_HANDLE, NULL, NULL);

	KeInitializeEvent(&Fdo->XenstoreWatchThreadEvent, NotificationEvent, FALSE);

	status = PsCreateSystemThread(&ThreadHandle,
		THREAD_ALL_ACCESS,
		&ObjectAttributes,
		NULL,
		NULL,
		BusXenstoreWatchThread,
		Device);
	
	if (!NT_SUCCESS(status))
	{
		Error("Failed to create xenstore watch thread\n");
		return STATUS_UNSUCCESSFUL;
	}

	ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL,
		KernelMode, (PVOID*)&Fdo->XenstoreWatchThreadHandle, NULL);

	ZwClose(ThreadHandle);

	KeSetEvent(&Fdo->XenstoreWatchThreadEvent, IO_NO_INCREMENT, FALSE);

	Trace("<====\n");

	return STATUS_SUCCESS;
}

NTSTATUS
BusEvtDeviceAdd(
	IN WDFDRIVER        Driver,
	IN PWDFDEVICE_INIT  DeviceInit
)
{
	NTSTATUS                   status;
	WDF_CHILD_LIST_CONFIG      Config;
	WDF_OBJECT_ATTRIBUTES      Attributes;
	WDFDEVICE                  Device;
	WDF_IO_QUEUE_CONFIG        QueueConfig;
	PNP_BUS_INFORMATION        BusInfo;
	WDFQUEUE                   Queue;
	PFDO_DEVICE_CONTEXT		   Fdo;
	WDF_PNPPOWER_EVENT_CALLBACKS    pnpPowerCallbacks;

	UNREFERENCED_PARAMETER(Driver);

	PAGED_CODE();

	Trace("====>\n");

	WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
	WdfDeviceInitSetExclusive(DeviceInit, TRUE);

	//
	// Since this is pure software bus enumerator, we don't have to register for
	// any PNP/Power callbacks. Framework will take the default action for
	// all the PNP and Power IRPs.
	//

	//
	// WDF_ DEVICE_LIST_CONFIG describes how the framework should handle
	// dynamic child enumeration on behalf of the driver writer.
	// Since we are a bus driver, we need to specify identification description
	// for our child devices. This description will serve as the identity of our
	// child device. Since the description is opaque to the framework, we
	// have to provide bunch of callbacks to compare, copy, or free
	// any other resources associated with the description.
	//
	WDF_CHILD_LIST_CONFIG_INIT(&Config,
		sizeof(PDO_IDENTIFICATION_DESCRIPTION),
		BusEvtDeviceListCreatePdo
	);
	//
	// This function pointer will be called when the framework needs to copy a
	// identification description from one location to another.  An implementation
	// of this function is only necessary if the description contains description
	// relative pointer values (like  LIST_ENTRY for instance) .
	// If set to NULL, the framework will use RtlCopyMemory to copy an identification .
	// description. In this sample, it's not required to provide these callbacks.
	// they are added just for illustration.
	//
	Config.EvtChildListIdentificationDescriptionDuplicate =
		BusEvtChildListIdentificationDescriptionDuplicate;

	//
	// This function pointer will be called when the framework needs to compare
	// two identificaiton descriptions.  If left NULL a call to RtlCompareMemory
	// will be used to compare two identificaiton descriptions.
	//
	Config.EvtChildListIdentificationDescriptionCompare =
		BusEvtChildListIdentificationDescriptionCompare;
	//
	// This function pointer will be called when the framework needs to free a
	// identification description.  An implementation of this function is only
	// necessary if the description contains dynamically allocated memory
	// (by the driver writer) that needs to be freed. The actual identification
	// description pointer itself will be freed by the framework.
	//
	Config.EvtChildListIdentificationDescriptionCleanup =
		BusEvtChildListIdentificationDescriptionCleanup;

	Config.EvtChildListScanForChildren = BusEvtChildListScanForChildren;

	//
	// Tell the framework to use the built-in childlist to track the state
	// of the device based on the configuration we just created.
	//
	WdfFdoInitSetDefaultChildListConfig(DeviceInit,
		&Config,
		WDF_NO_OBJECT_ATTRIBUTES);

	//
	// Initialize attributes structure to specify size and accessor function
	// for storing device context.
	//
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attributes, FDO_DEVICE_CONTEXT);
	//Attributes.EvtCleanupCallback = BusEvtDestroyCallback;
	Attributes.ExecutionLevel = WdfExecutionLevelDispatch;

	WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
	//pnpPowerCallbacks.EvtDevicePrepareHardware = BusEvtDevicePrepareHardware;
	//pnpPowerCallbacks.EvtDeviceReleaseHardware = BusEvtDeviceReleaseHardware;
	pnpPowerCallbacks.EvtDeviceD0Entry = BusEvtDeviceD0Entry;
	pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled = BusEvtDeviceD0ExitPreInterruptsDisabled;

	WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

	//
	// Create a framework device object. In response to this call, framework
	// creates a WDM deviceobject and attach to the PDO.
	//
	status = WdfDeviceCreate(&DeviceInit, &Attributes, &Device);

	if (!NT_SUCCESS(status)) {
		Error("DeviceCreate failed - status: 0x%x\n", status);
		return status;
	}

	Fdo = BusFdoGetContext(Device);

	//
	// Configure a default queue so that requests that are not
	// configure-fowarded using DeviceConfigureRequestDispatching to goto
	// other queues get dispatched here.
	//
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
		&QueueConfig,
		WdfIoQueueDispatchParallel
	);

	QueueConfig.EvtIoDeviceControl = BusEvtIoDeviceControl;

	//
	// By default, Static Driver Verifier (SDV) displays a warning if it 
	// doesn't find the EvtIoStop callback on a power-managed queue. 
	// The 'assume' below causes SDV to suppress this warning. If the driver 
	// has not explicitly set PowerManaged to WdfFalse, the framework creates
	// power-managed queues when the device is not a filter driver.  Normally 
	// the EvtIoStop is required for power-managed queues, but for this driver
	// it is not needed b/c the driver doesn't hold on to the requests or 
	// forward them to other drivers. This driver completes the requests 
	// directly in the queue's handlers. If the EvtIoStop callback is not 
	// implemented, the framework waits for all driver-owned requests to be
	// done before moving in the Dx/sleep states or before removing the 
	// device, which is the correct behavior for this type of driver.
	// If the requests were taking an indeterminate amount of time to complete,
	// or if the driver forwarded the requests to a lower driver/another stack,
	// the queue should have an EvtIoStop/EvtIoResume.
	//
	__analysis_assume(QueueConfig.EvtIoStop != 0);
	status = WdfIoQueueCreate(Device,
		&QueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		&Queue);
	__analysis_assume(QueueConfig.EvtIoStop == 0);

	if (!NT_SUCCESS(status)) {
		Error("WdfIoQueueCreate failed: status = 0x%x\n", status);
		return status;
	}

	//
	// Get the device context.
	//
	//deviceData = FdoGetData(device);

	//
	// This value is used in responding to the IRP_MN_QUERY_BUS_INFORMATION
	// for the child devices. This is an optional information provided to
	// uniquely idenitfy the bus the device is connected.
	//
	BusInfo.BusTypeGuid = GUID_BUS_XEN_VUSB_INTERFACE_STANDARD;
	BusInfo.LegacyBusType = PNPBus;
	BusInfo.BusNumber = 0;

	WdfDeviceSetBusInformationForChildren(Device, &BusInfo);

	// STORE_INTERFACE

	status = WdfFdoQueryForInterface(Device,
		&GUID_XENBUS_STORE_INTERFACE,
		&Fdo->StoreInterface.Interface,
		sizeof(Fdo->StoreInterface),
		XENBUS_STORE_INTERFACE_VERSION_MAX,
		NULL);

	if (!NT_SUCCESS(status))
	{
		Error("Failed to query xenbus store interface: 0x%x\n", status);
		return STATUS_SUCCESS;
	}

	status = XENBUS_STORE(Acquire, &Fdo->StoreInterface);

	if (!NT_SUCCESS(status))
	{
		Error("Failed to acquire xenbus store interface: 0x%x\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	Info("successfully acquired xenbus store interface\n");

	//BusEvtDevicePrepareHardware(Device, NULL, NULL);

	return status;
}

#if 0
NTSTATUS
BusPlugInDevice(
	IN WDFDEVICE       Device,
	IN ULONG           DeviceId
)

/*++

Routine Description:

The user application has told us that a new device on the bus has arrived.

We therefore create a description structure in stack, fill in information about
the child device and call WdfChildListAddOrUpdateChildDescriptionAsPresent
to add the device.

--*/

{
	WDFCHILDLIST ChildList;
	PDO_IDENTIFICATION_DESCRIPTION Description;
	NTSTATUS         status;

	PAGED_CODE();

	Trace("====>\n");

	Info("Request to plug in device id: %lu\n", DeviceId);

	ChildList = WdfFdoGetDefaultChildList(Device);

	if (!ChildList)
	{
		Error("Failed to get default child list\n");
		return STATUS_NO_SUCH_DEVICE;
	}

	//
	// Initialize the description with the information about the newly
	// plugged in device.
	//
	WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(
		&Description.Header,
		sizeof(Description)
	);

	Description.DeviceId = DeviceId;

	//
	// Call the framework to add this child to the childlist. This call
	// will internaly call our DescriptionCompare callback to check
	// whether this device is a new device or existing device. If
	// it's a new device, the framework will call DescriptionDuplicate to create
	// a copy of this description in nonpaged pool.
	// The actual creation of the child device will happen when the framework
	// receives QUERY_DEVICE_RELATION request from the PNP manager in
	// response to InvalidateDeviceRelations call made as part of adding
	// a new child.
	//
	status = WdfChildListAddOrUpdateChildDescriptionAsPresent(
		ChildList,
		&Description.Header,
		NULL);

	if (!NT_SUCCESS(status) && (status != STATUS_OBJECT_NAME_EXISTS))
	{
		Error("Failed to plug in device id 0x%x\n", DeviceId);
	}

	Trace("<====\n");

	return status;
}

NTSTATUS
BusUnPlugDevice(
	IN WDFDEVICE   Device,
	IN ULONG       DeviceId
)
/*++

Routine Description:

The application has told us a device has departed from the bus.

We therefore need to flag the PDO as no longer present.

Arguments:


Returns:

STATUS_SUCCESS upon successful removal from the list
STATUS_INVALID_PARAMETER if the removal was unsuccessful

--*/

{
	NTSTATUS       status;
	WDFCHILDLIST   ChildList;

	PAGED_CODE();

	Trace("====>\n");

	Info("Request to unplug device id: %lu\n", DeviceId);

	ChildList = WdfFdoGetDefaultChildList(Device);

	if (0 == DeviceId)
	{
		//
		// Unplug everybody.  We do this by starting a scan and then not reporting
		// any children upon its completion
		//
		status = STATUS_SUCCESS;

		WdfChildListBeginScan(ChildList);
		//
		// A call to WdfChildListBeginScan indicates to the framework that the
		// driver is about to scan for dynamic children. After this call has
		// returned, all previously reported children associated with this will be
		// marked as potentially missing.  A call to either
		// WdfChildListUpdateChildDescriptionAsPresent  or
		// WdfChildListMarkAllChildDescriptionsPresent will mark all previuosly
		// reported missing children as present.  If any children currently
		// present are not reported present by calling
		// WdfChildListUpdateChildDescriptionAsPresent at the time of
		// WdfChildListEndScan, they will be reported as missing to the PnP subsystem
		// After WdfChildListEndScan call has returned, the framework will
		// invalidate the device relations for the FDO associated with the list
		// and report the changes
		//
		WdfChildListEndScan(ChildList);
	}
	else
	{
		PDO_IDENTIFICATION_DESCRIPTION Description;

		WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(
			&Description.Header,
			sizeof(Description)
		);

		Description.DeviceId = DeviceId;

		//
		// WdfFdoUpdateChildDescriptionAsMissing indicates to the framework that a
		// child device that was previuosly detected is no longe present on the bus.
		// This API can be called by itself or after a call to WdfChildListBeginScan.
		// After this call has returned, the framework will invalidate the device
		// relations for the FDO associated with the list and report the changes.
		//
		status = WdfChildListUpdateChildDescriptionAsMissing(ChildList,
			&Description.Header);

		if (status == STATUS_NO_SUCH_DEVICE) {
			Info("Request to unplug unknown device id = 0x%x\n",
				DeviceId);
		}
	}

	Trace("<====\n");

	return status;
}

NTSTATUS
BusEjectDevice(
	IN WDFDEVICE   Device,
	IN ULONG       DeviceId
)
{
	WDFDEVICE        hChild;
	NTSTATUS         status = STATUS_INVALID_PARAMETER;
	WDFCHILDLIST     ChildList;

	Trace("====>\n");

	PAGED_CODE();

	Info("Request to eject device id: %lu\n", DeviceId);

	ChildList = WdfFdoGetDefaultChildList(Device);

	//
	// A zero DeviceId means eject all children
	//
	if (0 == DeviceId) {
		WDF_CHILD_LIST_ITERATOR     iterator;

		WDF_CHILD_LIST_ITERATOR_INIT(&iterator,
			WdfRetrievePresentChildren);

		WdfChildListBeginIteration(ChildList, &iterator);

		for (; ; ) {
			WDF_CHILD_RETRIEVE_INFO         childInfo;
			PDO_IDENTIFICATION_DESCRIPTION  description;
			BOOLEAN                         ret;

			//
			// Init the structures.
			//
			WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&description.Header, sizeof(description));
			WDF_CHILD_RETRIEVE_INFO_INIT(&childInfo, &description.Header);

			WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(
				&description.Header,
				sizeof(description)
			);
			//
			// Get the device identification description
			//
			status = WdfChildListRetrieveNextDevice(ChildList,
				&iterator,
				&hChild,
				&childInfo);

			if (!NT_SUCCESS(status) || status == STATUS_NO_MORE_ENTRIES) {
				break;
			}

			ASSERT(childInfo.Status == WdfChildListRetrieveDeviceSuccess);

			//
			// Use that description to request an eject.
			//
			ret = WdfChildListRequestChildEject(ChildList, &description.Header);
			if (!ret) {
				WDFVERIFY(ret);
			}
		}

		WdfChildListEndIteration(ChildList, &iterator);

		if (status == STATUS_NO_MORE_ENTRIES) {
			status = STATUS_SUCCESS;
		}
	}
	else {
		PDO_IDENTIFICATION_DESCRIPTION description;

		WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(
			&description.Header,
			sizeof(description)
		);

		description.DeviceId = DeviceId;

		if (WdfChildListRequestChildEject(ChildList, &description.Header)) {
			status = STATUS_SUCCESS;
		}
	}

	Trace("<====\n");
	return status;
}

static FORCEINLINE CHAR
__toupper(
	IN  CHAR    Character
)
{
	if (Character < 'a' || Character > 'z')
		return Character;

	return 'A' + Character - 'a';
}

static FORCEINLINE VOID
BusFreeAnsi(
	IN  PANSI_STRING    Ansi
)
{
	ULONG               Index;

	for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
		ExFreePool(Ansi[Index].Buffer);

	ExFreePool(Ansi);
}

static FORCEINLINE PANSI_STRING
BusMultiSzToUpcaseAnsi(
	_Inout_z_  PCHAR       Buffer
)
{
	PANSI_STRING    Ansi;
	LONG            Index;
	LONG            Count;
	NTSTATUS        status;

	Index = 0;
	Count = 0;
	for (;;) {
		if (Buffer[Index] == '\0') {
			Count++;
			Index++;

			// Check for double NUL
			if (Buffer[Index] == '\0')
				break;
		}
		else {
			Buffer[Index] = __toupper(Buffer[Index]);
			Index++;
		}
	}

	Ansi = (PANSI_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(ANSI_STRING) * (Count + 1), BUS_TAG);

	status = STATUS_NO_MEMORY;
	if (Ansi == NULL)
		goto fail1;

	for (Index = 0; Index < Count; Index++) {
		ULONG   Length;

		Length = (ULONG)strlen(Buffer);
		Ansi[Index].MaximumLength = (USHORT)(Length + 1);
		Ansi[Index].Buffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, Ansi[Index].MaximumLength, BUS_TAG);

		status = STATUS_NO_MEMORY;
		if (Ansi[Index].Buffer == NULL)
			goto fail2;

		RtlCopyMemory(Ansi[Index].Buffer, Buffer, Length);
		Ansi[Index].Length = (USHORT)Length;

		Buffer += Length + 1;
	}

	return Ansi;

fail2:
	Error("fail2\n");

	while (--Index >= 0)
		ExFreePool(Ansi[Index].Buffer);

	ExFreePool(Ansi);

fail1:
	Error("fail1 (%08x)\n", status);

	return NULL;
}
#endif
VOID
BusEvtChildListScanForChildren(
	_In_ WDFCHILDLIST ChildList
)
{
	NTSTATUS		status;
	size_t			Index;
	PFDO_DEVICE_CONTEXT Fdo;
	WDFDEVICE       Device;
	PCHAR           Buffer;

	Trace("====>\n");

	Device = WdfChildListGetDevice(ChildList);

	if (!Device)
	{
		Error("Failed to retrieve Device\n");
		return;
	}

	Fdo = BusFdoGetContext(Device);

	Info("Fdo = 0x%x\n", Fdo);

	if (!Fdo)
	{
		Error("Failed to retrieve FDO context\n");
		return;
	}

	status = XENBUS_STORE(Directory,
		&Fdo->StoreInterface,
		NULL,
		"device",
		"vusb",
		&Buffer);

	if (!NT_SUCCESS(status))
	{
		Info("Failed to perform directory in xenstore.\n");
		return;
	}

#if 0
	XenUsbDevices = BusMultiSzToUpcaseAnsi(Buffer);
	if (XenUsbDevices == NULL)
	{
		Info("No devices found.\n");
		goto fail;
	}
#endif
	WdfChildListBeginScan(ChildList);
	for (Index = 0;;)
	{
		PDO_IDENTIFICATION_DESCRIPTION Description;
		PCHAR           DeviceString = &Buffer[Index];
		size_t			Length;
		ULONG			DeviceId;

		if (DeviceString[0] == 0)
		{
			break;
		}

		Length = strlen(DeviceString);
		Index += Length + 1;
		
		Info("Parsing xenbus state for node: device/vusb/%s\n",
			DeviceString);

		if (sscanf_s(DeviceString, "%lu", &DeviceId) != 1)
		{
			Error("Failed to parse xenbus state for node: device/vusb/%s\n",
				DeviceString);
			continue;
		}

		Info("Parsed xenbus state for node: device/vusb/%lu\n", DeviceId);

		//
		// Initialize the description with the information about the newly
		// plugged in device.
		//
		WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(
			&Description.Header,
			sizeof(Description)
		);

		Description.DeviceId = DeviceId;

		//
		// Call the framework to add this child to the childlist. This call
		// will internaly call our DescriptionCompare callback to check
		// whether this device is a new device or existing device. If
		// it's a new device, the framework will call DescriptionDuplicate to create
		// a copy of this description in nonpaged pool.
		// The actual creation of the child device will happen when the framework
		// receives QUERY_DEVICE_RELATION request from the PNP manager in
		// response to InvalidateDeviceRelations call made as part of adding
		// a new child.
		//

		// Info("Marking as present: device/vusb/%lu\n", DeviceId);

		status = WdfChildListAddOrUpdateChildDescriptionAsPresent(
			ChildList,
			&Description.Header,
			NULL);

		if (!NT_SUCCESS(status) && (status != STATUS_OBJECT_NAME_EXISTS))
		{
			Error("Failed to mark as present: device/vusb/%d\n", DeviceId);
			continue;
		}
	}

	Info("Ending list scan\n");

	WdfChildListEndScan(ChildList);
#if 0
	BusFreeAnsi(XenUsbDevices);
#endif

	XENBUS_STORE(Free,
		&Fdo->StoreInterface,
		Buffer);

	Trace("<====\n");
}

NTSTATUS
BusEvtChildListIdentificationDescriptionDuplicate(
	WDFCHILDLIST DeviceList,
	PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER SourceIdentificationDescription,
	PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER DestinationIdentificationDescription
)
/*++

Routine Description:

It is called when the framework needs to make a copy of a description.
This happens when a request is made to create a new child device by
calling WdfChildListAddOrUpdateChildDescriptionAsPresent.
If this function is left unspecified, RtlCopyMemory will be used to copy the
source description to destination. Memory for the description is managed by the
framework.

NOTE:   Callback is invoked with an internal lock held.  So do not call out
to any WDF function which will require this lock
(basically any other WDFCHILDLIST api)

Arguments:

DeviceList - Handle to the default WDFCHILDLIST created by the framework.
SourceIdentificationDescription - Description of the child being created -memory in
the calling thread stack.
DestinationIdentificationDescription - Created by the framework in nonpaged pool.

Return Value:

NT Status code.

--*/
{
	PPDO_IDENTIFICATION_DESCRIPTION src, dst;

	UNREFERENCED_PARAMETER(DeviceList);

	src = CONTAINING_RECORD(SourceIdentificationDescription,
		PDO_IDENTIFICATION_DESCRIPTION,
		Header);
	dst = CONTAINING_RECORD(DestinationIdentificationDescription,
		PDO_IDENTIFICATION_DESCRIPTION,
		Header);  

	dst->DeviceId = src->DeviceId;
	return STATUS_SUCCESS;
}

BOOLEAN
BusEvtChildListIdentificationDescriptionCompare(
	WDFCHILDLIST DeviceList,
	PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER FirstIdentificationDescription,
	PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER SecondIdentificationDescription
)
/*++

Routine Description:

It is called when the framework needs to compare one description with another.
Typically this happens whenever a request is made to add a new child device.
If this function is left unspecified, RtlCompareMemory will be used to compare the
descriptions.

NOTE:   Callback is invoked with an internal lock held.  So do not call out
to any WDF function which will require this lock
(basically any other WDFCHILDLIST api)

Arguments:

DeviceList - Handle to the default WDFCHILDLIST created by the framework.

Return Value:

TRUE or FALSE.

--*/
{
	PPDO_IDENTIFICATION_DESCRIPTION lhs, rhs;

	UNREFERENCED_PARAMETER(DeviceList);

	lhs = CONTAINING_RECORD(FirstIdentificationDescription,
		PDO_IDENTIFICATION_DESCRIPTION,
		Header);
	rhs = CONTAINING_RECORD(SecondIdentificationDescription,
		PDO_IDENTIFICATION_DESCRIPTION,
		Header);

	return (lhs->DeviceId == rhs->DeviceId) ? TRUE : FALSE;
}

#pragma prefast(push)
#pragma prefast(disable:6101, "No need to assign IdentificationDescription")

VOID
BusEvtChildListIdentificationDescriptionCleanup(
	_In_ WDFCHILDLIST DeviceList,
	_Out_ PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription
)
/*++

Routine Description:

It is called to free up any memory resources allocated as part of the description.
This happens when a child device is unplugged or ejected from the bus.
Memory for the description itself will be freed by the framework.

Arguments:

DeviceList - Handle to the default WDFCHILDLIST created by the framework.

IdentificationDescription - Description of the child being deleted

Return Value:


--*/
{
	PPDO_IDENTIFICATION_DESCRIPTION pDesc;

	UNREFERENCED_PARAMETER(DeviceList);

	pDesc = CONTAINING_RECORD(IdentificationDescription,
		PDO_IDENTIFICATION_DESCRIPTION,
		Header);

	// free any memory allocations pointed to by pDesc
	// but at the moment, we have none.
}

#pragma prefast(pop) // disable:6101

NTSTATUS
BusEvtDeviceListCreatePdo(
	WDFCHILDLIST DeviceList,
	PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription,
	PWDFDEVICE_INIT ChildInit
)
/*++

Routine Description:

Called by the framework in response to Query-Device relation when
a new PDO for a child device needs to be created.

Arguments:

DeviceList - Handle to the default WDFCHILDLIST created by the framework as part
of FDO.

IdentificationDescription - Decription of the new child device.

ChildInit - It's a opaque structure used in collecting device settings
and passed in as a parameter to CreateDevice.

Return Value:

NT Status code.

--*/
{
	WDFDEVICE Device;
	PPDO_IDENTIFICATION_DESCRIPTION pDesc;
	NTSTATUS status;

	PAGED_CODE();

	Trace("====>\n");

	Device = WdfChildListGetDevice(DeviceList);

	pDesc = CONTAINING_RECORD(IdentificationDescription,
		PDO_IDENTIFICATION_DESCRIPTION,
		Header);

	status = BusCreatePdo(Device,
		ChildInit,
		pDesc->DeviceId);

	Trace("<====\n");

	return status;
}

NTSTATUS
BusEvtDeviceD0Entry(
	_In_ WDFDEVICE Device,
	IN  WDF_POWER_DEVICE_STATE PreviousState
)
{
	//UNREFERENCED_PARAMETER(ResourcesRaw);
	//UNREFERENCED_PARAMETER(ResourcesTranslated); 
	
	NTSTATUS status;

	Trace("====>\n");

	status = BusCreateXenstoreWatchThread(Device);

	if (!NT_SUCCESS(status))
	{
		Error("Failed to create xenstore watch thread.\n");
	}

	Trace("<====\n");

	return status;
}

NTSTATUS
BusEvtDeviceD0ExitPreInterruptsDisabled(
	_In_ WDFDEVICE Device,
	IN  WDF_POWER_DEVICE_STATE TargetState
)
{
//	UNREFERENCED_PARAMETER(ResourcesTranslated);

	Trace("====>\n");

	BusDestroyXenstoreWatchThread(Device);

	Trace("<====\n");

	return STATUS_SUCCESS;
}

NTSTATUS
BusCreatePdo(
	_In_ WDFDEVICE       Device,
	_In_ PWDFDEVICE_INIT DeviceInit,
	_In_ ULONG           DeviceId
)
/*++

Routine Description:

This routine creates and initialize a PDO.

Arguments:

Return Value:

NT Status code.

--*/
{
	NTSTATUS                    status;
	PPDO_DEVICE_CONTEXT            pdoData = NULL;
	WDFDEVICE                   hChild = NULL;
	//WDF_QUERY_INTERFACE_CONFIG  qiConfig;
	WDF_OBJECT_ATTRIBUTES       pdoAttributes;
	WDF_DEVICE_PNP_CAPABILITIES pnpCaps;
	WDF_DEVICE_POWER_CAPABILITIES powerCaps;
	//TOASTER_INTERFACE_STANDARD  ToasterInterface;
	DECLARE_UNICODE_STRING_SIZE(deviceName, MAX_INSTANCE_ID_LEN);
	DECLARE_UNICODE_STRING_SIZE(deviceId, MAX_INSTANCE_ID_LEN);

	PAGED_CODE();

	UNREFERENCED_PARAMETER(Device);

	Trace("====>\n");

	//
	// Set DeviceType
	//
	WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);

	status = RtlUnicodeStringPrintf(&deviceName, L"Xen Virtual USB Device %lu", DeviceId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = RtlUnicodeStringPrintf(&deviceId, L"%lu", DeviceId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = WdfPdoInitAssignDeviceID(DeviceInit, &deviceId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = WdfPdoInitAddHardwareID(DeviceInit, &deviceId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = WdfPdoInitAssignInstanceID(DeviceInit, &deviceId);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//
	// You can call WdfPdoInitAddDeviceText multiple times, adding device
	// text for multiple locales. When the system displays the text, it
	// chooses the text that matches the current locale, if available.
	// Otherwise it will use the string for the default locale.
	// The driver can specify the driver's default locale by calling
	// WdfPdoInitSetDefaultLocale.
	//
	status = WdfPdoInitAddDeviceText(DeviceInit,
		&deviceName,
		&deviceName,
		0x409);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	WdfPdoInitSetDefaultLocale(DeviceInit, 0x409);

	//
	// Initialize the attributes to specify the size of PDO device extension.
	// All the state information private to the PDO will be tracked here.
	//
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&pdoAttributes, PDO_DEVICE_CONTEXT);

	status = WdfDeviceCreate(&DeviceInit, &pdoAttributes, &hChild);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	//
	// Get the device context.
	//
	pdoData = BusPdoGetContext(hChild);

	pdoData->DeviceId = DeviceId;

	//
	// Set some properties for the child device.
	//
	WDF_DEVICE_PNP_CAPABILITIES_INIT(&pnpCaps);
	pnpCaps.Removable = WdfTrue;
	pnpCaps.EjectSupported = WdfTrue;
	pnpCaps.SurpriseRemovalOK = WdfTrue;

	pnpCaps.Address = DeviceId;
	pnpCaps.UINumber = DeviceId;

	WdfDeviceSetPnpCapabilities(hChild, &pnpCaps);

	WDF_DEVICE_POWER_CAPABILITIES_INIT(&powerCaps);

	powerCaps.DeviceD1 = WdfTrue;
	powerCaps.WakeFromD1 = WdfTrue;
	powerCaps.DeviceWake = PowerDeviceD1;

	powerCaps.DeviceState[PowerSystemWorking] = PowerDeviceD1;
	powerCaps.DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
	powerCaps.DeviceState[PowerSystemSleeping2] = PowerDeviceD2;
	powerCaps.DeviceState[PowerSystemSleeping3] = PowerDeviceD2;
	powerCaps.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
	powerCaps.DeviceState[PowerSystemShutdown] = PowerDeviceD3;

	WdfDeviceSetPowerCapabilities(hChild, &powerCaps);

	return status;
}