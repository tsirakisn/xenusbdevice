//
// Copyright (c) Citrix Systems, Inc.
//
/// @file xenlower.cpp lowlevel bus access implementation.
/// This module is the lower edge interface to the underlying
/// xenbus and hypercalls.
//
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

#define INITGUID

#include <xen.h>
#include "Trace.h"
#include <ntddk.h>
#include <wdf.h>
#pragma warning(push)
#pragma warning(disable:6011)
#include <ntstrsafe.h>
#pragma warning(pop)
#include <stdlib.h>
#include <debug_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <range_set_interface.h>
#include <store_interface.h>
#include <suspend_interface.h>
#include <unplug_interface.h>
#include "xenlower.h"
#include "Driver.h"

#pragma warning(disable : 4127 ) //conditional expression is constant

// Me likey
#if DBG
#define STR2(x) #x
#define STR1(x) STR2(x)
#define LOC __FILE__ "("STR1(__LINE__)") : Warning Msg: " __FUNCTION__
#define XXX_TODO(hint) __pragma(message(LOC " XXX TODO: " hint))
#else
#define XXX_TODO(hint)
#endif

//#define DBG_GREF 1

#ifdef DBG_GREF
static VOID
_XenLowerTraceGref(PCSTR Caller, grant_ref_t greft, GRANT_REF gref)
{
    grant_ref_t greftun = xen_GRANT_REF(gref);

    TraceInfo(("%s: GRANT_REF greft: %d (0x%x) greftun: %d (0x%x) wrapped: %2.2x:%2.2x:%2.2x:%2.2x\n",
        Caller, greft, greft, greftun, greftun,
        gref.__wrapped_data[0], gref.__wrapped_data[1],
        gref.__wrapped_data[2], gref.__wrapped_data[3]));
}

#define XenLowerTraceGref(g1, g2) \
    _XenLowerTraceGref(__FUNCTION__, g1, g2)
#else
#define XenLowerTraceGref(g1, g2) do {} while (FALSE)
#endif

struct XEN_LOWER
{
    WDFDEVICE WdfDevice;
    PVOID XenUpper;
    PDEVICE_OBJECT Pdo;
    CHAR FrontendPath[XEN_LOWER_MAX_PATH];
    CHAR BackendPath[XEN_LOWER_MAX_PATH];
    USHORT BackendDomid;

    PXENBUS_EVTCHN_CHANNEL Channel;
    PXENBUS_GNTTAB_ENTRY SringGrantRef;
    PXENBUS_GNTTAB_CACHE GnttabCache;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
    XENBUS_SUSPEND_FUNCTION     ResumeCallback;

    PXENBUS_DEBUG_CALLBACK      DebugCallback;

    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;
    //XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
    //XENBUS_CACHE_INTERFACE      CacheInterface;
    XENBUS_GNTTAB_INTERFACE     GnttabInterface;
    //XENBUS_UNPLUG_INTERFACE     UnplugInterface;
};

//
// Xen Lower helpers
//

static VOID
XenLowerUnregisterSuspendHandler(
    PXEN_LOWER XenLower)
{
    if (!XenLower->SuspendCallbackLate)
        return;

    XENBUS_SUSPEND(Deregister,
        &XenLower->SuspendInterface,
        XenLower->SuspendCallbackLate);
    XenLower->SuspendCallbackLate = NULL;
}

static VOID
XenLowerRevokeGrantRef(
    PXEN_LOWER XenLower)
{
    if (!XenLower->SringGrantRef)
        return;

    XENBUS_GNTTAB(RevokeForeignAccess,
        &XenLower->GnttabInterface,
        XenLower->GnttabCache,
        TRUE,
        XenLower->SringGrantRef);

    XenLower->SringGrantRef = NULL;
}

static BOOLEAN
XenLowerAcquireInterfaces(
    PXEN_LOWER XenLower)
{
    NTSTATUS status;

    // DEBUG_INTERFACE

    status = WdfFdoQueryForInterface(XenLower->WdfDevice,
        &GUID_XENBUS_DEBUG_INTERFACE,
        (PINTERFACE)&XenLower->DebugInterface,
        sizeof(XenLower->DebugInterface),
        XENBUS_DEBUG_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus debug interface: 0x%x\n", status);
        goto fail;
    }

    status = XENBUS_DEBUG(Acquire, &XenLower->DebugInterface);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus debug interface: 0x%x\n", status);
        goto fail;
    }

    Trace("successfully acquired xenbus debug interface\n");

    // EVTCHN_INTERFACE

    status = WdfFdoQueryForInterface(XenLower->WdfDevice,
        &GUID_XENBUS_EVTCHN_INTERFACE,
        (PINTERFACE)&XenLower->EvtchnInterface,
        sizeof(XenLower->EvtchnInterface),
        XENBUS_EVTCHN_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus evtchn interface: 0x%x\n", status);
        goto fail;
    }

    status = XENBUS_EVTCHN(Acquire, &XenLower->EvtchnInterface);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus evtchn interface: 0x%x\n", status);
        goto fail;
    }

    Trace("successfully acquired xenbus evtchn interface\n");

    // GNTTAB_INTERFACE

    status = WdfFdoQueryForInterface(XenLower->WdfDevice,
        &GUID_XENBUS_GNTTAB_INTERFACE,
        &XenLower->GnttabInterface.Interface,
        sizeof(XenLower->GnttabInterface),
        XENBUS_GNTTAB_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus gnttab interface: 0x%x\n", status);
        return NULL;
    }

    status = XENBUS_GNTTAB(Acquire, &XenLower->GnttabInterface);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to acquire xenbus gnttab interface: 0x%x\n", status);
        goto fail;
    }

    Trace("successfully acquired xenbus gnttab interface\n");

    // STORE_INTERFACE

    status = WdfFdoQueryForInterface(XenLower->WdfDevice,
        &GUID_XENBUS_STORE_INTERFACE,
        &XenLower->StoreInterface.Interface,
        sizeof(XenLower->StoreInterface),
        XENBUS_STORE_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus store interface: 0x%x\n", status);
        return NULL;
    }

    status = XENBUS_STORE(Acquire, &XenLower->StoreInterface);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to acquire xenbus store interface: 0x%x\n", status);
        goto fail;
    }

    Trace("successfully acquired xenbus store interface\n");

    // SUSPEND_INTERFACE

    status = WdfFdoQueryForInterface(XenLower->WdfDevice,
        &GUID_XENBUS_SUSPEND_INTERFACE,
        &XenLower->SuspendInterface.Interface,
        sizeof(XenLower->SuspendInterface),
        XENBUS_SUSPEND_INTERFACE_VERSION_MAX,
        NULL);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to query xenbus suspend interface: 0x%x\n", status);
        return NULL;
    }

    status = XENBUS_SUSPEND(Acquire, &XenLower->SuspendInterface);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to acquire xenbus suspend interface: 0x%x\n", status);
        goto fail;
    }

    Trace("successfully acquired xenbus suspend interface\n");

    return TRUE;
fail:
    return FALSE;
}

static VOID
XenLowerReleaseInterfaces(
    PXEN_LOWER XenLower)
{
    NTSTATUS status;

    // DEBUG_INTERFACE

    XENBUS_DEBUG(Release, &XenLower->DebugInterface);
    
    Trace("successfully released xenbus debug interface\n");

    // EVTCHN_INTERFACE

    XENBUS_EVTCHN(Release, &XenLower->EvtchnInterface);

    Trace("successfully released xenbus evtchn interface\n");

    // GNTTAB_INTERFACE

    XENBUS_GNTTAB(Release, &XenLower->GnttabInterface);

    Trace("successfully released xenbus gnttab interface\n");

    // STORE_INTERFACE

    XENBUS_STORE(Release, &XenLower->StoreInterface);

    Trace("successfully released xenbus store interface\n");

    // SUSPEND_INTERFACE

    XENBUS_SUSPEND(Release, &XenLower->SuspendInterface);

    Trace("successfully released xenbus suspend interface\n");
}

//
// Xen Lower services
//

PXEN_LOWER
XenLowerAlloc(
    VOID)
{
    PXEN_LOWER p =
        (PXEN_LOWER)ExAllocatePoolWithTag(NonPagedPool, sizeof(XEN_LOWER), XVU9);
    if (p)
    {
        RtlZeroMemory(p, sizeof(XEN_LOWER));
    }
    return p;
}

VOID
XenLowerFree(
    PXEN_LOWER XenLower)
{
    if (!XenLower)
        return;

    XenLowerUnregisterSuspendHandler(XenLower);

    XenLowerDisconnectEvtChnDPC(XenLower);

    XenLowerReleaseInterfaces(XenLower);

    ExFreePool(XenLower);
}

#include <wdmguid.h>
BOOLEAN
XenLowerInit(
    PXEN_LOWER XenLower,
    PVOID XenUpper,
    PDEVICE_OBJECT Pdo,
    WDFDEVICE WdfDevice)
{
    NTSTATUS status;
    BUS_INTERFACE_STANDARD BusInterface;
    USHORT DeviceId = 0;
    int BytesRead;

    XenLower->XenUpper = XenUpper;
    XenLower->Pdo = Pdo;
    XenLower->WdfDevice = WdfDevice;

    XenLowerAcquireInterfaces(XenLower);

    // Get the BUS_INTERFACE_STANDARD for our device so that we can
    // read & write to PCI config space.
    status = WdfFdoQueryForInterface(WdfDevice,
        &GUID_BUS_INTERFACE_STANDARD,
        (PINTERFACE)&BusInterface,
        sizeof(BUS_INTERFACE_STANDARD),
        1, // Version
        NULL);

    if (!NT_SUCCESS(status))
    {
        TraceError("failed to query interface for pci bus\n");
        return FALSE;
    }

    Trace("succesfully queried bus interface - reading PCI bus data...\n");

    BytesRead = BusInterface.GetBusData(
        BusInterface.Context,
        PCI_WHICHSPACE_CONFIG, //READ
        &DeviceId,
        FIELD_OFFSET(PCI_COMMON_HEADER, DeviceID),
        FIELD_SIZE(PCI_COMMON_HEADER, DeviceID));

    Trace("DeviceId = 0x%x\n", DeviceId);

    // release bus interface
    BusInterface.InterfaceDereference(BusInterface.Context);

    if (BytesRead != sizeof(DeviceId)) {
        TraceError("GetBusData failed for DeviceId\n");
        return FALSE;
    }

    status = RtlStringCbPrintfA(
        XenLower->FrontendPath,
        sizeof(XenLower->FrontendPath),
        "device/vusb/%d",
        8199);

    if (status != STATUS_SUCCESS)
    {
        XenLower->FrontendPath[0] = 0;
        TraceError("Failed to copy front end path - status: 0x%x\n", status);
        return FALSE;
    }

    Trace("device path: %s\n", XenLower->FrontendPath);

    return TRUE;
}


BOOLEAN
XenLowerBackendInit(
    PXEN_LOWER XenLower)
{
    PCHAR Buffer;
    NTSTATUS status;

    // Note this is split from the XenLowerInit so it can be called on the resume
    // path in case backend values change.

    XXX_TODO("--XT-- All the backend path handling assumes dom0 is the backend, this will change for device domains")
    // XXX TODO all the backend path handling assumes dom0 is the backend. This will
    // not necessarily be true with device domains. The changes to support this go
    // beyond this module though.
    status = XENBUS_STORE(Read,
        &XenLower->StoreInterface,
        NULL,
        XenLower->FrontendPath,
        "backend",
        &Buffer);

    if (!NT_SUCCESS(status))
    {
        TraceError("XENBUS_STORE READ failed to return the back end path, fatal.\n");
        return FALSE;
    }

    status = RtlStringCchCopyA(XenLower->BackendPath,
        sizeof(XenLower->BackendPath),
        Buffer);

    XENBUS_STORE(Free,
        &XenLower->StoreInterface,
        Buffer);

    // READ DOMAIN ID
    status = XENBUS_STORE(Read,
        &XenLower->StoreInterface,
        NULL,
        XenLower->FrontendPath,
        "backend-id",
        &Buffer);

    if (!NT_SUCCESS(status))
    {
        TraceError("XENBUS_STORE READ failed to return the backend-id, fatal.\n");
        return FALSE;
    }

    if (sscanf_s(Buffer, "%hu", &XenLower->BackendDomid) != 1)
    {
        TraceError("failed to parse backend domid\n");
        return FALSE;
    }

    XENBUS_STORE(Free,
        &XenLower->StoreInterface,
        Buffer);

    // XXX TODO for now we only support a dom0 backend so check that here. Later
    // when we support a device domain for vusb, other domids will be fine.
    XXX_TODO("--XT-- For now we only support a dom0 backend so check that here");
    if (XenLower->BackendDomid != 0)
    {
        TraceError("cannot connect to backend Domid: %d, only dom0 supported currently\n",
            XenLower->BackendDomid);
        return FALSE;
    }

    Trace("XenLower initialized - FrontendPath: %s  BackendPath: %s BackendDomid: %hd\n",
        XenLower->FrontendPath, XenLower->BackendPath, XenLower->BackendDomid);

    return TRUE;
}

PVOID
XenLowerGetUpper(
    PXEN_LOWER XenLower)
{
    return XenLower->XenUpper;
}

ULONG
XenLowerInterfaceVersion(
    PXEN_LOWER XenLower)
{
    NTSTATUS status;
    ULONG version = 0;
    PCHAR Buffer;

    status = XENBUS_STORE(Read,
        &XenLower->StoreInterface,
        NULL,
        XenLower->BackendPath,
        "version",
        &Buffer);

    if (!NT_SUCCESS(status))
    {
        TraceError("XENBUS_STORE READ failed to return the back end version, fatal.\n");
        return 0;
    }

    if (sscanf_s(Buffer, "%lu", &version) != 1)
    {
        TraceError("failed to parse interface version\n");
        return 0;
    }

    XENBUS_STORE(Free,
        &XenLower->StoreInterface,
        Buffer);

    // Need to now write the version we support to the frontend
    status = XENBUS_STORE(Printf,
        &XenLower->StoreInterface,
        NULL,
        XenLower->FrontendPath,
        "version",
        "%d",
        XEN_LOWER_INTERFACE_VERSION);

    if (!NT_SUCCESS(status))
    {
        TraceError("xenstore printf for version failed.\n");
        return 0;
    }

    Trace("Read backend version: %d  -  Wrote frontend version: %d\n",
        version, XEN_LOWER_INTERFACE_VERSION);

    return version;
}

PCHAR
XenLowerGetFrontendPath(
    PXEN_LOWER XenLower)
{
    return XenLower->FrontendPath;
}

PCHAR
XenLowerGetBackendPath(
    PXEN_LOWER XenLower)
{
    return XenLower->BackendPath;
}

BOOLEAN
XenLowerGetSring(
    PXEN_LOWER XenLower,
    PFN_NUMBER Pfn)
{
    NTSTATUS status;

    status = XENBUS_GNTTAB(PermitForeignAccess,
        &XenLower->GnttabInterface,
        XenLower->GnttabCache,
        TRUE,
        XenLower->BackendDomid,
        Pfn,
        FALSE,
        &XenLower->SringGrantRef);

    if (!NT_SUCCESS(status))
    {
        TraceError("GnttabGrantForeignAccess() failed to return shared ring grant ref.\n");
        return FALSE;
    }

    // Note the gref will be written to xenstore later in the second connect part
    // in anticipation of supporting suspend/resume.
    return TRUE;
}

BOOLEAN
XenLowerConnectEvtChnDPC(
    PXEN_LOWER XenLower,
    PKSERVICE_ROUTINE DpcCallback,
    VOID *Context)
{
    NTSTATUS status;

    XenLower->Channel = XENBUS_EVTCHN(Open,
        &XenLower->EvtchnInterface,
        XENBUS_EVTCHN_TYPE_UNBOUND,
        DpcCallback,
        Context,
        XenLower->BackendDomid,
        FALSE);

    if (XenLower->Channel == NULL)
    {
        TraceError("failed to allocate DPC for Event Channel.\n");
        return FALSE;
    }

    XENBUS_EVTCHN(Unmask,
        &XenLower->EvtchnInterface,
        XenLower->Channel,
        FALSE);

    return TRUE;
}

VOID
XenLowerScheduleEvtChnDPC(
    PXEN_LOWER XenLower)
{
    if (!XenLower->Channel)
        return;

    XENBUS_EVTCHN(Trigger,
            &XenLower->EvtchnInterface,
            XenLower->Channel);
}

VOID
XenLowerDisconnectEvtChnDPC(
    PXEN_LOWER XenLower)
{
    if (!XenLower->Channel)
        return;

    XENBUS_EVTCHN(Close,
        &XenLower->EvtchnInterface,
        XenLower->Channel);

    XenLower->Channel = NULL;
}

static VOID
FrontendWaitForBackendXenbusStateChange(
    IN      PXEN_LOWER          XenLower,
    IN OUT  XenbusState         *State
)
{
    KEVENT                      Event;
    PXENBUS_STORE_WATCH         Watch;
    LARGE_INTEGER               Start;
    ULONGLONG                   TimeDelta;
    LARGE_INTEGER               Timeout;
    XenbusState                 Old = *State;
    NTSTATUS                    status;

    Trace("%s: ====> %d\n", XenLower->BackendPath, *State);

    //xxx ASSERT(FrontendIsOnline(Frontend));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = XENBUS_STORE(WatchAdd,
        &XenLower->StoreInterface,
        XenLower->BackendPath,
        "state",
        &Event,
        &Watch);

    if (!NT_SUCCESS(status))
        Watch = NULL;

    KeQuerySystemTime(&Start);
    TimeDelta = 0;

    Timeout.QuadPart = 0;

    while (*State == Old && TimeDelta < 120000) {
        PCHAR           Buffer;
        LARGE_INTEGER   Now;

        if (Watch != NULL) {
            ULONG   Attempt = 0;

            while (++Attempt < 1000) {
                status = KeWaitForSingleObject(&Event,
                    Executive,
                    KernelMode,
                    FALSE,
                    &Timeout);

                if (status != STATUS_TIMEOUT)
                    break;

                // We are waiting for a watch event at DISPATCH_LEVEL so
                // it is our responsibility to poll the store ring.
                XENBUS_STORE(Poll,
                    &XenLower->StoreInterface);

                KeStallExecutionProcessor(1000);   // 1ms
            }

            KeClearEvent(&Event);
        }

        status = XENBUS_STORE(Read,
            &XenLower->StoreInterface,
            NULL,
            XenLower->BackendPath,
            "state",
            &Buffer);

        if (!NT_SUCCESS(status)) {
            *State = XenbusStateUnknown;
        }
        else {
            if (sscanf_s(Buffer, "%d", State) != 1)
            {
                TraceError("failed to parse xenbus state\n");
                continue;
            }

            XENBUS_STORE(Free,
                &XenLower->StoreInterface,
                Buffer);
        }

        KeQuerySystemTime(&Now);

        TimeDelta = (Now.QuadPart - Start.QuadPart) / 10000ull;
    }

    if (Watch != NULL)
        (VOID) XENBUS_STORE(WatchRemove,
            &XenLower->StoreInterface,
            Watch);

    Trace("%s: <==== (%d)\n", XenLower->BackendPath, *State);
}

#if 0
static VOID
XenLowerDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
)
{
    PXEN_LOWER XenLower = (PXEN_LOWER) Argument;

    XENBUS_DEBUG(Printf,
        &XenLower->DebugInterface,
        "PATH: %s\n",
        XenLower->FrontendPath);
}

static NTSTATUS
XenLowerFrontendConnect(
    IN  PXEN_LOWER XenLower
)
{
    XenbusState             State;
    ULONG                   Attempt;
    NTSTATUS                status;

    Trace("====>\n");

    status = XENBUS_DEBUG(Acquire, &XenLower->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
        &XenLower->DebugInterface,
        __MODULE__ "|FRONTEND",
        XenLowerDebugCallback,
        XenLower,
        &XenLower->DebugCallback);


    ///

    XENBUS_DEBUG(Deregister,
        &XenLower->DebugInterface,
        XenLower->DebugCallback);
    XenLower->DebugCallback = NULL;

}
#endif

static NTSTATUS
XenLowerConnectBackendInternal(
    PXEN_LOWER XenLower)
{
    NTSTATUS                        status = STATUS_SUCCESS;
    XenbusState                     state;
    ULONG                           Port;

    if (!XenLower->Channel)
    {
        TraceError("no event channel port, this routine must be called after event channel initialization\n");
        return STATUS_UNSUCCESSFUL;
    }

    //---------------------------Backend Wait Ready-------------------------------//
    //
    // Wait for backend to get ready for initialization.
    //

    status = XENBUS_STORE(Printf,
        &XenLower->StoreInterface,
        NULL,
        XenLower->FrontendPath,
        "state",
        "%u",
        XenbusStateInitialising);

    if (!NT_SUCCESS(status))
    {
        TraceError("Failed to change front end state to XenbusStateInitialising(%d) status: 0x%x\n",
            XenbusStateInitialising, status);
        return STATUS_UNSUCCESSFUL;
    }

    Trace("Front end state set to XenbusStateInitialising(%d)\n", XenbusStateInitialising);

    for (state = XenbusStateUnknown; state != XenbusStateInitWait; )
    {
        FrontendWaitForBackendXenbusStateChange(XenLower, &state);

        if (state == XenbusStateClosing || state == XenbusStateUnknown)
        {
            TraceError("backend '%s' went away before we could connect to it?\n", XenLower->BackendPath);
            return STATUS_UNSUCCESSFUL;
        }
    }

    Trace("Back end state went to XenbusStateInitWait(%d)\n", XenbusStateInitWait);
    
    //----------------------------Backend Connect---------------------------------//    

    //
    // Communicate configuration to backend.
    //
    ULONG Attempt = 0;
    do
    {
        PXENBUS_STORE_TRANSACTION   Transaction;

        status = XENBUS_STORE(TransactionStart,
            &XenLower->StoreInterface,
            &Transaction);
        
        status = XENBUS_STORE(Printf,
            &XenLower->StoreInterface,
            Transaction,
            XenLower->FrontendPath,
            "ring-ref",
            "%u",
            XENBUS_GNTTAB(GetReference,
                &XenLower->GnttabInterface,
                XenLower->SringGrantRef));

        if (!NT_SUCCESS(status))
            continue;

        Port = XENBUS_EVTCHN(GetPort,
            &XenLower->EvtchnInterface,
            XenLower->Channel);

        status = XENBUS_STORE(Printf,
            &XenLower->StoreInterface,
            Transaction,
            XenLower->FrontendPath,
            "event-channel",
            "%u",
            Port);

        if (!NT_SUCCESS(status))
            continue;

        status = XENBUS_STORE(Printf,
            &XenLower->StoreInterface,
            NULL,
            XenLower->FrontendPath,
            "state",
            "%u",
            XenbusStateConnected);

        if (!NT_SUCCESS(status))
        {
            TraceError("Failed to change front end state to XenbusStateConnected(%d) status: 0x%x\n",
                XenbusStateConnected, status);
            return STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(TransactionEnd,
            &XenLower->StoreInterface,
            Transaction,
            TRUE);

        if (status != STATUS_RETRY || ++Attempt > 10)
            break;

        continue;

abort:
        (VOID)XENBUS_STORE(TransactionEnd,
            &XenLower->StoreInterface,
            Transaction,
            FALSE);
        break;
    } while (status == STATUS_RETRY);
    
    Trace("Front end state set to XenbusStateConnected(%d)\n", XenbusStateConnected);

    //
    // Wait for backend to accept configuration and complete initialization.
    //

    for (state = XenbusStateUnknown; state != XenbusStateConnected; )
    {
        FrontendWaitForBackendXenbusStateChange(XenLower, &state);

        if (state == XenbusStateClosing || state == XenbusStateClosed || state == XenbusStateUnknown)
        {
            TraceError("Failed to connect '%s' <-> '%s' backend state: %d\n",
                XenLower->FrontendPath,
                XenLower->BackendPath,
                state);

            return STATUS_UNSUCCESSFUL;
        }
    }

    Trace("Connected '%s' <-> '%s' \n", XenLower->FrontendPath, XenLower->BackendPath);
    return STATUS_SUCCESS;
}

// XXX: not even used
static VOID
XenLowerRegisterSuspendHandler(
    PXEN_LOWER XenLower,
    XENBUS_SUSPEND_FUNCTION ResumeCallback)
{
    NTSTATUS status;

    if (!ResumeCallback)
        return;

    status = XENBUS_SUSPEND(Register,
        &XenLower->SuspendInterface,
        SUSPEND_CALLBACK_LATE,
        ResumeCallback,
        XenLower,
        &XenLower->SuspendCallbackLate);

    if (!NT_SUCCESS(status))
    {
        TraceError("failed to register suspend handler.\n");
    }
}

NTSTATUS
XenLowerConnectBackend(
    PXEN_LOWER XenLower,
    XENBUS_SUSPEND_FUNCTION ResumeCallback)
{
    NTSTATUS status;

    status = XenLowerConnectBackendInternal(XenLower);

    XenLowerRegisterSuspendHandler(XenLower, ResumeCallback);

    return status;
}

NTSTATUS
XenLowerResumeConnectBackend(
    PXEN_LOWER XenLower,
    VOID *Internal)
{
    return XenLowerConnectBackendInternal(XenLower);
}

VOID
XenLowerDisonnectBackend(
    PXEN_LOWER XenLower)
{
    NTSTATUS status;
    XenbusState festate;
    XenbusState bestate;

    if (strlen(XenLower->BackendPath) == 0)
    {
        TraceError("shutting down an adapter %s which wasn't properly created?\n", XenLower->FrontendPath);
        return;        
    }

    // Wait for the backend to stabilise before we close it
    bestate = XenbusStateUnknown;
    for (bestate = XenbusStateUnknown; bestate != XenbusStateInitialising; )
    {
        FrontendWaitForBackendXenbusStateChange(XenLower, &bestate);
    }

    // Now close the frontend
    festate = XenbusStateClosing;
    while (bestate != XenbusStateClosing && bestate != XenbusStateClosed && XenbusStateClosing != XenbusStateUnknown)
    {
        NTSTATUS status = XENBUS_STORE(Printf,
            &XenLower->StoreInterface,
            NULL,
            XenLower->FrontendPath,
            "state",
            "%u",
            XenbusStateClosing);

        if (!NT_SUCCESS(status))
        {
            TraceError("Failed to change front end state to XenbusStateClosing(%d) status: 0x%x\n",
                XenbusStateClosing, status);
        }

        FrontendWaitForBackendXenbusStateChange(XenLower, &bestate);
    }

    festate = XenbusStateClosed;
    while (bestate != XenbusStateClosed && XenbusStateClosing != XenbusStateUnknown)
    {
        status = XENBUS_STORE(Printf,
            &XenLower->StoreInterface,
            NULL,
            XenLower->FrontendPath,
            "state",
            "%u",
            XenbusStateClosed);

        if (!NT_SUCCESS(status))
        {
            TraceError("Failed to change front end state to XenbusStateClosed(%d) status: 0x%x\n",
                XenbusStateClosed, status);
        }

        FrontendWaitForBackendXenbusStateChange(XenLower, &bestate);
    }

    // Unhook this here since there will be no reconnecting at this point.
    XenLowerUnregisterSuspendHandler(XenLower);

    // Clear the XenLower->BackendPath which sort of indicates shutdown or
    // not properly initialized.

    // --XT-- keep backend path, useful on resume to check whether device was
    //        unplugged during suspend
    // memset(&XenLower->BackendPath[0], 0, XEN_LOWER_MAX_PATH);
}

//
// Xen lower XENPCI_VECTORS vectors
//

NTSTATUS
XenLowerEvtChnNotify(
    PXEN_LOWER XenLower)
{
    if (!XenLower->Channel)
    {
        TraceError("no event channel port, cannot notify anything.\n");
        return STATUS_UNSUCCESSFUL;
    }

    XENBUS_EVTCHN(Send,
        &XenLower->EvtchnInterface,
        XenLower->Channel);

    return STATUS_SUCCESS;
}

ULONG
XenLowerGntTblGetReference(
    PXEN_LOWER XenLower, 
    PXENBUS_GNTTAB_ENTRY Entry)
{
    return XENBUS_GNTTAB(GetReference,
        &XenLower->GnttabInterface,
        Entry);
}

PXENBUS_GNTTAB_ENTRY
XenLowerGntTblGrantAccess(
    PXEN_LOWER XenLower,
    uint16_t Domid,
    uint32_t Pfn,
    BOOLEAN Readonly)
{
    NTSTATUS status;
    PXENBUS_GNTTAB_ENTRY entry;

    status = XENBUS_GNTTAB(PermitForeignAccess,
        &XenLower->GnttabInterface,
        XenLower->GnttabCache,
        TRUE,
        Domid,
        Pfn,
        Readonly,
        &entry);

    if (!NT_SUCCESS(status))
    {
        TraceError("failed to permit foreign access for pfn=0x%x\n", Pfn);
        return NULL;
    }

    return entry;
}

BOOLEAN
XenLowerGntTblEndAccess(
    PXEN_LOWER XenLower,
    PXENBUS_GNTTAB_ENTRY Entry)
{
    NTSTATUS status;

    status = XENBUS_GNTTAB(RevokeForeignAccess,
        &XenLower->GnttabInterface,
        XenLower->GnttabCache,
        TRUE,
        Entry);

    if (!NT_SUCCESS(status))
    {
        TraceError("failed to RevokeForeignAccess for grant entry\n");
        return FALSE;
    }

    return TRUE;
}

XenbusState
XenLowerGetBackendState(
    PXEN_LOWER XenLower)
{
    NTSTATUS status;
    PCHAR Buffer;
    XenbusState state;

    status = XENBUS_STORE(Read,
        &XenLower->StoreInterface,
        NULL,
        XenLower->BackendPath,
        "state",
        &Buffer);

    if (!NT_SUCCESS(status))
    {
        TraceError("failed to read backend state\n");
        return XenbusStateUnknown;
    }

    if (sscanf_s(Buffer, "%d", &state) != 1)
    {
        TraceError("failed to parse backend state\n");
        return XenbusStateUnknown;
    }

    XENBUS_STORE(Free,
        &XenLower->StoreInterface,
        Buffer);

    return state;
}

BOOLEAN
XenLowerGetOnline(
    PXEN_LOWER XenLower)
{
    NTSTATUS status; 
    PCHAR Buffer;
    int state;

    status = XENBUS_STORE(Read,
        &XenLower->StoreInterface,
        NULL,
        XenLower->BackendPath,
        "online",
        &Buffer);

    if (!NT_SUCCESS(status))
    {
        TraceError("failed to read backend online state\n");
        return FALSE;
    }

    if (sscanf_s(Buffer, "%d", &state) != 1)
    {
        TraceError("failed to parse backend online state");
        return FALSE;
    }

    XENBUS_STORE(Free,
        &XenLower->StoreInterface,
        Buffer);

    return (state == 1);
}
