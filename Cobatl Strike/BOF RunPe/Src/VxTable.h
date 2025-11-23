#pragma once

#include "Native.h"

typedef struct _VX_TABLE_ENTRY {
	PVOID	Gadget;
	DWORD	SyscallNumber;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY	NtCreateThreadEx;
	VX_TABLE_ENTRY	NtResumeThread;
	VX_TABLE_ENTRY	NtWaitForSingleObject;
	VX_TABLE_ENTRY	NtClose;
	VX_TABLE_ENTRY	NtCreateEvent;
	VX_TABLE_ENTRY	NtProtectVirtualMemory;
	VX_TABLE_ENTRY	NtAllocateVirtualMemory;
	VX_TABLE_ENTRY	NtCreateFile;	
	VX_TABLE_ENTRY	NtReadFile;
	VX_TABLE_ENTRY	NtGetContextThread;
	VX_TABLE_ENTRY	NtSetContextThread;	
	VX_TABLE_ENTRY	NtTerminateThread;
	VX_TABLE_ENTRY	NtSetEvent;
	VX_TABLE_ENTRY	NtFreeVirtualMemory;
} VX_TABLE, *PVX_TABLE;


