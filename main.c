#include "hkdrv.h"

UINT64 GetDynamicOffset(OFFSET_TYPE Type)
{
	RTL_OSVERSIONINFOW VersionInfo = { 0 };
	RtlGetVersion(&VersionInfo);
	ULONG BuildNumber = VersionInfo.dwBuildNumber;
	switch (Type)
	{
	case UserDirectoryTableBase:
		if (BuildNumber >= Win10_1803 && BuildNumber <= Win10_1809) return 0x0278;
		if (BuildNumber >= Win10_1903 && BuildNumber <= Win10_1909) return 0x0280;
		if (BuildNumber >= Win10_2004 && BuildNumber <= Win11_23H2) return 0x0388;
		if (BuildNumber >= Win11_24H2 && BuildNumber <= Win11_25H2) return 0x0158;
	case Protection:
		if (BuildNumber >= Win10_1803 && BuildNumber <= Win10_1809) return 0x6ca;
		if (BuildNumber >= Win10_1903 && BuildNumber <= Win10_1909) return 0x6fa;
		if (BuildNumber >= Win10_2004 && BuildNumber <= Win11_23H2) return 0x87a;
		if (BuildNumber >= Win11_24H2 && BuildNumber <= Win11_25H2) return 0x5fa;
	default:
		break;
	}
	return 0;
}

UINT64 GetProcessCr3(PEPROCESS Process)
{
	if (!Process)
	{
		return 0;
	}

	uintptr_t DirBase = *(uintptr_t*)((UINT8*)Process + 0x28);

	if (!DirBase)
	{
		UINT64 Offset = GetDynamicOffset(UserDirectoryTableBase);
		DirBase = *(uintptr_t*)((UINT8*)Process + Offset);
	}

	if ((DirBase >> 0x38) == 0x40)
	{
		uintptr_t SavedDirBase = 0;
		KAPC_STATE ApcState = { 0 };
		KeStackAttachProcess(Process, &ApcState);
		SavedDirBase = __readcr3();
		KeUnstackDetachProcess(&ApcState);
		return SavedDirBase;
	}
	return DirBase;
}

VOID HKMemcpy(const void* Dstp, const void* Srcp, SIZE_T Len)
{
	ULONG* Dst = (ULONG*)Dstp;
	ULONG* Src = (ULONG*)Srcp;
	SIZE_T i, Tail;

	for (i = 0; i < (Len / sizeof(ULONG)); i++)
	{
		*Dst++ = *Src++;
	}

	Tail = Len & (sizeof(ULONG) - 1);
	if (Tail)
	{

		UCHAR* Dstb = (UCHAR*)Dstp;
		UCHAR* Srcb = (UCHAR*)Srcp;

		for (i = Len - Tail; i < Len; i++)
		{
			Dstb[i] = Srcb[i];
		}
	}
}

NTSTATUS ReadPhysicalMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS CopyAddress = { 0 };
	CopyAddress.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
	return MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

NTSTATUS WritePhysicalMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesWrite)
{
	if (!TargetAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}
	
	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
	{
		return STATUS_UNSUCCESSFUL;
	}

	HKMemcpy(pmapped_mem, Buffer, Size);

	*BytesWrite = Size;
	MmUnmapIoSpace(pmapped_mem, Size);

	return STATUS_SUCCESS;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress)
{
	DirectoryTableBase &= ~0xf;							// 清除页表目录基址的低4位，保留高位的页表目录基址
	UINT64 PageOffset = VirtualAddress & 0xFFF;			// 计算线性地址的页内偏移量，即取线性地址的低12位（页偏移大小为12位）
	UINT64 PteIndex = (VirtualAddress >> 12) & 0x1FF;	// 获取页表项索引，通过右移12位得到原始索引，然后通过位与操作取低9位（页表项索引占9位）
	UINT64 PtIndex = (VirtualAddress >> 21) & 0x1FF;	// 获取页中目录项索引，通过右移21位得到原始索引，然后通过位与操作取低9位（页中目录项索引占9位）
	UINT64 PdIndex = (VirtualAddress >> 30) & 0x1FF;	// 获取页面目录索引，通过右移30位得到原始索引，然后通过位与操作取低9位（页面目录索引占9位）
	UINT64 PdpIndex = (VirtualAddress >> 39) & 0x1FF;	// 获取页面目录指针索引，通过右移39位得到原始索引，然后通过位与操作取低9位（页面目录指针索引占9位）

	SIZE_T ReadSize = 0;
	UINT64 PdpEntry = 0;
	if (ReadPhysicalMemory((PVOID)(DirectoryTableBase + 8 * PdpIndex), &PdpEntry, sizeof(PdpEntry), &ReadSize) || ~PdpEntry & 1)
	{
		return 0;
	}
		
	UINT64 PdEntry = 0;
	if (ReadPhysicalMemory((PVOID)((PdpEntry & PageMask) + 8 * PdIndex), &PdEntry, sizeof(PdEntry), &ReadSize) || ~PdEntry & 1)
	{
		return 0;
	}
		
	if (PdEntry & 0x80)
	{
		return (PdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
	}
		
	UINT64 PtEntry = 0;
	if (ReadPhysicalMemory((PVOID)((PdEntry & PageMask) + 8 * PtIndex), &PtEntry, sizeof(PtEntry), &ReadSize) || ~PtEntry & 1)
	{
		return 0;
	}

	if (PtEntry & 0x80)
	{
		return (PtEntry & PageMask) + (VirtualAddress & ~(~0ull << 21));
	}

	UINT64 PteEntry = 0;
	if (ReadPhysicalMemory((PVOID)((PtEntry & PageMask) + 8 * PteIndex), &PteEntry, sizeof(PteEntry), &ReadSize) || !PteEntry)
	{
		return 0;
	}

	return (PteEntry & PageMask) + PageOffset;
}

UINT64 FindMin(INT32 A, SIZE_T B)
{
	return (A < (INT32)B) ? A : (INT32)B;
}

NTSTATUS HandleReadWriteRequest(PReadWriteRequest Request)
{
	if (!Request->ProcessId)
	{
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS Process = NULL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process)))
	{
		return STATUS_UNSUCCESSFUL;
	}

	UINT64 DirBase = GetProcessCr3(Process);
	ObDereferenceObject(Process);

	SIZE_T Offset = 0;
	SIZE_T TotalSize = Request->Size;

	INT64 PhysicalAddress = TranslateLinearAddress(DirBase, Request->Address + Offset);
	if (!PhysicalAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}

	UINT64 FinalSize = FindMin(PAGE_SIZE - (PhysicalAddress & 0xFFF), TotalSize);
	SIZE_T BytesTrough = 0;
	NTSTATUS nStatus = 0;

	if (Request->Write)
	{
		nStatus = WritePhysicalMemory((PVOID)PhysicalAddress, (PVOID)(Request->Buffer + Offset), FinalSize, &BytesTrough);
	}
	else
	{
		nStatus = ReadPhysicalMemory((PVOID)PhysicalAddress, (PVOID)(Request->Buffer + Offset), FinalSize, &BytesTrough);
	}
	
	return nStatus;
}

NTSTATUS HandleProtectProcessRequest(PProcessRequest Request)
{
	if (!Request->ProcessId)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PEPROCESS Process = NULL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process)))
	{
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		UINT64 Offset = GetDynamicOffset(Protection);
		PPS_PROTECTION pProtection = (PPS_PROTECTION)((ULONG64)Process + Offset);
		pProtection->Flags.Signer = PsProtectedSignerWinTcb;
		pProtection->Flags.Type = PsProtectedTypeProtected;

		ObDereferenceObject(Process);
		return STATUS_SUCCESS;
	}
}

NTSTATUS HandleHideProcessRequest(PProcessRequest Request)
{
	if (!Request->ProcessId)
	{
		return STATUS_UNSUCCESSFUL;
	}

	PEPROCESS Process = NULL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process)))
	{
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}
	else
	{
		UnlinkActiveProcessLists(Process);
		DbgPrintEx(99, 0, "+[HK]HideProcess Successfully pid:%d\n", (HANDLE)Request->ProcessId);
		ObDereferenceObject(Process);
		return STATUS_SUCCESS;
	}
}

NTSTATUS HandleForceDeleteFileRequest(PDeleteFileRequest Request)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PDEVICE_OBJECT pDeviceObject = NULL;
	PVOID pHandleFileObject = NULL;

	// 判断中断等级不大于0
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (Request->FilePath.Buffer == NULL || Request->FilePath.Length <= 0)
	{
		return STATUS_UNSUCCESSFUL;
	}

	__try
	{
		// 初始化结构
		InitializeObjectAttributes(&ObjectAttributes, &Request->FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// 文件系统筛选器驱动程序 仅向指定设备对象下面的筛选器和文件系统发送创建请求。
		nStatus = IoCreateFileSpecifyDeviceObjectHint(
			&hFile,
			SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
			&ObjectAttributes,
			&IoStatusBlock,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
			CreateFileTypeNone,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK,
			pDeviceObject);

		if (!NT_SUCCESS(nStatus))
		{
			return STATUS_UNSUCCESSFUL;
		}

		// 在对象句柄上提供访问验证，如果可以授予访问权限，则返回指向对象的正文的相应指针。
		nStatus = ObReferenceObjectByHandle(hFile, 0, 0, 0, &pHandleFileObject, 0);
		if (!NT_SUCCESS(nStatus))
		{
			return STATUS_UNSUCCESSFUL;
		}

		// 镜像节对象设置为0
		((PFILE_OBJECT)(pHandleFileObject))->SectionObjectPointer->ImageSectionObject = 0;

		// 删除权限打开
		((PFILE_OBJECT)(pHandleFileObject))->DeleteAccess = 1;

		nStatus = ZwDeleteFile(&ObjectAttributes);
		if (!NT_SUCCESS(nStatus))
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
	__finally
	{
		if (pHandleFileObject != NULL)
		{
			ObDereferenceObject(pHandleFileObject);
			pHandleFileObject = NULL;
		}

		if (hFile != NULL || hFile != (PVOID)-1)
		{
			ZwClose(hFile);
			hFile = (PVOID)-1;
		}
	}
	return nStatus;
}

NTSTATUS HandleKillProcessRequest(PProcessRequest Request)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	HANDLE Handle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	CLIENT_ID ClientId = { 0 };

	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	ClientId.UniqueProcess = (HANDLE)Request->ProcessId;
	ClientId.UniqueThread = 0;

	// 打开进程
	nStatus = ZwOpenProcess(&Handle, GENERIC_ALL, &ObjectAttributes, &ClientId);
	if (!NT_SUCCESS(nStatus))
	{
		ZwClose(Handle);
		return nStatus;
	}

	// 发送终止信号
	ZwTerminateProcess(Handle, 0);
	ZwClose(Handle);

	return nStatus;
}

NTSTATUS HandleAllocFreeMemoryRequest(PAllocFreeMemoryRequest Request)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	HANDLE Handle = NULL;
	CLIENT_ID ClientId = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PVOID BaseAddress = NULL;
	ClientId.UniqueThread = 0;
	ClientId.UniqueProcess = (HANDLE)Request->ProcessId;

	__try
	{
		nStatus = ZwOpenProcess(&Handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
		if (!NT_SUCCESS(nStatus))
		{
			ZwClose(Handle);
			return nStatus;
		}
		if (Request->Free)
		{
			BaseAddress = *(PVOID*)Request->Buffer;
			nStatus = ZwFreeVirtualMemory(Handle, &BaseAddress, &Request->Size, MEM_RELEASE);
		}
		else
		{
			nStatus = ZwAllocateVirtualMemory(Handle, &BaseAddress, 0, &Request->Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			*(PVOID*)Request->Buffer = BaseAddress;
		}
		
		if (!NT_SUCCESS(nStatus))
		{
			ZwClose(Handle);
			return nStatus;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ZwClose(Handle);
		return nStatus;
	}

	ZwClose(Handle);
	return nStatus;
}

NTSTATUS HandleGetModuleAddressRequest(PModuleAddressRequest Request)
{
	UINT64 ModulesBase = 0;
	NTSTATUS nStatus = STATUS_SUCCESS;
	KAPC_STATE KAPC = { 0 };
	PEPROCESS  Process = NULL;
	UNICODE_STRING ModuleName = { 0 };
	
	PPEB64 pPEB64 = NULL; //PEB结构指针;
	PLDR_DATA_TABLE_ENTRY64 pLdrDataEntry64 = NULL; //LDR链表入口;
	PLIST_ENTRY64 pListEntryStart64 = NULL, pListEntryEnd64 = NULL;; //链表头节点、尾节点;

	PPEB32 pPEB32 = NULL; //PEB结构指针;
	PLDR_DATA_TABLE_ENTRY32 pLdrDataEntry32 = NULL; //LDR链表入口;
	PLIST_ENTRY32 pListEntryStart32 = NULL, pListEntryEnd32 = NULL; //链表头节点、尾节点;

	WCHAR LocalBuffer[256];
	RtlInitEmptyUnicodeString(&ModuleName, LocalBuffer, sizeof(LocalBuffer));
	RtlCopyUnicodeString(&ModuleName, &Request->ModuleName);

	nStatus = PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);

	if (!NT_SUCCESS(nStatus) && !MmIsAddressValid(Process))
	{
		return STATUS_UNSUCCESSFUL;
	}

	KeStackAttachProcess(Process, &KAPC);

	pPEB64 = PsGetProcessPeb(Process);

	if (pPEB64 && pPEB64->Ldr)
	{
		UNICODE_STRING QueryModuleName = { 0 };
		pListEntryStart64 = pListEntryEnd64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)pPEB64->Ldr)->InMemoryOrderModuleList.Flink);
		do {
			pLdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(pListEntryStart64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);
			RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry64->BaseDllName.Buffer);
			if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
			{
				ModulesBase = (UINT64)pLdrDataEntry64->DllBase;
				break;
			}
			pListEntryStart64 = (PLIST_ENTRY64)pListEntryStart64->Flink;

		} while (pListEntryStart64 != pListEntryEnd64);
	}
	
#ifdef _AMD64_

	pPEB32 = PsGetProcessWow64Process(Process);
	if (pPEB32 && pPEB32->Ldr)
	{
		UNICODE_STRING QueryModuleName = { 0 };
		pListEntryStart32 = pListEntryEnd32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);
		do {
			pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(pListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
			RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry32->BaseDllName.Buffer);
			if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
			{
				ModulesBase = (UINT64)pLdrDataEntry32->DllBase;
				break;
			}
			pListEntryStart32 = (PLIST_ENTRY32)pListEntryStart32->Flink;

		} while (pListEntryStart32 != pListEntryEnd32);
	}
#endif
	KeUnstackDetachProcess(&KAPC);
	RtlCopyMemory((PVOID)Request->Address, &ModulesBase, sizeof(ModulesBase));
	ObDereferenceObject(Process);
	return nStatus;
}

NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS nStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG IoCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG BytesReturned = 0;

	switch (IoCode)
	{
	case IOCTL_READ_WRITE:
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ReadWriteRequest))
		{
			nStatus = HandleReadWriteRequest((PReadWriteRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(ReadWriteRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
		break;
	case IOCTL_PROTECT_PROCESS:
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ProcessRequest))
		{
			nStatus = HandleProtectProcessRequest((PProcessRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(ProcessRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
		break;
	case IOCTL_DELETE_FILE:
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(DeleteFileRequest))
		{
			nStatus = HandleForceDeleteFileRequest((PDeleteFileRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(DeleteFileRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
		break;
	case IOCTL_KILL_PROCESS:
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ProcessRequest))
		{
			nStatus = HandleKillProcessRequest((PProcessRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(ProcessRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
		break;
	case IOCTL_ALLOC_FREE_MEMORY:
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(AllocFreeMemoryRequest))
		{
			nStatus = HandleAllocFreeMemoryRequest((PAllocFreeMemoryRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(AllocFreeMemoryRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
		break;
	case IOCTL_MODULE_ADDRESS:
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ModuleAddressRequest))
		{
			nStatus = HandleGetModuleAddressRequest((PModuleAddressRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(ModuleAddressRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
		break;
	case IOCTL_HIDE_PROCESS:
		// 隱藏目標 Process
		// 取得從應用程式傳來的資料
		if (pStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(ProcessRequest))
		{
			nStatus = HandleHideProcessRequest((PProcessRequest)Irp->AssociatedIrp.SystemBuffer);
			BytesReturned = sizeof(ProcessRequest);
		}
		else
		{
			nStatus = STATUS_INFO_LENGTH_MISMATCH;
			BytesReturned = 0;
		}
	default:
		break;
	}

	Irp->IoStatus.Status = nStatus;
	Irp->IoStatus.Information = BytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return nStatus;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);

	switch (pStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrintEx(99, 0, "+[HK]Device Created Successfully\n");
		break;
	case IRP_MJ_CLOSE:
		DbgPrintEx(99, 0, "+[HK]Device Close Successfully\n");
		break;
	default:
		break;
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

void UnLoadDriver(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	NTSTATUS nStatus = 0;
	UNICODE_STRING ustrLinkName;
	RtlInitUnicodeString(&ustrLinkName, L"\\DosDevices\\HKDrv");

	nStatus = IoDeleteSymbolicLink(&ustrLinkName);

	if (!NT_SUCCESS(nStatus))
	{
		return;
	}

	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrintEx(99, 0, "+[HK]Unload Success\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS nStatus = 0;
	UNICODE_STRING  ustrLinkName = { 0 };
	UNICODE_STRING  ustrDrvName = { 0 };
	PDEVICE_OBJECT  pDevice = NULL;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = UnsupportedDispatch;
	}
	
	DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControlHandler;
	DriverObject->DriverUnload = UnLoadDriver;

	RtlInitUnicodeString(&ustrDrvName, L"\\Device\\HKDrv");
	RtlInitUnicodeString(&ustrLinkName, L"\\DosDevices\\HKDrv");

	nStatus = IoCreateDevice(DriverObject, 0, &ustrDrvName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice);
	
	if (!NT_SUCCESS(nStatus))
	{
		DbgPrintEx(99, 0, "+[HK]IoCreateDevice:Fail\n");
		return nStatus;
	}

	nStatus = IoCreateSymbolicLink(&ustrLinkName, &ustrDrvName);

	if (!NT_SUCCESS(nStatus))
	{
		DbgPrintEx(99, 0, "+[HK]IoCreateSymbolicLink:Fail\n");
		IoDeleteDevice(pDevice);
		return nStatus;
	}

	DriverObject->Flags |= DO_BUFFERED_IO;
	DriverObject->Flags &= ~DO_DEVICE_INITIALIZING;

	DbgPrintEx(99, 0, "+[HK]Load Success\n");
	DbgPrintEx(99, 0, "Hello World, Windows Driver!\n");

	return nStatus;
}