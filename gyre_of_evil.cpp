// BlueBone.cpp : Questo file contiene la funzione 'main', in cui inizia e termina l'esecuzione del programma.
//

#include <iostream>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

#define NT_SUCCESS(x) ((x) >= 0)



typedef NTSTATUS(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);



typedef DWORD64(WINAPI* _NtCreateThreadEx64)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD64 dwStackSize, DWORD64 dw1, DWORD64 dw2, LPVOID Unknown);

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA, * PTHREAD_DATA;

HANDLE WINAPI ThreadProc(PTHREAD_DATA data)
{
	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI ThreadProcEnd()
{
	return 0;
}

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL);

pfnNtQueryInformationProcess myNtQueryInformationProcess;

int LoadNTDLLFunctions()
{
	HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
	if (hNtDll == NULL)
		return 0;

	myNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	return myNtQueryInformationProcess == NULL ? 0 : 1;
}

#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))

#define OPTHDROFFSET(ptr) ((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)))


LPVOID  WINAPI GetModuleEntryPoint(
	LPVOID    lpFile)
{
	PIMAGE_OPTIONAL_HEADER   poh;
	poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET(lpFile);
	return poh == NULL ? NULL : (LPVOID)poh->AddressOfEntryPoint;
}

DWORD GetEntryPoint(HANDLE proc)
{
	NTSTATUS ntret;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD imagebase;
	DWORD enrypoint;

	//load NtQueryInformationProcess
	if (!LoadNTDLLFunctions())
		return 1;

	//get peb address
	ntret = (*myNtQueryInformationProcess)(proc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (ntret != 0)
		return 2;

	// get base address of module
	if (!ReadProcessMemory(proc, (LPCVOID)((DWORD)(pbi.PebBaseAddress) + 8), &imagebase, sizeof(imagebase), NULL))
		return 3;

	//read PE header
	unsigned char* pe = new unsigned char[4096]; //whole memory page should be quite enough
	if (!ReadProcessMemory(proc, (LPCVOID)(imagebase), pe, 4096, NULL))
	{
		delete[] pe;
		return 4;
	}

	enrypoint = imagebase + (DWORD)(GetModuleEntryPoint((LPVOID)pe));
	delete[] pe;

	return enrypoint;
}



void fndmodule(int pid)
{
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	Module32First(hsnapshot, &me32);
	do
	{
		printf("%S\n", me32.szExePath);
		// this should help you
		if (wcsstr(me32.szExePath, L"paydaytheheistgame.exe")) // fill in exe title here, it will break out when it find this process and return the base address.
		{
			printf("%p",(DWORD)me32.modBaseAddr);
			break;
		}
	} while (Module32Next(hsnapshot, &me32));
	CloseHandle(hsnapshot);
}


HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	FARPROC pFunc = NULL;
	HANDLE hThread = NULL;

	pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if (pFunc == NULL)
	{
		printf("[!]GetProcAddress (\"NtCreateThreadEx\")error\n");
		return NULL;
	}
	//((_NtCreateThreadEx64)pFunc)(&hThread, 0x1FFFFF, NULL, hProcess, pThreadProc, pRemoteBuf, FALSE, NULL, NULL, NULL, NULL);
	HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, 0);
	if (hThread == NULL)
	{
		printf("[!]MyCreateRemoteThread : NtCreateThreadEx error\n");
		return NULL;
	}

	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{
		printf("[!]MyCreateRemoteThread : WaitForSingleObject error\n");
		return NULL;
	}
	return hThread;
}

BOOL InjectDll(UINT32 ProcessId, char* DllPath)
{
	if (strstr(DllPath, "\\\\") != 0)
	{
		printf("[!]Wrong Dll path\n");
		return FALSE;
	}
	if (strstr(DllPath, "\\") == 0)
	{
		printf("[!]Need Dll full path\n");
		return FALSE;
	}

	size_t len = strlen(DllPath) + 1;
	size_t converted = 0;
	wchar_t* DllFullPath;
	DllFullPath = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, DllFullPath, len, DllPath, _TRUNCATE);

	LPVOID pThreadData = NULL;
	LPVOID pCode = NULL;
	HANDLE ProcessHandle = NULL;
	HANDLE hThread = NULL;
	BOOL bRet = FALSE;

	__try
	{
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
		if (ProcessHandle == NULL)
		{
			printf("[!]OpenProcess error\n");
			__leave;
		}
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
		data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
		data.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(k32, "LoadLibraryW");



		memcpy(data.DllName, DllFullPath, (wcslen(DllFullPath) + 1) * sizeof(WCHAR));
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;

		/*0:  48 89 c8                mov    rax, rcx
			3 : 4c 8b 18                mov    r11, QWORD PTR[rax]
			6 : 48 8b 48 10             mov    rcx, QWORD PTR[rax + 0x10]
			a : 48 8b 50 18             mov    rdx, QWORD PTR[rax + 0x18]
			e : 41 ff d3                call   r11*/
		char sherco[100] ="\x48\x89\xC8\x4C\x8B\x18\x48\x89\xC2\x48\x83\xC2\x20\x48\x89\xC1\x48\x83\xC1\x10\x50\x41\xFF\xD3\x58\x48\x8B\x48\x18\x4C\x8B\x58\x08\x48\x81\xEC\x00\x00\x10\x00\x41\xFF\xD3\x48\x81\xC4\x00\x00\x10\x00\xC3"


			;

		printf("result %p\n", GetModuleHandle(L"usbmon.dll"));
		pThreadData = VirtualAllocEx(ProcessHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		LoadLibraryW(L"usbmon.dll");
		
		
		
		
		//data.fnRtlInitUnicodeString(&data.UnicodeString, data.DllName);
		//NTSTATUS result = data.fnLdrLoadDll(data.DllPath, data.Flags, &data.UnicodeString, &data.ModuleHandle);
		
		
		
		
		
		
		// printf("result %d\n", result);

		BOOL bWriteOK = WriteProcessMemory(ProcessHandle, pThreadData, &data, sizeof(data), NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error\n");
			__leave;
		}

		DWORD SizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		printf("%p size\n", SizeOfCode);
		pCode = VirtualAllocEx(ProcessHandle, NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]VirtualAllocEx error,%d\n", GetLastError());
			__leave;
		}
		bWriteOK = WriteProcessMemory(ProcessHandle, pCode, &sherco, 100, NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error,%d\n", GetLastError());
			__leave;
		}

		hThread = MyCreateRemoteThread(ProcessHandle, (LPTHREAD_START_ROUTINE)pCode, pThreadData);
		if (hThread == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]MyCreateRemoteThread error\n");
			__leave;
		}

		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(ProcessHandle, pThreadData, 0, MEM_RELEASE);
		if (pCode != NULL)
			VirtualFreeEx(ProcessHandle, pCode, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (ProcessHandle != NULL)
			CloseHandle(ProcessHandle);
	}
	return bRet;

}


bool IsProcess32Bit(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess == NULL)
    {
        std::cout << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64))
    {
        CloseHandle(hProcess);
        return isWow64; // TRUE if the process is 32-bit, FALSE if it's 64-bit
    }
    else
    {
        std::cout << "IsWow64Process failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }
}
bool inject(int pid, const char* path)
{		
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	HMODULE pModuleHandle = GetModuleHandleW(L"kernel32.dll");

	if (!pModuleHandle)
		return false;

	void* fpLoadLibraryA = GetProcAddress(pModuleHandle, "LoadLibraryA");

	if (!fpLoadLibraryA)
		return false;

	void* memory = VirtualAllocEx(hProcess, NULL, 32,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!memory)
	{
		printf("[!]VirtualAllocEx error,%d\n", GetLastError());
		return false;

	}

	if (!WriteProcessMemory(hProcess, memory, path, 32, NULL))
	{
		printf("[!]WPM error,%d\n", GetLastError());
		return false;
	}

	HANDLE pThreadHandle = CreateRemoteThread(hProcess, NULL, NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(fpLoadLibraryA), memory, NULL, NULL);

	if (!pThreadHandle)
		return false;

	WaitForSingleObject(pThreadHandle, INFINITE);

	CloseHandle(pThreadHandle);
	return true;
}
BOOL EnableDebugPrivilege()
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes =  SE_PRIVILEGE_ENABLED ;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

char riggedBytes[5];
char modifyFileAtOffset(const std::wstring& inputFileName, const std::string& outputFileName, std::streampos offset, char newValue) {
	// Open the input file
	char toSave = 'a';
	std::ifstream inputFile(inputFileName, std::ios::binary);
	if (!inputFile) {
		std::cerr << "Error opening input file: " << std::endl;
		return toSave;
	}

	// Read the entire file into a buffer
	std::vector<char> buffer((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
	inputFile.close();

	// Check if the offset is valid
	if (offset < 0 || static_cast<size_t>(offset) >= buffer.size()) {
		std::cerr << "Offset is out of range." << std::endl;
		return toSave;
	}
	toSave = buffer[static_cast<size_t>(offset)];

	// Modify the byte at the specified offset
	buffer[static_cast<size_t>(offset)] = newValue;

	// Write the modified buffer to the new output file
	std::ofstream outputFile(outputFileName, std::ios::binary);
	if (!outputFile) {
		std::cerr << "Error opening output file: " << outputFileName << std::endl;
		return toSave;
	}

	outputFile.write(buffer.data(), buffer.size());
	outputFile.close();
	return toSave;
}


void rigEntryPoint(const wchar_t* libPath) {
	// manually load the dll
   /* wchar_t basePath[19];
	wcscpy_s( basePath, L"\\Windows\\System32\\");
	wcscat_s(basePath,lib );*/ //utterly broken code 
	HANDLE dllFile = CreateFileW(libPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dllFileSize = GetFileSize(dllFile, NULL);
	HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(dllFile);

	// analyze the dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
	
	
	IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS));

	const int sectionCount = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);

	long entryPointRVA = pOptionalHeader->AddressOfEntryPoint;

	DWORD EPoffset = 10; // Example offset
	for (DWORD i = 0; i < sectionCount; ++i) {
		// Print section name

		std::cout << "Section " << i + 1 << ": " << std::string((char*)pSectionHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME) << std::endl;

		// You could also print more information, for example:
		std::cout << "\tVirtual Address: " << std::hex << pSectionHeader[i].VirtualAddress << std::endl;
		std::cout << "\tSize: " << std::dec << pSectionHeader[i].Misc.VirtualSize << std::endl;
		std::cout << "\tPointer to Raw Data: " << std::hex << pSectionHeader[i].PointerToRawData << std::endl;
		std::cout << "\tSize of Raw Data: " << std::dec << pSectionHeader[i].SizeOfRawData << std::endl;

		if (entryPointRVA >= pSectionHeader[i].VirtualAddress &&
			entryPointRVA < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
			EPoffset = entryPointRVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
			printf("%x\n", EPoffset);
			break;
		}

	}    

	std::string outputFileName = "output_file.bin"; // Replace with your desired output file name
	std::wstring outputFinal = L"output_file.bin"; // Replace with your desired output file name
	char newValue = '\xEB'; // Specify the new byte value to be written

	riggedBytes[0]=modifyFileAtOffset(libPath, outputFileName, EPoffset, newValue);

	 newValue = '\xFE'; // Specify the new byte value to be written
	 riggedBytes[1] = modifyFileAtOffset(outputFinal, outputFileName, EPoffset+1, newValue);

	newValue = '\x00'; // Specify the new byte value to be written
	riggedBytes[2] = modifyFileAtOffset(outputFinal, outputFileName, EPoffset + 2, newValue);
	riggedBytes[3] = modifyFileAtOffset(outputFinal, outputFileName, EPoffset + 3, newValue);
	riggedBytes[4] = modifyFileAtOffset(outputFinal, outputFileName, EPoffset + 4, newValue);

	for (int i = 0; i < 5; i++)
	{
		printf("%x\n", riggedBytes[i] & 0xff);
	}
	/*
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

	// find the original function code
	PVOID pNtCreateThreadExOriginal = NULL;
	for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
		if (!strcmp(pFunctionName, funToCheck))
		{
			pNtCreateThreadExOriginal = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
			break;
		}
	}

	// compare functions
	PVOID pNtCreateThreadEx = GetProcAddress(GetModuleHandleW(lib), funToCheck);
	if (memcmp(pNtCreateThreadEx, pNtCreateThreadExOriginal, 16))
	{
		printf("chicken");
		abort();
	}*/

}

int main()
{
    // Process information structure
    PROCESS_INFORMATION procInfo;
    ZeroMemory(&procInfo, sizeof(procInfo));

    // Startup information structure
    STARTUPINFO startInfo;
    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);

    // Name of the executable to run (for example, "notepad.exe")
    LPCWSTR executableName = L"C:\\Users\\gianm\\source\\repos\\cavia32\\x64\\Debug\\cavia32.exe";

	rigEntryPoint(executableName);
    // Create the process in suspended mode
    BOOL success = CreateProcess(
		L"output_file.bin",   // Path to executable
        NULL,             // Command line arguments
        NULL,             // Process handle not inheritable
        NULL,             // Primary thread handle not inheritable
        FALSE,            // Handles are not inheritable
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,  // Suspended creation
        NULL,             // Use parent's environment block
        NULL,             // Use parent's starting directory 
        &startInfo,      // Pointer to STARTUPINFO structure
        &procInfo        // Pointer to PROCESS_INFORMATION structure
    );

	if (success) {
		std::cout << "Process created in suspended mode. Process ID: " << procInfo.dwProcessId << std::endl;

		// At this point, the process is created but not running.
		// You can set breakpoints or modify memory if required here.
		std::cout << IsProcess32Bit(procInfo.dwProcessId);
		// To resume the process, call ResumeThread() on the primary thread of the process
		//printf("%p\n", GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrLoadDll"));
		//InjectDll(procInfo.dwProcessId, (char*)"C:\\Windows\\System32\\ntdll.dll");

		fndmodule(procInfo.dwProcessId);
		
		getchar();

		ResumeThread(procInfo.hThread);
		inject(procInfo.dwProcessId, "C:\\Windows\\System32\\usbmon.dll");
		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL;  // Request full context

		if (GetThreadContext(procInfo.hThread, &context)) {
			// Successfully obtained thread context
			std::cout << "Thread Context obtained successfully." << std::endl;
			printf("%p\n", context.Rip);
		}
		else {
			std::cerr << "Error obtaining thread context: " << GetLastError() << std::endl;
		}

		SuspendThread(procInfo.hThread);
		SIZE_T* written = 0;
		WriteProcessMemory(procInfo.hProcess, (void*)context.Rip, riggedBytes, 5, written);
		ResumeThread(procInfo.hThread);

		// Close handles to the process and thread
		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);

	}
    else {
        std::cerr << "Failed to create process. Error: " << GetLastError() << std::endl;
    }

    return 0;
}

// Per eseguire il programma: CTRL+F5 oppure Debug > Avvia senza eseguire debug
// Per eseguire il debug del programma: F5 oppure Debug > Avvia debug

// Suggerimenti per iniziare: 
//   1. Usare la finestra Esplora soluzioni per aggiungere/gestire i file
//   2. Usare la finestra Team Explorer per connettersi al controllo del codice sorgente
//   3. Usare la finestra di output per visualizzare l'output di compilazione e altri messaggi
//   4. Usare la finestra Elenco errori per visualizzare gli errori
//   5. Passare a Progetto > Aggiungi nuovo elemento per creare nuovi file di codice oppure a Progetto > Aggiungi elemento esistente per aggiungere file di codice esistenti al progetto
//   6. Per aprire di nuovo questo progetto in futuro, passare a File > Apri > Progetto e selezionare il file con estensione sln
