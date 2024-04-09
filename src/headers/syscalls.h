#pragma once

#ifndef SYSCALLS_H
#define SYSCALLS_H

/*
* Define syscalls
*/

extern "C" void SetJumpAddress(uintptr_t jumpAddress);

EXTERN_C NTSTATUS NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded,
    int SSN
);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten,
    int SSN
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection,
    int SSN
);

EXTERN_C NTSTATUS NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId,
    int SSN
);

EXTERN_C NTSTATUS NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options,
    int SSN
);

EXTERN_C NTSTATUS NtQueryObject(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG Length,
    PULONG ResultLength,
    int SSN
);

EXTERN_C NTSTATUS NtOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle,
    int SSN
);

EXTERN_C NTSTATUS NtQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength,
    int SSN
);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES TokenPrivileges,
    ULONG PreviousPrivilegesLength,
    PTOKEN_PRIVILEGES PreviousPrivileges,
    PULONG RequiredLength,
    int SSN
);

EXTERN_C NTSTATUS NtDuplicateToken(
    HANDLE ExistingToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType,
    PHANDLE NewToken,
    int SSN
);

EXTERN_C NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength,
    int SSN
);

EXTERN_C NTSTATUS NtClose(
    HANDLE Handle,
    int SSN
);

EXTERN_C NTSTATUS NtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    int SSN
);

#endif