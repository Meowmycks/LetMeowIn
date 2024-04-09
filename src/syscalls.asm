.data
jumpAddress dq 0                    ; Variable to hold address of 'syscall-ret' trampoline

.code
SetJumpAddress proc                 ; Function to set jumpAddress
    mov [jumpAddress], rcx          ; Assume the new address is passed in RCX
    ret
SetJumpAddress endp

NtReadVirtualMemory proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtReadVirtualMemory endp

NtWriteVirtualMemory proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtProtectVirtualMemory endp

NtOpenProcess proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+28h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtOpenProcess endp

NtDuplicateObject proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+40h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtDuplicateObject endp

NtQueryObject proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtQueryObject endp

NtOpenProcessToken proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, r9                     ; Move syscall ID into RAX register. Syscall ID is fourth parameter passed. Assume it's in R9.
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtOpenProcessToken endp

NtQueryInformationToken proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+30h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtQueryInformationToken endp

NtAdjustPrivilegesToken proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+38h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtAdjustPrivilegesToken endp

NtDuplicateToken proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+38h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtDuplicateToken endp

NtQuerySystemInformation proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+28h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtQuerySystemInformation endp

NtClose proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, rdx                    ; Move syscall ID into RAX register. Syscall ID is second parameter passed. Assume it's in RDX.
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtClose endp

NtSetInformationThread proc
    mov r11, [jumpAddress]          ; Load indirect syscall address into R11 register
    mov rax, [rsp+28h]              ; Move syscall ID into RAX register
    mov r10, rcx
    jmp r11                         ; Indirect syscall via jump to address stored in R11
NtSetInformationThread endp
end
