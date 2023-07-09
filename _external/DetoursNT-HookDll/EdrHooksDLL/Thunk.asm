include ksamd64.inc

EXTERNDEF __imp_RtlCaptureContext:QWORD

.code

BackupStuffs proc
    mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
    mov     gs:[2d8h], r10            ; Win10 TEB InstrumentationCallbackPreviousPc
    mov     r10, rcx                  ; Save original RCX
    sub     rsp, 4d0h                 ; Alloc stack space for CONTEXT structure
    and     rsp, -10h                 ; RSP must be 16 byte aligned before calls
    mov     rcx, rsp
    call    __imp_RtlCaptureContext   ; Save the current register state. RtlCaptureContext does not require shadow space
    add     rsp, 4d0h                 ; Restore the stack pointer
    ret                               ; Return to the caller. The address of the CONTEXT structure is in RCX
BackupStuffs endp

end