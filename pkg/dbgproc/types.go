package dbgproc

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// most of this is taken from https://github.com/go-delve/delve

const (
	PROCESS_ALL_ACCESS      = 0x1F0FFF
	_ThreadBasicInformation = 0

	_DBG_CONTINUE              = 0x00010002
	_DBG_EXCEPTION_NOT_HANDLED = 0x80010001

	_EXCEPTION_DEBUG_EVENT      = 1
	_CREATE_THREAD_DEBUG_EVENT  = 2
	_CREATE_PROCESS_DEBUG_EVENT = 3
	_EXIT_THREAD_DEBUG_EVENT    = 4
	_EXIT_PROCESS_DEBUG_EVENT   = 5
	_LOAD_DLL_DEBUG_EVENT       = 6
	_UNLOAD_DLL_DEBUG_EVENT     = 7
	_OUTPUT_DEBUG_STRING_EVENT  = 8
	_RIP_EVENT                  = 9

	// DEBUG_ONLY_THIS_PROCESS tracks https://msdn.microsoft.com/en-us/library/windows/desktop/ms684863(v=vs.85).aspx
	_DEBUG_ONLY_THIS_PROCESS = 0x00000002

	_EXCEPTION_BREAKPOINT  = 0x80000003
	_EXCEPTION_SINGLE_STEP = 0x80000004

	_EXCEPTION_MAXIMUM_PARAMETERS = 15

	_MEM_FREE    = 0x10000
	_MEM_RESERVE = 0x2000

	_PAGE_EXECUTE           = 0x10
	_PAGE_EXECUTE_READ      = 0x20
	_PAGE_EXECUTE_READWRITE = 0x40
	_PAGE_EXECUTE_WRITECOPY = 0x80
	_PAGE_NOACCESS          = 0x01
	_PAGE_READONLY          = 0x02
	_PAGE_READWRITE         = 0x04
	_PAGE_WRITECOPY         = 0x08

	_PAGE_GUARD = 0x100

	_CONTEXT_AMD64               = 0x100000
	_CONTEXT_CONTROL             = (_CONTEXT_AMD64 | 0x1)
	_CONTEXT_INTEGER             = (_CONTEXT_AMD64 | 0x2)
	_CONTEXT_SEGMENTS            = (_CONTEXT_AMD64 | 0x4)
	_CONTEXT_FLOATING_POINT      = (_CONTEXT_AMD64 | 0x8)
	_CONTEXT_DEBUG_REGISTERS     = (_CONTEXT_AMD64 | 0x10)
	_CONTEXT_FULL                = (_CONTEXT_CONTROL | _CONTEXT_INTEGER | _CONTEXT_FLOATING_POINT)
	_CONTEXT_ALL                 = (_CONTEXT_CONTROL | _CONTEXT_INTEGER | _CONTEXT_SEGMENTS | _CONTEXT_FLOATING_POINT | _CONTEXT_DEBUG_REGISTERS)
	_CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
	_CONTEXT_SERVICE_ACTIVE      = 0x10000000
	_CONTEXT_EXCEPTION_REQUEST   = 0x40000000
	_CONTEXT_EXCEPTION_REPORTING = 0x80000000
)
const (
	waitBlocking int = 1 << iota
	waitSuspendNewThreads
	waitDontHandleExceptions
)

type _NTSTATUS int32

type _CLIENT_ID struct {
	UniqueProcess syscall.Handle
	UniqueThread  syscall.Handle
}

type _THREAD_BASIC_INFORMATION struct {
	ExitStatus     _NTSTATUS
	TebBaseAddress uintptr
	ClientId       _CLIENT_ID
	AffinityMask   uintptr
	Priority       int32
	BasePriority   int32
}

type _CREATE_PROCESS_DEBUG_INFO struct {
	File                syscall.Handle
	Process             syscall.Handle
	Thread              syscall.Handle
	BaseOfImage         uintptr
	DebugInfoFileOffset uint32
	DebugInfoSize       uint32
	ThreadLocalBase     uintptr
	StartAddress        uintptr
	ImageName           uintptr
	Unicode             uint16
}

type CreateProcessInfo _CREATE_PROCESS_DEBUG_INFO

type _CREATE_THREAD_DEBUG_INFO struct {
	Thread          syscall.Handle
	ThreadLocalBase uintptr
	StartAddress    uintptr
}

type _EXIT_PROCESS_DEBUG_INFO struct {
	ExitCode uint32
}
type ExitProcess _EXIT_PROCESS_DEBUG_INFO

type _LOAD_DLL_DEBUG_INFO struct {
	File                windows.Handle
	BaseOfDll           uintptr
	DebugInfoFileOffset uint32
	DebugInfoSize       uint32
	ImageName           *uint16
	Unicode             uint16
}

type LoadDllInfo _LOAD_DLL_DEBUG_INFO

type _OUTPUT_DEBUG_STRING_INFO struct {
	DebugStringData   *uint16
	Unicode           uint16
	DebugStringLength uint16
}
type OutputDebugStringInfo _OUTPUT_DEBUG_STRING_INFO

type _EXCEPTION_DEBUG_INFO struct {
	ExceptionRecord _EXCEPTION_RECORD
	FirstChance     uint32
}

type _EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *_EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [_EXCEPTION_MAXIMUM_PARAMETERS]uintptr
}

type _MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uint64
	State             uint32
	Protect           uint32
	Type              uint32
}

func _NT_SUCCESS(x _NTSTATUS) bool {
	return x >= 0
}

type _DEBUG_EVENT struct {
	DebugEventCode uint32
	ProcessId      uint32
	ThreadId       uint32
	_              uint32 // to align Union properly
	U              [160]byte
}
