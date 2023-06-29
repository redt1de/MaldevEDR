package symbols

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MAX_SYM_NAME = 256
)

var (
	kernel32 = windows.NewLazyDLL("kernel32.dll")
	dbghelp  = windows.NewLazyDLL("dbghelp.dll")

	pInitializeCriticalSection = kernel32.NewProc("InitializeCriticalSection")
	pEnterCriticalSection      = kernel32.NewProc("EnterCriticalSection")
	pLeaveCriticalSection      = kernel32.NewProc("LeaveCriticalSection")

	pSymFromAddr   = dbghelp.NewProc("SymFromAddr")
	pSymInitialize = dbghelp.NewProc("SymInitialize")
	pSymCleanup    = dbghelp.NewProc("SymCleanup")
)

/*
	typedef struct _SYMBOL_INFO {
	  ULONG   SizeOfStruct;
	  ULONG   TypeIndex;
	  ULONG64 Reserved[2];
	  ULONG   Index;
	  ULONG   Size;
	  ULONG64 ModBase;
	  ULONG   Flags;
	  ULONG64 Value;
	  ULONG64 Address;
	  ULONG   Register;
	  ULONG   Scope;
	  ULONG   Tag;
	  ULONG   NameLen;
	  ULONG   MaxNameLen;
	  CHAR    Name[1];
	} SYMBOL_INFO, *PSYMBOL_INFO;
*/
type _SYMBOL_INFO struct {
	SizeOfStruct uint32    // +4 = 4
	TypeIndex    uint32    // +4 = 8
	Reserved     [2]uint64 // 8 + 8?? = 24 ??
	Index        uint32    // + 4 = 28
	Size         uint32    // +4 = 32
	ModBase      uint64    // + 8 = 40
	Flags        uint32    // + 4 = 44
	Value        uint64    // + 8 = 48
	Address      uint64    // + 8 = 56 correct
	Register     uint32    // + 4 = 60
	Scope        uint32    // + 4 = 64
	Tag          uint32    // + 4 = 68
	NameLen      uint32    // + 4 = 72 correct
	MaxNameLen   uint32    // + 4 = 76
	Name         *byte     //ends up being at offset 84
}

// makeSymbolBuffer preps a buffer to match SYMBOL_INFO, WINAPI does not like go structs here.
func makeSymbolBuffer() []byte {
	symbolBuf := make([]byte, unsafe.Sizeof(_SYMBOL_INFO{})+MAX_SYM_NAME)
	for i := range symbolBuf {
		symbolBuf[i] = 0xcc
	}

	// manually set symbol.SizeOfStruct = uint32(unsafe.Sizeof(SYMBOL_INFO{}))
	symbolBuf[0] = 0x58
	symbolBuf[1] = 0x00
	symbolBuf[2] = 0x00
	symbolBuf[3] = 0x00

	// manually set symbol.MaxNameLen = MAX_SYM_NAME
	symbolBuf[80] = 0xd0
	symbolBuf[81] = 0x07
	symbolBuf[82] = 0x00
	symbolBuf[83] = 0x00
	// return uintptr(unsafe.Pointer(&symbolBuf[0]))
	return symbolBuf
}

// TODO: need to move SymInitialize so we are not calling ir on every addr
func LookupAddr(hProc windows.Handle, addr uint64) string {
	var ret string
	ret = fmt.Sprintf("(0x%x) UNKNOWN", addr)
	pSymInitialize.Call(uintptr(hProc), uintptr(0), uintptr(1))
	defer pSymCleanup.Call(uintptr(hProc))

	symbolBuffer := makeSymbolBuffer()
	symbol := (*_SYMBOL_INFO)(unsafe.Pointer(&symbolBuffer[0]))
	var displacement = uint64(0)
	r1, _, _ := pSymFromAddr.Call(uintptr(hProc), uintptr(addr), uintptr(unsafe.Pointer(&displacement)), uintptr(unsafe.Pointer(symbol)))
	if r1 != 1 {
		return ret
	}

	var hModule windows.Handle
	lpModuleName := (*uint16)(unsafe.Pointer(uintptr(symbol.Address)))
	err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, lpModuleName, &hModule)
	defer windows.CloseHandle(hModule)
	modName := ""
	if err == nil {
		var baseName uint16
		err = windows.GetModuleBaseName(hProc, hModule, &baseName, uint32(256))
		if err == nil && baseName != 0 {
			modName = windows.UTF16PtrToString(&baseName)
		}
	}

	nameOffset := 84
	funcName := string(symbolBuffer[nameOffset : nameOffset+int(symbol.NameLen)]) // struct alignment is off, need to figure out why
	offset := addr - symbol.Address

	if modName != "" {
		ret = fmt.Sprintf("(0x%x) %s!%s+0x%x", addr, modName, funcName, offset)
	}

	return ret
}
