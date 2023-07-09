package main

import (
	"os"
	"strings"
	"text/template"
)

// NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
// NTSYSCALLAPI NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
// NTSYSCALLAPI NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PVOID *Buffer, ULONG NumberOfBytesToWrite, ULONG NumberOfBytesWritten);

const hookTemplate = `
----------------------------------------------------- hooks.h -------------------------------------------------------
////////////////////////////////////////////////////////////// {{.FnName}} //////////////////////////////////////////////
EXTERN_C NTSYSAPI NTSTATUS NTAPI {{.FnName}}({{.RawArgs}});
typedef NTSTATUS(NTAPI* fn{{.FnName}})({{.RawArgs}});

static fn{{.FnName}} Orig{{.FnName}};

EXTERN_C NTSTATUS NTAPI  Hooked{{.FnName}}({{.RawArgs}})
{
	NTSTATUS retVal = Orig{{.FnName}}({{.PassArgs}});

    IncrementCurrentNestingLevel();

    do {
        if (GetCurrentNestingLevel() > 1) {
            break;
        }
        CHAR jout[1000];
        {{.Jstring}}
        WritePipeSingle(jout);
    } while (false);

	DecrementCurrentNestingLevel();
   return  retVal;

}
----------------------------------------------------- DLL_PROCESS_ATTACH -------------------------------------------------------
Orig{{.FnName}} = {{.FnName}};
DetourAttach((PVOID*)&Orig{{.FnName}}, Hooked{{.FnName}});
----------------------------------------------------- DLL_PROCESS_DETACH -------------------------------------------------------
DetourDetach((PVOID*)&Orig{{.FnName}}, Hooked{{.FnName}});
`

type CallData struct {
	FnName   string
	RawArgs  string
	Jstring  string
	PassArgs string
}

func main() {
	data := `NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)`

	data = strings.ReplaceAll(data, "NTSYSCALLAPI", "NTSYSAPI")
	data = strings.ReplaceAll(data, " *", "* ")
	data = strings.ReplaceAll(data, ", ", ",")
	var calldata CallData
	tmp := strings.Split(data, "(")
	funcName := tmp[0]

	parms := strings.Split(strings.TrimRight(tmp[1], ")"), ",")
	rawargs := strings.Join(parms, ", ")

	arglist := []string{}
	jstring := `sprintf(jout, "{\"Function\":\"` + funcName + `\",\"mode\":\"userland\",\"Args\":{`
	for _, p := range parms {
		ptmp := strings.Split(p, " ")
		datype := ptmp[0]
		nme := ptmp[1]

		var formchar string
		switch datype {
		case "HANDLE":
			formchar = "0x%x"
		case "PVOID*":
			formchar = "0x%x"
		default:
			formchar = "0x%x"
		}

		jstring += `\"` + nme + `\":\"` + formchar + `\",`
		arglist = append(arglist, nme)

	}
	jstring = strings.TrimRight(jstring, ",")

	jstring += `}}",` + strings.Join(arglist, ", ")
	jstring += `);`

	calldata.FnName = funcName
	calldata.RawArgs = rawargs
	calldata.Jstring = jstring
	calldata.PassArgs = strings.Join(arglist, ", ")
	// fmt.Println(jstring)

	tpl := template.New("t1")
	tpl, err := tpl.Parse(hookTemplate)
	if err != nil {
		panic(err)
	}

	err = tpl.Execute(os.Stdout, calldata)
	if err != nil {
		panic(err)
	}
}
