package main

import (
	"fmt"
	"strings"
)

func main() {
	data := `NtAllocateVirtualMemory(HANDLE ProcessHandle,PVOID* BaseAddress,ULONG_PTR ZeroBits,PSIZE_T RegionSize,ULONG AllocationType,ULONG Protect)`

	tmp := strings.Split(data, "(")
	funcName := tmp[0]
	parms := strings.Split(strings.TrimRight(tmp[1], ")"), ",")

	arglist := []string{}
	jstring := `wsprintfA(jout, "{\"Function\":\"` + funcName + `\",\"EventData\":{`
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

	jstring += `}}",` + strings.Join(arglist, ",")
	jstring += `);`
	fmt.Println(jstring)
}
