TODO:
    - need a mutex on ModStores, concurrent read/writes will crash.
    - need a way to lock loggers so we dont mix events + data if concurrent
    - de-dupe etw events, some come in twice, especially hooked funcs, deepequals on event json?
    - add ability to hook/monitor processes created by mal file. using call back CREATE_PROCESS_DEBUG_EVENT ?????
    - need some vars/funcs in parsers to compare addresses to image base,ntdll kernel32 etc. 'InImageBase(ReturnAddress)' or '(ReturnAddress > $NTDLL.SIZE && ReturnAddress < $NTDLL.BASE + $NTDLL.SIZE)' 
        - may be able to use text/template

            type NtDll struct{
                Base
                Size
            }

            parse rule, replace $NTDLL.SIZE with {{.Size}}, pass NtDll struct to text template.

            OR

            handle symbol lookup in DLL, then we can just do matching based off string.  '! ReturnAddress matches "*ntdll*"'

