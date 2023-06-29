# Query Language
 - Rule queries are performed against the JSON data for each event. 
 - expressions are evaluated using the package: https://github.com/antonmedv/expr
 - syntax information can be found here https://expr.medv.io/docs/Language-Definition
 - queries must return true | false
 - if a value in the JSON is quoted, then the match in your query needs to be. (i.e. they are treated as strings VS int/bool/etc)
 - regex via the "matches" operator need to be quoted
 - Rules are inclusive, so if you need to exclude certain events, you can use the ! operator. 
 - To develop new rules, run MaldevEDR with the -no-rules and -debug flags. This will present a ton of data, but you can pick out the relevant details you need to create a rule.

## Additional Syntax
there are several additional operations added to expr to make event filtering easier:
 ### $value in any | InAny($value):  compares all fields to $value, if any match it returns true. you can use either format, "$value in any" will be converted to InAny($value) by the preprocessors
 ```
 "malicious.exe" in any
 ```
 or
 ```
 InAny("malicious.exe")
 ```
 ### $regex matches any | MatchesAny($regex): compares all fields to the regex. All values are converted to strings for this comparision so you can search for parts of numerical values. 
 ```
 "(?i)MalIciOus.ExE$" matches any
 ```
 or
 ```
 InAny("(?i)MalIciOus.ExE$")
 ```



## Examples for the following event (-debug output)
```
 [+] Channel: Microsoft-Windows-Sysmon/Operational Event ID: 10 Task: Process accessed (rule: ProcessAccess) Rule: TESTING
{
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Computer": "BradVM",
  "EventID": 10,
  "Correlation": {
    "ActivityID": "{00000000-0000-0000-0000-000000000000}",
    "RelatedActivityID": "{00000000-0000-0000-0000-000000000000}"
  },
  "Execution": {
    "ProcessID": 3836,
    "ThreadID": 4500
  },
  "Keywords": {
    "Value": 9223372036854775808,
    "Name": ""
  },
  "Level": {
    "Value": 4,
    "Name": "Information"
  },
  "Opcode": {
    "Value": 0,
    "Name": "Info"
  },
  "Task": {
    "Value": 10,
    "Name": "Process accessed (rule: ProcessAccess)"
  },
  "Provider": {
    "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
    "Name": "Microsoft-Windows-Sysmon"
  },
  "TimeCreated": {
    "SystemTime": "2023-06-17T18:17:35.7621307Z"
  }
,
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9e9c4|C:\\Windows\\System32\\KERNELBASE.dll+5b3d3|C:\\Windows\\System32\\KERNELBASE.dll+59c1e|C:\\Windows\\System32\\KERNELBASE.dll+597c6|C:\\Windows\\System32\\KERNEL32.DLL+6789c|UNKNOWN(0000019766E7010B)",
  "GrantedAccess": "0x1FFFFF",
  "RuleName": "-",
  "SourceImage": "z:\\c\\Direct-Syscalls-vs-Indirect-Syscalls\\popcalc-direct.exe",
  "SourceProcessGUID": "{a480cd19-f8bf-648d-a208-000000008400}",
  "SourceProcessId": "5840",
  "SourceThreadId": "1716",
  "SourceUser": "VM\\Some.User",
  "StackTrace": [
    "0x0",
    "0x7ff8a098dc64",
    "0x7ff8a093f3ee",
    "0x7ff8a093f219",
    "0x7ff74e510644",
    "0x7ff74e5120fe",
    "0x7ff74e527837",
    "0x7ff74e5ca432",
    "0x7ff89ee27614",
    "0x7ff8a09426f1"
  ],
  "TargetImage": "C:\\Windows\\SYSTEM32\\calc.exe",
  "TargetProcessGUID": "{a480cd19-f8bf-648d-a308-000000008400}",
  "TargetProcessId": "5512",
  "TargetUser": "VM\\Some.User",
  "UtcTime": "2023-06-17 18:17:35.761"
}
```

#### match this event
```
EventID==10
```

#### match this event, only if its from a certain exe, check with case-insensitive regex
```
EventID == 10 && SourceImage matches "(?i)popcalc-direct.exe"
```
or 
```
EventID == 10 && SourceImage matches "(?i).*popcalc.*"
```