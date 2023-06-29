



# !!! THIS IS NOT A REAL EDR/AV SOLUTION, DO NOT USE IN A PRODUCTION ENVIRONMENT !!!

This project is still in initial development.  Some functionality is working, some is not.
- Threatcheck is working
- ETW is working
- DLL injection/hooks are not working yet.


MaldevEDR is a project I created to serve 2 purposes. 
1. I wanted to learn more about Windows API, and how detections work, 
2. Provide a tool that Red Teams can use during malware development, to gain insight into what target EDR/AV may see during an engagement.  MaldevEDR does not perform prevent anything, it simply alerts to information. It is designed to be configurable so we can adapt to different EDR vendors and new tactics.


## TODO
- [ ] Need a DLL to inject, and finish implementing the injection module
- [ ] Clean up module exits, I have a feeling there may be some scenerios where channels block or errors prevent exit. plus its kind of a mess.
- [ ] Devlop some real rules for the etw config. As of right now its just test rules.

## Modules
#### ThreatCheck
- Performs static analysis on a file using Defenders CLI.  This a plain and simple rip-off of Rasta-Mouse's ThreatCheck, just ported to Golang for use in this project.

#### ETW
- ETW providers that require PPL such as Defenders Threat Intel, are handled differently than normal providers. there is a tool in cmd/ThreatIntelProxy that can be run in kernel mode, and will forward etw events to a named pipe. Up to you how you run this in PPL mode, but the easiest is via kdu.exe > vulnerable drivers (not not all work. -prv 1 has been so far)
- ETW rules are handled application side instead passing them to the provider/consumer. This allows us to perform more checks using a custom query language.
- See QUERY_LANGUAGE.md for more information on rule syntax

#### Inject
- still working on this, but the goal is to inject a DLL into the target to mimic userland hooks, and detect manual syscalls via instrumentation callbacks.

#### Analyze
- performs all checks.

## Notes:
- spawned processes are initially created suspened, debugger is attached, and then resumed. I may add options in the future to use a normal os.Exec() if we need to avoid DEBUG.
- if you spawn a process for for any ETW monitoring, all rules are appended with a matcher for the process name or pid automatically.
- the use of expr is a security risk, its essentially an eval on user supplied data, but again this should not run anywhere but a dedicated malware VM.
-

