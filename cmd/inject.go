/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// injectCmd represents the inject command
var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Inject a monitoring DLL into a target process",
	Long:  `???????????????????????????????????????????`,
	Run: func(cmd *cobra.Command, args []string) {
		// spawn, _ := cmd.Flags().GetString("spawn")
		// pid, _ := cmd.Flags().GetUint32("pid")

		// if spawn == "" && pid <= 0 {
		// 	tmp := util.ConsoleLogger{}
		// 	tmp.WriteFatal("you must specify -s or -p so I know where to inject")
		// }

		// injector := dllinject.NewInjector()
		// injector.Logger = &util.ConsoleLogger{}

		// shutdown := make(chan bool)
		// if spawn != "" {
		// 	dSess, err := dbgproc.NewDebugProc(spawn, true)
		// 	if err != nil {
		// 		injector.Logger.WriteFatal(err)
		// 	}
		// 	injector.Logger.WriteInfo("Creating debug process:", dSess.ProcessImage, "PID:", dSess.ProcessPid)
		// 	injector.Pid = dSess.ProcessPid
		// 	injector.ProcessHandle = dSess.ProcessHandle

		// 	dSess.CreateProcessCB = func(ep dbgproc.CreateProcessInfo) { // using the createprocess event in debug loop to call inject.  we cant suspened,inject resume. and if we inject after resume we miss events.
		// 		err = injector.Inject(dllinject.DLLPATH)
		// 		if err != nil {
		// 			injector.End()
		// 			injector.Logger.WriteFatal("failed to inject DLL:", err)
		// 		}
		// 		injector.Logger.WriteInfo("DLL injected")
		// 	}

		// 	dSess.ExitProcessCB = func(ep dbgproc.ExitProcess) {
		// 		injector.Logger.WriteInfo("Process Exiting...")
		// 		// time.Sleep(3 * time.Second)
		// 		injector.End()
		// 		shutdown <- true
		// 	}

		// 	go injector.Monitor()

		// 	time.Sleep(time.Millisecond * 1000)

		// 	injector.Logger.WriteInfo("Resuming process...")
		// 	dSess.Start()

		// 	<-shutdown

		// } else {

		// }

	},
}

func init() {
	rootCmd.AddCommand(injectCmd)
	injectCmd.Flags().StringP("spawn", "s", "", "spawn a process")
	injectCmd.Flags().StringP("dll", "d", "", "use a custom DLL(not implemented yet)")
	injectCmd.Flags().Uint32P("pid", "p", 0, "injection into process by PID")
}
