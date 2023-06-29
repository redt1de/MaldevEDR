package ewatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/antonmedv/expr"
	"github.com/redt1de/MaldevEDR/pkg/ewatch/etw"
)

func (cf *EWatcher) Stop() {
	cf.Session.Stop()
	cf.stopChan <- true
}

func (cf *EWatcher) Start() error {
	var enabledCount int
	enabledCount = 0
	cf.Session = etw.NewRealTimeSession("MaldevEDR")
	defer cf.Session.Stop()
	providerProps := uint32(0)
	if cf.DisableRules {
		cf.Logger.WriteInfo("Yaml rules are disabled!!")
	}

	if cf.Override != "" {
		cf.Logger.WriteInfo("overriding all rules with: " + cf.Override)
	}

	if cf.Append != "" {
		cf.Logger.WriteInfo("appending to all rules: " + cf.Append)
	}

	for _, upr := range cf.UserModeProviders {
		if !upr.Enabled {
			continue
		}
		if upr.StackTrace {
			providerProps = uint32(providerProps | etw.EVENT_ENABLE_PROPERTY_STACK_TRACE)
		}

		if err := cf.Session.EnableProvider(etw.MustParseProvider(upr.Name), providerProps); err != nil {
			cf.Logger.WriteFatal("Failed to enable user mode provider(" + upr.Name + "): " + err.Error())
		}
		enabledCount++
		cf.Logger.WriteInfo("Monitoring:", upr.Name)
	}

	consumer := etw.NewRealTimeConsumer(context.Background())
	defer consumer.Stop()
	consumer.FromSessions(cf.Session)

	go func() {
		for e := range consumer.Events {

			////////////////// TESTING SYMBOL RESOLUTION ////////////////
			// if cf.Spawn != nil {
			// 	val, ok := e.EventData["StackTrace"]
			// 	// If the key exists
			// 	if ok {

			// 		aInterface := val.([]string)
			// 		// aString := make([]string, len(aInterface))
			// 		for _, v := range aInterface {
			// 			v = strings.TrimLeft(v, "0x")
			// 			if v == "0" {
			// 				continue
			// 			}
			// 			ui64, _ := strconv.ParseUint(v, 16, 64)
			// 			fmt.Println(symbols.LookupAddr(*cf.Spawn.ProcessHandle, ui64))
			// 		}
			// 	}

			// }

			////////////////////////////////////////////
			sysJson, err := json.MarshalIndent(e.System, "", "  ")
			if err != nil {
				log.Println(err)
				continue
			}
			evtJson, err := json.MarshalIndent(e.EventData, "", "  ")
			if err != nil {
				log.Println(err)
				continue
			}
			cmbJson := strings.TrimRight(string(sysJson), "}") + "," + strings.TrimLeft(string(evtJson), "{")

			if cf.Override != "" {
				match, q := cf.ruleMatches(cmbJson, cf.Override)
				if match {
					// cf.Logger.WriteThreat("Channel:", e.System.Channel, "Event ID:", e.System.EventID, "Task:", e.System.Task.Name, "Matches: "+q)
					cf.Logger.WriteThreat("Channel:", e.System.Channel, ", Task:", e.System.Task.Name, ", Matches: "+q)
					if cf.Verbose == 2 {
						cf.Logger.Write(cmbJson)
					} else if cf.Verbose == 1 {
						cf.Logger.Write(string(evtJson))
					}

				}
			} else {
				if cf.DisableRules {
					match, q := cf.ruleMatches(cmbJson, "")
					if match {
						// cf.Logger.WriteThreat("Channel:", e.System.Channel, "Event ID:", e.System.EventID, "Task:", e.System.Task.Name, "Matches: "+q)
						cf.Logger.WriteThreat("Channel:", e.System.Channel, ", Task:", e.System.Task.Name, ", Matches: "+q)

						if cf.Verbose == 2 {
							cf.Logger.Write(cmbJson)
						} else if cf.Verbose == 1 {
							cf.Logger.Write(string(evtJson))
						}

					}
				} else {
					AllProviders := append(cf.UserModeProviders, cf.PplProviders...)

					for _, prov := range AllProviders {
						if prov.Name == e.System.Provider.Name && prov.Enabled {
							prov.Rules = append(prov.Rules, cf.GlobalRules...)
							for _, rule := range prov.Rules {
								match, _ := cf.ruleMatches(cmbJson, rule.Query)
								if match {
									// cf.Logger.WriteThreat("Channel:", e.System.Channel, "Event ID:", e.System.EventID, "Task:", e.System.Task.Name, "Matches:", rule.Name)
									cf.Logger.WriteThreat("Channel:", e.System.Channel, ", Task:", e.System.Task.Name, ", Matches:", rule.Name)
									if rule.Msg != "" {
										cf.Logger.Write(cf.parseMsg(rule.Msg, cmbJson))
									}
									if cf.Verbose == 2 {
										cf.Logger.Write(cmbJson)
									} else if cf.Verbose == 1 {
										cf.Logger.Write(string(evtJson))
									}

								}
							}
						}
					}
				}
			}

		}
	}()
	///////////////////////////// proxy events
	var pipeStarted bool
	for _, ppl := range cf.PplProviders {
		if ppl.Enabled {
			if pipeStarted {
				cf.Logger.WriteInfo("Monitoring:", ppl.Name, "via ThreatIntelProxy")
				enabledCount++
			} else {
				pipePath := `\\.\pipe\MalDevEDR\events`
				f, err := winio.DialPipe(pipePath, nil)
				if err != nil {
					// log.Fatalf("error opening pipe: %v", err)
					cf.Logger.WriteErr("failed to open the ThreatIntelProxy pipe, but PPL providers are enabled.")
					cf.Logger.WriteInfo("Make sure ThreatIntelProxy is running if you want to monitor PPL providers")
					break
				}
				enabledCount++
				cf.Logger.WriteInfo("Monitoring:", ppl.Name, "via ThreatIntelProxy")
				go func() {
					for {
						d := json.NewDecoder(f)
						var event etw.Event
						err = d.Decode(&event)
						if err != nil {
							fmt.Println(err)
							break
						}
						consumer.Events <- &event
					}
					f.Close()
				}()
			}
		}
	}

	if enabledCount < 1 {
		e := errors.New("no providers are enabled, shutting down")
		consumer.Stop()
		cf.Session.Stop()
		cf.Running = false
		cf.Logger.WriteErr(e)
		return e
	}
	////////////////////////////////////////////////

	if err := consumer.Start(); err != nil {
		cf.Logger.WriteFatal(err)
	}

	cf.Running = true
	<-cf.stopChan // wait for approval to shutdown

	if consumer.Err() != nil {
		cf.Logger.WriteFatal(consumer.Err())
	}
	cf.Running = false
	return nil
}

func (cf *EWatcher) parseMsg(msg string, jsn string) string {
	var ret string
	mp := make(QueryData)
	json.Unmarshal([]byte(jsn), &mp)

	msg = `DoMessage( ` + msg + ` )`
	output, err := expr.Eval(msg, mp)
	if err != nil {
		cf.Logger.WriteErr("failed to parse message: ", msg+"\n", err)

	}
	// cf.Logger.Write(">>>>>>>", output)
	ret = fmt.Sprintf("%s", output)
	ret = strings.TrimRight(ret, "\n")
	return ret

}

// func (cf *EWatcher) spawnProcess(fpath string) (int, error) {
// 	cmd := exec.Command(fpath)
// 	cmd.Stdout = os.Stdout
// 	err := cmd.Start()
// 	if err != nil {
// 		return 0, err
// 	}

// 	cf.Logger.WriteInfo(fmt.Sprintf("Spawned process: %s  (PID:%d)", filepath.Base(fpath), cmd.Process.Pid))
// 	cf.Logger.WriteInfo("Adding rules to match process")
// 	return cmd.Process.Pid, nil
// }
