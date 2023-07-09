//go:build windows
// +build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/redt1de/MaldevEDR/pkg/config"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/ewatch/etw"
)

var shutdown chan bool

// GOOS=windows GOARCH=amd64 go build -o ../../_external/ThreatIntelProxy/ThreatIntelProxy.exe .
func main() {
	var cpath string
	flag.StringVar(&cpath, "c", "../../config.yaml", "Path to config file")
	flag.Parse()
	shutdown = make(chan bool)

	edr, err := config.NewEdr(cpath)
	if err != nil {
		log.Fatal(err)
	}

	cfg := edr.Etw
	ewatch.EtwInit(&cfg)

	pipePath := `\\.\pipe\MalDevEDR\events`

	s := etw.NewRealTimeSession("ThreatIntelProxy")
	defer s.Stop()

	for _, p := range cfg.PplProviders {
		providerProps := uint32(0)
		if p.StackTrace {
			providerProps = uint32(providerProps | etw.EVENT_ENABLE_PROPERTY_STACK_TRACE)
		}
		if err := s.EnableProvider(etw.MustParseProvider(p.Name), providerProps); err != nil {
			log.Println(3, err, p.Name)
		}
	}

	c := etw.NewRealTimeConsumer(context.Background())

	defer c.Stop()

	c.FromSessions(s)

	go func() {
		var b []byte
		for e := range c.Events {
			conn, err := winio.DialPipe(pipePath, nil)
			if err != nil {
				if strings.Contains(err.Error(), "The system cannot find the file specified") { // ignore events if the client is not running/listening
					continue
				}
				log.Println(err)
			}
			if b, err = json.Marshal(e); err != nil {
				log.Println(err)
			}

			_, err = conn.Write(b)
			if err != nil {
				log.Println(err)

				// shutdown <- true
				// break
			}

		}

	}()

	if err := c.Start(); err != nil {
		log.Println(1, err)
	}

	<-shutdown
	c.Stop()
	s.Stop()
	log.Println("Stopped ETW session...")
	if c.Err() != nil {
		log.Println(2, c.Err())
	}

}
