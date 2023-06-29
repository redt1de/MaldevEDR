//go:build windows
// +build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/redt1de/MaldevEDR/pkg/ewatch"
	"github.com/redt1de/MaldevEDR/pkg/ewatch/etw"
)

var shutdown chan bool

// GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/proxy.exe ./cmd/ThreatIntelProxy; GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/edr.exe .
func main() {
	var cpath string
	flag.StringVar(&cpath, "c", "./etw.yaml", "Path to config file")
	shutdown = make(chan bool)
	cfg, err := ewatch.NewEtw(cpath)
	if err != nil {
		log.Fatal(err)
	}

	pipePath := `\\.\pipe\MalDevEDR\events`

	l, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	defer l.Close()
	log.Printf("Server listening op pipe %v\n", pipePath)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}
		go handleClient(cfg, conn)
	}

}

func handleClient(cfg *ewatch.EWatcher, c net.Conn) {
	defer c.Close()
	log.Printf("Client connected [%s]", c.RemoteAddr().Network())
	startSess(cfg, c)
	log.Println("Client disconnected")
}

func startSess(cfg *ewatch.EWatcher, conn net.Conn) {
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
		var err error
		for e := range c.Events {
			if b, err = json.Marshal(e); err != nil {
				log.Println(err)
			}

			_, err := conn.Write(b)
			if err != nil {
				log.Println(err)

				shutdown <- true
				break
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
