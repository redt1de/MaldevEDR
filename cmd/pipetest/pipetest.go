//go:build windows
// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/textproto"

	"github.com/Microsoft/go-winio"
)

var shutdown chan bool

// GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/pipetest.exe ./cmd/pipetest;
func main() {
	pipePath := `\\.\pipe\MalDevEDR\hooks`

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
		go handleClient(conn)
	}

}

func handleClient(c net.Conn) {
	defer c.Close()
	// log.Printf("Client connected [%s]", c.RemoteAddr().Network())
	reader := bufio.NewReader(c)
	tp := textproto.NewReader(reader)

	for {
		line, err := tp.ReadLine()
		if err != nil {
			break
		}
		fmt.Println(line)

	}
	log.Println("Client disconnected")
}
