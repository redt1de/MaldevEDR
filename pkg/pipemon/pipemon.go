package pipemon

import (
	"errors"
	"log"
	"net"

	"github.com/Microsoft/go-winio"
)

type PipeHandler func(net.Conn)

type Pipe struct {
	Path    string
	Handler PipeHandler
	Error   func(error)
	stop    bool
}

func defaultErrCB(e error) {
	log.Fatal("pipemon default error callback:" + e.Error())
}

func NewPipe(pipePath string, handler PipeHandler) *Pipe {
	return &Pipe{Path: pipePath, Handler: handler, Error: defaultErrCB}
}

func (p *Pipe) Monitor() {
	p.stop = false
	l, err := winio.ListenPipe(p.Path, nil)
	if err != nil {
		p.Error(errors.New("listen error: " + err.Error()))
		return
	}

	defer l.Close()
	// log.Printf("Server listening op pipe %v\n", p.Path)

	for {
		if p.stop {
			break
		}
		conn, err := l.Accept()
		if err != nil {
			p.Error(errors.New("accept error:" + err.Error()))
		}

		go p.Handler(conn)
	}

}

func (p *Pipe) Stop() {
	p.stop = true
}
