package l7proxify

// Copyright 2016 Mark Wolfe. All rights reserved.
// Use of this source code is governed by the MIT
// license which can be found in the LICENSE file.

import (
	"net"

	"github.com/apex/log"
)

// A Handler responds to an incoming proxy connection.
type Handler interface {
	ProxyConnection(cin *net.TCPConn)
}

// Server the core of the proxy server
type Server struct {
}

// ListenAndServe listen and start proxying connections
func ListenAndServe(addr string, handler Handler) error {

	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	l, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer l.Close()

	for {
		// Wait for a connection.
		conn, err := l.AcceptTCP()
		if err != nil {
			log.WithError(err).Error("accept failed")
		}

		// Handle the connection in a new goroutine.
		go handler.ProxyConnection(conn)
	}
}
