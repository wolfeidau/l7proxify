package l7proxify

// Copyright 2016 Mark Wolfe. All rights reserved.
// Use of this source code is governed by the MIT
// license which can be found in the LICENSE file.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/apex/log"
)

// Session state for a client
type Session struct {
	fromBytes, toBytes int64
	laddr, raddr       net.Addr
	lconn, rconn       *Conn
	Log                log.Interface

	// hand     bytes.Buffer // handshake data waiting to be read
	// rawInput *block       // raw input, right off the wire
	//
	wait sync.WaitGroup
}

// NewSession new proxy session
func NewSession(lconn *net.TCPConn) *Session {
	return &Session{
		laddr: lconn.LocalAddr(),
		lconn: NewConn(lconn),
		Log:   log.WithField("sessionID", generateID()),
	}
}

// Start processing data through the proxied connection
//
// This will attempt to parse the SSL handshake client hello and retrieve the
// hostname out of the SNI attribute to use as the endpoint for connection.
//
// It will pass this hostname to the rule matcher and take the action returned,
// or if nil is the result reject the connection.
//
func (s *Session) Start() {

	var err error

	defer s.lconn.Close()

	s.Log.Info("Starting session")

	// START SSL Handshake Reading

	lmsg, err := s.lconn.peakHandshake()
	if err != nil {
		s.Log.WithError(err).Error("read handshake failed")
		return
	}

	clientHello, ok := lmsg.(*clientHelloMsg)

	if !ok {
		s.Log.Errorf("clientHello expected")
		return
	}

	if clientHello.serverName == "" {
		s.Log.Errorf("clientHello missing serverName")
		return
	}

	rm := MatchRule(clientHello.serverName)

	if rm == nil {
		s.Log.WithField("serverName", clientHello.serverName).Error("No matching rule found connection is rejected")
		return
	}

	s.Log.WithFields(log.Fields{
		"name":   rm.Rule.Name,
		"action": rm.Rule.Action,
	}).Debug("Rule matched")

	switch rm.Action {
	case ActionReject:
		s.Log.WithField("serverName", clientHello.serverName).Error("Connection rejected")
		return
	case ActionAccept:
		s.Log.WithField("serverName", clientHello.serverName).Debug("Connection accepted")
	}

	remoteAddr := fmt.Sprintf("%s:%d", clientHello.serverName, 443) // todo not hard coded

	s.Log.WithField("remoteAddr", remoteAddr).Info("opening connection")

	raddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		s.Log.WithError(err).Error("resolve failed")
		return
	}

	c, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		s.Log.WithError(err).Error("remote connection")
		return
	}

	s.rconn = NewConn(c)

	defer s.rconn.Close()

	_, err = s.rconn.Write(s.lconn.RawInput.data)
	if err != nil {
		s.Log.Errorf("Write failed '%s'\n", err)
		return
	}

	smsg, err := s.rconn.peakHandshake()
	if err != nil {
		s.Log.WithError(err).Error("read handshake failed")
		return
	}

	serverHello, ok := smsg.(*serverHelloMsg)

	if !ok {
		s.Log.Errorf("serverHello expected")
		return
	}

	_, err = s.lconn.Write(s.rconn.RawInput.data)
	if err != nil {
		s.Log.Errorf("Write failed '%s'\n", err)
		return
	}

	s.Log.Debugf("serverHello ocspStapling '%v'\n", serverHello.ocspStapling)

	//
	// cmsg, err := s.rconn.readHandshake()
	// if err != nil {
	// 	s.Log.WithError(err).Error("read handshake failed")
	// 	return
	// }
	//
	// certificate, ok := cmsg.(*certificateMsg)
	//
	// if !ok {
	// 	s.Log.Errorf("certificate expected")
	// 	return
	// }
	//
	// _, err = s.lconn.Write(s.rconn.RawInput.data)
	// if err != nil {
	// 	s.Log.Errorf("Write failed '%s'\n", err)
	// 	return
	// }
	//
	// s.Log.Debugf("certificates count '%v'\n", len(certificate.certificates))

	s.wait.Add(2)

	go s.pipe(s.lconn, s.rconn, &s.toBytes)
	go s.pipe(s.rconn, s.lconn, &s.fromBytes)

	s.wait.Wait()

	s.Log.WithFields(log.Fields{
		"toBytes":   s.toBytes,
		"fromBytes": s.fromBytes,
	}).Infof("connection finished")

}

func (s *Session) pipe(to, from net.Conn, bytesCopied *int64) {
	var err error
	defer s.wait.Done()
	*bytesCopied, err = io.Copy(to, from)
	if err != nil {
		s.Log.WithError(err).Error("pipe failed")
	}
}

// TLSHandler pulls apart and proxies TLS connections using the client hello
// SNI field.
type TLSHandler struct {
}

// ProxyConnection proxy a TLS connection
func (tlsh *TLSHandler) ProxyConnection(cin *net.TCPConn) {
	s := NewSession(cin)
	go s.Start()
}

func generateID() string {
	r := make([]byte, 10)
	_, err := rand.Read(r)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(r)
}
