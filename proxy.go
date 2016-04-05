package l7proxify

// Copyright 2016 Mark Wolfe. All rights reserved.
// Use of this source code is governed by the MIT
// license which can be found in the LICENSE file.

import (
	"bytes"
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
	lconn, rconn       *net.TCPConn
	Log                log.Interface

	hand     bytes.Buffer // handshake data waiting to be read
	rawInput *block       // raw input, right off the wire

	wait sync.WaitGroup
}

// NewSession new proxy session
func NewSession(lconn *net.TCPConn) *Session {
	return &Session{
		laddr: lconn.LocalAddr(),
		lconn: lconn,
		Log:   log.WithField("conn", lconn.RemoteAddr().String()),
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

	msg, err := s.readHandshake()
	if err != nil {
		s.Log.WithError(err).Error("read handshake failed")
		return
	}

	clientHello, ok := msg.(*clientHelloMsg)

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

	s.rconn, err = net.DialTCP("tcp", nil, raddr)
	if err != nil {
		s.Log.WithError(err).Error("remote connection")
		return
	}
	defer s.rconn.Close()

	_, err = s.rconn.Write(s.rawInput.data)
	if err != nil {
		s.Log.Errorf("Write failed '%s'\n", err)
		return
	}

	s.wait.Add(2)

	go s.pipe(s.lconn, s.rconn, &s.toBytes)
	go s.pipe(s.rconn, s.lconn, &s.fromBytes)

	s.wait.Wait()

	s.Log.WithFields(log.Fields{
		"toBytes":   s.toBytes,
		"fromBytes": s.fromBytes,
	}).Infof("connection finished")

}

func (s *Session) pipe(to, from *net.TCPConn, bytesCopied *int64) {
	var err error
	defer s.wait.Done()
	*bytesCopied, err = io.Copy(to, from)
	if err != nil {
		s.Log.WithError(err).Error("pipe failed")
	}
}

func (s *Session) readHandshake() (interface{}, error) {
	for s.hand.Len() < 4 {
		if err := s.readRecord(recordTypeHandshake); err != nil {
			return nil, err
		}
	}

	data := s.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, fmt.Errorf("tls: oversized handshake with length %d", n)
	}

	data = s.hand.Next(4 + n)
	var m handshakeMessage
	switch data[0] {
	case typeClientHello:
		m = new(clientHelloMsg)
	default:
		return nil, fmt.Errorf("unexpected message type %d", data[0])
	}

	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, fmt.Errorf("unexpected message type %d", data[0])
	}

	//s.Log.Infof("msg unmarshalled: %+v", m)

	return m, nil
}

func (s *Session) readRecord(want recordType) error {

	var err error

	if s.rawInput == nil {
		s.rawInput = newBlock()
	}
	b := s.rawInput

	if err = b.readFromUntil(s.lconn, recordHeaderLen); err != nil {
		s.Log.WithError(err).Error("header peek failed")
		return err
	}

	typ := recordType(b.data[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if want == recordTypeHandshake && typ == 0x80 {
		return fmt.Errorf("tls: unsupported SSLv2 handshake received")
	}

	vers := uint16(b.data[1])<<8 | uint16(b.data[2])
	n := int(b.data[3])<<8 | int(b.data[4])

	if n > maxCiphertext {
		return fmt.Errorf("tls: oversized record received with length %d", n)
	}

	s.Log.WithFields(log.Fields{
		"typ":  typ,
		"vers": vers,
		"n":    n,
	}).Info("record")

	if err = b.readFromUntil(s.lconn, recordHeaderLen+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		s.Log.WithError(err).Error("record peek failed")
		return err
	}

	data := b.data[recordHeaderLen:]

	switch typ {
	default:
		return fmt.Errorf("tls: unexpected record type")
	case recordTypeHandshake:
		if typ != want {
			return fmt.Errorf("tls: wanted record type %d got %d", want, typ)
		}
		s.hand.Write(data)
	}

	return nil
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
