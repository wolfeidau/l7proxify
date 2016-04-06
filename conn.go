package l7proxify

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/apex/log"
)

// Conn used within l7proxify
type Conn struct {
	*net.TCPConn

	Log      log.Interface
	hand     bytes.Buffer // handshake data waiting to be read
	RawInput *block       // raw input, right off the wire
}

// NewConn new l7proxify connection
func NewConn(conn *net.TCPConn) *Conn {
	return &Conn{
		TCPConn: conn,
		Log:     log.WithField("conn", conn.RemoteAddr().String()),
	}
}

func (c *Conn) readHandshake() (interface{}, error) {
	for c.hand.Len() < 4 {
		if err := c.readRecord(recordTypeHandshake); err != nil {
			return nil, err
		}
	}

	data := c.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, fmt.Errorf("tls: oversized handshake with length %d", n)
	}

	data = c.hand.Next(4 + n)
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

func (c *Conn) readRecord(want recordType) error {

	var err error

	if c.RawInput == nil {
		c.RawInput = newBlock()
	}
	b := c.RawInput

	if err = b.readFromUntil(c, recordHeaderLen); err != nil {
		c.Log.WithError(err).Error("header peek failed")
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

	c.Log.WithFields(log.Fields{
		"typ":  typ,
		"vers": vers,
		"n":    n,
	}).Info("record")

	if err = b.readFromUntil(c, recordHeaderLen+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		c.Log.WithError(err).Error("record peek failed")
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
		c.hand.Write(data)
	}

	return nil
}
