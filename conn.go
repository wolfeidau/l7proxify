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

	Log log.Interface

	rawInput bytes.Buffer
}

// NewConn new l7proxify connection
func NewConn(conn *net.TCPConn) *Conn {
	return &Conn{
		TCPConn: conn,
		Log:     log.WithField("conn", conn.RemoteAddr().String()),
	}
}

func (c *Conn) peakHandshake() (interface{}, error) {
	for c.rawInput.Len() < 4 {
		if err := c.peakRecord(recordTypeHandshake); err != nil {
			return nil, err
		}
	}

	// build a slice minus the record header
	data := c.rawInput.Bytes()[recordHeaderLen:]

	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, fmt.Errorf("tls: oversized handshake with length %d", n)
	}

	var m handshakeMessage
	switch data[0] {
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeCertificate:
		m = new(certificateMsg)
	case typeFinished:
		m = new(finishedMsg)
	default:
		return nil, fmt.Errorf("unexpected message type %d", data[0])
	}

	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, fmt.Errorf("unexpected message type %d", data[0])
	}

	return m, nil
}

func (c *Conn) peakRecord(want recordType) error {

	var (
		err error
	)

	data := make([]byte, recordHeaderLen)

	if _, err = io.ReadAtLeast(c, data, recordHeaderLen); err != nil {
		c.Log.WithError(err).Error("header peek failed")
		return err
	}

	c.Log.WithField("data", fmt.Sprintf("%x", data)).Debug("header")

	typ := recordType(data[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if want == recordTypeHandshake && typ == 0x80 {
		return fmt.Errorf("tls: unsupported SSLv2 handshake received")
	}

	vers := uint16(data[1])<<8 | uint16(data[2])
	n := int(data[3])<<8 | int(data[4])

	if n > maxCiphertext {
		return fmt.Errorf("tls: oversized record received with length %d", n)
	}

	c.Log.WithFields(log.Fields{
		"typ":  typ,
		"vers": vers,
		"n":    n,
	}).Info("record")

	c.rawInput.Write(data)

	record := make([]byte, n)

	if _, err = io.ReadAtLeast(c, record, n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		c.Log.WithError(err).Error("record peek failed")
		return err
	}

	switch typ {
	default:
		return fmt.Errorf("tls: unexpected record type")
	case recordTypeHandshake:
		if typ != want {
			return fmt.Errorf("tls: wanted record type %d got %d", want, typ)
		}
		c.rawInput.Write(record)
	}

	return nil
}

// WritePeak write the current peak buffer to the supplied writer
// and reset the peack buffers.
func (c *Conn) WritePeak(w io.Writer) (int, error) {

	data := c.rawInput.Bytes()
	c.rawInput.Reset()

	c.Log.WithField("len", len(data)).Debug("write peak")

	return w.Write(data)
}
