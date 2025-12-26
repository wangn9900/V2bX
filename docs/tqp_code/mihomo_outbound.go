// Package outbound - TQP outbound for mihomo
//
// Copy this to: mihomo/adapter/outbound/tqp.go
package outbound

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	TQP_VERSION  = 0x01
	TQP_CMD_AUTH = 0x01
	TQP_AUTH_OK  = 0x00

	ATYP_IPV4   = 0x01
	ATYP_DOMAIN = 0x03
	ATYP_IPV6   = 0x04
)

type TQP struct {
	*Base
	uuid        string
	serverName  string
	skipVerify  bool
	fingerprint string
}

type TQPOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	UUID           string `proxy:"uuid"`
	TLS            bool   `proxy:"tls,omitempty"`
	ServerName     string `proxy:"servername,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string `proxy:"client-fingerprint,omitempty"`
}

func NewTQP(option TQPOption) (*TQP, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	return &TQP{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.TQP,
			udp:    false, // TQP does not support UDP
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		uuid:        option.UUID,
		serverName:  option.ServerName,
		skipVerify:  option.SkipCertVerify,
		fingerprint: option.Fingerprint,
	}, nil
}

func (t *TQP) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	// 1. Dial TCP connection
	c, err := dialer.DialContext(ctx, "tcp", t.addr, t.Base.DialOptions(nil)...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	// 2. TLS handshake
	tlsConfig := &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
		MinVersion:         tls.VersionTLS13,
	}
	if t.serverName == "" {
		host, _, _ := net.SplitHostPort(t.addr)
		tlsConfig.ServerName = host
	}

	tlsConn := tls.Client(c, tlsConfig)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	// 3. TQP Authentication
	if err = t.authenticate(tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// 4. Send destination address
	if err = t.writeDestination(tlsConn, metadata); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// 5. Create encrypted connection
	key := deriveKey(t.uuid)
	cipher, _ := NewTQPCipher(key)
	encConn := &TQPConn{
		Conn:   tlsConn,
		cipher: cipher,
	}

	return NewConn(encConn, t), nil
}

func (t *TQP) authenticate(conn net.Conn) error {
	timestamp := uint64(time.Now().Unix())
	authHash := computeAuthHash(t.uuid, timestamp, t.addr)

	// Build auth frame (42 bytes)
	authFrame := make([]byte, 42)
	authFrame[0] = TQP_VERSION
	authFrame[1] = TQP_CMD_AUTH
	binary.BigEndian.PutUint64(authFrame[2:10], timestamp)
	copy(authFrame[10:42], authHash)

	// Send auth frame
	if _, err := conn.Write(authFrame); err != nil {
		return err
	}

	// Read auth response (1 byte)
	response := make([]byte, 1)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	if response[0] != TQP_AUTH_OK {
		return errors.New("TQP authentication failed")
	}

	return nil
}

func (t *TQP) writeDestination(conn net.Conn, metadata *C.Metadata) error {
	var buf []byte

	if metadata.Host != "" {
		// Domain
		hostBytes := []byte(metadata.Host)
		buf = make([]byte, 1+1+len(hostBytes)+2)
		buf[0] = ATYP_DOMAIN
		buf[1] = byte(len(hostBytes))
		copy(buf[2:], hostBytes)
		binary.BigEndian.PutUint16(buf[2+len(hostBytes):], metadata.DstPort)
	} else if metadata.DstIP.To4() != nil {
		// IPv4
		buf = make([]byte, 1+4+2)
		buf[0] = ATYP_IPV4
		copy(buf[1:5], metadata.DstIP.To4())
		binary.BigEndian.PutUint16(buf[5:], metadata.DstPort)
	} else {
		// IPv6
		buf = make([]byte, 1+16+2)
		buf[0] = ATYP_IPV6
		copy(buf[1:17], metadata.DstIP.To16())
		binary.BigEndian.PutUint16(buf[17:], metadata.DstPort)
	}

	_, err := conn.Write(buf)
	return err
}

// SupportUDP returns false as TQP doesn't support UDP
func (t *TQP) SupportUDP() bool {
	return false
}

// Helper functions
func deriveKey(uuid string) []byte {
	h := sha256.New()
	h.Write([]byte(uuid))
	h.Write([]byte("TQP-KEY-DERIVE-V1"))
	return h.Sum(nil)
}

func computeAuthHash(uuid string, timestamp uint64, serverAddr string) []byte {
	h := hmac.New(sha256.New, []byte(uuid))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, timestamp)
	h.Write(ts)
	h.Write([]byte(serverAddr))
	return h.Sum(nil)
}

// TQPCipher for encryption
type TQPCipher struct {
	sendNonce uint64
	recvNonce uint64
	key       []byte
}

func NewTQPCipher(key []byte) (*TQPCipher, error) {
	return &TQPCipher{key: key}, nil
}

// TQPConn wraps connection with encryption
type TQPConn struct {
	net.Conn
	cipher *TQPCipher
}

func (c *TQPConn) Read(b []byte) (int, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lenBuf)

	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, encrypted); err != nil {
		return 0, err
	}

	aead, _ := chacha20poly1305.New(c.cipher.key)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], c.cipher.recvNonce)
	c.cipher.recvNonce++

	decrypted, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return 0, err
	}

	copy(b, decrypted)
	return len(decrypted), nil
}

func (c *TQPConn) Write(b []byte) (int, error) {
	aead, _ := chacha20poly1305.New(c.cipher.key)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], c.cipher.sendNonce)
	c.cipher.sendNonce++

	encrypted := aead.Seal(nil, nonce, b, nil)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(encrypted)))
	if _, err := c.Conn.Write(lenBuf); err != nil {
		return 0, err
	}

	if _, err := c.Conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(b), nil
}
