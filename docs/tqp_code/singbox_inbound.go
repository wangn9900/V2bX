// Package tqp implements the TianQue Protocol for sing-box
// This is the server-side (inbound) implementation
//
// Copy this directory to: sing-box_mod/protocol/tqp/
package tqp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Protocol constants
	TQP_VERSION     = 0x01
	TQP_CMD_AUTH    = 0x01
	TQP_CMD_PING    = 0x02
	TQP_CMD_CLOSE   = 0xFF
	TQP_AUTH_OK     = 0x00
	TQP_AUTH_FAILED = 0x01

	// Address types (compatible with SOCKS5)
	ATYP_IPV4   = 0x01
	ATYP_DOMAIN = 0x03
	ATYP_IPV6   = 0x04

	// Timing
	AUTH_TIMEOUT    = 30 * time.Second
	TIME_TOLERANCE  = 120 // seconds, allow 2 minutes clock drift
)

var _ adapter.Inbound = (*Inbound)(nil)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TQPInboundOptions](registry, C.TypeTQP, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router      adapter.Router
	logger      log.ContextLogger
	listener    *tls.Listener
	tlsConfig   tls.ServerConfig
	users       map[string]*User // uuid -> user
	fallbackAddr M.Socksaddr     // fallback for failed auth
}

type User struct {
	UUID     string
	Password []byte // derived key for encryption
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TQPInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeTQP, tag),
		router:  router,
		logger:  logger,
		users:   make(map[string]*User),
	}

	// Parse users
	for _, u := range options.Users {
		key := deriveKey(u.UUID)
		inbound.users[u.UUID] = &User{
			UUID:     u.UUID,
			Password: key,
		}
	}

	// TLS config
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	// Fallback address for failed auth (masquerade)
	if options.Fallback != nil {
		inbound.fallbackAddr = M.ParseSocksaddr(options.Fallback.Server + ":" + options.Fallback.ServerPort)
	}

	return inbound, nil
}

func (i *Inbound) Start() error {
	// Start TLS listener
	// Implementation depends on sing-box listener infrastructure
	return nil
}

func (i *Inbound) Close() error {
	return common.Close(i.listener)
}

// Handle new connection
func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	// Set auth timeout
	conn.SetReadDeadline(time.Now().Add(AUTH_TIMEOUT))

	// Read auth frame (42 bytes)
	authFrame := make([]byte, 42)
	_, err := io.ReadFull(conn, authFrame)
	if err != nil {
		return i.handleFallback(conn)
	}

	// Parse auth frame
	version := authFrame[0]
	cmd := authFrame[1]
	timestamp := binary.BigEndian.Uint64(authFrame[2:10])
	authHash := authFrame[10:42]

	// Version check
	if version != TQP_VERSION {
		return i.handleFallback(conn)
	}

	// Command check
	if cmd != TQP_CMD_AUTH {
		return i.handleFallback(conn)
	}

	// Time check (prevent replay)
	now := uint64(time.Now().Unix())
	if abs(int64(now)-int64(timestamp)) > TIME_TOLERANCE {
		i.logger.Debug("TQP auth failed: timestamp out of range")
		return i.handleFallback(conn)
	}

	// Find user by trying all UUIDs
	var matchedUser *User
	for _, user := range i.users {
		expectedHash := computeAuthHash(user.UUID, timestamp, metadata.Destination.String())
		if hmac.Equal(authHash, expectedHash) {
			matchedUser = user
			break
		}
	}

	if matchedUser == nil {
		i.logger.Debug("TQP auth failed: no matching user")
		return i.handleFallback(conn)
	}

	// Auth success
	conn.SetReadDeadline(time.Time{}) // clear deadline
	conn.Write([]byte{TQP_AUTH_OK})

	// Read target address
	destination, err := i.readDestination(conn)
	if err != nil {
		return err
	}

	// Create cipher for this connection
	cipher, err := NewTQPCipher(matchedUser.Password)
	if err != nil {
		return err
	}

	// Wrap connection with encryption
	encryptedConn := &TQPConn{
		Conn:   conn,
		cipher: cipher,
	}

	// Update metadata
	metadata.Destination = destination
	metadata.User = matchedUser.UUID

	// Route to destination
	return i.router.RouteConnection(ctx, encryptedConn, metadata)
}

func (i *Inbound) readDestination(conn net.Conn) (M.Socksaddr, error) {
	// Read address type
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(conn, addrType); err != nil {
		return M.Socksaddr{}, err
	}

	var addr M.Socksaddr
	switch addrType[0] {
	case ATYP_IPV4:
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return M.Socksaddr{}, err
		}
		addr.Addr = M.AddrFromIP(net.IP(ipBytes))
	case ATYP_IPV6:
		ipBytes := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return M.Socksaddr{}, err
		}
		addr.Addr = M.AddrFromIP(net.IP(ipBytes))
	case ATYP_DOMAIN:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return M.Socksaddr{}, err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return M.Socksaddr{}, err
		}
		addr.Fqdn = string(domain)
	default:
		return M.Socksaddr{}, errors.New("unsupported address type")
	}

	// Read port
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return M.Socksaddr{}, err
	}
	addr.Port = binary.BigEndian.Uint16(portBytes)

	return addr, nil
}

// Fallback handler - return normal website content
func (i *Inbound) handleFallback(conn net.Conn) error {
	if i.fallbackAddr.IsValid() {
		// Connect to fallback server and relay
		fallbackConn, err := net.Dial("tcp", i.fallbackAddr.String())
		if err != nil {
			conn.Close()
			return err
		}
		go relay(conn, fallbackConn)
		return nil
	}

	// Default: return a simple HTTP response
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><body>Welcome</body></html>")
	conn.Write(response)
	conn.Close()
	return nil
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

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func relay(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	go io.Copy(a, b)
	io.Copy(b, a)
}

// TQPCipher handles encryption/decryption
type TQPCipher struct {
	sendNonce uint64
	recvNonce uint64
	key       []byte
}

func NewTQPCipher(key []byte) (*TQPCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	return &TQPCipher{key: key}, nil
}

// TQPConn wraps a connection with TQP encryption
type TQPConn struct {
	net.Conn
	cipher *TQPCipher
}

func (c *TQPConn) Read(b []byte) (int, error) {
	// Read length prefix (2 bytes)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lenBuf)

	// Read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, encrypted); err != nil {
		return 0, err
	}

	// Decrypt
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
	// Encrypt
	aead, _ := chacha20poly1305.New(c.cipher.key)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], c.cipher.sendNonce)
	c.cipher.sendNonce++

	encrypted := aead.Seal(nil, nonce, b, nil)

	// Write length prefix
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(encrypted)))
	if _, err := c.Conn.Write(lenBuf); err != nil {
		return 0, err
	}

	// Write encrypted data
	if _, err := c.Conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(b), nil
}
