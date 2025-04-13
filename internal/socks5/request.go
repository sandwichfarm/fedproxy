package socks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/context"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)


// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr AddrSpec
	bufConn      io.Reader
}

func (req *Request) ConnectAddress() string {
	return req.DestAddr.Address()
}

type socksConn interface {
	io.WriteCloser
	RemoteAddr() net.Addr
}

// readRequest creates a new Request from the tcp connection
func readRequest(bufConn io.Reader, req *Request)  error {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		return fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	err := readAddrSpec(bufConn, &req.DestAddr)
	if err != nil {
		return err
	}
	req.Version = socks5Version
	req.Command = header[1]
	req.bufConn = bufConn
	return nil
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(req *Request, conn socksConn) error {
	ctx := context.Background()

	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(ctx, conn, req)
	case BindCommand:
		return s.handleBind(ctx, conn, req)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(ctx context.Context, conn socksConn, req *Request) error {
	// Check if this is allowed
	s.config.Logger.Printf("Processing connect request to %s", req.DestAddr.String())
	
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		s.config.Logger.Printf("Connect to %v blocked by rules", req.DestAddr)
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			s.config.Logger.Printf("Failed to send rule failure reply: %v", err)
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}
	
	s.config.Logger.Printf("Connect to %v allowed by rules", req.DestAddr)

	// Attempt to connect
	dial := s.config.Dial
	if dial == nil {
		s.config.Logger.Printf("Using default dialer for %v", req.DestAddr)
		dial = func(addr string) (net.Conn, error) {
			return net.Dial("tcp", addr)
		}
	} else {
		s.config.Logger.Printf("Using custom dialer for %v", req.DestAddr)
	}
	
	s.config.Logger.Printf("Dialing connection to %v", req.ConnectAddress())
	target, err := dial(req.ConnectAddress())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
			s.config.Logger.Printf("Connection refused to %v: %v", req.DestAddr, err)
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
			s.config.Logger.Printf("Network unreachable for %v: %v", req.DestAddr, err)
		} else {
			s.config.Logger.Printf("Host unreachable for %v: %v", req.DestAddr, err)
		}
		if err := sendReply(conn, resp, nil); err != nil {
			s.config.Logger.Printf("Failed to send connection failure reply: %v", err)
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()
	
	s.config.Logger.Printf("Successfully established connection to %v", req.DestAddr)

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	s.config.Logger.Printf("Sending success reply to client with bound address: %v", bind.String())
	if err := sendReply(conn, successReply, &bind); err != nil {
		s.config.Logger.Printf("Failed to send success reply: %v", err)
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	s.config.Logger.Printf("Starting bidirectional proxy between client and target: %v", req.DestAddr)
	errCh := make(chan error, 2)
	go s.proxy(target, req.bufConn, errCh)
	go s.proxy(conn, target, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			s.config.Logger.Printf("Proxy error: %v", e)
			// return from this function closes target (and conn).
			return e
		}
	}
	s.config.Logger.Printf("Completed proxying for %v", req.DestAddr)
	return nil
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(ctx context.Context, conn socksConn, req *Request) error {
	// Check if this is allowed
	if ctx_, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Bind to %v blocked by rules", req.DestAddr)
	} else {
		ctx = ctx_
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader, d *AddrSpec) error {

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return err
		}
		d.FQDN = string(fqdn)

	default:
		return unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}


// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func (s *Server) proxy(dst socksConn, src io.Reader, errCh chan error) {
	var buf [1024 * 4]byte
	dstName := "target"
	if conn, ok := dst.(net.Conn); ok {
		dstName = conn.RemoteAddr().String()
	}
	srcName := "client"
	if srcConn, ok := src.(net.Conn); ok {
		srcName = srcConn.RemoteAddr().String()
	}
	
	s.config.Logger.Printf("Starting to proxy data from %s to %s", srcName, dstName)
	
	// Check if this involves an onion site
	isOnion := false
	if dstAddr, ok := dst.(net.Addr); ok {
		dstStr := dstAddr.String()
		if strings.Contains(dstStr, ".onion") {
			isOnion = true
			s.config.Logger.Printf("Proxying data to onion site: %s", dstStr)
		}
	}
	
	// Track progress during copy operation by copying in smaller chunks
	var total int64
	var err error
	loggingThreshold := int64(64 * 1024) // Default: log every 64KB
	if isOnion {
		loggingThreshold = 4 * 1024 // For onion sites: log every 4KB
	}
	
	for {
		// Use smaller buffer for more frequent updates
		nr, er := src.Read(buf[:4096])
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write result")
				}
			}
			total += int64(nw)
			
			// Log progress periodically
			if total % loggingThreshold == 0 { // Log based on threshold
				s.config.Logger.Printf("Transferred %d bytes from %s to %s", total, srcName, dstName)
			}
			
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = fmt.Errorf("short write")
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	
	dst.Close()
	if err != nil && err != io.EOF {
		s.config.Logger.Printf("Error copying data from %s to %s: %v", srcName, dstName, err)
	} else {
		s.config.Logger.Printf("Completed copying %d bytes from %s to %s", total, srcName, dstName)
	}
	errCh <- err
}
