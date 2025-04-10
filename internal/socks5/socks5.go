package socks5

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	socks5Version = uint8(5)
)

type Config struct {
	AuthMethods []Authenticator

	Credentials CredentialStore

	Rules RuleSet

	BindIP net.IP

	Logger *log.Logger

	Dial func(addr string) (net.Conn, error)
}

type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

func New(conf *Config) (*Server, error) {
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
	return nil
}

func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}
	var req Request
	err = readRequest(bufConn, &req)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	req.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		req.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	if err := s.handleRequest(&req, conn); err != nil {
		if netErr, ok := err.(*net.OpError); ok && netErr.Err.Error() == "use of closed network connection" {
			return nil
		}
		if err == io.EOF {
			return nil
		}
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}
