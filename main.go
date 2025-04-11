package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/sandwichfarm/hedproxy/internal/logging"
	"github.com/sandwichfarm/hedproxy/internal/socks5"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type httpProxyHandler struct {
	onion      proxy.Dialer
	i2p        proxy.Dialer
	loki       proxy.Dialer
	passthrough string
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (h *httpProxyHandler) dialOut(addr string) (net.Conn, error) {
	// Parse the address as a URL
	parsedURL, err := url.Parse("//" + addr) // Add // prefix to parse as authority
	if err != nil {
		logging.Error("Invalid address format %s: %v", addr, err)
		return nil, fmt.Errorf("invalid address format %s: %v", addr, err)
	}

	// Get host and port
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "80" // Default to port 80 if not specified
	}
	
	logging.Debug("Dialing out to %s:%s", host, port)
	
	// Check if it's a clearnet URL and passthrough is set to clearnet
	if h.passthrough == "clearnet" && !strings.HasSuffix(host, ".onion") && !strings.HasSuffix(host, ".i2p") && !strings.HasSuffix(host, ".loki") {
		logging.Info("Using clearnet for: %s", host)
		return net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	}
	
	if strings.HasSuffix(host, ".loki") {
		logging.Info("Using lokinet for: %s", host)
		if h.loki == nil {
			logging.Error("Lokinet proxy not configured")
			return nil, fmt.Errorf("lokinet proxy not configured")
		}
		return h.loki.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	}
	if strings.HasSuffix(host, ".i2p") {
		logging.Info("Using i2p for: %s", host)
		if h.i2p == nil {
			logging.Error("I2P proxy not configured")
			return nil, fmt.Errorf("i2p proxy not configured")
		}
		return h.i2p.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	}
	logging.Info("Using tor for: %s", host)
	if h.onion == nil {
		logging.Error("Tor proxy not configured")
		return nil, fmt.Errorf("tor proxy not configured")
	}
	return h.onion.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logging.Debug("Received request: %s %s", r.Method, r.Host)
	
	if r.Method == http.MethodConnect {
		outConn, err := h.dialOut(r.Host)
		if err != nil {
			logging.Error("Failed to dial out: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			outConn.Close()
			logging.Error("Hijack not supported")
			http.Error(w, "hijack disallowed", http.StatusInternalServerError)
			return
		}
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(http.StatusOK)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			outConn.Close()
			logging.Error("Failed to hijack connection: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		logging.Debug("Starting connection transfer")
		go transfer(conn, outConn)
		go transfer(outConn, conn)
	} else {
		logging.Debug("Proxying request: %s %s", r.Method, r.URL)
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			logging.Error("Failed to proxy request: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func main() {
	// Optional proxy flags
	onionSocks := flag.String("tor", "", "Tor SOCKS proxy address (e.g., 127.0.0.1:9050)")
	i2pSocks := flag.String("i2p", "", "I2P SOCKS proxy address (e.g., 127.0.0.1:4447)")
	lokiSocks := flag.String("loki", "", "Lokinet SOCKS proxy address (e.g., 127.0.0.1:9050)")
	
	// Logging flags
	verbose := flag.Bool("v", false, "Enable verbose logging (DEBUG level)")
	logLevel := flag.String("logLevel", "ERROR", "Set log level (SILENT, ERROR, WARNING, NOTICE, INFO, DEBUG)")
	
	// Other flags
	passthrough := flag.String("passthrough", "", "Set passthrough mode (e.g., 'clearnet' for direct clearnet access)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <proto> <bind> [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  proto: Protocol to use (http or socks)\n")
		fmt.Fprintf(os.Stderr, "  bind: Address to bind to (e.g., 127.0.0.1:2000)\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Get positional arguments
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	proto := args[0]
	bindAddr := args[1]

	// Set log level
	if *verbose {
		logging.SetLevel(logging.DEBUG)
	}
	if err := logging.SetLevelFromString(*logLevel); err != nil {
		logging.Error("Invalid log level: %v", err)
		os.Exit(1)
	}

	// Validate required arguments
	if proto != "http" && proto != "socks" {
		logging.Error("Protocol must be either 'http' or 'socks'")
		flag.Usage()
		os.Exit(1)
	}
	if bindAddr == "" {
		logging.Error("Bind address is required")
		flag.Usage()
		os.Exit(1)
	}

	// Validate that at least one proxy is configured
	if *onionSocks == "" && *i2pSocks == "" && *lokiSocks == "" {
		logging.Error("At least one proxy must be configured (-tor, -i2p, or -loki)")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize proxy dialers
	var onionsock, i2psock, lokisock proxy.Dialer
	var err error

	if *onionSocks != "" {
		logging.Info("Initializing Tor proxy at %s", *onionSocks)
		onionsock, err = proxy.SOCKS5("tcp", *onionSocks, nil, nil)
		if err != nil {
			logging.Error("Failed to create Tor proxy to %s: %s", *onionSocks, err.Error())
			os.Exit(1)
		}
	}

	if *i2pSocks != "" {
		logging.Info("Initializing I2P proxy at %s", *i2pSocks)
		i2psock, err = proxy.SOCKS5("tcp", *i2pSocks, nil, nil)
		if err != nil {
			logging.Error("Failed to create I2P proxy to %s: %s", *i2pSocks, err.Error())
			os.Exit(1)
		}
	}

	if *lokiSocks != "" {
		logging.Info("Initializing Lokinet proxy at %s", *lokiSocks)
		lokisock, err = proxy.SOCKS5("tcp", *lokiSocks, nil, nil)
		if err != nil {
			logging.Error("Failed to create Lokinet proxy to %s: %s", *lokiSocks, err.Error())
			os.Exit(1)
		}
	}

	usehttp := proto == "http"
	if usehttp {
		logging.Notice("Starting HTTP proxy on %s", bindAddr)
		serv := &http.Server{
			Addr: bindAddr,
			Handler: &httpProxyHandler{
				onion:      onionsock,
				i2p:        i2psock,
				loki:       lokisock,
				passthrough: *passthrough,
			},
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		err = serv.ListenAndServe()
		if err != nil {
			logging.Error("HTTP proxy error: %s", err.Error())
		}
	} else {
		logging.Notice("Starting SOCKS proxy on %s", bindAddr)
		serv, err := socks5.New(&socks5.Config{
			Dial: func(addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				host = strings.TrimSuffix(host, ".")
				logging.Debug("SOCKS request for: %s", host)
				if err != nil {
					return nil, err
				}
				
				// Check if it's a clearnet URL and passthrough is set to clearnet
				if *passthrough == "clearnet" && !strings.HasSuffix(host, ".onion") && !strings.HasSuffix(host, ".i2p") && !strings.HasSuffix(host, ".loki") {
					logging.Info("Using clearnet for: %s", host)
					return net.Dial("tcp", addr)
				}
				
				if strings.HasSuffix(host, ".loki") {
					logging.Info("Using lokinet for: %s", host)
					if lokisock == nil {
						logging.Error("Lokinet proxy not configured")
						return nil, fmt.Errorf("lokinet proxy not configured")
					}
					return lokisock.Dial("tcp", addr)
				}
				if strings.HasSuffix(host, ".i2p") {
					logging.Info("Using i2p for: %s", host)
					if i2psock == nil {
						logging.Error("I2P proxy not configured")
						return nil, fmt.Errorf("i2p proxy not configured")
					}
					return i2psock.Dial("tcp", addr)
				}
				logging.Info("Using tor for: %s", host)
				if onionsock == nil {
					logging.Error("Tor proxy not configured")
					return nil, fmt.Errorf("tor proxy not configured")
				}
				return onionsock.Dial("tcp", addr)
			},
		})

		if err != nil {
			logging.Error("Failed to create SOCKS proxy: %s", err.Error())
			os.Exit(1)
		}

		l, err := net.Listen("tcp", bindAddr)
		if err != nil {
			logging.Error("Failed to listen on %s: %s", bindAddr, err.Error())
			os.Exit(1)
		}
		serv.Serve(l)
	}
}
