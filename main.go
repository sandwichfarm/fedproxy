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

const (
	defaultTorHost   = "127.0.0.1"
	defaultI2PHost   = "127.0.0.1"
	defaultLokiHost  = "127.0.0.1"
	defaultTorPort   = "9050"
	defaultI2PPort   = "4447"
	defaultLokiPort  = "1194"
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
	logging.Debug("Starting data transfer between connections")
	n, err := io.Copy(dst, src)
	if err != nil {
		logging.Error("Error during data transfer: %v", err)
	}
	logging.Debug("Completed data transfer: %d bytes transferred", n)
}

func copyHeader(dst, src http.Header) {
	logging.Debug("Copying headers from source to destination")
	for k, vv := range src {
		for _, v := range vv {
			logging.Debug("Header: %s: %s", k, v)
			dst.Add(k, v)
		}
	}
	logging.Debug("Completed copying %d headers", len(src))
}

func (h *httpProxyHandler) dialOut(addr string) (net.Conn, error) {
	logging.Debug("Attempting to dial out to address: %s", addr)
	
	// Parse the address as a URL
	parsedURL, err := url.Parse("//" + addr) // Add // prefix to parse as authority
	if err != nil {
		logging.Error("Invalid address format %s: %v", addr, err)
		return nil, fmt.Errorf("invalid address format %s: %v", addr, err)
	}
	logging.Debug("Successfully parsed address: %s", addr)

	// Get host and port
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "80" // Default to port 80 if not specified
		logging.Debug("No port specified, using default port 80")
	}
	
	logging.Debug("Dialing out to %s:%s", host, port)
	
	// Check if it's a clearnet URL and passthrough is set to clearnet
	if h.passthrough == "clearnet" && !strings.HasSuffix(host, ".onion") && !strings.HasSuffix(host, ".i2p") && !strings.HasSuffix(host, ".loki") {
		logging.Info("Using clearnet for: %s", host)
		logging.Debug("Dialing direct TCP connection to %s:%s", host, port)
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			logging.Error("Failed to establish clearnet connection to %s:%s: %v", host, port, err)
		} else {
			logging.Debug("Successfully established clearnet connection to %s:%s", host, port)
		}
		return conn, err
	}
	
	if strings.HasSuffix(host, ".loki") {
		logging.Info("Using lokinet for: %s", host)
		if h.loki == nil {
			logging.Error("Lokinet proxy not configured")
			return nil, fmt.Errorf("lokinet proxy not configured")
		}
		logging.Debug("Dialing through Lokinet proxy to %s:%s", host, port)
		conn, err := h.loki.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			logging.Error("Failed to establish Lokinet connection to %s:%s: %v", host, port, err)
		} else {
			logging.Debug("Successfully established Lokinet connection to %s:%s", host, port)
		}
		return conn, err
	}
	if strings.HasSuffix(host, ".i2p") {
		logging.Info("Using i2p for: %s", host)
		if h.i2p == nil {
			logging.Error("I2P proxy not configured")
			return nil, fmt.Errorf("i2p proxy not configured")
		}
		logging.Debug("Dialing through I2P proxy to %s:%s", host, port)
		conn, err := h.i2p.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			logging.Error("Failed to establish I2P connection to %s:%s: %v", host, port, err)
		} else {
			logging.Debug("Successfully established I2P connection to %s:%s", host, port)
		}
		return conn, err
	}
	
	logging.Info("Using tor for: %s", host)
	if h.onion == nil {
		logging.Error("Tor proxy not configured")
		return nil, fmt.Errorf("tor proxy not configured")
	}
	logging.Debug("Attempting to dial onion address %s via Tor SOCKS proxy", addr)
	
	// Extra verbose logging for onion addresses
	if strings.HasSuffix(host, ".onion") {
		logging.Notice("Connecting to .onion site: %s", host)
	}
	
	conn, err := h.onion.Dial("tcp", addr)
	if err != nil {
		logging.Error("Failed to connect to onion site %s: %v", addr, err)
		return nil, err
	}
	
	if strings.HasSuffix(host, ".onion") {
		logging.Notice("Successfully established connection to .onion site: %s", host)
		logging.Info("Connection established to %s - local: %s, remote: %s", 
			host, conn.LocalAddr().String(), conn.RemoteAddr().String())
	} else {
		logging.Notice("Successfully connected via Tor: %s", host)
	}
	return conn, nil
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logging.Debug("Received request: %s %s %s", r.Method, r.Host, r.URL.String())
	logging.Debug("User-Agent: %s", r.UserAgent())
	
	if r.Method == http.MethodConnect {
		logging.Debug("Handling CONNECT request for %s", r.Host)
		outConn, err := h.dialOut(r.Host)
		if err != nil {
			logging.Error("Failed to dial out to %s: %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		logging.Debug("Successfully established connection to %s", r.Host)
		
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			outConn.Close()
			logging.Error("Hijacking not supported by the response writer")
			http.Error(w, "hijack disallowed", http.StatusInternalServerError)
			return
		}
		logging.Debug("Response writer supports hijacking, proceeding")
		
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(http.StatusOK)
		logging.Debug("Sent 200 OK response to client")
		
		conn, _, err := hijacker.Hijack()
		if err != nil {
			outConn.Close()
			logging.Error("Failed to hijack connection: %v", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		logging.Info("Successfully hijacked connection for %s", r.Host)
		
		logging.Debug("Starting bidirectional data transfer for %s", r.Host)
		go transfer(conn, outConn)
		go transfer(outConn, conn)
	} else {
		logging.Debug("Handling direct proxy request for %s %s", r.Method, r.URL)
		
		// Log request details
		logging.Debug("Request headers:")
		for name, values := range r.Header {
			for _, value := range values {
				logging.Debug("  %s: %s", name, value)
			}
		}
		
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			logging.Error("Failed to proxy request to %s: %v", r.URL, err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		
		logging.Debug("Received response from %s with status: %d %s", 
			r.URL, resp.StatusCode, resp.Status)
		
		// Log response details
		logging.Debug("Response headers:")
		for name, values := range resp.Header {
			for _, value := range values {
				logging.Debug("  %s: %s", name, value)
			}
		}
		
		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		logging.Debug("Wrote response headers to client")
		
		n, err := io.Copy(w, resp.Body)
		if err != nil {
			logging.Error("Error copying response body: %v", err)
		}
		logging.Debug("Copied %d bytes of response body to client", n)
	}
}

func main() {
	// First, set a default log level of ERROR
	logging.SetLevel(logging.ERROR)

	// Optional proxy flags
	onionSocks := flag.String("tor", "", "Tor SOCKS proxy address (e.g., 127.0.0.1:9050)")
	i2pSocks := flag.String("i2p", "", "I2P SOCKS proxy address (e.g., 127.0.0.1:4447)")
	lokiSocks := flag.String("loki", "", "Lokinet SOCKS proxy address (e.g., 127.0.0.1:1194)")
	
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

	// We need to manually check if flags like -tor were provided without values
	// This has to be done before flag.Parse()
	torFlagProvided := false
	i2pFlagProvided := false
	lokiFlagProvided := false
	
	// Pre-process logLevel and verbose flags before any other processing
	preProcessLogLevel := "ERROR" // Default
	preProcessVerbose := false
	
	for i, arg := range os.Args {
		// Check for flags like -tor or --tor when they're the last arg or followed by another flag
		// or if it has a value (not starting with -)
		if arg == "-tor" || arg == "--tor" {
			torFlagProvided = true
		}
		if arg == "-i2p" || arg == "--i2p" {
			i2pFlagProvided = true
		}
		if arg == "-loki" || arg == "--loki" {
			lokiFlagProvided = true
		}
		
		// Pre-parse log level settings
		if arg == "-logLevel" && i+1 < len(os.Args) {
			preProcessLogLevel = os.Args[i+1]
		} else if strings.HasPrefix(arg, "-logLevel=") {
			preProcessLogLevel = strings.TrimPrefix(arg, "-logLevel=")
		}
		
		if arg == "-v" || arg == "--v" {
			preProcessVerbose = true
		}
	}
	
	// Apply pre-processed log level settings
	if preProcessVerbose {
		logging.SetLevel(logging.DEBUG)
	}
	
	if err := logging.SetLevelFromString(preProcessLogLevel); err != nil {
		logging.Error("Invalid log level: %v", err)
	}

	// Now we can safely log anything and it will respect the log level
	logging.Debug("Original command line args: %v", os.Args)
	
	// Initialize proxy dialers
	var onionsock, i2psock, lokisock proxy.Dialer
	var err error

	// Parse flags 
	flag.Parse()
	logging.Debug("Parsed flags - onionSocks: '%s', i2pSocks: '%s', lokiSocks: '%s'", *onionSocks, *i2pSocks, *lokiSocks)
	
	// Apply the official settings from parsed flags (which could override pre-processed values)
	if *verbose {
		logging.SetLevel(logging.DEBUG)
		logging.Debug("Verbose flag enabled")
	}
	
	if err := logging.SetLevelFromString(*logLevel); err != nil {
		logging.Error("Invalid log level: %v", err)
		os.Exit(1)
	}
	logging.Debug("Final log level: %s", *logLevel)

	// Get positional arguments
	args := flag.Args()
	if len(args) < 2 {
		logging.Error("Missing required arguments: proto and bind")
		flag.Usage()
		os.Exit(1)
	}

	proto := args[0]
	bindAddr := args[1]

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

	// Helper function to get proxy address with defaults if needed
	getProxyAddr := func(addr string, flagProvided bool, defaultHost string, defaultPort string) string {
		logging.Debug("getProxyAddr input: '%s', flagProvided: %v", addr, flagProvided)
		
		// If the flag wasn't provided at all, return empty
		if !flagProvided {
			return ""
		}
		
		// If a valid addr is provided, use it
		if addr != "" {
			// If no port specified, add the default port
			if !strings.Contains(addr, ":") {
				logging.Debug("No port specified, using default port: %s", defaultPort)
				return fmt.Sprintf("%s:%s", addr, defaultPort)
			}
			return addr
		}
		
		// Flag was provided without value, use default
		logging.Debug("Flag provided without value, using default: %s:%s", defaultHost, defaultPort)
		return fmt.Sprintf("%s:%s", defaultHost, defaultPort)
	}

	// Set up proxy addresses with defaults if needed
	torAddr := getProxyAddr(*onionSocks, torFlagProvided, defaultTorHost, defaultTorPort)
	i2pAddr := getProxyAddr(*i2pSocks, i2pFlagProvided, defaultI2PHost, defaultI2PPort)
	lokiAddr := getProxyAddr(*lokiSocks, lokiFlagProvided, defaultLokiHost, defaultLokiPort)

	logging.Debug("Raw flag values - tor: '%s', i2p: '%s', loki: '%s'", *onionSocks, *i2pSocks, *lokiSocks)
	logging.Debug("Flag provided - tor: %v, i2p: %v, loki: %v", torFlagProvided, i2pFlagProvided, lokiFlagProvided)
	logging.Debug("Final addresses - Tor: '%s', I2P: '%s', Lokinet: '%s'", torAddr, i2pAddr, lokiAddr)

	// Validate that at least one proxy is configured
	if torAddr == "" && i2pAddr == "" && lokiAddr == "" {
		logging.Error("At least one proxy must be configured (-tor, -i2p, or -loki)")
		flag.Usage()
		os.Exit(1)
	}

	if torAddr != "" {
		logging.Info("Initializing Tor proxy at %s", torAddr)
		onionsock, err = proxy.SOCKS5("tcp", torAddr, nil, nil)
		if err != nil {
			logging.Error("Failed to create Tor proxy to %s: %s", torAddr, err.Error())
			os.Exit(1)
		}
	}

	if i2pAddr != "" {
		logging.Info("Initializing I2P proxy at %s", i2pAddr)
		i2psock, err = proxy.SOCKS5("tcp", i2pAddr, nil, nil)
		if err != nil {
			logging.Error("Failed to create I2P proxy to %s: %s", i2pAddr, err.Error())
			os.Exit(1)
		}
	}

	if lokiAddr != "" {
		logging.Info("Initializing Lokinet proxy at %s", lokiAddr)
		lokisock, err = proxy.SOCKS5("tcp", lokiAddr, nil, nil)
		if err != nil {
			logging.Error("Failed to create Lokinet proxy to %s: %s", lokiAddr, err.Error())
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
		
		// Add extra debug logging to track proxy creation
		logging.Debug("Creating SOCKS5 server with custom logger")
		logging.Debug("Current log level is set to DEBUG")
		
		var serv *socks5.Server
		serv, err = socks5.New(&socks5.Config{
			Logger: socks5.CreateLogger(),
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
				logging.Debug("Attempting to dial onion address %s via Tor SOCKS proxy", addr)
				
				// Extra verbose logging for onion addresses
				if strings.HasSuffix(host, ".onion") {
					logging.Notice("Connecting to .onion site: %s", host)
				}
				
				conn, err := onionsock.Dial("tcp", addr)
				if err != nil {
					logging.Error("Failed to connect to onion site %s: %v", addr, err)
					return nil, err
				}
				
				if strings.HasSuffix(host, ".onion") {
					logging.Notice("Successfully established connection to .onion site: %s", host)
					logging.Info("Connection established to %s - local: %s, remote: %s", 
						host, conn.LocalAddr().String(), conn.RemoteAddr().String())
				} else {
					logging.Notice("Successfully connected via Tor: %s", host)
				}
				
				return conn, nil
			},
		})

		if err != nil {
			logging.Error("Failed to create SOCKS proxy: %s", err.Error())
			os.Exit(1)
		}

		var l net.Listener
		l, err = net.Listen("tcp", bindAddr)
		if err != nil {
			logging.Error("Failed to listen on %s: %s", bindAddr, err.Error())
			os.Exit(1)
		}
		
		logging.Notice("SOCKS5 server listening on %s", bindAddr)
		logging.Debug("Starting to serve SOCKS connections...")
		
		// Make sure we see if there are any errors when serving
		err = serv.Serve(l)
		if err != nil {
			logging.Error("SOCKS5 server error: %v", err)
			os.Exit(1)
		}
	}
}
