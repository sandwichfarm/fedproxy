package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/sandwichfarm/hedproxy/internal/socks5"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

type httpProxyHandler struct {
	onion      proxy.Dialer
	i2p        proxy.Dialer
	loki       proxy.Dialer
	verbose    bool
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
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	
	// Check if it's a clearnet URL and passthrough is set to clearnet
	if h.passthrough == "clearnet" && !strings.HasSuffix(host, ".onion") && !strings.HasSuffix(host, ".i2p") && !strings.HasSuffix(host, ".loki") {
		if h.verbose {
			fmt.Printf("Using clearnet for: %s\n", host)
		}
		return net.Dial("tcp", addr)
	}
	
	if strings.HasSuffix(host, ".loki") {
		if h.verbose {
			fmt.Printf("Using lokinet for: %s\n", host)
		}
		if h.loki == nil {
			return nil, fmt.Errorf("lokinet proxy not configured")
		}
		return h.loki.Dial("tcp", addr)
	}
	if strings.HasSuffix(host, ".i2p") {
		if h.verbose {
			fmt.Printf("Using i2p for: %s\n", host)
		}
		if h.i2p == nil {
			return nil, fmt.Errorf("i2p proxy not configured")
		}
		return h.i2p.Dial("tcp", addr)
	}
	if h.verbose {
		fmt.Printf("Using tor for: %s\n", host)
	}
	if h.onion == nil {
		return nil, fmt.Errorf("tor proxy not configured")
	}
	return h.onion.Dial("tcp", addr)
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.verbose {
		fmt.Printf("Received request: %s %s\n", r.Method, r.Host)
	}
	
	if r.Method == http.MethodConnect {
		outConn, err := h.dialOut(r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			outConn.Close()
			http.Error(w, "hijack disallowed", http.StatusInternalServerError)
			return
		}
		w.Header().Del("Transfer-Encoding")
		w.WriteHeader(http.StatusOK)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			outConn.Close()
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		go transfer(conn, outConn)
		go transfer(outConn, conn)
	} else {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
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
	// Required flags
	proto := flag.String("proto", "", "Protocol to use (http or socks)")
	bindAddr := flag.String("bind", "", "Address to bind to (e.g., 127.0.0.1:2000)")
	
	// Optional proxy flags
	onionSocks := flag.String("tor", "", "Tor SOCKS proxy address (e.g., 127.0.0.1:9050)")
	i2pSocks := flag.String("i2p", "", "I2P SOCKS proxy address (e.g., 127.0.0.1:4447)")
	lokiSocks := flag.String("loki", "", "Lokinet SOCKS proxy address (e.g., 127.0.0.1:9050)")
	
	// Other flags
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	passthrough := flag.String("passthrough", "", "Set passthrough mode (e.g., 'clearnet' for direct clearnet access)")

	flag.Parse()

	// Validate required flags
	if *proto == "" {
		fmt.Println("Error: -proto flag is required (http or socks)")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *proto != "http" && *proto != "socks" {
		fmt.Println("Error: -proto must be either 'http' or 'socks'")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *bindAddr == "" {
		fmt.Println("Error: -bind flag is required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate that at least one proxy is configured
	if *onionSocks == "" && *i2pSocks == "" && *lokiSocks == "" {
		fmt.Println("Error: At least one proxy must be configured (-tor, -i2p, or -loki)")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Initialize proxy dialers
	var onionsock, i2psock, lokisock proxy.Dialer
	var err error

	if *onionSocks != "" {
		onionsock, err = proxy.SOCKS5("tcp", *onionSocks, nil, nil)
		if err != nil {
			fmt.Printf("Failed to create Tor proxy to %s: %s\n", *onionSocks, err.Error())
			os.Exit(1)
		}
	}

	if *i2pSocks != "" {
		i2psock, err = proxy.SOCKS5("tcp", *i2pSocks, nil, nil)
		if err != nil {
			fmt.Printf("Failed to create I2P proxy to %s: %s\n", *i2pSocks, err.Error())
			os.Exit(1)
		}
	}

	if *lokiSocks != "" {
		lokisock, err = proxy.SOCKS5("tcp", *lokiSocks, nil, nil)
		if err != nil {
			fmt.Printf("Failed to create Lokinet proxy to %s: %s\n", *lokiSocks, err.Error())
			os.Exit(1)
		}
	}

	usehttp := *proto == "http"
	if usehttp {
		serv := &http.Server{
			Addr: *bindAddr,
			Handler: &httpProxyHandler{
				onion:      onionsock,
				i2p:        i2psock,
				loki:       lokisock,
				verbose:    *verbose,
				passthrough: *passthrough,
			},
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		if *verbose {
			fmt.Printf("Setting up HTTP proxy at %s\n", serv.Addr)
		}
		err = serv.ListenAndServe()
		if err != nil {
			fmt.Printf("%s\n", err.Error())
		}
	} else {
		serv, err := socks5.New(&socks5.Config{
			Dial: func(addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				host = strings.TrimSuffix(host, ".")
				if *verbose {
					fmt.Printf("SOCKS request for: %s\n", host)
				}
				if err != nil {
					return nil, err
				}
				
				// Check if it's a clearnet URL and passthrough is set to clearnet
				if *passthrough == "clearnet" && !strings.HasSuffix(host, ".onion") && !strings.HasSuffix(host, ".i2p") && !strings.HasSuffix(host, ".loki") {
					if *verbose {
						fmt.Printf("Using clearnet for: %s\n", host)
					}
					return net.Dial("tcp", addr)
				}
				
				if strings.HasSuffix(host, ".loki") {
					if *verbose {
						fmt.Printf("Using lokinet for: %s\n", host)
					}
					if lokisock == nil {
						return nil, fmt.Errorf("lokinet proxy not configured")
					}
					return lokisock.Dial("tcp", addr)
				}
				if strings.HasSuffix(host, ".i2p") {
					if *verbose {
						fmt.Printf("Using i2p for: %s\n", host)
					}
					if i2psock == nil {
						return nil, fmt.Errorf("i2p proxy not configured")
					}
					return i2psock.Dial("tcp", addr)
				}
				if *verbose {
					fmt.Printf("Using tor for: %s\n", host)
				}
				if onionsock == nil {
					return nil, fmt.Errorf("tor proxy not configured")
				}
				return onionsock.Dial("tcp", addr)
			},
		})

		if err != nil {
			fmt.Printf("Failed to create SOCKS proxy: %s\n", err.Error())
			os.Exit(1)
		}

		l, err := net.Listen("tcp", *bindAddr)
		if err != nil {
			fmt.Printf("Failed to listen on %s: %s\n", *bindAddr, err.Error())
			os.Exit(1)
		}
		if *verbose {
			fmt.Printf("Setting up SOCKS proxy at %s\n", *bindAddr)
		}
		serv.Serve(l)
	}
}
