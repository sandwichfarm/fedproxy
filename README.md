# fedproxy

Routes `.onion` and clearnet domains over tor, `.i2p` domains over i2p, and `.loki` domains over lokinet if it's configured.

## Building

```bash
$ go get -u github.com/majestrate/fedproxy
$ cp $(GOPATH)/bin/fedproxy /usr/local/bin/fedproxy
```

## Usage

Basic usage:
```bash
$ fedproxy [flags] proto bindaddr onionsocksaddr i2psocksaddr
```

Where:
- `proto` is either "http" or "socks"
- `bindaddr` is the address to listen on (e.g., "127.0.0.1:2000")
- `onionsocksaddr` is the Tor SOCKS proxy address (e.g., "127.0.0.1:9050")
- `i2psocksaddr` is the I2P SOCKS proxy address (e.g., "127.0.0.1:4447")

### Flags

- `-verbose`: Enable verbose logging (default: false)
- `-passthrough`: Set passthrough mode (e.g., 'clearnet' for direct clearnet access)

### Examples

1. Basic SOCKS proxy:
```bash
$ fedproxy socks 127.0.0.1:2000 127.0.0.1:9050 127.0.0.1:4447
```

2. HTTP proxy with verbose logging:
```bash
$ fedproxy -verbose http 127.0.0.1:8080 127.0.0.1:9050 127.0.0.1:4447
```

3. SOCKS proxy with clearnet passthrough:
```bash
$ fedproxy -passthrough=clearnet socks 127.0.0.1:2000 127.0.0.1:9050 127.0.0.1:4447
```

4. HTTP proxy with both flags:
```bash
$ fedproxy -verbose -passthrough=clearnet http 127.0.0.1:8080 127.0.0.1:9050 127.0.0.1:4447
```

Then use the proxy at the specified bind address (e.g., `127.0.0.1:2000` for SOCKS or `127.0.0.1:8080` for HTTP).
