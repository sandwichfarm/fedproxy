# HedProxy

A simple proxy that routes traffic through Tor, I2P, and Lokinet based on the domain being accessed.

## Features

- Automatically routes `.onion` domains through Tor
- Automatically routes `.i2p` domains through I2P
- Automatically routes `.loki` domains through Lokinet
- Supports both HTTP and SOCKS5 proxy protocols
- Configurable logging levels
- Optional clearnet passthrough mode

## Requirements

- Go 1.16 or later
- Tor SOCKS proxy (default: 127.0.0.1:9050)
- I2P SOCKS proxy (default: 127.0.0.1:4447)
- Lokinet SOCKS proxy (default: 127.0.0.1:1194)

## Installation

```bash
go install github.com/sandwichfarm/hedproxy@latest
```

## Usage

```bash
hedproxy <proto> <bind> [options]
```

### Arguments

- `proto`: Protocol to use (http or socks)
- `bind`: Address to bind to (e.g., 127.0.0.1:2000)

### Options

- `-tor`: Tor SOCKS proxy address (e.g., 127.0.0.1:9050). If no value is provided, defaults to 127.0.0.1:9050
- `-i2p`: I2P SOCKS proxy address (e.g., 127.0.0.1:4447). If no value is provided, defaults to 127.0.0.1:4447
- `-loki`: Lokinet SOCKS proxy address (e.g., 127.0.0.1:1194). If no value is provided, defaults to 127.0.0.1:1194
- `-v`: Enable verbose logging (DEBUG level)
- `-logLevel`: Set log level (SILENT, ERROR, WARNING, NOTICE, INFO, DEBUG)
- `-passthrough`: Set passthrough mode (e.g., 'clearnet' for direct clearnet access)

### Examples

Start an HTTP proxy on port 2000 with default Tor proxy:
```bash
hedproxy http 127.0.0.1:2000 -tor
```

Start a SOCKS5 proxy on port 2001 with all three networks using default ports:
```bash
hedproxy socks 127.0.0.1:2001 -tor -i2p -loki
```

Start a proxy with custom Tor proxy address:
```bash
hedproxy http 127.0.0.1:2000 -tor 192.168.1.1:9050
```

Start a proxy with custom host but default port:
```bash
hedproxy http 127.0.0.1:2000 -tor 192.168.1.1
```

Start a proxy with verbose logging:
```bash
hedproxy http 127.0.0.1:2000 -tor -v
```

Start a proxy with specific log level:
```bash
hedproxy http 127.0.0.1:2000 -tor -logLevel INFO
```

Start a proxy with clearnet passthrough:
```bash
hedproxy http 127.0.0.1:2000 -tor -passthrough clearnet
```

## Logging

HedProxy supports multiple log levels:

- `SILENT`: No logging
- `ERROR`: Error messages only
- `WARNING`: Warning and error messages
- `NOTICE`: Notice, warning, and error messages
- `INFO`: Info, notice, warning, and error messages
- `DEBUG`: All messages including debug information

The default log level is `ERROR`. You can use the `-v` flag as a shortcut for `DEBUG` level, or specify a specific level using `-logLevel`. If both are specified, `-logLevel` takes precedence.

## Configuration

### HTTP Proxy

To use the HTTP proxy, configure your application to use the proxy address you specified. For example, in Firefox:

1. Go to Preferences > Network Settings
2. Select "Manual proxy configuration"
3. Enter the HTTP proxy address (e.g., 127.0.0.1:2000)

### SOCKS5 Proxy

To use the SOCKS5 proxy, configure your application to use the SOCKS5 proxy address you specified. For example, in Firefox:

1. Go to Preferences > Network Settings
2. Select "Manual proxy configuration"
3. Enter the SOCKS5 proxy address (e.g., 127.0.0.1:2001)
4. Select "SOCKS v5"

## Notes

- At least one proxy (Tor, I2P, or Lokinet) must be configured
- The proxy will automatically route traffic based on the domain being accessed
- If `-passthrough clearnet` is specified, clearnet traffic will be routed directly instead of through Tor
- When using the HTTP proxy, HTTPS traffic is supported through CONNECT tunneling
- Proxy flags can be used without values to use default host and port
- Proxy flags can be used with just a hostname to use default port
- Proxy flags can be used with full address to override both host and port

## Why the fork?
I liked **fedproxy** but needed a less opinionated solution.

**fedproxy** is loki-first, assumes loki is running over VPN/transparent proxy (default Loki desktop experience) and treats tor and i2p as second-class citizens, and clearnet as a third-class citizen.
**hedproxy** treats all as first class citizens and assumes nothing.

## Differences from fedproxy

- Logging is off by default (use `-v` to enable loggingg)
- Uses flags instead of positional arguments
- lokinet has same routing pattern as tor and i2p instead of assuming the host will handle it with a transparent proxy.
- A flag for clearnet URLS to be optionally routed through clearnet instead of tor.
- Fixed a few lingering bugs

## Acknowledgements

**hedproxy** is a fork of the spectacular [fedproxy](https://github.com/majestrate/fedproxy) by [majestrate](https://github.com/majestrate). 
