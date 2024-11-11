# dirtysocks

A SOCKS5 proxy with usermode WireGuard capabilities.

Meant to be a replacement/comparable to [`wireproxy`](https://github.com/pufferffish/wireproxy)

## Usage

```
A usermode WireGuard implementation with a SOCKS5 proxy

Usage: dirtysocks-bin [OPTIONS] --config <CONFIG>

Options:
  -c, --config <CONFIG>  The `wg-quick` config file to read
      --host <HOST>      The socket address the SOCKS5 proxy should listen on [default: 127.0.0.1:3000]
  -h, --help             Print help
  -V, --version          Print version
```

## Examples

```
dirtysocks-bin --config <wg-quick config file> --host 127.0.0.1:1234
```

## Implementation

Follows a very similar implementation to [`onetun`](https://github.com/aramperes/onetun), except it doesn't yet support UDP.

However, there are bandwidth issues, which were previously seen in [onetun#29](https://github.com/aramperes/onetun/issues/29). I am currently looking into the causes of said bandwidth issues.
