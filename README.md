## About

A very small utility for making self-signed certificates and private keys using ocaml-x509 and ocaml-nocrypto for key generation.  Intended as a (non-drop-in) replacement for these uses of the command-line `openssl` utility.

## Install

`certify` is now available in `opam`, [a free source-based package manager for OCaml](https://github.com/ocaml/opam).  You can install `certify` via opam with `opam install certify`.

Outside of opam:

```
git clone https://github.com/yomimono/ocaml-certify
cd ocaml-certify
ocaml pkg/pkg.ml build
```

Binaries will be in `_build/src`, and you can install them wherever you like, or just use them in place.

## Running

For help, try `selfsign --help`, `sign --help`, or `csr --help`.

- `selfsign` produces a private key and self-signed certificate
- `sign` takes a certificate signing request, and a CA (key and certificate), and produces a certificate
- `csr` produces a private key and a certificate signing request

## Tests

Simple `openssl` interoperability tests are in `tests/test.sh`.
