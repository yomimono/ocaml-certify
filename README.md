## About

A very small utility for common certificate operations using ocaml-x509 and ocaml-nocrypto for key generation.  Intended as a (non-drop-in) replacement for these uses of the command-line `openssl` utility.

## Install

`certify` is now available in `opam`, [a free source-based package manager for OCaml](https://github.com/ocaml/opam).  You can install `certify` via opam with `opam install certify`.

Outside of opam:

```
git clone https://github.com/yomimono/ocaml-certify
dune build
```

The `certify` binary will be in `_build/default/install/bin`, and you can install it wherever you like, or just use it in place.

## Running

For help, try `certify selfsign --help`, `certify sign --help`, or `certify csr --help`.

- `certify selfsign` produces a private key and self-signed certificate
- `certify sign` takes a certificate signing request, and a CA (key and certificate), and produces a certificate
- `certify csr` produces a private key and a certificate signing request

## Tests

Simple `openssl` interoperability tests are in `tests/test.sh`.
