## About

A very small utility for making self-signed certificates and private keys using ocaml-x509 and ocaml-nocrypto for key generation.  Intended as a (non-drop-in) replacement for these uses of the command-line `openssl` utility.

## Dependencies

`certify` depends on `cmdliner`, `x509`, and `nocrypto`.  To install these packages via opam:

```
opam install nocrypto x509 cmdliner
```

## Install

To install with opam: 

```
opam pin add certify https://github.com/yomimono/ocaml-certify.git
opam install certify
```

Outside of opam:

```
git clone https://github.com/yomimono/ocaml-certify
cd ocaml-certify
./configure
make
make install
```

## Running

For help, try `selfsign --help` or `csr --help`.
