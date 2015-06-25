## About

A very small utility for making self-signed certificates and private keys using ocaml-x509 and ocaml-nocrypto for key generation.  Intended as a (non-drop-in) replacement for these uses of the command-line `openssl` utility.

## Dependencies

`ocaml-certify` depends on capabilities in `x509` and `nocrypto` that are available on the primary branch of its main repository but have not yet been released.  It uses the latest release of `cmdliner`.  To get dependencies for ocaml-certify via `opam`:

```
opam pin add x509 https://github.com/mirleft/ocaml-x509
opam pin add nocrypto https://github.com/mirleft/nocrypto
opam install nocrypto x509 cmdliner
```

If you wish to also use `ocaml-tls` or any of its dependencies, you'll need to also pin `ocaml-tls` to the primary branch of its main repository:

```
opam pin add https://github.com/mirleft/ocaml-tls
```

## Install

To install with opam: 

```
opam pin add https://github.com/yomimono/ocaml-certify
opam install ocaml-certify
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
