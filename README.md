## About

A very small utility for making self-signed certificates and private keys using ocaml-x509 and ocaml-nocrypto for key generation.  Intended as a (non-drop-in) replacement for these uses of the command-line `openssl` utility.

## Dependencies

`ocaml-certify` depends on capabilities in `x509` that are not yet merged, and capabilities of `ocaml-nocrypto` that are available on the primary branch of its main repository but have not yet been released.  It uses the latest release of `cmdliner`.  To get dependencies for ocaml-certify via `opam`:

```
opam pin add x509 https://github.com/mirleft/ocaml-x509#naming
opam pin add nocrypto https://github.com/mirleft/nocrypto
opam install nocrypto x509 cmdliner
```

If you wish to also use `ocaml-tls` or any of its dependencies, you'll need to also pin a branch of `ocaml-tls` which agrees with the above pins:

```
opam pin add https://github.com/mirleft/ocaml-tls#naming-updates
```

## Running

For help, try `selfsign --help` or `csr --help`.
