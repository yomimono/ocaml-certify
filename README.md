## About

A very small utility for making self-signed certificates and private keys using ocaml-x509 and ocaml-nocrypto for key generation.  Intended as a (non-drop-in) replacement for this use of the command-line `openssl` utility.

## Dependencies

`ocaml-selfsign` depends on capabilities in `ocaml-509` that are not yet released, but are available on the primary branch of its main repository.  It uses the latest releases of `ocaml-nocrypto` and `cmdliner`.  To get dependencies for ocaml-selfsign via `opam`:

```
opam pin add ocaml-x509 https://github.com/mirleft/ocaml-x509
opam install ocaml-nocrypto cmdliner
```

## Running

For help, try `ocaml-selfsign --help`.
