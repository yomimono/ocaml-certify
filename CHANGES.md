## v0.3.2 (2019-11-02):
* maintenance: use newer yet x509 (v0.8.0) (@hannesm)

## v0.3.1 (2019-09-30):
* maintenance: use newer x509 (v0.7.1) (@hannesm)

## v0.3 (2019-07-26):
* breaking change: `sign`, `selfsign`, and `csr` are now subcommands of a `certify` binary.  To update your workflow, simply prepend `certify` to any command you previously ran. (@reynir)
* improvements: allow --key for key filename in `sign`; write to csr.pem by default in `csr`. (@yomimono)
* maintenance: use newer x509 (v.0.7.0); make opam 2.0-compliant; use dune instead of topkg/ocamlfind; fix tests for some platforms. (@hannesm, @yomimono)

## v0.2 (2017-12-24):
* maintenance: use newer asn1-combinators, x509, and OCaml; use topkg instead of oasis; add simple tests.

## v0.1 (2017-12-13):
* Initial release providing `sign`, `selfsign`, and `csr`.
