open Cmdliner
open Common

let org =
  let doc = "Organization name for the certificate signing request." in
  Arg.(required & pos ~rev:false 1 (some string) None & info [] ~doc ~docv:"O")

let certfile =
  let doc = "Filename to which to save the completed certificate-signing request." in
  Arg.(value & opt string "csr.pem" & info ["c"; "certificate"; "csr"; "out"] ~doc)

let csr org cn bits certfile keyfile =
  Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
  let privkey = `RSA (Mirage_crypto_pk.Rsa.generate ~bits ()) in
  let dn = X509.Distinguished_name.[
      Relative_distinguished_name.(singleton (CN cn)) ;
      Relative_distinguished_name.(singleton (O org)) ;
    ]
  in
  match X509.Signing_request.create dn privkey with
  | Error _ as e -> e
  | Ok csr ->
    let csr_pem = X509.Signing_request.encode_pem csr in
    let key_pem = X509.Private_key.encode_pem privkey in
    match (write_pem certfile csr_pem, write_pem keyfile key_pem) with
    | Ok (), Ok () -> Ok ()
    | Error str, _ | _, Error str -> Error str

let info =
  let doc = "generate a certificate-signing request" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Cmd.info "csr" ~doc ~man

  let csr_t = Cmd.v info Term.(term_result (const csr $ org $ common_name $ length $ certfile $ keyfile))
