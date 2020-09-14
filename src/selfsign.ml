open Cmdliner
open Common

let selfsign name length days is_ca certfile keyfile =
  Mirage_crypto_rng_unix.initialize ();
  let privkey = Mirage_crypto_pk.Rsa.generate ~bits:length ()
  and issuer =
    [ X509.Distinguished_name.(Relative_distinguished_name.singleton (CN name)) ]
  in
  let csr = X509.Signing_request.create issuer (`RSA privkey) in
  let ent = if is_ca then `CA else `Server in
  match Common.sign days (`RSA privkey) (`RSA (Mirage_crypto_pk.Rsa.pub_of_priv privkey)) issuer csr [] ent with
  | Error str -> Error str
  | Ok cert ->
     let cert_pem = X509.Certificate.encode_pem cert in
     let key_pem = X509.Private_key.encode_pem (`RSA privkey) in
     (match write_pem certfile cert_pem, write_pem keyfile key_pem with
      | Ok (), Ok () -> Ok ()
      | Error str, _
      | _, Error str -> Error str)

let certfile =
  let doc = "Filename to which to save the completed certificate." in
  Arg.(value & opt string "certificate.pem" & info ["c"; "certificate"; "out"] ~doc)

let selfsign_t = Term.(term_result (pure selfsign $ common_name
                                      $ length $ days $ is_ca
                                      $ certfile $ keyfile ))

let selfsign_info =
  let doc = "generate a self-signed certificate" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "selfsign" ~doc ~man
