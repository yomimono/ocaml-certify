open Cmdliner

let sign days is_ca client key cacert csr certfile altnames =
  match Common.(read_pem key, read_pem cacert, read_pem csr) with
  | Error str, _, _
  | _, Error str, _
  | _, _, Error str -> Error str
  | Ok key, Ok cacert, Ok csr ->
    match
      X509.Private_key.decode_pem key,
      X509.Certificate.decode_pem cacert,
      X509.Signing_request.decode_pem csr
    with
    | Error (`Msg e), _, _
    | _, Error (`Msg e), _
    | _, _, Error (`Msg e) -> Error (`Msg e)
    | Ok key, Ok cacert, Ok csr ->
      let ent = match is_ca, client with
        | true, _ -> `CA
        | false, true -> `Client
        | false, false -> `Server
      in
      let names =
        match altnames with
        | [] -> []
        | altnames ->
          match X509.(Distinguished_name.common_name Signing_request.((info csr).subject)) with
          | Some x -> x :: altnames
          | None -> altnames
      in
      let issuer = X509.Certificate.subject cacert in
      let pubkey = X509.Certificate.public_key cacert in
      Nocrypto_entropy_unix.initialize ();
      match Common.sign days key pubkey issuer csr names ent with
      | Error str -> Error str
      | Ok cert ->
        Common.write_pem certfile (X509.Certificate.encode_pem cert)

let client =
  let doc = "Add ExtendedKeyUsage extension to be ClientAuth \
             (ServerAuth if absent and not CA)" in
  Arg.(value & flag & info ["client"] ~doc)

let altnames =
  let doc = "Add DNSName to SubjectAlternativeName" in
  Arg.(value & opt_all string [] & info ["altname"] ~doc)

let keyin =
  let doc = "Filename of the private key." in
  Arg.(value & opt string "key.pem" & info ["keyin";"key"] ~doc)

let cain =
  let doc = "Filename of the CA certificate." in
  Arg.(value & opt string "cacert.pem" & info ["cain"] ~doc)

let csrin =
  let doc = "Filename of the CSR." in
  Arg.(value & opt string "csr.pem" & info ["csrin"] ~doc)

let certfile =
  let doc = "Filename to which to save the signed certificate." in
  Arg.(value & opt string "certificate.pem" & info ["c"; "certificate"; "out"] ~doc)

let days =
  let doc = "The number of days from the start date on which the signature will expire." in
  Arg.(value & opt int 365 & info ["d"; "days"] ~doc)

let is_ca =
  let doc = "Sign a CA cert (and include appropriate extensions)." in
  Arg.(value & flag & info ["C"; "ca"] ~doc)

let sign_t = Term.(term_result (pure sign $ days $ is_ca $ client $ keyin $ cain $ csrin $ certfile $ altnames))

let sign_info =
  let doc = "sign a certificate" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "sign" ~doc ~man
