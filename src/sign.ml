open Cmdliner

let sign days is_ca client altname key cacert csr certfile altnames =
  match Common.(read_pem key, read_pem cacert, read_pem csr) with
  | Common.Ok key, Common.Ok cacert, Common.Ok csr ->
     let key = X509.Encoding.Pem.Private_key.of_pem_cstruct1 key
     and cacert = X509.Encoding.Pem.Certificate.of_pem_cstruct1 cacert
     and csr = X509.Encoding.Pem.Certificate_signing_request.of_pem_cstruct1 csr
     in
     let ent = match is_ca, client with
       | true, _ -> `CA
       | false, true -> `Client
       | false, false -> `Server
     in
     let names =
       if altname then
         let info = X509.CA.info csr in
         match List.filter (function `CN _ -> true | _ -> false) info.X509.CA.subject with
         | [ `CN x ] -> x :: altnames
         | _ -> altnames
       else
         []
     in
     let issuer = X509.subject cacert in
     let pubkey = X509.public_key cacert in
     Nocrypto_entropy_unix.initialize ();
     (match Common.sign days key pubkey issuer csr names ent with
      | Common.Error str -> Printf.eprintf "%s\n" str; `Error
      | Common.Ok cert ->
         (match Common.write_pem certfile (X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert) with
          | Common.Ok () -> `Ok
          | Common.Error str -> Printf.eprintf "%s\n" str; `Error))
  | Common.Error str, _, _
  | _, Common.Error str, _
  | _, _, Common.Error str -> Printf.eprintf "%s\n" str; `Error

let client =
  let doc = "Add ExtendedKeyUsage extension to be ClientAuth (ServerAuth if absent and not CA)" in
  Arg.(value & flag & info ["client"] ~doc)

let altname =
  let doc = "Add SubjectAlternativeName extension where DNSName is CommonName of the subject" in
  Arg.(value & flag & info ["altname"] ~doc)

let altnames =
  let doc = "Add DNSName to SubjectAlternativeName" in
  Arg.(value & pos_all string [] & info [] ~docv:"ALTNAME" ~doc)

let keyin =
  let doc = "Filename of the private key." in
  Arg.(value & opt string "key.pem" & info ["keyin"] ~doc)

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

let sign_t = Term.(pure sign $ days $ is_ca $ client $ altname $ keyin $ cain $ csrin $ certfile $ altnames)

let info =
  let doc = "sign a certificate" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "sign" ~doc ~man

let () =
  match Term.eval (sign_t, info) with
  | `Help -> exit 1 (* TODO: not clear to me how we generate this case *)
  | `Version -> exit 1  (* TODO: not clear to me how we generate this case *)
  | `Error _ -> exit 1
  | `Ok _ -> exit 0
