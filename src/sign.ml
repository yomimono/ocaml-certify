open Cmdliner

let sign days is_ca client altname key cacert csr certfile =
  match Common.(read_pem key, read_pem cacert, read_pem csr) with
  | Common.Ok key, Common.Ok cacert, Common.Ok csr ->
     let key = X509.Encoding.Pem.Private_key.of_pem_cstruct1 key
     and cacert = X509.Encoding.Pem.Certificate.of_pem_cstruct1 cacert
     and csr = X509.Encoding.Pem.Certificate_signing_request.of_pem_cstruct1 csr
     in
     let pub =
       let priv = match key with `RSA k -> k in
       Nocrypto.Rsa.pub_of_priv priv
     in
     ( match X509.public_key cacert with
       | `RSA pub' when pub = pub' ->
          Nocrypto_entropy_unix.initialize ();
          let info = X509.CA.info csr
          and valid_from, valid_until = Common.make_dates days
          and issuer = X509.subject cacert
          in
          let name =
            match List.filter (function `CN _ -> true | _ -> false) info.X509.CA.subject with
            | [ `CN x ] -> Some x
            | _ -> None
          in
          let extensions =
            let subject_key_id =
              let cs = X509.key_id info.X509.CA.public_key in
              (false, `Subject_key_id cs)
            and authority_key_id =
              let cs = X509.key_id (X509.public_key cacert) in
              let x = (Some cs, [], None) in
              (false, `Authority_key_id x)
            and exts =
              let ku = (true, (`Key_usage [ `Digital_signature ; `Key_encipherment ]))
              and bc = (true, `Basic_constraints (false, None))
              in
              match is_ca, client with
              | true, _ ->
                 [ (true, (`Basic_constraints (true, None)))
                 ; (true, (`Key_usage [ `Key_cert_sign
                                      ; `CRL_sign
                                      ; `Digital_signature
                                      ; `Content_commitment
                                      ]))
                 ]
              | false, true ->
                 [ bc ; ku
                   ; (true, (`Ext_key_usage [`Client_auth]))
                 ]
              | false, false ->
                 [ bc ; ku
                   ; (true, (`Ext_key_usage [`Server_auth]))
                 ]
            in
            let alt = match altname, name with
              | false, _ -> []
              | true, None -> []
              | true, Some x -> [ (false, `Subject_alt_name [ `DNS x ]) ]
            in
            authority_key_id :: subject_key_id :: exts @ alt
          in
          let cert = X509.CA.sign ~valid_from ~valid_until ~extensions csr key issuer in
          (match Common.write_pem certfile (X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert) with
           | Common.Ok () -> `Ok
           | Common.Error str -> Printf.eprintf "%s\n" str; `Error)
       | _ -> Printf.eprintf "public / private key doesn't match"; `Error)
  | Common.Error str, _, _
  | _, Common.Error str, _
  | _, _, Common.Error str -> Printf.eprintf "%s\n" str; `Error

let client =
  let doc = "Client or server certificate" in
  Arg.(value & flag & info ["client"] ~doc)

let altname =
  let doc = "include a subjectAltName in certificate" in
  Arg.(value & flag & info ["altname"] ~doc)

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
  Arg.(value & flag & info ["C"; "is_ca"] ~doc)

let sign_t = Term.(pure sign $ days $ is_ca $ client $ altname $ keyin $ cain $ csrin $ certfile)

let info =
  let doc = "sign a certificate" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "sign" ~doc ~man

let () =
  match Term.eval (sign_t, info) with
  | `Help -> exit 0 (* TODO: not clear to me how we generate this case *)
  | `Version -> exit 0  (* TODO: not clear to me how we generate this case *)
  | `Error _ -> exit 1
  | `Ok _ -> exit 0
