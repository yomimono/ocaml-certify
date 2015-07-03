open Cmdliner
open Common

let selfsign common_name length days is_ca certfile keyfile =
  let (issuer : X509.component list) =
    [ `CN common_name ]
  in
  let start,expire = make_dates days in
  Nocrypto_entropy_unix.initialize ();
  let privkey = Nocrypto.Rsa.generate length in
  let ext =
    let cs = X509.key_id (`RSA (Nocrypto.Rsa.pub_of_priv privkey)) in
    let subject_key_id = (false, (`Subject_key_id cs))
    and authority_key_id =
      let x = (Some cs, [], None) in
      (false, (`Authority_key_id x))
    in
    let ca_extensions =
      if not is_ca then []
      else
        [ (true, (`Basic_constraints (true, None)))
        ; (true, (`Key_usage [ `Key_cert_sign
                             ; `CRL_sign
                             ; `Digital_signature
                             ; `Content_commitment
                             ]))
        ]
    in
    authority_key_id :: subject_key_id :: ca_extensions
  in
  let csr = X509.CA.request issuer (`RSA privkey) in
  let cert = X509.CA.sign ~valid_from:start ~valid_until:expire ~extensions:ext
      csr (`RSA privkey) issuer in
  let cert_pem = X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert in
  let key_pem = X509.Encoding.Pem.Private_key.to_pem_cstruct1 (`RSA privkey) in
  match (write_pem certfile cert_pem, write_pem keyfile key_pem) with
  | Ok, Ok -> `Ok
  | Error str, _ | _, Error str -> Printf.eprintf "%s\n" str; `Error

let selfsign_t = Term.(pure selfsign $ common_name $ length $ days $ is_ca
                       $ certfile $ keyfile )

let info =
  let doc = "generate a self-signed certificate" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "selfsign" ~doc ~man

let () =
  match Term.eval (selfsign_t, info) with
  | `Help -> exit 0 (* TODO: not clear to me how we generate this case *)
  | `Version -> exit 0  (* TODO: not clear to me how we generate this case *)
  | `Error _ -> exit 1
  | `Ok _ -> exit 0
