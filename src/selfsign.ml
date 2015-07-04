open Cmdliner
open Common

let selfsign common_name length days is_ca certfile keyfile =
  Nocrypto_entropy_unix.initialize ();
  let privkey = Nocrypto.Rsa.generate length
  and issuer = [ `CN common_name ]
  in
  let csr = X509.CA.request issuer (`RSA privkey) in
  let ent = if is_ca then `CA else `Server in
  match Common.sign days (`RSA privkey) (`RSA (Nocrypto.Rsa.pub_of_priv privkey)) issuer csr None ent with
  | Ok cert ->
     let cert_pem = X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert in
     let key_pem = X509.Encoding.Pem.Private_key.to_pem_cstruct1 (`RSA privkey) in
     (match write_pem certfile cert_pem, write_pem keyfile key_pem with
      | Ok (), Ok () -> `Ok
      | Error str, _
      | _, Error str -> Printf.eprintf "%s\n" str; `Error)
  | Error str -> Printf.eprintf "%s\n" str; `Error

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
