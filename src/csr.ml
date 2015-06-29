open Cmdliner
open Common

let org =
  let doc = "Organization name for the certificate signing request." in
  Arg.(required & pos ~rev:false 1 (some string) None & info [] ~doc ~docv:"O")

let csr org cn length days certfile keyfile =
  Nocrypto_entropy_unix.initialize ();
  let privkey = `RSA (Nocrypto.Rsa.generate length) in
  let dn = [ `CN cn; `O org ] in
  let csr = X509.CA.request dn privkey in
  let csr_pem = X509.Encoding.Pem.Certificate_signing_request.to_pem_cstruct1 csr in
  let key_pem = X509.Encoding.Pem.Private_key.to_pem_cstruct1 privkey in
  match (write_pem certfile csr_pem, write_pem keyfile key_pem) with
  | Ok, Ok -> `Ok
  | Error str, _ | _, Error str -> Printf.eprintf "%s\n" str; `Error

let csr_t = Term.(pure csr $ org $ common_name $ length $ days $ certfile $ keyfile )

let info =
  let doc = "generate a certificate-signing request" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "csr" ~doc ~man

let () =
  match Term.eval (csr_t, info) with
  | `Help | `Version | `Ok _ -> exit 0
  | `Error _ -> exit 1
