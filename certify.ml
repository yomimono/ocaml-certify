open Cmdliner

type write_result =
  | Ok
  | Write_error of string

type entropy_result = 
  | Ok
  | Read_error of string

let seed_rng entropy_src how_much = 
  try
    let entropy_fd = Unix.openfile entropy_src [Unix.O_RDONLY] 0o000 in
    let bytes = Bytes.create how_much in
    let read_entropy = Unix.read entropy_fd bytes 0 how_much in
    let () = Unix.close entropy_fd in
    if (read_entropy = how_much) then begin
      Nocrypto.Rng.reseed (Cstruct.of_string bytes);
      Ok
    end else
      Read_error (
        Printf.sprintf "required amount of entropy (%d bytes) wasn't available at %s\n"
          how_much entropy_src)
  with
  | Unix.Unix_error(Unix.ENOENT, _, _)
  | Unix.Unix_error(Unix.ENODEV, _, _) -> 
    Read_error (Printf.sprintf "source %s doesn't exist -- try another?" entropy_src)

let translate_error dest = function
  | (Unix.EACCES) -> 
    Write_error (Printf.sprintf "Permission denied writing %s" dest)
  | (Unix.EISDIR) ->
    Write_error (Printf.sprintf "%s already exists and is a directory" dest)
  | (Unix.ENOENT) ->
    Write_error (Printf.sprintf "Part of the path %s doesn't exist" dest)
  | (Unix.ENOSPC) -> Write_error "No space left on device"
  | (Unix.EROFS) ->
    Write_error (Printf.sprintf "%s is on a read-only filesystem" dest)
  | e -> Write_error (Unix.error_message e)

let write_pem dest pem =
  try 
    let fd = Unix.openfile dest [Unix.O_WRONLY; Unix.O_CREAT] 0o600 in
    (* single_write promises either complete failure (resulting in an exception)
         or complete success, so disregard the returned number of bytes written
         and just handle the exceptions *)
    let _written_bytes = Unix.single_write fd (Cstruct.to_string pem) 0 (Cstruct.len pem) in
    let () = Unix.close fd in
    (Ok : write_result)
  with
  | Unix.Unix_error (e, _, _) -> translate_error dest e

let certify issuer common_name length certfile keyfile entropy_src =
  let entropy_amount = 1 in
  match (seed_rng entropy_src entropy_amount) with
  | Read_error str -> 
    Printf.eprintf "%s\n" str;
    `Error
  | Ok -> 
    let privkey = Nocrypto.Rsa.generate length in
    (* should be user-set too, but keep in mind we may get Invalid_argument for
                                          nonsense lengths *) 
    (* can extract the public privkey with Nocrypto.rsa.pub_of_priv *)
    let csr = X509.CA.generate common_name (`RSA privkey) in 
    let cert = X509.CA.sign (* TODO: let user change the valid period *)
        csr (`RSA privkey) issuer in
    let cert_pem = X509.Encoding.Pem.Cert.to_pem_cstruct1 cert in
    let key_pem = X509.Encoding.Pem.PrivateKey.to_pem_cstruct1 privkey in

    match (write_pem certfile cert_pem, write_pem keyfile key_pem) with
    | Ok, Ok -> `Ok
    | Write_error str, _ | _, Write_error str -> Printf.eprintf "%s" str; `Error

let issuer = 
  let doc = "Entity to list as issuer of the certificate" in
  Arg.(value & opt string "Yoyodyne Inc" & info ["i"; "issuer" ] ~doc)

let length =
  let doc = "Length of the key in bits." in
  Arg.(value & opt int 2048 & info ["l"; "length"] ~doc)
  
let certfile =
  let doc = "Filename to which to save the completed self-signed certificate." in
  Arg.(value & opt string "certificate.pem" & info ["c"; "certificate"] ~doc)

let keyfile =
  let doc = "Filename to which to save the private key for the self-signed certificate." in
  Arg.(value & opt string "key.pem" & info ["k"; "key"] ~doc)

let entropy_src = 
  let doc = "Source for entropy." in
  Arg.(value & opt string "/dev/urandom" & info ["e"; "entropy"] ~doc)

let common_name = 
  let doc = "Common name for which to issue the certificate." in
  (* TODO: should probably be required *)
  Arg.(value & opt string "yoyodyne.xyz" & info ["d"; "domain"] ~doc)

let certify_t = Term.(pure certify $ issuer $ common_name $ length $ certfile $ keyfile $ entropy_src)

let info =
  let doc = "generate a self-signed certificate" in
  let man = [ `S "BUGS"; `P "Submit bugs at https://github.com/yomimono/ocaml-selfsign";] in
  Term.info "certify" ~doc ~man

let () = 
  match Term.eval (certify_t, info) with 
  | `Help -> exit 0 (* TODO: not clear to me how we generate this case *)
  | `Version -> exit 0  (* TODO: not clear to me how we generate this case *)
  | `Error _ -> exit 1 
  | `Ok _ -> exit 0
