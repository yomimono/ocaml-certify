open Cmdliner

type result =
  | Ok
  | Error of string

let translate_error dest = function
  | (Unix.EACCES) -> 
    Error (Printf.sprintf "Permission denied writing %s" dest)
  | (Unix.EISDIR) ->
    Error (Printf.sprintf "%s already exists and is a directory" dest)
  | (Unix.ENOENT) ->
    Error (Printf.sprintf "Part of the path %s doesn't exist" dest)
  | (Unix.ENOSPC) -> Error "No space left on device"
  | (Unix.EROFS) ->
    Error (Printf.sprintf "%s is on a read-only filesystem" dest)
  | e -> Error (Unix.error_message e)

let make_dates days =
  let asn1_of_time time = 
    let tm = Unix.gmtime time in
    {
      (* irritatingly, posix months and Unix.tm months are differently indexed *)
      Asn.Time.date = Unix.(tm.tm_year, (tm.tm_mon + 1), tm.tm_mday);
      time = Unix.(tm.tm_hour, tm.tm_min, tm.tm_sec, 0.); (* no fractional secs in tm *)
      (* no tz info in tm, but we got it from gmtime so tzoffset should be 0 *)
      tz = None;
    }
  in
  let seconds = days * 24 * 60 * 60 in
  let start = asn1_of_time (Unix.time ()) in
  let expire = asn1_of_time (Unix.time () +. (float_of_int seconds)) in
  (start, expire)

let write_pem dest pem =
  try 
    let fd = Unix.openfile dest [Unix.O_WRONLY; Unix.O_CREAT] 0o600 in
    (* single_write promises either complete failure (resulting in an exception)
         or complete success, so disregard the returned number of bytes written
         and just handle the exceptions *)
    let _written_bytes = Unix.single_write fd (Cstruct.to_string pem) 0 (Cstruct.len pem) in
    let () = Unix.close fd in
    Ok
  with
  | Unix.Unix_error (e, _, _) -> translate_error dest e

let selfsign common_name length days certfile keyfile =
  let (issuer : X509.component list) =
    [ `CN common_name ]
  in
  let start,expire = make_dates days in
  Nocrypto_entropy_unix.initialize ();
  let privkey = `RSA (Nocrypto.Rsa.generate length) in
  let csr = X509.CA.generate issuer privkey in 
  (* default is sha256; TODO probably should allow user to choose sha1 as well *)
  let cert = X509.CA.sign ~valid_from:start ~valid_until:expire
      csr privkey issuer in
  let cert_pem = X509.Encoding.Pem.Cert.to_pem_cstruct1 cert in
  let key_pem = X509.Encoding.Pem.Private_key.to_pem_cstruct1 privkey in

  match (write_pem certfile cert_pem, write_pem keyfile key_pem) with
  | Ok, Ok -> `Ok
  | Error str, _ | _, Error str -> Printf.eprintf "%s\n" str; `Error

let length =
  let doc = "Length of the key in bits." in
  Arg.(value & opt int 2048 & info ["l"; "length"] ~doc)
  
let certfile =
  let doc = "Filename to which to save the completed self-signed certificate." in
  Arg.(value & opt string "certificate.pem" & info ["c"; "certificate"; "out"] ~doc)

let keyfile =
  let doc = "Filename to which to save the private key for the self-signed certificate." in
  Arg.(value & opt string "key.pem" & info ["k"; "key"; "keyout"] ~doc)

let days =
  let doc = "The number of days from the start date on which the certificate will expire." in
  Arg.(value & opt int 365 & info ["d"; "days"] ~doc)

let common_name = 
  let doc = "Common name for which to issue the certificate." in
  Arg.(required & pos ~rev:false 0 (some string) None & info [] ~doc ~docv:"CN")


let selfsign_t = Term.(pure selfsign $ common_name $ length $ days
                       $ certfile $ keyfile )

let info =
  let doc = "generate a self-signed certificate" in
  let man = [ `S "BUGS"; `P "Submit bugs at
  https://github.com/yomimono/ocaml-certify";] in
  Term.info "certify" ~doc ~man

let () = 
  match Term.eval (selfsign_t, info) with 
  | `Help -> exit 0 (* TODO: not clear to me how we generate this case *)
  | `Version -> exit 0  (* TODO: not clear to me how we generate this case *)
  | `Error _ -> exit 1 
  | `Ok _ -> exit 0
