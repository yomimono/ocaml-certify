open Cmdliner

type 'a result =
  | Ok of 'a
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
  let seconds = days * 24 * 60 * 60 in
  let start = Ptime_clock.now () in
  match Ptime.(add_span start @@ Span.of_int_s seconds) with
  | Some expire -> Some (start, expire)
  | None -> None

let extensions subject_pubkey auth_pubkey names entity =
  let subject_key_id =
    let cs = X509.key_id subject_pubkey in
    (false, `Subject_key_id cs)
  and authority_key_id =
    let cs = X509.key_id auth_pubkey in
    let x = (Some cs, [], None) in
    (false, `Authority_key_id x)
  and exts =
    let ku = (true, (`Key_usage [ `Digital_signature ; `Key_encipherment ]))
    and bc = (true, `Basic_constraints (false, None))
    in
    match entity with
    | `CA ->
       [ (true, (`Basic_constraints (true, None)))
       ; (true, (`Key_usage [ `Key_cert_sign
                            ; `CRL_sign
                            ; `Digital_signature
                            ; `Content_commitment
                            ]))
       ]
    | `Client ->
       [ bc ; ku
         ; (true, (`Ext_key_usage [`Client_auth]))
       ]
    | `Server ->
       [ bc ; ku
         ; (true, (`Ext_key_usage [`Server_auth]))
       ]
  in
  let alts = match names with
    | [] -> []
    | _ -> [ (false, `Subject_alt_name ( List.map (fun x -> `DNS x) names)) ]
  in
  authority_key_id :: subject_key_id :: exts @ alts

let sign days key pubkey issuer csr names entity =
  match make_dates days with
  | None -> Error "Validity period is too long to express - try a shorter one"
  | Some (valid_from, valid_until) ->
    match key, pubkey with
    | `RSA priv, `RSA pub when Nocrypto.Rsa.pub_of_priv priv = pub ->
      let info = X509.CA.info csr in
      let extensions = extensions info.X509.CA.public_key pubkey names entity in
      let cert = X509.CA.sign ~valid_from ~valid_until ~extensions csr key issuer in
      Ok cert
    | _ -> Error "public / private keys do not match"

let read_pem src =
  try
    let stat = Unix.stat src in
    let buf = Bytes.create (stat.Unix.st_size) in
    let fd = Unix.openfile src [Unix.O_RDONLY] 0 in
    let _read_b = Unix.read fd buf 0 stat.Unix.st_size in
    let () = Unix.close fd in
    Ok (Cstruct.of_bytes buf)
  with
  | Unix.Unix_error (e, _, _) -> translate_error src e

let write_pem dest pem =
  try
    let fd = Unix.openfile dest [Unix.O_WRONLY; Unix.O_CREAT] 0o600 in
    (* single_write promises either complete failure (resulting in an exception)
         or complete success, so disregard the returned number of bytes written
         and just handle the exceptions *)
    let _written_bytes = Unix.single_write fd (Cstruct.to_bytes pem) 0 (Cstruct.len pem) in
    let () = Unix.close fd in
    Ok ()
  with
  | Unix.Unix_error (e, _, _) -> translate_error dest e

let thing = "self-signed certificate or certificate signing request"

let length =
  let doc = "Length of the key in bits." in
  Arg.(value & opt int 2048 & info ["l"; "length"] ~doc)

let keyfile =
  let doc = "Filename to which to save the private key for the " ^ thing ^ "." in
  Arg.(value & opt string "key.pem" & info ["k"; "key"; "keyout"] ~doc)

let days =
  let doc = "The number of days from the start date on which the " ^ thing ^ " will expire." in
  Arg.(value & opt int 365 & info ["d"; "days"] ~doc)

let is_ca =
  let doc = "Sign a CA cert (and include appropriate extensions)." in
  Arg.(value & flag & info ["C"; "ca"] ~doc)

let common_name =
  let doc = "Common name for which to issue the " ^ thing ^ "." in
  Arg.(required & pos ~rev:false 0 (some string) None & info [] ~doc ~docv:"CN")

