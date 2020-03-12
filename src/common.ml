open Cmdliner

let translate_error dest = function
  | (Unix.EACCES) ->
    Error (`Msg (Printf.sprintf "Permission denied writing %s" dest))
  | (Unix.EISDIR) ->
    Error (`Msg (Printf.sprintf "%s already exists and is a directory" dest))
  | (Unix.ENOENT) ->
    Error (`Msg (Printf.sprintf "Part of the path %s doesn't exist" dest))
  | (Unix.ENOSPC) -> Error (`Msg "No space left on device")
  | (Unix.EROFS) ->
    Error (`Msg (Printf.sprintf "%s is on a read-only filesystem" dest))
  | e -> Error (`Msg (Unix.error_message e))

let make_dates days =
  let seconds = days * 24 * 60 * 60 in
  let start = Ptime_clock.now () in
  match Ptime.(add_span start @@ Span.of_int_s seconds) with
  | Some expire -> Some (start, expire)
  | None -> None

let extensions subject_pubkey auth_pubkey names entity =
  let open X509 in
  let extensions =
    let auth = Some (Public_key.id auth_pubkey), General_name.empty, None in
    Extension.(add Subject_key_id (false, Public_key.id subject_pubkey)
                 (singleton Authority_key_id (false, auth)))
  in
  let extensions = match names with
    | [] -> extensions
    | _ ->
      Extension.(add Subject_alt_name
                   (false, General_name.(singleton DNS names)) extensions)
  in

  let leaf_extensions =
    Extension.(add Key_usage (true, [ `Digital_signature ; `Key_encipherment ])
                 (add Basic_constraints (true, (false, None))
                    extensions))
  in
  match entity with
  | `CA ->
    let ku =
      [ `Key_cert_sign ; `CRL_sign ; `Digital_signature ; `Content_commitment ]
    in
    Extension.(add Basic_constraints (true, (true, None))
                 (add Key_usage (true, ku) extensions))
  | `Client ->
    Extension.(add Ext_key_usage (true, [`Client_auth]) leaf_extensions)
  | `Server ->
    Extension.(add Ext_key_usage (true, [`Server_auth]) leaf_extensions)

let sign days key pubkey issuer csr names entity =
  match make_dates days with
  | None -> Error (`Msg "Validity period is too long to express - try a shorter one")
  | Some (valid_from, valid_until) ->
    match key, pubkey with
    | `RSA priv, `RSA pub when Mirage_crypto_pk.Rsa.pub_of_priv priv = pub ->
      let info = X509.Signing_request.info csr in
      let extensions = extensions info.X509.Signing_request.public_key pubkey names entity in
      X509.Signing_request.sign ~valid_from ~valid_until ~extensions csr key issuer
    | _ -> Error (`Msg "public / private keys do not match")

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

