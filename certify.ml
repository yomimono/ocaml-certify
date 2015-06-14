type entropy_result = 
  | Ok of Cstruct.t
  | Read_error of string

type write_result =
  | Ok
  | Write_error of string

let () = 
  let issuer = "my totally rad self-signed thing \\o/" in
  let length = 2048 in
  let filename = "sweet_key.pem" in
  let entropy_src = "/dev/urandom" in
  let reqd_entropy_amount = 1 in
  let get_entropy how_much : entropy_result = 
    try
      let entropy_fd = Unix.openfile entropy_src [Unix.O_RDONLY] 0o000 in
      let bytes = Bytes.create how_much in
      let read_entropy = Unix.read entropy_fd bytes 0 how_much in
      let () = Unix.close entropy_fd in
      if (read_entropy = how_much) 
      then Ok (Cstruct.of_string bytes)
      else
        Read_error (
          Printf.sprintf "required amount of entropy (%d bytes) wasn't available at %s\n"
            reqd_entropy_amount entropy_src)
    with
    | Unix.Unix_error(Unix.ENOENT, _, _)
    | Unix.Unix_error(Unix.ENODEV, _, _) -> 
      Read_error (Printf.sprintf "source %s doesn't exist -- try another?" entropy_src)
  in
  let write_cert dest pem =
    try 
      let fd = Unix.openfile dest [Unix.O_WRONLY; Unix.O_CREAT] 0o600 in
      let _written_bytes = Unix.single_write fd (Cstruct.to_string pem) 0 (Cstruct.len pem) in
      (* seems kind of silly to get a return code when we're also supposed to get a bunch of
         Unix exceptions *)
      Unix.close fd;
      (Ok : write_result)
    with
    | Unix.Unix_error (Unix.EACCES, _, _) -> 
      Write_error (Printf.sprintf "Permission denied writing %s" dest)
    | Unix.Unix_error (Unix.EISDIR, _, _) ->
      Write_error (Printf.sprintf "%s already exists and is a directory" dest)
    | Unix.Unix_error (Unix.ENOENT, _, _) ->
      Write_error (Printf.sprintf "Part of the path %s doesn't exist" dest)
    | Unix.Unix_error (Unix.ENOSPC, _, _) ->
      Write_error "No space left on device"
    | Unix.Unix_error (Unix.EROFS, _, _) ->
      Write_error (Printf.sprintf "%s is on a read-only filesystem" dest)
  in
  match (get_entropy reqd_entropy_amount) with
  | Read_error str -> 
    Printf.eprintf "%s\n" str;
    exit 1
  | Ok entropy -> 
    Nocrypto.Rng.reseed entropy;
    let privkey = `RSA (Nocrypto.Rsa.generate length) in
    (* should be user-set too, but keep in mind we may get Invalid_argument for
                                          nonsense lengths *) 
    (* can extract the public privkey with Nocrypto.rsa.pub_of_priv *)
    let csr = X509.CA.generate "my rad site" privkey in 
    let cert = X509.CA.sign (* at least let user change the valid period *) csr privkey issuer in
    let pem = X509.Encoding.Pem.Cert.to_pem_cstruct1 cert in
    match write_cert filename pem with
    | Ok -> Printf.printf "key written to %s\n%!" filename
    | Write_error str -> Printf.eprintf "%s" str; exit 1
