let () = 
  let issuer = "my totally rad self-signed thing \o/" in
  let length = 2048 in
  let filename = "sweet_key.pem" in
  let privkey = `RSA (Nocrypto.Rsa.generate length) in
  let entropy_src = "/dev/random" in
  let entropy src = 
    let entropy_fd = Unix.openfile src [Unix.O_RDONLY] 0o777 in
    let bytes = Bytes.create 1 in
    let entropy = Unix.read entropy_fd bytes 0 1 in
    let _ = Unix.close entropy_fd in
    if entropy = 1 then Cstruct.of_string bytes else 
      raise (failwith "Couldn't read entropy!")
  in
  (* make and seed an Rng *)
  let rng = Nocrypto.Fortuna.create () in
  Nocrypto.Fortuna.reseed rng (entropy entropy_src);
  (* should be user-set too, but keep in mind we may get Invalid_argument for
                                          nonsense lengths *) 
  (* can extract the public privkey with Nocrypto.rsa.pub_of_priv *)
  let csr = X509.CA.generate "my rad site" privkey in 
  let cert = X509.CA.sign (* at least let user change the valid period *) csr privkey issuer in
  let pem = X509.Encoding.Pem.Cert.to_pem_cstruct1 cert in
  (* make that be a file; how badly doeUnix.s that suck with Pervasives? *)
  let fd = Unix.openfile filename [Unix.O_WRONLY] 0o277 in (* TODO: exc handling *)
  let _ = Unix.single_write fd (Cstruct.to_string pem) 0 (Cstruct.len pem) in
  (* seems kind of silly to get a return code when we're also supposed to get a bunch of
     Unix exceptions *)
  Unix.close fd;
  Printf.printf "key written to %s\n%!" filename

