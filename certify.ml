let () = 
  let issuer = "my totally rad self-signed thing \o/" in
  let length = 2048 in
  let filename = "sweet_key.pem" in
  let privkey = `RSA (Nocrypto.Rsa.generate length) in
  (* should be user-set too, but keep in mind we may get Invalid_argument for
                                          nonsense lengths *) 
  (* can extract the public privkey with Nocrypto.rsa.pub_of_priv *)
  let csr = X509.CA.generate "my rad site" privkey in 
  let cert = X509.CA.sign (* at least let user change the valid period *) csr privkey issuer in
  let pem = X509.Encoding.Pem.Cert.to_pem_cstruct1 cert in
  (* make that be a file; how badly does that suck with Pervasives? *)
  let fd = Unix.openfile filename [O_WRONLY] 0o277 in (* TODO: exc handling *)
  let _ = Unix.single_write fd (Cstruct.to_string pem) 0 (Cstruct.len pem) in
  (* seems kind of silly to get a return code when we're also supposed to get a bunch of
     Unix exceptions *)
  Printf.printf "key written to %s\n%!" filename

