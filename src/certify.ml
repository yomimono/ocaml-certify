open Cmdliner

let default =
  Term.(ret (const (`Help (`Auto, None))))
and info =
  let doc = "Certificate signing tools" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Cmd.info "certify" ~doc ~man

let () =
  Stdlib.exit @@
  Cmd.eval
  (Cmd.group info ~default
    [Sign.sign_t;
     Selfsign.selfsign_t;
     Csr.csr_t])
