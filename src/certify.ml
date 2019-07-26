open Cmdliner

let default =
  Term.(ret (const (`Help (`Auto, None))))
and default_info =
  let doc = "Certificate signing tools" in
  let man = [ `S "BUGS";
              `P "Submit bugs at https://github.com/yomimono/ocaml-certify";] in
  Term.info "certify" ~doc ~man

let () =
  Term.exit @@
  Term.eval_choice
    (default, default_info)
    [(Sign.sign_t, Sign.sign_info);
     (Selfsign.selfsign_t, Selfsign.selfsign_info);
     (Csr.csr_t, Csr.csr_info)]
