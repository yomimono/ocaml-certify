#!/usr/bin/env ocaml
#use "topfind";;
#require "topkg";;
open Topkg

let () =
  Pkg.describe "certify" @@ fun _c ->
  Ok [
    Pkg.bin "src/csr";
    Pkg.bin "src/selfsign";
    Pkg.bin "src/sign";
  ]