# Broadcast Encryption Scheme in Ocaml

## Introduction

In this project, two existing broadcast encryption schemes are implemented: ElGamal baseline, Boneh-Franklin. In addition, a new scheme based on ElGamal is implemented as well.

## Usage


For testing, you can run the following code in terminal:

1. `d folder_location`

2. `eval $(opam env)`

3. `ocamlbuild -use-ocamlfind -I src -I lib src/filename.native`

Note that only Zarith package is needed in order to compile Bignum.