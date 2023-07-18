# Braodcast-Encryption-Schemes
In this project, we implement three existing broadcast encryption schemes: ElGamal baseline, Boneh-Franklin, and a new scheme based on ElGamal.


For testing, you can run the following code in terminal:

cd folder_location

eval $(opam env)

ocamlbuild -use-ocamlfind -I src -I lib src/filename.native

Note that only Zarith package is needed in order to compile Bignum.
