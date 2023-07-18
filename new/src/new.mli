(* --------------------------------------------------------------------------- *)
type group = private {
  pbits : int;
  p     : Z.t;
  g     : Z.t;
}

type group1 = {
  nbits : int;
  nn    : Z.t;	
  lam : Z.t;
}


type key = private {
  group : group;
  key   : Z.t;
             }

type key_list = {
  group : group;
  key   : Z.t list;
             }

type pkey = key_list
type skey = key_list




type keys = private {
  skey : skey;
  pkey : pkey;
		
  
}

type cipher = Z.t * Z.t

(* --------------------------------------------------------------------------- *)
val random_safe_prime : int -> Z.t 

val sample_group : int -> group

(* building a group *)
val mk_group : int -> Z.t -> Z.t -> group

val mk_group1 : int -> Z.t -> group1










