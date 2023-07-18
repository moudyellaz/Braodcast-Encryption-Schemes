(* --------------------------------------------------------------------------- *)
type group = private {
  pbits : int;
  p     : Z.t;
  g     : Z.t;
}

type key = private {
  group : group;
  key   : Z.t;
             }

type key_list = {
  group : group;
  key   : Z.t list;
             }

type pkey = key
type skey = key_list
type hkey = key_list
type gkey = key_list



type keys = private {
  skey : skey;
  pkey : pkey;
  hkey : hkey;
  gkey : gkey;			
  
}

type cipher = Z.t * Z.t

(* --------------------------------------------------------------------------- *)
val random_safe_prime : int -> Z.t 

val sample_group : int -> group

(* building a group *)
val mk_group : int -> Z.t -> Z.t -> group



(* Key generation *)
 
val keygen : int -> group -> keys (* Z.t *) 


