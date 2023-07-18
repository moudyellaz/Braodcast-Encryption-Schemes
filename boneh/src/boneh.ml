(* --------------------------------------------------------------------------- *)
type group = {
  pbits : int;
  p     : Z.t;
  g     : Z.t;
}

type key = {
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





type keys = {
  skey : skey;
  pkey : pkey;
  hkey : hkey;
  gkey : gkey;
 
}

type cipher = Z.t * Z.t

(* --------------------------------------------------------------------------- *)

(* [q p] returns q = p/2*)
let q p = Z.shift_right p 1

(* [quad p q x] tests if x is a quadratic residue in p *)
let quad p x = Z.equal ( Z.powm x (q p) p) Z.one 

(* multiplication modulo *)

let mulm gr m n = Z.(mod) (Z.mul m n) gr.p

let mulmq q x y = Z.(mod) (Z.mul x y) q

(* --------------------------------------------------------------------------- *)

(* Return a random number of [n] bits *)
let _ = Random.self_init ()

let sample n =
  let rec aux n p = 
    if n = 0 then p
    else
      let b = Random.bool () in
      let q = Z.shift_left p 1 in (* 2p *)
      let q' = if b then Z.succ q  (* 2p + 1 *) else q (* 2p *) in
      aux (n-1) q' in
  if (n <= 0) then raise (Invalid_argument "sample");
  aux (n-1) Z.one

(* Return a random number between 1 and q-1 *)

let rec sample_le nbits q =
  let x = sample nbits in
  if Z.lt Z.zero x && Z.lt x q then x
  else sample_le nbits q



exception Check_safe_prime

(* Ensure that p is a safe prime of nbits *)

let check_safe_prime nbits p =
  if not (Z.leq Z.zero p && Z.numbits p = nbits &&
          Z.probab_prime (q p) 10 <> 0 && Z.probab_prime p 10 <> 0) then
    raise Check_safe_prime

(* Generate a safe prime order group *)

let rec random_safe_prime nbits =
  let q = sample (nbits - 1) in
  let q = Z.nextprime q in
  let p = Z.succ (Z.shift_left q 1) in
  try check_safe_prime nbits p; p
  with Check_safe_prime -> random_safe_prime nbits

let mk_group pbits p g =
  let sp = try check_safe_prime pbits p; true with Check_safe_prime -> false in
  if sp && quad p g then { pbits; p; g }
  else raise (Invalid_argument "mk_group")

let generator p =
  let g = Z.of_int 4 in
  if not (Z.lt g p) then raise (Invalid_argument "generator");
  g

let sample_group pbits =
  let p = random_safe_prime pbits in
  let g = generator p in
  { pbits; p; g }

exception BadElem


(* Key generation *)

let keygen n gr =
  let pbits = gr.pbits in
  let p = gr.p in
  let q = q gr.p in
  let g = gr.g in
  let alfa_list = List.init n (fun _ -> sample_le (pbits - 1) q) in
  let r_list = List.init n ( fun _ ->  sample_le (pbits - 1) q) in
  let h_list = List.map (fun r -> Z.powm g r p) r_list in
  let y = List.fold_left2 (fun acc h alfa -> mulm gr acc (Z.powm h alfa p)) Z.one h_list alfa_list in
  let alfa0 = List.nth alfa_list 0 in
  let inv_alfa0 = Z.powm alfa0 (Z.pred  (Z.pred q) ) q  in
  let gamma0_list = List.map (fun alfa -> mulmq q alfa inv_alfa0) alfa_list in (* list of alfa/alfa0 *)
  { skey = { group = gr; key = alfa_list};
    pkey = { group = gr; key = y };
    hkey = { group = gr; key = h_list};
    gkey = {group = gr; key = gamma0_list};
  }




(*   Safe Encrypt: we consider encoding the message as a quadratic residue    *)

let safe_encrypt (pk : pkey) h_list m =
  let gr = pk.group in
  let r = sample_le (gr.pbits - 1) (q gr.p) in
  let encodem =  Z.powm (Z.succ m) (Z.of_int 2) gr.p in
  ((List.map (fun h -> Z.powm h r gr.p) h_list),  mulm gr (Z.powm pk.key r gr.p) encodem)




(*  Decode  *)
let decode gr m =
  let p = gr.p in
  let q = q gr.p in
  let r = Z.powm m (Z.shift_right (Z.succ q) 1) p  in
  let m = if Z.leq r q then r else (Z.sub p r) in
  (Z.pred m)




 (*  Decrypt *)

let decrypt gkey alfa (u,v) =
  let gr = gkey.group in
  let bigu = List.fold_left2 (fun acc hri gammai -> mulm gr acc (Z.powm hri gammai gr.p)) Z.one u gkey.key in
  let bigualfa = Z.powm  bigu (Z.neg alfa) gr.p in
  let decmsg= mulm gr v bigualfa in
  decmsg


(* Safe Decrypt: we decrypt the message then we decode it  *)

let safe_decrypt gamma0_list alfa_0 (u,v) =  decode gamma0_list.group (decrypt  gamma0_list alfa_0 (u,v))





(*  Testing the key generation, the encryption and decryption  *)


let group1024 =
  let pbits = 1024 in
  let p =
    Z.of_string "125523584999034538210001592548399210296896604498265434746636864649711343642409219587158216217518029583876224875052771050097736562946444503265933852150653651984481512390890800346555452834223348242027110859441109903844595359631804185895073640995154120471519631783558242014298463411521978962333002749989287415283" in
  let g = Z.of_int 4 in
  mk_group pbits p g



(* Function keygen takes the number of elements and the group *)


let _ =

let t = Sys.time() in

let {pkey; skey; hkey; gkey} = keygen 100 group1024 in
Printf.printf "key generation time: %fs\n" (Sys.time() -. t);


let t = Sys.time() in
Format.printf "enter a number :@.";
let msg = Z.of_string (read_line ()) in
let (u, v) = (safe_encrypt pkey hkey.key msg) in
Printf.printf "encryption time: %fs\n" (Sys.time() -. t);


let alfa_0 = (List.nth skey.key 0) in
let t = Sys.time() in
let msg' = safe_decrypt  gkey alfa_0  (u,v) in
Format.printf "decryptedmsg = %s@."  (Z.to_string msg');
Printf.printf "decryption time: %fs\n" (Sys.time() -. t);



