(* --------------------------------------------------------------------------- *)
type group = {
  pbits : int;
  p     : Z.t;
  g     : Z.t;
}

type group1 = {
  nbits  : int;
  nn     : Z.t;
  lam    : Z.t;
}

type key = {
  group : group;
  key   : Z.t;
}

type key_list = {
  group : group;
  key   : Z.t list;
}

type pkey = key_list
type skey = key_list


type keys = {
  skey : skey;
  pkey : pkey;
}



type key1 = {
  group1 : group1;
  key1   : Z.t;
}

type key_list1 = {
  group1 : group1;
  key1   : Z.t list;
}

type pkey1 = key_list1
type skey1 = key_list1


type keys1 = {
  skey1 : skey1;
  pkey1 : pkey1;
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

let mulmn nn x y = Z.(mod) (Z.mul x y) nn

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


let sample1 n =
  let rec aux n p =
    if n = 0 then p
    else
      let b = Random.bool () in
      let q = Z.shift_left p 1 in (* 2p *)
      let q' = if b then Z.succ q  (* 2p + 1 *) else q (* 2p *) in
      aux (n-1) q' in
  if (n <= 0) then raise (Invalid_argument "sample1");
  aux (n) Z.zero



(* Return a random number between 1 and q-1 *)

let rec sample_le nbits q =
  let x = sample nbits in
  if Z.lt Z.zero x && Z.lt x q then x
  else sample_le nbits q

let rec sample1_le nbits q =
  let x = sample1 nbits in
  if Z.lt Z.zero x && Z.lt x q then x
  else sample1_le nbits q



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

(* Generate a composite number s.t. nn = pp * qq with pp and qq being large primes *)

let rec random_rsa nbits =
  let k = (nbits -1)/2 in
  let pp = sample (k) in
  let qq = sample (nbits- 1 - k) in
  let pp = Z.nextprime pp in
  let qq = Z.nextprime qq in
  let nn = Z.mul (pp) (qq) in
  nn, Z.mul (Z.pred pp) (Z.pred qq)

(* lam = \phi (nn) = (pp-1) * (qq-1)  *)

let rec mk_group1 nbits q =
  let nn, lam = random_rsa nbits in
  if Z.lt nn q  then {nbits; nn; lam}
  else raise (Invalid_argument "mk_group1")


(* Sample a lit of random coprime numbers *)

let sample_coprime nbits nn sz1 =
  let rec sample_coprime l p sz =(
    if sz = 0 then l
    else
      let k = sample1_le (nbits -1) (Z.sub nn Z.one) in
      let d = Z.gcd p k in
      let k = Z.div k d in
      let hasinv =
        try
          let _ = Z.powm k (Z.of_int (-1)) nn in
          true
        with _ -> false in
      if Z.equal k Z.one || not hasinv then sample_coprime l p sz
      else(
        sample_coprime (k :: l) (Z.mul k p) (sz - 1)))
  and sample_coprime_start () =
    let k = sample1_le (nbits -1) (Z.sub nn Z.one) in
      sample_coprime [k] k (sz1 - 1) in
  sample_coprime_start ()



(* Key generation *)

let keygen list_coprime  grnn =
  let nbits = grnn.nbits in
  let nn = grnn.nn in
  let h =  sample1_le (nbits - 1) (Z.sub nn Z.one)  in
  let y_list = List.map (fun x -> Z.powm h x nn) list_coprime in
  let h0 = List.nth y_list 0 in
  let n0 = List.nth list_coprime 0 in
  { skey1 = { group1 = grnn; key1 = y_list};
    pkey1 = { group1 = grnn; key1 = list_coprime};
  }, h0, n0, h


(*  Safe encrypt: we consider encoding the message as a quadratic residue  *)

let safe_encrypt gr h pkey1  m =
  let grnn = pkey1.group1 in
  let r = sample_le (gr.pbits - 1) (q gr.p) in
  let z = List.fold_left (fun acc x -> mulmn grnn.lam acc x ) Z.one  pkey1.key1 in
  let x = Z.powm h z  grnn.nn in
  let u = Z.powm gr.g r gr.p in
  let y = Z.powm gr.g x gr.p in
  let encodem =  Z.powm (Z.succ m) (Z.of_int 2) gr.p in
  let v = mulm gr (Z.powm y r gr.p)  encodem in
  (z,u,v)


(*  Decrypt  *)

let decrypt gr grnn n0 h0 (z,u,v) =
  let inv_n0 = Z.powm n0 (Z.neg Z.one ) grnn.lam in
  let n = mulmn grnn.lam z inv_n0 in
  let deckey = Z.powm h0 n grnn.nn in
  let ukey = Z.powm u (deckey) gr.p in
  let invukey = Z.powm ukey (Z.neg Z.one) gr.p in
  let decmsg = mulm gr v invukey in
  decmsg

(*  Decode  *)

let decode gr m =
  let p = gr.p in
  let q = q gr.p in
  let r = Z.powm m (Z.shift_right (Z.succ q) 1) p in
  let m = if Z.leq r q then r else (Z.sub p r) in
  (Z.pred m)


let safe_decrypt gr grnn n0 h0 (z,u,v) =  decode gr ( decrypt  gr grnn n0 h0 (z,u,v))

(* TEST *)

(* Prime order group of 2048 bits *)

let group2048 =
  let pbits = 2048 in
  let p =
    Z.of_string "24925026077872033086982128773144156070930052356895809861577950135418377574211849310999123887205673512775902799452180863503402222525790865125285810105373049146485375560833884845443434718995997758231256538004706350109882402510607255756968312364186124777691604319035505210778290825528949663120103108839230624303144082906306084227530010950176938290649690868524475769150758297253798961128224181216909740158954131464504212465690037069020225425162419949763220461791922610001565328761339635461532922192250378595318305271738480032909215606553859281505806338182942956913983900939570244567193750213549310026628337873757601365267" in
  let g = Z.of_int 4 in
  mk_group pbits p g

(* A composite group < q *)
let grnn =
let nbits = 1023 in
let q = Z.of_string "62761792499517269105000796274199605148448302249132717373318432324855671821204609793579108108759014791938112437526385525048868281473222251632966926075326825992240756195445400173277726417111674121013555429720554951922297679815902092947536820497577060235759815891779121007149231705760989481166501374994643707641" in
mk_group1 nbits q





let _ =
  let l = ( sample_coprime 1023 grnn.lam 100 ) in
  let t = Sys.time() in
  let {pkey1}, h0, n0, h =  keygen l  grnn in 
  Printf.printf "key generation  time: %fs\n" (Sys.time() -. t);

  let t = Sys.time() in
  Format.printf "enter a number :@.";
  let msg = Z.of_string (read_line ()) in
  let (z,u,v) =  safe_encrypt group2048 h  pkey1  msg in
  Format.printf "msg = %s@."  (Z.to_string msg);
  Printf.printf "encryption  time: %fs\n" (Sys.time() -. t);

  let t = Sys.time() in
  let msg' =  safe_decrypt group2048 grnn n0 h0 (z,u,v) in
  Format.printf "decryptedmsg = %s@."  (Z.to_string msg');
  Printf.printf "decryption time: %fs\n" (Sys.time() -. t);






