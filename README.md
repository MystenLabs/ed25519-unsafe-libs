# ed25519-unsafe-libs
List of unsafe ed25519 signature libraries that allow a public api where secret and public key can be provided independently as signing function inputs. Misuse of these public apis can result to private key exposure.

All of the libraries in our analysis are enlisted in [IANIX :: Things that use Ed25519](https://ianix.com/pub/ed25519-deployment.html).

## What is the issue?
Note that normally and according to the related [rfc8032](https://datatracker.ietf.org/doc/html/rfc8032), EdDSA signatures are deterministic, and thus for the same input message to be signed, a unique signature output that includes two elements, a curve point `R` and a scalar `S`, is returned. 

An algorithmic detail is that that signer's public key is invloved in the deterministic computation of the `S` part of the signature only, but not in the `R` value. The latter implies that if an adversary could somehow use the signing function as an Oracle (that expects arbitrary public keys as inputs), then it is possible that for the same message one can get two signatures sharing the same `R` and only differ on the `S` part. Unfortunately, when this happens, one can easily extract the private key; this [StackOverflow post](https://crypto.stackexchange.com/questions/13129) post explains why this is feasible.

That said, public apis should NOT allow a decoupled private/public key-pair as signing input. To circumvent that, many implementations store the public key along with the private key (or seed) and consider the whole keypair as the secret OR they always re-derive the public key inside the signing function. Unfortunately, a large number of existing libraries fail to address this issue by allowing arbitrary public keys as inputs without checking if the input public key corresponds to the input private key.

*Of course, this does not mean that all applications with dependencies to these libraries are prone to key exposure attacks; actually, most are probably safe due to usually not publicly exposing the affected api to their users. On the other hand, even when these apis are not exposed, there are applications with different TCB threat model strategies on how the private and public keys are managed and stored. That said, to prevent this attack, developers should also enforce an integrity protection protocol for the public keys as well.*

Here, we enlist some of the affected libraries along with the related code-references.

![Ed25519 api misuse resulting to key extraction](dalek_api_misuse.jpg?raw=true "Ed25519 api misuse resulting to key extraction")
Fig 1. An example api misuse in the ed25519-dalek Rust crate.

## Affected libraries
* C: Trezor firmware <br />
[https://github.com/trezor/trezor-firmware/blob/master/crypto/ed25519-donna/ed25519.c#L110](https://github.com/trezor/trezor-firmware/blob/master/crypto/ed25519-donna/ed25519.c#L110)

* ASM/C: iroha-ed25519 (Hyperledger Project) <br />
[https://github.com/hyperledger/iroha-ed25519/blob/main/lib/ed25519/ref10/ed25519.c#L27](https://github.com/hyperledger/iroha-ed25519/blob/main/lib/ed25519/ref10/ed25519.c#L27)
and
[https://github.com/hyperledger/iroha-ed25519/blob/main/lib/ed25519/amd64-64-24k-pic/ed25519.c#L30](https://github.com/hyperledger/iroha-ed25519/blob/main/lib/ed25519/amd64-64-24k-pic/ed25519.c#L30)

* C: ed25519-donna (Andrew Moon) <br />
[https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L59](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L59)

* C: ed25519 (Orson Peters) <br />
[https://github.com/orlp/ed25519/blob/master/src/sign.c#L7](https://github.com/orlp/ed25519/blob/master/src/sign.c#L7)

* C: libbrine (Kevin Smith) <br />
[https://github.com/kevsmith/libbrine/blob/master/src/ed25519/sign.c#L7](https://github.com/kevsmith/libbrine/blob/master/src/ed25519/sign.c#L7)

* C++: Ed25519 (ArduinoLibs) <br />
[https://rweather.github.io/arduinolibs/classEd25519.html#a36ecf67b4c5d2d39a31888f56af1f8a5](https://rweather.github.io/arduinolibs/classEd25519.html#a36ecf67b4c5d2d39a31888f56af1f8a5)

* C#: ed25519 (Hans Wolff) <br />
[https://github.com/hanswolff/ed25519/blob/master/Ed25519/Ed25519.cs#L146](https://github.com/hanswolff/ed25519/blob/master/Ed25519/Ed25519.cs#L146)

* C#: Ed25519 (CryptoManiac) <br />
[https://github.com/CryptoManiac/Ed25519/blob/972829ac688847895d5105f19ca1e5777131b421/Chaos.NaCl/Internal/Ed25519Ref10/keypair.cs#L7](https://github.com/CryptoManiac/Ed25519/blob/972829ac688847895d5105f19ca1e5777131b421/Chaos.NaCl/Internal/Ed25519Ref10/keypair.cs#L7)

* Dart: ed25519_dart (Oleksii Semeshchuk) <br />
[https://github.com/semolex/ed25519_dart/blob/master/lib/src/ed25519_dart_base.dart#L200](https://github.com/semolex/ed25519_dart/blob/master/lib/src/ed25519_dart_base.dart#L200)

* Dart: riclava_ed25519 (riclava) <br />
[https://github.com/riclava/ed25519/blob/master/lib/ed25519.dart#L125](https://github.com/riclava/ed25519/blob/master/lib/ed25519.dart#L125)

* Clojure: ed25519 (Kevin Downey) <br />
[https://github.com/hiredman/ed25519/blob/master/src/ed25519/core.clj#L168](https://github.com/hiredman/ed25519/blob/master/src/ed25519/core.clj#L168)

* Elixir: ed25519_ex (Matt Miller) <br />
[https://github.com/mwmiller/ed25519_ex/blob/master/lib/ed25519.ex#L146](https://github.com/mwmiller/ed25519_ex/blob/master/lib/ed25519.ex#L146
)

* Haskell: hs-scraps (Vincent Hanquez) <br />
[https://github.com/vincenthz/hs-scraps/blob/master/Crypto/Signature/Ed25519.hs#L115](https://github.com/vincenthz/hs-scraps/blob/master/Crypto/Signature/Ed25519.hs#L115)

* Java: ed25519-java (k3d3) <br />
[https://github.com/k3d3/ed25519-java/blob/master/ed25519.java#L144](https://github.com/k3d3/ed25519-java/blob/master/ed25519.java#L144)

* Java: ed25519 (Bjorn Arnelid) <br />
[https://github.com/BjornArnelid/ed25519/blob/master/src/ed25519/application/Ed25519.java#L32](https://github.com/BjornArnelid/ed25519/blob/master/src/ed25519/application/Ed25519.java#L32)

* Java: Punisher.NaCl (Arpan Jati) <br />
[https://github.com/arpanj/Punisher.NaCl/blob/c9619ca3028b90d0556c0473e4eba1d429a3744c/Punisher.NaCl/src/Punisher/NaCl/Ed25519Operations.java#L72](https://github.com/arpanj/Punisher.NaCl/blob/c9619ca3028b90d0556c0473e4eba1d429a3744c/Punisher.NaCl/src/Punisher/NaCl/Ed25519Operations.java#L72)

* Java: ED25519 (Mick Michalski) <br />
[https://github.com/michami/ED25519/blob/master/ED25519.java#L60](https://github.com/michami/ED25519/blob/master/ED25519.java#L60)

* Perl: Crypt::Ed25519 (Marc Lehmann) <br />
[https://metacpan.org/release/MLEHMANN/Crypt-Ed25519-0.9/view/Ed25519.pm#$signature-=-Crypt::Ed25519::sign-$message,-$public_key,-$private_key](https://metacpan.org/release/MLEHMANN/Crypt-Ed25519-0.9/view/Ed25519.pm#$signature-=-Crypt::Ed25519::sign-$message,-$public_key,-$private_key)

* Python: ed25519.py (Ed25519 authors) <br />
[https://ed25519.cr.yp.to/python/ed25519.py](https://ed25519.cr.yp.to/python/ed25519.py)

* Python: ed25519 (Python Cryptographic Authority) <br />
[https://github.com/pyca/ed25519/blob/main/ed25519.py#L243](https://github.com/pyca/ed25519/blob/main/ed25519.py#L243)
(*authors mention it’s unsafe against side channels anyway*)

* Python: python-pure25519 (Brian Warner) <br />
[https://github.com/warner/python-pure25519/blob/master/pure25519/eddsa.py#L21](https://github.com/warner/python-pure25519/blob/master/pure25519/eddsa.py#L21)

* Python: nmed25519 (naturalmessage) <br />
[https://github.com/naturalmessage/nmed25519/blob/master/nmed25519.py#L150](https://github.com/naturalmessage/nmed25519/blob/master/nmed25519.py#L150)

* Python: ed25519.py (Shiho Midorikawa) <br />
[https://gist.github.com/elliptic-shiho/f41fd75cc30646a61d7ad63043fdd56e#file-ed25519-py-L77](https://gist.github.com/elliptic-shiho/f41fd75cc30646a61d7ad63043fdd56e#file-ed25519-py-L77)

* Rust: ed25519-dalek (Isis Agora Lovecruft) <br />
[https://github.com/dalek-cryptography/ed25519-dalek/blob/main/src/secret.rs#L399](https://github.com/dalek-cryptography/ed25519-dalek/blob/main/src/secret.rs#L399)

* Python bindings for ed25519-dalek: py-ed25519-bindings <br />
[https://github.com/polkascan/py-ed25519-bindings/blob/master/src/lib.rs#L111](https://github.com/polkascan/py-ed25519-bindings/blob/master/src/lib.rs#L111)

* Swift: ed25519swift (pebble8888) <br />
[https://github.com/pebble8888/ed25519swift/blob/master/Ed25519ref/ed25519s.swift#L120](https://github.com/pebble8888/ed25519swift/blob/master/Ed25519ref/ed25519s.swift#L120)

* threshold-ed25519 — Threshold Signatures using Ed25519 <br />
[https://gitlab.com/unit410/threshold-ed25519/-/blob/main/pkg/ed25519.go#L161](https://gitlab.com/unit410/threshold-ed25519/-/blob/main/pkg/ed25519.go#L161)
