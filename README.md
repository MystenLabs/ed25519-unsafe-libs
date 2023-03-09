# ed25519-unsafe-libs
List of potentially unsafe ed25519 signature libraries that allow a public api where secret and public key can be provided independently as signing function inputs. Misuse of these public apis can result to private key exposure.

Μost of the repositories in our analysis are enlisted in [IANIX :: Things that use Ed25519](https://ianix.com/pub/ed25519-deployment.html).

Number of impacted libraries: 47 <br />
Number of libraries that fixed the issue after the announcement: 7 <br />
*last updated: Mar 09, 2023*

## Proof of Concept implementations that demonstrate this potential exploit:
* Rust: [ed25519-chalkias-exploit](https://github.com/MystenLabs/ed25519-unsafe-libs/tree/main/ed25519-chalkias-exploit)
* Python: [Ed25519 Vulnerability in Python](https://asecuritysite.com/eddsa/ed03), *Buchanan, William J (2022). Ed25519 Vulnerability in Python (Recovering Private Key). Asecuritysite.com.*

## Talks:
* Invited talk to USA's National Institute of Standards and Technology (NIST) Crypto Reading Club: [slides - Taming the Many EdDSAs](https://csrc.nist.gov/csrc/media/Presentations/2023/crclub-2023-03-08/images-media/20230308-crypto-club-slides--taming-the-many-EdDSAs.pdf), *Konstantinos Chalkias, François Garillot, Valeria Nikolaenco (2023). Taming the Many EdDSAs & Ed25519 Signing Attacks.*

## News and social network coverage of this attack
* [NIST Crypto Reading Club](https://csrc.nist.gov/presentations/2023/crclub-2023-03-08) "Taming the Many EdDSAs" *(March 08, 2023)*
* [The Daily Swig](https://portswigger.net/daily-swig/dozens-of-cryptography-libraries-vulnerable-to-private-key-theft) "Dozens of cryptography libraries vulnerable to private key theft" *(June 28, 2022)*
* [Risky Biz News](https://riskybiznews.substack.com/p/risky-biz-news-hackers-hit-iranian#%C2%A7vulnerabilities-and-bug-bounty) "New crypto vulnerability: Tens of cryptography libraries have misimplemented the Ed25519 digital signature algorithm" *(June 28, 2022)*
* [SafeHeron blogpost](https://blog.safeheron.com/blog/safeheron-originals/analysis-on-ed25519-use-risks-your-wallet-private-key-can-be-stolen) "Analysis on Ed25519 Use Risks: Your Wallet Private Key Can Be Stolen" *(June 17, 2022)*
* [kryptera.se](https://kryptera.se/sarbarhet-i-flertalet-ed25519-bibliotek) "Vulnerability in most ed25519 libraries" (in Swedish) *(June 29, 2022)*
* [Difesa e Sicurezza](https://www.difesaesicurezza.com/cyber/cybersecurity-importante-vulnerabilita-sulle-librerie-ed25519/) & [Yoroi](https://yoroi.company/warning/librerie-crittografiche-ed25519-potenzialmente-non-sicure) "Librerie crittografiche ed25519 potenzialmente non sicure" (in Italian) *(July 1 & June 29, 2022)*
* [Medium post by Prof Bill Buchanan OBE](https://medium.com/asecuritysite-when-bob-met-alice/ed25519-is-great-but-9f75eab65f) "Ed25519 is Great, But ..." *(July 1, 2022)* 
* [Reddit r/crypto](https://www.reddit.com/r/crypto/comments/vfl2se/initial_impact_report_about_this_weeks_eddsa/) *(best post of the month - June 18, 2022)*
* [Reddit r/cryptography](https://www.reddit.com/r/cryptography/comments/vextlk/40_unsafe_ed25519_libs_where_private_key_can_be/) *(June 17, 2022)*
* Interesting tweets:
    - [tweet 1](https://twitter.com/kostascrypto/status/1535579208960790528) (by Kostas Kryptos - "The original 26 vulnerable libs")
    - [tweet 2](https://twitter.com/kostascrypto/status/1538351278413058048) (by Kostas Kryptos - "Aftermath of the 40 vulnerable libs")
    - [tweet 3](https://twitter.com/campuscodi/status/1541927414648827905) (by Catalin Cimpanu - "40 cryptography libraries are impacted by same Ed25519 misimplementation")
    - [tweet 4](https://twitter.com/kennyog/status/1538768590404452353) (by Kenny Paterson - "Potential for widespread EdDSA private key recovery, cf. [http://kopenpgp.com](http://kopenpgp.com) where same vector exploited in OpenPGP libs")
    - [tweet 5](https://twitter.com/EllipticKiwi/status/1538632666571894784) (by Steven Galbraith - "A hazard for deterministic signatures: better check it is the correct public key!")
    - [tweet 6](https://twitter.com/riyazdf/status/1538352392164364288) (by Riyaz Faizullabhoy - "If you’re using EdDSA in prod please take a look")
    - [tweet 7](https://twitter.com/bpreneel1/status/1542065725174587397) (by Bart Preneel - "Reminder that implementing cryptographic algorithms securely and correctly is hard").

## What is the issue?
Note that normally and according to the related [rfc8032](https://datatracker.ietf.org/doc/html/rfc8032), EdDSA signatures are deterministic, and thus for the same input message to be signed, a unique signature output that includes two elements, a curve point `R` and a scalar `S`, is returned. 

An algorithmic detail is that that signer's public key is involved in the deterministic computation of the `S` part of the signature only, but not in the `R` value. The latter implies that if an adversary could somehow use the signing function as an Oracle (that expects arbitrary public keys as inputs), then it is possible that for the same message one can get two signatures sharing the same `R` and only differ on the `S` part. Unfortunately, when this happens, one can easily extract the private key; this [StackOverflow post](https://crypto.stackexchange.com/questions/13129) post explains why this is feasible.

That said, public apis should NOT allow a decoupled private/public key-pair as signing input. To circumvent that, many implementations store the public key along with the private key (or seed) and consider the whole keypair as the secret OR they always re-derive the public key inside the signing function. Unfortunately, a large number of existing libraries fail to address this issue by allowing arbitrary public keys as inputs without checking if the input public key corresponds to the input private key.

*Of course, this does not mean that all applications with dependencies to these libraries are prone to key exposure attacks; actually, most are probably safe due to usually not publicly exposing the affected api to their users and coupling their pub/priv key pair just before the `sign` invocation. On the other hand, even when these apis are not exposed, there are applications with different TCB threat model strategies on how the private and public keys are managed and stored. That said, to prevent this attack, developers should also enforce an integrity protection protocol for the public keys as well.*

Here, we enlist some of the affected libraries along with the related code-references.

![Ed25519 api misuse resulting to key extraction](dalek_api_misuse.jpg?raw=true "Ed25519 api misuse resulting to key extraction")
Fig 1. An example api misuse in the ed25519-dalek Rust crate.

## Affected libraries

* C: OpenGNB <br />
[https://github.com/gnbdev/opengnb/blob/master/libs/ed25519/sign.c#L7](https://github.com/gnbdev/opengnb/blob/master/libs/ed25519/sign.c#L7)

* C: GNU Nettle <br />
[https://github.com/gnutls/nettle/blob/fe7ae87d1b837e82f7c7968b068bca7d853a4cec/ed25519-sha512-sign.c#L43](https://github.com/gnutls/nettle/blob/fe7ae87d1b837e82f7c7968b068bca7d853a4cec/ed25519-sha512-sign.c#L43)

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
[https://github.com/mwmiller/ed25519_ex/blob/master/lib/ed25519.ex#L146](https://github.com/mwmiller/ed25519_ex/blob/master/lib/ed25519.ex#L146)

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

* Java: vRallev/ECC-25519 (Ralf Wondratschek) <br />
[https://github.com/vRallev/ECC-25519/blob/master/ECC-25519-Java/src/main/java/net/vrallev/java/ecc/Ecc25519Helper.java#L102](https://github.com/vRallev/ECC-25519/blob/master/ECC-25519-Java/src/main/java/net/vrallev/java/ecc/Ecc25519Helper.java#L102)

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

* Python: bindings for ed25519-dalek: py-ed25519-bindings <br />
[https://github.com/polkascan/py-ed25519-bindings/blob/master/src/lib.rs#L111](https://github.com/polkascan/py-ed25519-bindings/blob/master/src/lib.rs#L111)

* Swift: ed25519swift (pebble8888) <br />
[https://github.com/pebble8888/ed25519swift/blob/master/Ed25519ref/ed25519s.swift#L120](https://github.com/pebble8888/ed25519swift/blob/master/Ed25519ref/ed25519s.swift#L120)

* JS: supercop.js (1p6 Flynx) <br />
[https://github.com/1p6/supercop.js/blob/master/index.js#L29](https://github.com/1p6/supercop.js/blob/master/index.js#L29)

* JS: substack/ed25519-supercop (James Halliday) <br />
[https://github.com/substack/ed25519-supercop/blob/master/index.js#L3](https://github.com/substack/ed25519-supercop/blob/master/index.js#L3)

* C: libeddsa (Philipp Lay) <br />
[https://github.com/phlay/libeddsa/blob/master/lib/ed25519-sha512.c#L85](https://github.com/phlay/libeddsa/blob/master/lib/ed25519-sha512.c#L85)

* C#: SommerEngineering/Ed25519 (Thorsten Sommer) <br />
[https://github.com/SommerEngineering/Ed25519/blob/master/Ed25519/Signer.cs#L80](https://github.com/SommerEngineering/Ed25519/blob/master/Ed25519/Signer.cs#L80)

* CUDA: ChorusOne/solanity <br />
[https://github.com/ChorusOne/solanity/blob/master/src/cuda-ecc-ed25519/sign.cu#L10](https://github.com/ChorusOne/solanity/blob/master/src/cuda-ecc-ed25519/sign.cu#L10)

* C: ncme/c25519 (Daniel Beer and Nikolas Rösener) <br />
[https://github.com/ncme/c25519/blob/master/src/edsign.c#L115](https://github.com/ncme/c25519/blob/master/src/edsign.c#L115)

* C: luazen (Phil Leblanc) <br />
[https://github.com/philanc/luazen/blob/master/src/x25519.c#L508](https://github.com/philanc/luazen/blob/master/src/x25519.c#L508) (*authors modified the function to accept pk instead of the original nacl 64-byte sk which includes pk as the last 32 bytes*)

* C++: amber (Pelayo Bernedo) <br />
[https://github.com/bernedogit/amber/blob/master/src/group25519.cpp#L1661](https://github.com/bernedogit/amber/blob/master/src/group25519.cpp#L1661)

* C: FLD ECC AVX2 (Armando Faz-Hern\'{a}ndez and Julio L\'{o}pez and Ricardo Dahab) <br />
[https://github.com/armfazh/fld-ecc-vec/blob/master/src/sign255.c#L391](https://github.com/armfazh/fld-ecc-vec/blob/master/src/sign255.c#L391)

* Elixir: mwmiller/ed25519_ex (Matt Miller) <br />
[https://github.com/mwmiller/ed25519_ex/blob/master/lib/ed25519.ex#L146](https://github.com/mwmiller/ed25519_ex/blob/master/lib/ed25519.ex#L146)(*Public key is optional. Per author's comment: if only the secret key is provided, the public key will be derived therefrom. This adds significant overhead*)

* PHP (C wrapper): php-ed25519-ext <br />
[https://github.com/encedo/php-ed25519-ext/blob/master/ed25519-ext.c#L93](https://github.com/encedo/php-ed25519-ext/blob/master/ed25519-ext.c#L93)

* Nim: niv/ed25519.nim (Bernhard Stöckner) <br />
[https://github.com/niv/ed25519.nim/blob/master/ed25519.nim#L26](https://github.com/niv/ed25519.nim/blob/master/ed25519.nim#L26)

* Typescript: mipher (Marco Paland) <br />
[https://github.com/mpaland/mipher/blob/master/src/x25519.ts#L936](https://github.com/mpaland/mipher/blob/master/src/x25519.ts#L936)

* Lua: LuaMonocypher <br />
[https://github.com/philanc/luamonocypher/blob/main/src/luamonocypher.c#L268](https://github.com/philanc/luamonocypher/blob/main/src/luamonocypher.c#L268)

* Crystal: monocypher.cr <br />
[https://github.com/konovod/monocypher.cr/blob/master/src/monocypher.cr#L39](https://github.com/konovod/monocypher.cr/blob/master/src/monocypher.cr#L39)

* Python: py_ssh_keygen_ed25519 (Péter Szabó) <br />
[https://github.com/pts/py_ssh_keygen_ed25519/blob/master/ed25519_compact.py#L128](https://github.com/pts/py_ssh_keygen_ed25519/blob/master/ed25519_compact.py#L128) (*Public key is optional*)

* Javascript: KinomaJS <br />
[https://github.com/Kinoma/kinomajs/blob/701879d37e7fe5001420e0053cd60df6b91e4553/xs6/extensions/crypt/crypt_ed25519.js#L92](https://github.com/Kinoma/kinomajs/blob/701879d37e7fe5001420e0053cd60df6b91e4553/xs6/extensions/crypt/crypt_ed25519.js#L92) (*Public key is optional*)

* Haskell: gen-ed25-keypair <br />
[https://github.com/awakesecurity/gen-ed25-keypair](https://github.com/awakesecurity/gen-ed25-keypair)

* C: horse25519 (Yawning Angel) <br />
[https://github.com/Yawning/horse25519/blob/master/src/ref10/sign.c#L7](https://github.com/Yawning/horse25519/blob/master/src/ref10/sign.c#L7) *Note: This repo includes a copy of djb's ref10 ed25519 implementation lifted from supercop to avoid pulling in another dependency, but the intention is to provide a standalone executable that does ed25519 vanity keypair generation. While it does use the API in an odd way, this is intentional as it's already doing something extremely exotic and unusual with respect to key generation and the lib is not meant to be used for signing.*

## Fixed libraries
* C: Trezor firmware <br />
Fixed in this PR: [https://github.com/trezor/trezor-firmware/pull/2349](https://github.com/trezor/trezor-firmware/pull/2349) *(Fix merged on June 27, 2022)*

* Java: ed25519-elisabeth (Jack Grigg) <br />
Fixed in this commit: [https://github.com/cryptography-cafe/ed25519-elisabeth/commit/49545ce47d550fed807522dff86546c812ccbbac](https://github.com/cryptography-cafe/ed25519-elisabeth/commit/49545ce47d550fed807522dff86546c812ccbbac) *(Fix merged on June 19, 2022)*

* C: Harbour (Viktor Szakats) <br />
Fixed in this commit: [https://github.com/vszakats/hb/commit/bae610b63d35c6c1793d94a3bf9467c3b1eded18](https://github.com/vszakats/hb/commit/bae610b63d35c6c1793d94a3bf9467c3b1eded18) *(Fix merged on June 30, 2022)*

* Rust/Wasm: polkadot-js/wasm <br />
Fixed in this PR: [https://github.com/polkadot-js/wasm/pull/381/files](https://github.com/polkadot-js/wasm/pull/381/files) *(Fix merged on July 3, 2022)*

* C: horse25519 (Yawning Angel) <br />
Fixed in this PR: [https://github.com/Yawning/horse25519/pull/3](https://github.com/Yawning/horse25519/pull/3) *(Fix merged on August 15, 2022)*

* Erlang: erlang-libdecaf <br />
Fixed in this commit: [https://github.com/potatosalad/erlang-libdecaf/commit/16ba07ea122660e95f6cfa9107e28ed58bada713](https://github.com/potatosalad/erlang-libdecaf/commit/16ba07ea122660e95f6cfa9107e28ed58bada713). Logic addressed in this issue: [ed25519-unsafe-libs/issues/7](https://github.com/MystenLabs/ed25519-unsafe-libs/issues/7) *(Fix merged on August 28, 2022)*

* C: Monocypher (Loup Vaillant) <br />
Fixed in this commit: [https://github.com/LoupVaillant/Monocypher/commit/da7b5407d20329f21a53ea993f516fb55e2f5e26](https://github.com/LoupVaillant/Monocypher/commit/da7b5407d20329f21a53ea993f516fb55e2f5e26) *(Fix merged on February 27, 2023)*

## False Positives (probably safe)
Libraries originally reported as vulnerable, but removed from the list based on community feedback.

* Go: threshold-ed25519 — Threshold Signatures using Ed25519 <br />
[https://gitlab.com/unit410/threshold-ed25519/-/blob/main/pkg/ed25519.go#L161](https://gitlab.com/unit410/threshold-ed25519/-/blob/main/pkg/ed25519.go#L161) -> see report [https://github.com/MystenLabs/ed25519-unsafe-libs/pull/9](https://github.com/MystenLabs/ed25519-unsafe-libs/pull/9) *(reported on Oct 27, 2022 by nitronit)*
