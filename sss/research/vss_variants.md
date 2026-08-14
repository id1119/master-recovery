# Verifiable Secret Sharing (VSS) improvements over plain Shamir — research survey

Implementation-ready notes on the major VSS constructions, from Feldman (1987) through
KZG/NI-VSS (2023-2025). Baseline for every comparison is **plain Shamir secret sharing**
(Shamir, "How to share a secret", CACM 22(11), 1979; DOI 10.1145/359168.359176): a
(t+1)-out-of-n threshold scheme in which a dealer picks a random degree-$t$ polynomial
$f(x) = a_0 + a_1 x + \dots + a_t x^t$ over a finite field $\mathbb{F}_q$, sets $a_0 = s$,
and hands $P_i$ the private share $s_i = f(i)$. Any $t+1$ shares Lagrange-interpolate back to
$s = \sum_{i \in S} s_i \cdot \lambda_i$, $\lambda_i = \prod_{j \in S, j\neq i} j/(j-i) \bmod q$.
Shamir has **zero protection** against a corrupt dealer (inconsistent shares) or corrupt
shareholders (wrong shares at reconstruction); it also leaks nothing only if the dealer is
honest. All of the schemes below add some form of *verifiability*, at the price of a
number-theoretic assumption, extra rounds, or extra communication.

---

## 1. Feldman VSS (1987)

- **Reference.** Paul Feldman, *"A Practical Scheme for Non-interactive Verifiable Secret Sharing"*,
  28th IEEE Symposium on Foundations of Computer Science (FOCS), 1987, pp. 427-437.
  DOI 10.1109/SFCS.1987.4. Full text: https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf
- **Problem it solves vs plain Shamir.** Feldman adds the first *non-interactive* check that the
  dealer's shares are consistent with a single degree-$t$ polynomial, and (because the check
  works on the released values) that shareholders at reconstruction are submitting correct shares.
  The dealer broadcasts a commitment to every polynomial coefficient; each shareholder can verify
  its own share with one modular equation and no interaction. Plain Shamir gives the receiver no
  way to tell a bad share from a good one. Security is computational: share-commitments are
  *binding* under the discrete-logarithm assumption, and (as a price) hiding *of the secret* is
  also only computational because $g^{a_0} = g^s$ is public.
- **Construction.** Work in $\mathbb{Z}_p^*$ where $p, q$ are primes with $q \mid p-1$ and
  $g \in \mathbb{Z}_p^*$ of order $q$. Everything secret lives in $\mathbb{Z}_q$; all public
  values are powers of $g$ modulo $p$.
  1. Dealer picks secret $s \in \mathbb{Z}_q$ and random $a_1,\dots,a_t \in \mathbb{Z}_q$, sets
     $f(x) = s + a_1 x + \dots + a_t x^t \pmod q$.
  2. Dealer broadcasts commitments $C_j = g^{a_j} \bmod p$ for $j = 0,\dots,t$ (with $a_0 = s$).
  3. Dealer privately sends each $P_i$ the share $s_i = f(i) \bmod q$.
  4. $P_i$ accepts iff
     $$g^{s_i} \equiv \prod_{j=0}^{t} C_j^{\,i^{\,j}} \pmod p .$$
     (Everything on the right is public, so this is a pure local check.)
  5. Reconstruction: every revealed share is first re-checked with the same equation; only
     valid shares are Lagrange-interpolated. The interpolation happens in $\mathbb{Z}_q$ (the
     exponents), so the dealer's commitments pin the polynomial coefficients
     $(g^{a_0},\dots,g^{a_t})$ exactly; two consistent share-sets can differ only by shares
     $s_i$ that satisfy the equation, which uniquely fixes $f \bmod q$.
- **Cost vs Shamir.** Communication: Shamir needs $n$ private field elements plus 0 public data;
  Feldman adds a broadcast of $(t+1)$ group elements ($C_0,\dots,C_t$) — integers $\bmod p$,
  about $t+1$ times larger than a share. Computation: the dealer's extra cost is $t+1$ modular
  exponentiations plus $n$ evaluations of a degree-$t$ polynomial; each shareholder pays $O(t)$
  exponentiations (evaluate $\prod_j C_j^{i^j}$) instead of $O(1)$. The 2-round formulation by
  Feldman in the same paper shows communication $O(nk)$ and computation
  $O((n\log n + k)(nk\log k))$ for a security parameter $k$. Asymptotically: Feldman is "Shamir
  + one broadcast + O(tn) exponentiations".
- **Composability.** *Works well with:* robust reconstruction (verify-then-interpolate),
  dealer-funded proactive refresh (each party refresh-share plus dealer commits to the zero-sum
  refresh polynomial — see Herzberg, Jarecki, Krawczyk, Yung, CRYPTO '95,
  DOI 10.1007/3-540-44750-4_27), and honest-dealer MPC. *Does not directly work as a privacy
  primitive in MPC*: it reveals $g^s$, so the shared secret is only computationally hidden.
  *Heavily used as the engine of DKG*: the named "Joint-Feldman DKG" (= Pedersen's DKG from
  CRYPTO '91) runs $n$ parallel Feldman VSS instances and sums the qualified polynomials. That
  combination has a **known distributional flaw**. Gennaro, Jarecki, Krawczyk, Rabin
  ("Secure Distributed Key Generation for Discrete-Log Based Cryptosystems", EUROCRYPT '03 and
  J. Cryptology 20(1):51-83, 2007, DOI 10.1007/s00145-006-0347-3) show an attacker that biases
  the joint key by disqualifying dealers *after* seeing their $g^{z_i}$ commitments; GJKR's fixed
  DKG uses Pedersen VSS (Section 2) for the commitment phase and a final Feldman round to expose
  $g^x$. So: fine as a black-box VSS, fragile when embedded in a DKG without the GJKR fix.
- **Implementation pitfalls.**
  - *Subgroup checks:* always verify $g \ne 1$ and $g^q \equiv 1 \pmod p$, and for each
    commitment check $C_j^q \equiv 1 \pmod p$; otherwise a malformed $C_j$ in a small subgroup
    enables Pohlig-Hellman-style leakage of $a_j$. Never work in the full $\mathbb{Z}_p^*$.
  - *Modulus confusion:* shares and polynomial arithmetic live in $\mathbb{Z}_q$ (exponents);
    at no point treat a share as an element of $\mathbb{Z}_p^*$. A classic bug is interpolating
    over $p$ instead of $q$.
  - Compute $i^j$ in $\mathbb{Z}_q$ (share points as field elements; use $i \in \{1,\dots,n\}$,
    never $0$). Watch out: the check exponent $i^j$ must be reduced mod $q$, then raise $C_j$
    to it mod $p$.
  - Since $C_0 = g^s$ is public, this scheme is **not** suitable for sharing secrets that must
    stay unconditionally hidden or for hiding $s$ from the public; choose Pedersen instead.
  - Rejection sampling: if any $a_j$ turns out to make a share collide (e.g. $s_i = 0$,
    $f(i) = 0$), most implementations simply restart the share; it costs nothing in a correct
    field but is worth handling explicitly.

---

## 2. Pedersen VSS (1991)

- **Reference.** Torben P. Pedersen, *"Non-Interactive and Information-Theoretic Secure
  Verifiable Secret Sharing"*, CRYPTO '91, LNCS 576, pp. 129-140.
  DOI 10.1007/3-540-46766-1_9. PDF: https://cgi.di.uoa.gr/~aggelos/crypto/page8/assets/Pedersen-VSS.PDF
- **Problem it solves vs plain Shamir.** Pedersen keeps Feldman's non-interactive per-share
  verification but repairs its *hiding* weakness: the dealer's commitment no longer reveals
  $g^s$, so the shared secret is hidden **information-theoretically** (unconditionally, even
  against an unbounded adversary), while a cheating dealer can still only open the commitment
  two ways if it can solve discrete log — i.e. share-binding stays computational. This is the
  standard "best of both worlds" trade-off: IT hiding + computational binding, the exact dual
  of Feldman (computational hiding + computational binding).
- **Construction.** Parameters: primes $p,q$, $q \mid p-1$, two independent generators
  $g, h \in \mathbb{Z}_p^*$ of the order-$q$ subgroup with **unknown** $\log_g h$
  (generated via a Secp-group style hash-to-point or a joint coin-flipping protocol).
  1. Dealer selects two random degree-$t$ polynomials
     $f(x) = s + a_1 x + \dots + a_t x^t \bmod q$ and
     $f'(x) = b_0 + b_1 x + \dots + b_t x^t \bmod q$ ($b_0$ uniformly random in $\mathbb{Z}_q$).
  2. Broadcasts double commitments $C_j = g^{a_j} h^{b_j} \bmod p$ for $j = 0,\dots,t$
     (including $C_0 = g^s h^{b_0}$; note $s$ itself is masked).
  3. Sends $P_i$ the pair $(s_i, t_i) = (f(i), f'(i)) \bmod q$.
  4. $P_i$ accepts iff
     $$g^{s_i} h^{t_i} \equiv \prod_{j=0}^{t} C_j^{\,i^{\,j}} \pmod p .$$
  5. Reconstruction uses only the $s_i$ components (Lagrange over $\mathbb{Z}_q$); the $t_i$
     are blinders.
  *Why hiding is IT:* for any candidate secret $s'$, there is a unique $b_0'$ with
  $g^{s'} h^{b'_0} = C_0$, and given any $\le t$ shares the joint distribution of
  $\{(s_i,t_i)\}$ conditioned on the public commitments is uniform over all consistent
  $(s', b_0')$ — the adversary's view is independent of $s$. *Why binding is computational:*
  opening the same $C_j$ to two different coefficients $(a_j, b_j) \ne (a_j', b_j')$ yields
  $h^{b_j - b_j'} = g^{a_j' - a_j}$, i.e. solves $\log_g h$.
- **Cost vs Shamir.** Each share is two field elements instead of one (information rate $1/2$
  as the paper states; distribution and verification cost about $2k$ modular multiplications per
  bit of secret). Broadcast adds $t+1$ double-exponentiation commitments of size ~$|p|$ bits
  each. Reconstruction cost is identical to Shamir plus per-share re-verification.
- **Composability.** *Works well with:* robust reconstruction, proactive refresh (the refresh
  polynomial $\delta$ is dealt with $\delta'(0) = 0$, so both $s$ and mask $b_0$ stay put or are
  intentionally reshared), MPC (additively homomorphic: sum of shares = share of sum), and most
  importantly **DKG** — GJKR's fixed distributed key generation does exactly a Pedersen VSS
  commitment phase followed by a Feldman-style public-key round. *Known caveats:* (a) if a real
  third party generates $(g, h)$ it must destroy/withhold $\log_g h$; a dealer who knows
  $\log_g h$ can open commitments arbitrarily. (b) Pedersen VSS by itself does *not* give you
  $g^s$; getting the public value needs the extra Feldman layer, which is why GJKR separates the
  two phases. Amortized, per-share verification is still one $O(t)$ exponent-chain per party.
- **Implementation pitfalls.**
  - *Generator hygiene:* never pick $h = g^e$ yourself and then pretend it's hidden; generate
    deterministically from a public seed/hash-to-curve, or run a coin-toss. Verify orders as in
    Section 1.
  - Share pairs must be kept together; leaking $t_i$ for a fixed $i$ doesn't hurt one share,
    but leaking $$(t_i)$ across $t+1$ indices reveals $f'$ and can be used to strip hiding.
  - For DKG embedding, follow GJKR exactly: *first* commit (Pedersen), *then* reveal
    (Feldman). Reversing leaks $g^{z_i}$ before QUAL is fixed and reopens the bias attack.
  - The commitment equation is in the exponents; the $i^j$ power must be computed mod $q$ and
    the product mod $p$. Reject shares that do not land in $\mathbb{Z}_q$.

---

## 3. Schoenmakers PVSS (1999) — publicly verifiable secret sharing

- **Reference.** Berry Schoenmakers, *"A Simple Publicly Verifiable Secret Sharing Scheme and its
  Application to Electronic Voting"*, CRYPTO '99, LNCS 1666, pp. 148-164.
  DOI 10.1007/3-540-48405-1_10. PDF: https://berry.win.tue.nl/papers/crypto99.pdf
  (Predecessors: M. Stadler, "Publicly Verifiable Secret Sharing", EUROCRYPT '96,
  DOI 10.1007/3-540-68339-9_17 (double-discrete-log PVSS); E. Fujisaki, T. Okamoto, "A practical
  and provably secure scheme for publicly verifiable secret sharing", ASIACRYPT '98.)
- **Problem it solves vs plain Shamir.** PVSS allows **any third party** to verify the dealer's
  distribution — not only the recipients — which requires that shares travel over *insecure
  broadcast* encrypted so that only the intended recipient can read them. Against plain Shamir,
  the gain is double: (i) it removes the trusted-private-channel assumption in the distribution,
  (ii) the verification transcript is public, so voting systems and DRNGs can have outside
  auditors. It is necessarily *computationally hiding*: private channels are replaced by
  encryption, and encryption needs computational assumptions (DDH here).
- **Construction.** Fix a cyclic group $G_q = \langle g \rangle$ of prime order $q$ (chosen so
  the DLP is hard). Each recipient $P_i$ has a key pair $x_i \in \mathbb{Z}_q^*$, public
  $y_i = g^{x_i}$. The scheme shares a secret $S \in \mathbb{Z}_q$ **in the exponent**: all
  useful values are $g^{\text{something}}$. Let $Y = g^S$.
  1. Dealer picks $f(x) = S + a_1 x + \dots + a_t x^t \bmod q$; broadcasts commitments
     $C_j = g^{a_j}$ for $j=0..t$ (so $C_0 = Y$).
  2. Computes $Y_i = g^{f(i)}$ for each $i$ and encrypts each under ElGamal with $y_i$:
     pick $r_i \in \mathbb{Z}_q$, broadcast $E_i = (W_i, V_i)$ with $W_i = g^{r_i}$,
     $V_i = Y_i \cdot y_i^{r_i}$.
  3. Dealer proves correctness (Schnorr-style; made non-interactive by
     $c = H($transcript$)$). Choose secret nonces $u_0,\dots,u_t$ and $w_1,\dots,w_n$; broadcast
     $B_j = g^{u_j}$ (j=0..t) and $B_i' = g^{w_i}$. On challenge $c$, release
     $z_j = u_j + c\,a_j \bmod q$ and $z_i = w_i + c\,r_i \bmod q$. Verifier checks, for all
     $j=0..t$ and $i=1..n$:
     $$g^{z_j} = B_j\, C_j^c, \qquad
       g^{z_i} = B_i'\, W_i^c, \qquad
       y_i^{z_i} = y_i^{w_i}\, (V_i / Y_i)^c ,$$
     where $Y_i$ is *computed by the verifier* as $\prod_{j=0}^{t} C_j^{i^j}$ (public!). The
     third equation is computable because $y_i$ and $w_i$ are public. It proves $V_i$ genuinely
     encrypts $Y_i = g^{f(i)}$.
  4. **Reconstruction is public.** Each $P_i$ decrypts $Y_i = V_i / W_i^{x_i} = g^{f(i)}$ and
     publishes it; anyone re-checks $Y_i = \prod_j C_j^{i^j}$ and then computes
     $Y = g^S$ via Lagrange in the exponent: $\prod_{i \in S} Y_i^{\lambda_i} = g^{\sum \lambda_i f(i)} = g^S = C_0$.
     Recovering the *field element* $S$ itself is a discrete log (infeasible in general);
     Section 4 of the paper handles small secrets (e.g. election choices) by exhaustive
     pullback from $g^S$.
- **Cost vs Shamir.** The running time is $O(n \cdot k)$ ($k$ = security parameter) and it is
  "essentially optimal" per the abstract; the dealer does $O(nt)$ exponentiations
  ($n$ share-encryptions dominate), verifiers do $O(nt)$ checks (but note the per-$i$ checks
  reuse the same $Y_i$). Communication: $O(n)$ group elements broadcast (commitments +
  ciphertexts + proof) — comparable to Feldman's broadcast but now *on public channels*, so the
  "private channel" saving is a constant-factor win in real deployments. A factor of $k$
  cheaper than Stadler's discrete-log PVSS; the security assumption is DDH (equivalently
  semantic security of ElGamal) — the weakest assumption of the PVSS family at the time.
- **Composability.** *Ideal for* threshold decryption/DKG-derived protocols where the useful
  object is $g^x$ (public key / signature material): anyone can verify the dealer, and any party
  can verify each reconstruction share without knowing secret keys. *Not for* MPC that needs to
  reconstruct the actual field secret $s$ (only $g^s$ comes out, absent a DL). *Proactive
  refresh / resharing* can be layered (Groths NI-VSS continuation, Section 4.1/6)
  but the original paper doesn't give a protocol. *Dealer-free DKG:* the natural use is each
  party acting as dealer over a broadcast channel — exactly the Internet-Computer-style flow
  (S. 4.1). Blinding and FS proofs compose but every proof must bind the full transcript.
- **Implementation pitfalls.**
  - All recipients must be in the same order-$q$ subgroup; check $y_i^q = 1$ and $y_i \ne 1$.
  - The $r_i$ per-recipient randomness must be fresh; reusing $r_i$ across sharings reveals
    share relationships (ElGamal semantical security collapses).
  - Fiat–Shamir challenge must hash $C$ and all $E_i$ (and ideally the instance id and a
    nonce); replaying a transcript against a different $Y$ is a classic attack.
  - Beware the in-exponent limitation: if your application wants $S$ back as an integer, this
    scheme alone can't do it for large uniform secrets — use Groth's NI-VSS (Section 6) which
    hands back field-element shares under CCA-secure encryption.
  - Do not run plain ElGamal over a composite-order group or over a group where DDH fails
    (e.g., $\mathbb{Z}_p^*$ with $p-1$ smooth); use a prime-order curve or a subgroup of
    $\mathbb{Z}_p^*$ with $q$ prime.

---

## 4. Modern improvements

### 4.1 KZG polynomial-commitment-based VSS (eVSS / KZG-VSS; Tomescu et al.; Zhang et al.; Momose–Das–Ren; Groth NI-VSS; cgVSS)

- **Reference.** (a) A. Kate, G. Zaverucha, I. Goldberg, "Constant-Size Commitments to Polynomials
  and Their Applications", ASIACRYPT '10, LNCS 6477, pp. 177-194, DOI 10.1007/978-3-642-17373-8_11.
  (b) S. Das, Z. Xiang, L. Ren, "Efficient Verifiable Secret Sharing with Share Recovery in BFT
  Protocols", ACM CCS 2019, DOI 10.1145/3319535.3354207 (KZG-VSSR and Ped-VSSR).
  (c) A. Tomescu, R. Chen, Y. Zheng, I. Abraham, B. Pinkas, G. Gueta, D. Malkhi, "Towards Scalable
  Threshold Cryptosystems", IEEE S&P 2020 (ePrint 2019/1368; the AMT faster-proof technique).
  (d) J. Zhang et al., "Polynomial Commitment with a One-to-Many Prover and Applications", USENIX
  Security 2022, https://www.usenix.org/system/files/sec22-zhang-jiaheng.pdf (FFT-batched proofs).
  (e) A. Momose, S. Das, L. Ren, "On the Security of KZG Commitment for VSS", ACM CCS 2023,
  ePrint 2023/1350, DOI 10.1145/3576915.3623127. (f) J. Groth, "Non-interactive distributed key
  generation and key resharing", ePrint 2021/339. (g) A. Kate et al., "Non-interactive VSS using
  Class Groups and Application to DKG" (cgVSS), ePrint 2023/451.
- **Problem it solves vs plain Shamir.** KZG commits to the whole sharing polynomial with one
  group element, and each shareholder receives a *constant-size* proof that its share is the
  correct evaluation. This makes the dealer's broadcast $O(1)$ (vs. $O(t)$ commitments), lets a
  *public* verifier check any share by touching one group element and doing a few pairings, and
  enables fully non-interactive, publicly verifiable distribution (the "eVSS" flow: commit,
  send shares+proofs, complain if a proof fails). It reduces per-share proof bandwidth from
  $O(t)$ group elements (Feldman) to $O(1)$, at the cost of a structured reference string (SRS)
  from a one-time power-of-tau setup and the $t$-SDH assumption. Compared with plain Shamir it
  adds full dealer binding *and* public auditability of reconstruction.
- **Construction.** Setup produces an SRS $(g, g^{\tau}, g^{\tau^2}, \dots, g^{\tau^t}) \in G_1$
  with pairing $e: G_1 \times G_2 \to G_T$ and a trapdoor $\tau$ that must be destroyed.
  1. Dealer picks $f(X) = s + a_1 X + \dots + a_t X^t \in \mathbb{F}_p[X]$; computes the
     commitment $C = \prod_{j=0}^{t} (g^{\tau^j})^{a_j} = g^{f(\tau)}$. Broadcasts $C$.
  2. For each shareholder $i$ (evaluation points, e.g. $1,\dots,n$), computes share
     $s_i = f(i)$ and the quotient polynomial $q_i(X) = (f(X) - f(i))/(X - i)$, and the proof
     $\pi_i = g^{q_i(\tau)}$. Sends $(s_i, \pi_i)$ privately.
  3. $P_i$ (or anyone) verifies:
     $$e(C / g^{s_i},\, g^{e}) = e(\pi_i,\, g^{\tau} / g^{i}),$$
     equivalently $e(C/g^{s_i}, g) e(\pi_i^{-1}, g^{\tau}/g^i) = 1$.
  4. Reconstruction: collect $\ge t+1$ shares that each verify; since the $s_i$ are actual
     field elements, plain Lagrange interpolation recovers $s$ (the commitment is
     degree-binding, cf. Momose-Das-Ren). Dealers' proofs make bad shares immediately
     detectable; repeating rounds of share+proof delivery implements VSSR (share recovery)
     for BFT systems.
  *Batch variants:* Tomescu et al. precompute all $n$ proofs in $\Theta(n\log t)$ via
  authenticated multipoint-evaluation trees (AMTs) instead of $\Theta(nt)$; Zhang et al. batch all
  $n$ proofs at cost $O(n \log n)$ (one proof, FFT-based) for a KZG committed polynomial, and also
  give a transparent (no SRS) variant. Momose–Das–Ren make KZG *degree-binding* in the standard
  model and support all degrees up to the SRS bound (important because degree-binding is what
  guarantees two reconstructions agree on the threshold).
- **Cost vs Shamir.** Dealer: $O(nt)$ or (AMT/FFT) $O(n \log^2 t)$/$O(n \log n)$; each share
  $+$ proof is 2 group/field elements per recipient (communication $O(n)$ like Shamir, but all
  share-protecting data is $O(1)$ per share instead of $O(t)$). Broadcast: one group element.
  Verification: one shared-pairing equation per share → verifier time $O(1)$ (or $O(t \log t)$
  batch). This makes it the cheapest *fully publicly verifiable* VSS known for large $n$; vs
  plain Shamir you pay for the SRS setup once and pairings per share, and gain correctness
  guarantees Shamir simply cannot express.
- **Composability.** *Works with* proactive refresh (KZG commitments are homomorphic, so fresh
  zero polynomials can be committed/opened the same way) and DKG (Groth's NI-DKG is exactly the
  non-interactive, publicly verifiable DKG built on this; the Internet Computer deploys it). KZG
  pledges & proofs are publicly checkable, so *public reconstruction* drops out for free.
  *Caveats:* degree-binding is NOT automatically guaranteed in the plain model (the whole point of
  Momose–Das–Ren) — with a split-SRS or adversary-controlled $\tau$ the committed "polynomial"
  might be a higher-degree power series, letting different $t{+}1$-sets reconstruct different
  values. The SRS trapdoor must be destroyed; a leaked $\tau$ is catastrophic (breaks binding and
  lets the dealer equivocate). Feist–Khovratovich and Tomescu restrict evaluation points to roots
  of unity for efficiency — don't mix that with arbitrary public exponents without care.
- **Implementation pitfalls.**
  - Verify $g^{\tau^j} \in G_1$ (order-$p$ subgroup membership) and that the SRS is well-formed;
  - use curve/subgroup-safe pairings (BLS12-381 BN254 with correct checks); never allow
    $i = \tau \bmod p$ as an evaluation point (leaks trapdoor);
  - keep the SRS fixed across sessions or handle transcript-level domain separation;
  - for DKG, ensure the public key $g^s$ extraction happens (commitments give $g^{f(\tau)}$, not
    $g^{f(0)}$ — use the committed coefficient $C' = \prod_j (g^{\tau^j})^{a_j}$ with the right
    CRS index so that coefficient 0 maps to $g^{a_0}$);
  - transparent/FFT variants trade prover time for proof size/verifier time — pick per
    deployment (Zhang et al. report $20\times$ smaller proofs than AMT-based at $3\times$ prover
    cost for $2^{21}$ parties).

### 4.2 MVSS — Moderated verifiable secret sharing, and "multi-party" (joint) VSS

- **Reference.** Jonathan Katz, Chiu-Yuen Koo, *"On Expected Constant-Round Protocols for
  Byzantine Agreement"*, CRYPTO 2006, ePrint 2006/065 (introduces **moderated VSS/mVSS**).
  Discussion/term "MVSS" also appears in J. Katz and students' "Studies on Fault-Tolerant
  Broadcast and MPC" (C.-Y. Koo's thesis) and in the CHURP line of threshold tech. In the
  blockchain/topology literature "MVSS" is sometimes shorthand for *multi-party VSS* = any
  combined $n$-dealer sharing (the DKG pattern of Sections 1-2; see also Cachin et al. Section
  4.3) — clarify terminology with your reader.
- **Problem it solves vs plain Shamir.** Moderated VSS is not about secret sharing math but
  about *where verification happens without a broadcast channel*. It designates a "moderator"
  who simulates the broadcast; as long as one honest party trusts the moderator, the full
  security of the underlying VSS holds; if the moderator is corrupt everybody can detect
  failure. This gives constant-expected-round Byzantine agreement in the pure point-to-point
  model (no trusted broadcast) while retaining VSS guarantees, which plain Shamir plus a naive
  multicast cannot do even with an honest dealer.
- **Construction.** Generic compiler: take any constant-round VSS $\Pi$ that uses a broadcast
  in its sharing phase. Replace every broadcast step of $\Pi$ by *two gradecasts*: the sender
  gradecasts the message, then the moderator gradecasts what it received. A party forks: if the
  two agree with grade 2, use the value as if broadcast; otherwise set flag $success := 0$. At
  the end everyone outputs the flag; if any honest party has $flag = 1$ then the protocol still
  satisfies VSS (dealer honest ⇒ legitimate secret shared; view of corrupt parties independent
  of $s$; reconstruction yields one value). Instantiated with an authenticated gradecast
  (J. Katz-C. Koo construction) the compiler achieves $t < n/2$; the plain version $t < n/3$.
- **Cost vs Shamir.** One VSS instance costs roughly 2× its broadcast rounds plus rerouting;
  asymptotic complexity of the resulting protocol is unchanged from the underlying VSS, but the
  *round* cost is constant-expected and the point-to-point setting removes the strongest
  deployment assumption (a usable broadcast infrastructure). For the *multi-party* reading, the
  cost is $n$ VSS instances: $O(n^2)$ messages and $O(n)$ field elements per party
  (plus $O(n)$ broadcast commitments when using Feldman/Pedersen).
- **Composability.** Moderated VSS composes into weak/common coin constructions (Katz-Koo;
  the layered-moderator line extended by Abraham et al. 2025 ePrint 2025/2078) and gives
  expected-constant-round BA. *Incompatibility note:* it preserves VSS security only for
  parties that keep $flag=1$; compose carefully with protocols that assume *all* honest parties
  commit. The multi-party/Joint interpretation composes with proactive refresh and DKG as in
  Sections 1-2 (with the GJKR caveat).
- **Implementation pitfalls.** Gradecast outputs must be monotone (grade 2 = trusted, grade
  $\le 1$ = unsure); a moderator that selectively broadcasts to a subset of parties must still
  produce the *same* semantics for everyone — implement gradecast carefully because the
  "one-round" requirements are easy to get wrong in emulation. Use domain-separated transcripts
  when layering mVSS instances for the common-coin analysis.

### 4.3 Asynchronous VSS (AVSS) — Cachin–Kursawe–Lysyanskaya–Strobl 2002 and the modern line (incl. "Abraham et al.")

- **Reference.** Christian Cachin, Klaus Kursawe, Anna Lysyanskaya, Reto Strobl, *"Asynchronous
  Verifiable Secret Sharing and Proactive Cryptosystems"*, ACM CCS 2002, ePrint 2002/134,
  DOI 10.1145/586110.586124. *(The user's suggested "Petridis–Shoup" is a misrender: the correct
  author list is Cachin–Kursawe–Lysyanskaya–Strobl; Shoup is a co-author of a different
  asynchronous-Byzantine line — Cachin–Kursawe–Shoup, PODC 2000.)* Modern successors:
  A. Patra, A. Choudhary, C. P. Rangan, "Efficient Asynchronous VSS and MPC" (ePrint 2010/007;
  eAVSS/eAVSS-SC, ePrint 2012/619); S. Das, Z. Xiang, L. Ren, "Asynchronous Data Dissemination
  and its Applications", CCS 2021, ePrint 2021/777; N. Alhaddad, M. Varia, H. Zhang,
  "High-Threshold AVSS with Optimal Communication Complexity", ePrint 2021/118; I. Abraham,
  G. Asharov, S. Patil, A. Patra, "Asymptotically Free Broadcast in Constant Expected Time via
  Packed VSS", TCC 2022/ePrint 2022/1266, and "Perfect Asynchronous MPC with Linear Communication
  Overhead", EUROCRYPT 2024/ePrint 2024/432; V. Shoup, N. P. Smart, "Lightweight AVSS with Optimal
  Resilience", ePrint 2023/536 = J. Cryptology 37:27, 2024; H. Cheng et al., "Resilience-Optimal
  Lightweight HAVSS", ePrint 2024/1761; PC-based AVSS: Haven (FC 2021), Bingo (CRYPTO 2023),
  eAVSS (Das et al.), FRISS (USENIX Security 2024).
- **Problem it solves vs plain Shamir.** AVSS removes the synchronized-clock assumption: in an
  asynchronous network the dealer may be arbitrarily delayed, and plain Shamir + a reliable
  broadcast cannot even terminate (Fischer–Lynch–Paterson / Dolev–Strong-style impossibility).
  AVSS guarantees: (i) *termination* — if a correct dealer runs the protocol, every correct
  party eventually outputs; (ii) *agreement* — correct parties converge on one value/identifies
  a corrupt dealer; (iii) *secrecy* — up to $t$ corrupt parties learn nothing about $s$;
  (iv) *correctness/commitment* — the shares held by honest parties lie on one degree-$(k{-}1)$
  polynomial. It is the tool that makes distributed key generation and threshold signatures work
  without a consensus/timing assumption, ICANN-for-scale blockchains being the flagship use.
- **Construction** (CKLS core, DL-based, work in $\mathbb{Z}_p^*$, order-$q$ subgroup $g$).
  The dealer shares via a **bivariate** polynomial of degree $k-1$ in each variable with
  $F(0,0) = s$:
  1. Pick $F(x,y) = \sum_{i=0}^{k-1}\sum_{j=0}^{k-1} f_{ij} x^i y^j \in \mathbb{Z}_q[x,y]$,
     $f_{00} = s$. (Pedersen style adds a second random bivariate poly $G$ for hiding — the
     base paper uses Feldman-style exponentials $E_{ij} = g^{f_{ij}}$ as commitments, giving
     computational hiding; the IT variant uses $g^{f_{ij}} h^{g_{ij}}$.)
  2. Send $P_i$ the two univariate slices $f_i(x){:=}F(x,i)$ and $g_i(y){:=}F(i,y)$.
  3. Each $P_i$ then exchanges cross-evaluations: $P_i$ gives $P_j$ the point
     $f_i(j) = F(i,j)$; $P_j$ verifies $g^{f_i(j)} = \prod_{i',j'} E_{i'j'}^{\,i^{i'} j^{j'}}$
     (subshare check) and the symmetry $f_i(j) = g_j(i)$.
  4. Two asynchronous rounds of Bracha-style `echo` / `ready` diffusion (each party forwards
     what it received and counts messages) guarantee termination and agreement even though no
     bound on delay exists; the dealer is (collectively) disqualified if enough parties report
     inconsistencies. Reconstruction: any $k-t$ parties broadcast their univariate slices;
     verifiers check evaluations against the broadcast commitments, interpolate $F$, output
     $s = F(0,0)$.
  *Why bivariate:* the two slices let $P_i$ detect a lying $P_j$ locally (symmetry check),
  which is what plays the role of "broadcast" in the PKI-less setting; and any two honest
  parties' polynomials are pinned together by the public $E_{ij}$.
- **Cost vs Shamir.** CKLS: **O(n²) messages** and **O(κ n³) communication** (κ = security
  parameter/secret size); resilience $n > 3t$; dual-threshold $(n, k, t)$ with
  $n-2t \ge k > t$. The eprint 2010/007 + ePrint 2012/619 line cut communication to **O(κ n²)**
  (univariate, PolyCommit-based, and an eAVSS-SC variant that gives every honest party a share).
  Das–Xiang–Ren (CCS 2021) give AVSS/ACSS/dual-threshold ACSS with **O(κ n²)** communication,
  information-theoretic, **no trusted setup**. Alhaddad/Varia/Zhang get a **high-threshold AVSS**
  (T < n/3, P < n−T) also at O(n²) messages and optimal O(n) communication for large secrets.
  Versus synchronous Shamir + assumed broadcast: the asymptotic *computation* stays polynomial,
  but rounds become untimed — this is the whole point, and you pay an extra factor of n in
  typical communication.
- **Composability.** *Composes with* asynchronous proactive cryptosystems (CKLS Part II gives
  proactive refresh for DL-shares in the asynchronous model with a local-phase timer), ad hoc
  AVSS/ACSS used for asynchronous DKG (e.g., ADKG built on AVSS/RBC), and AB/BA modules
  (Canetti–Rabin). *Notes:* Abraham et al. 2024 resort to *trivariate* polynomials to get
  linear-communication asynchronous MPC — trivariate is the current state of the art for
  rate-1 AVSS-as-a-subroutine; Shoup–Smart show the fully lightweight (hash-only) AVSS only
  yields *standard* secrecy, not *high-threshold* secrecy — Cheng et al. 2024/1761 close that
  gap with a lightweight HAVSS at $\tilde O(\lambda n^3)$ communication. Batching (Shoup–Smart)
  makes amortized communication linear in $n$ on the happy path.
- **Implementation pitfalls.** The subshare consistency equation is the correctness linchpin —
  get the double exponent $i^{i'} j^{j'}$ exactly right (each factor mod $q$); off-by-one degree
  errors silently break commitment. Asynchronous `echo`/`ready` must count quorums, not "first
  responder". Do not add timing assumptions, or you reintroduce the sync fragility the scheme
  exists to avoid. For the Pedersen variant keep $G$'s coefficients secret; for the Feldman
  variant accept that hiding is computational. Avoid reusing an $(n,k,t)$ configuration that
  violates $n - 2t \ge k$.

### 4.4 Synchronous VSS with optimal round complexity

- **Reference.** R. Gennaro, Y. Ishai, E. Kushilevitz, T. Rabin, *"The Round Complexity of
  Verifiable Secret Sharing and Secure Multicast"*, STOC 2001 (perfect-security 3-round lower
  bound for $n = 3t+1$, exp-complexity 3-round protocol; 2-round tight for $n > 4t$);
  M. Fitzi, J. Garay, S. Gollakota, C. P. Rangan, K. Srinathan, *"Round-Optimal and Efficient
  Verifiable Secret Sharing"*, TCC 2006, LNCS 3876, pp. 329-342, DOI 10.1007/11681878_17
  (first *efficient* 3-round VSS for $n > 3t$); J. Katz et al. confirmed—see also the "single
  broadcast round" variant; A. Patra, A. Choudhury, C. P. Rangan, T. Rabin, *"The Round
  Complexity of Verifiable Secret Sharing Revisited"*, CRYPTO 2009 (ePrint 2008/172; statistical
  2-round sharing for $n = 3t+1$); B. Applebaum, E. Kachlon, A. Patra, *"The Round Complexity of
  Statistical MPC with Optimal Resiliency"*, STOC 2023 (ePrint 2023/418; 3-round statistical VSS
  iff $t < n/2$).
- **Problem it solves vs plain Shamir.** Round count matters when VSS is a subroutine: plain
  Shamir's sharing is literally one round of private messages, but it's unverifiable. The works
  above settle the *fewest rounds* in which shares can still be verified, split between perfect
  (error-free, $t<n/3$) and statistical ($t<n/2$ with negligible error) security.
  Summary of achievable sharing rounds:
  * perfect: 3 rounds iff $n > 3t$ (GIKR01 lower + Fitzi06 efficient);
    2 rounds iff $n > 4t$; 1 round for $t=1$ ($n>3$);
  * statistical: 2 rounds for $n = 3t+1$ (Patra09) — impossible for $t \ge n/3$; 3 rounds for
    $t < n/2$ (App-Kachlon-Patra 2023, matching their lower bound), 4-round efficient variant.
  Compared with "Shamir + Feldman broadcast", the win is: fewer rounds (down from 4-6 to 2-3)
  at equal or better resilience, with the same VSS guarantees, which lowers the critical path of
  Byzantine agreement and MPC composed on top.
- **Construction.** The three-round perfect protocol (Fitzi et al.): (1) dealer uses a
  *symmetric bivariate* polynomial $F(x,y)$ with $F(0,0) = s$, sends each $P_i$ the rows
  $f_i(x) = F(x,i)$ and $g_i(y) = F(i,y)$; (2) parties perform pairwise consistency checks of
  $f_i(j)$ vs $g_j(i)$ and broadcast complaints; (3) dealer resolves complaints by broadcasting
  disputed sub-shares (or is disqualified). Reconstruction: (all parties broadcast their row),
  error-correct the rows, interpolate, output $F(0,0)$. The efficiency trick vs GIKR's
  exponential-time 3-round protocol is replacing the exponential number of random-pad checks by
  the (low-degree) symmetric-bivariate + verification structure; WSS (weak secret sharing) is
  used as a building block ($3 \le$ rounds for WSS when $n \le 4t$; 1 round when $n > 4t$).
  The statistical 2-round variant (Patra09) allows negligible reconstruction error, which is
  what breaks the perfect-3-round barrier; the STOC'23 3-round $t<n/2$ uses ICSig-style
  *information-checking signatures* so that reconstruction rejects forged shares of corrupt
  parties.
- **Cost vs Shamir.** Same field-element communication as Shamir plus two to three rounds of
  point-to-point messages + one broadcast; computation stays polynomial (the bivariate
  structure costs $O(n^2)$ against $O(n)$ in pure Shamir, and perfect-security VSS requires
  $n = 3t+1$ which Shamir doesn't). Amortized: many sequential VSS can run at $1 + \varepsilon$
  rounds per instance (Fitzi06; GIKR01 random-pad trick). Round-optimality is the entire
  measurable win: from $4$ to $2$-$3$ rounds while retaining the VSS guarantee that Shamir lacks.
- **Composability.** *Excellent for MPC and BA composition:* round-optimal VSS slots directly
  into GIKR/Fitzi-style constant-round MPC and expected-constant-round BA; the statistical
  2-round and $t<n/2$ 3-round variants are the building blocks of statistical MPC at optimal
  resilience (STOC'23). *Compatible with* proactive refresh and DKG in the synchronous model,
  since these protocols only rearrange the scheduling of a standard bivariate-shared secret. The
  trade (vs plain Shamir): more rounds than 1, but that's unavoidable for *verifiability* —
  plain Shamir cannot achieve it at any round count.
- **Implementation pitfalls.** Symmetry $F(i,j)=F(j,i)$ must be enforced everywhere; an
  asymmetric matrix silently enables equivocation. Complaint windowing must be synchronized
  (this is synchronous-only; do not reuse on an async net). For the statistical variants, the
  error probability is only *negligible* — be consistent with the application's security level.
  When composing sequentially, carry the correction term $c_j = s_j - r_j$ in the correct phase
  or you leak/break hiding.

### 4.5 Hierarchical VSS

- **Reference.** Tamir Tassa, *"Hierarchical Threshold Secret Sharing"*, TCC 2004, LNCS 2951,
  pp. 473-490 (now also J. Cryptology 2007); T. Tassa and N. Dyn, "Multipartite Secret Sharing"
  (bivariate variant); G. Traverso, D. Demaio, et al., *"Dynamic and Verifiable Hierarchical
  Secret Sharing"*, ICITS 2016 / ePrint 2017/724 (Birkhoff + Feldman-style verification,
  dynamic parties/thresholds); GDP / N. Alhaddad et al. and the PVGSS line (ePrint 2025/664)
  for *verifiable generalized* access structures.
- **Problem it solves vs plain Shamir.** Shamir realizes only a flat $(t,n)$ threshold. In
  hierarchical settings (bank transfers, command hierarchies) the policy is: a set is authorized
  if it contains $k_0$ users from level 0, $k_1$ users from levels $\{0,1\}$, etc.
  (conjunctive; disjunctive dual: some $L$ with $\ge t_L$ from top $L+1$ levels). Tassa's scheme
  is *ideal* (each participant holds one field element) and works by giving lower-level users
  *higher-order derivatives* of the sharing polynomial, which carry less information — a plain
  Shamir share carries the same weight regardless of rank and cannot express the hierarchy
  without blowing up share size.
- **Construction** (Tassa, conjunctive). Fix levels $0 \le L \le m$ with thresholds
  $k_0 < k_1 < \dots < k_m$. Dealer picks a random polynomial $P(x)$ of degree $< k_m$ with
  $P(0) = s$ (i.e. $P(x) = s + a_1 x + \dots + a_{k_m-1} x^{k_m-1}$). A user $u$ at level $L$
  gets the *derivative* share $P^{(k_L - 1)}(u)$ (with $k_{-1} = 0$, so level-0 users get
  $P(u)$ — ordinary points; higher levels get higher-derivative evaluations, which involve only
  the top coefficients). Reconstruction: authorized sets solve the resulting **Birkhoff
  interpolation** system (points + derivatives/incidences) that recovers $P$ (and hence $s$);
  the linear system must be non-singular, guaranteed by monotone ID assignment
  ($u < v \iff L(u) < L(v)$) with $|F_q|$ large per the paper's bounds, or by random IDs with
  small failure probability $\nu(t,q)$. Dynamic verifiable variant (Traverso et al.): pick the
  polynomial, commit to *all* coefficients (Feldman-style $g^{a_j}$), share derivative
  evaluations, and when adding/removing/renewing shares publish the update polynomial with the
  same commitment discipline so every shareholder can verify its (new) derivative share.
- **Cost vs Shamir.** Ideal: share size equals Shamir's (1 field element). Dealer: $O(k_m
  i)$ evaluations incl. derivatives (linear in the max threshold); reconstruction: solve a
  $k_m \times k_m$ linear system instead of Lagrange (cost $O(k_m^3)$ naively, or the same O(n)
  counts with preprocessed interpolation). Setup needs a field large enough over the derived
  bounds (Tassa's Theorem 3.1: $2^{-t}(t+1)^{(t+1)/2} N^{(t-1)t/2} < q$ for monotone IDs) —
  typically a modest constant factor over Shamir's $|F_q| > n$. The dynamic variant adds one
  broadcast per operation.
- **Composability.** *Works with* verifiability in the standard sense (Feldman/Pedersen
  commitments apply to the coefficient poly; the disjunctive multi-level scheme of the ePrint
  2008/018 note is itself constructed from Pedersen's techniques and can be made fully
  verifiable). *Composes* with the usual proactive-refresh/robust-reconstruction machinery as
  long as the derivative structure is preserved — refresh polynomials must keep
  $(k_L{-}1)$-derivative semantics. *Caveats:* Birkhoff systems are less numerically forgiving
  than plain Lagrange; dynamic threshold *changes* require careful re-derivation of the
  Birkhoff system (Traverso et al. handle this explicitly; plain Shamir-based systems don't
  need it). Combining hierarchical + (publicly verifiable) reconstruction is currently only
  mature for threshold structures (PVGSS, S.6); generalized access structures plus public
  auditability is 2025-state-of-the-art.
- **Implementation pitfalls.** The ID→level monotone-allocation constraint is load-bearing; a
  non-monotone assignment can make an *authorized* set's matrix singular and reconstruction
  fail. Derivative formulas in $F_q$ need actual polynomial-derivative arithmetic (integer
  coefficients mod $q$, falling factorials) — off-by-one in the exponent order silently breaks
  the threshold. Verify the linear system's rank at setup with a small abort-on-zero check
  (O(1) probability; cheap to re-run with new IDs). When deriving "level $L$ user gets
  $P^{(k_L-1)}(u)$", the $\binom{}{}$ factors inside derivatives must be reduced mod $q$.

---

## 5. Cheating detection without public keys: IT-MACs and pairwise checking

### 5.1 Rabin–Ben-Or style pairwise-consistency VSS (1989)

- **Reference.** Tal Rabin, Michael Ben-Or, *"Verifiable Secret Sharing and Multiparty Protocols
  with Honest Majority"*, STOC 1989, DOI 10.1145/73007.73014; PDF:
  https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/rabinVSS.pdf. (Predecessor: Chor,
  Goldwasser, Micali, Awerbuch, FOCS 1985 — first VSS, exponential communication.) See also the
  *perfectly-secure VSS survey*, A. Chandramouli, A. Choudhury, A. Patra, ePrint 2021/445.
- **Problem it solves vs plain Shamir.** Gives **information-theoretically secure** VSS —
  no number theory at all — for $n \ge 2t+1$ with statistically small error (and perfect
  variants for $n \ge 3t+1$ with a weak broadcast). Plain Shamir offers no detection of dealer or
  shareholder cheating; Rabin–Ben-Or pairs every share with values that let *honest parties*
  detect a lying partner, using only information-checking (IC) signatures/check vectors, not
  discrete logs. This is the foundation of information-theoretic MPC (BGW/CCD + RB).
- **Construction.** Over $\mathbb{Z}_p$, $p > 2^k$ (security level $2^{-k}$), with private
  pairwise channels + broadcast.
  1. **Information checking.** To pass value $s$ from dealer $D$ to intermediary $INT$ toward
     recipient $R$: $D$ picks random $b_i \ne 0,\ y_i$ and check vectors $c_i = s + b_i y_i$
     (2k pairs); $INT$ learns the $(s, y_i)$; $R$ keeps the check vectors; $INT$ picks $k$
     distinct indices, $R$ reveals them, $INT$ aborts if inconsistent — this authenticates to
     $R$ without keys.
  2. **Sharing.** $D$ picks $f(z) = s + a_1 z + \dots + a_t z^t$ and $k(n)$-many random witness
     polys $g_j(z)$, sends $(\beta_i{:=}f(\alpha_i),\; \gamma_{ji}{:=}g_j(\alpha_i))$ to $P_i$.
  3. **Second-level sharing + consistency.** Each $P_i$ re-shares its received values with all
     others using WSS, then parties *pairwise* compare cross-points: $P_i$'s claimed point on
     $f$ must equal $P_j$'s, else complaint; the dealer resolves disputes by broadcasting
     anything challenged publicly.
  4. **Zero-knowledge phase.** For each gossip index $j$, a designated challenger presses the
     dealer to open either $g_j$ or $f + g_j$; shares that fail are ruled out. A polynomial
     whose $t{+}1$ accepted points agree interpolates a unique $s$; adversarial parties that
     try to inject errors get identified and their shares discarded — *robust* reconstruction
     with only $t{+}1$ honest shares needed.
  Error probability $2^{-\Omega(k)}$; the scheme is polynomial in $n, k$.
- **Cost vs Shamir.** Information rate $O(1/n)$-ish per piece in the basic form; communication
  $O(n^2) \cdot k$ bits for one sharing (vs. $O(n)$ in Shamir), and the number-theory-free
  arithmetic is cheap. Round count: constant rounds of point-to-point plus (for $n \le 3t$)
  broadcast usage. Modern optimizations (Cramer–Damgård–Dziembowski–Hirt–Rabin; ePrint 2021/445
  survey) bring communication to $O(n^2)$ field elements with $n = 2t+1$.
- **Composability.** *The* building block of statistically/perfectly secure MPC with honest
  majority (BGW/CCD/RB: any functionality computable iff $t < n/2$). Composes with
  proactive refresh in the IT setting (refresh via fresh random zero-sum polys re-verified the
  same way) and with dealer-free DKG-style key agreement for IT primitives. *Limitation:* the
  error probability is statistical, not unbounded (perfect schemes need $n \ge 3t+1$ or a
  single-broadcast assumption). Works with continuous-time (liveness) compositions only where a
  broadcast exists or $n \ge 3t+1$.
- **Implementation pitfalls.** The $2k$ check-vector pairs and the index-reveal step must be
  executed verbatim (the "reveal k then verify" order prevents selective forgery). Subscripts:
  witness polys $g_j$ indexed per *gossip column*; the challenger-selection load-balancing
  (each $g_j$ challenged by exactly $P_{j \bmod n}$) is what makes the ZK phase tight — get the
  challenge assignment right.   Field must be large enough ($|F_q| \ge 2^k$ for the desired
  error), and the "expose $g_j$ or $f{+}g_j$" challenge must be a genuinely random choice per
  index, otherwise an adaptive adversary can pass the ZK phase with inconsistent shares.

### 5.2 IT-MAC authenticated secret sharing (SPDZ-style share authentication)

- **Reference.** SPDZ: I. Damgård, V. Pastro, N. Smart, S. Zakarias, *"Multiparty Computation
  from Somewhat Homomorphic Encryption"*, CRYPTO 2012 (IT-MACs, batch MAC-check). BDOZ:
  Bendlin, Damgård, Orlandi, Zakarias, *"Semi-homomorphic encryption and multiparty
  computation"*,   EUROCRYPT 2011 (per-party MAC keys). MASCOT: Keller et al., CCS 2016. SPDZ2k (mod $2^k$
  MACs): *"SPDZ2k: Efficient MPC mod $2^k$"*, ePrint 2018/482, CCS 2018.
  CESS/cheater-identification: C. Baum, I. Damgård, C. Orlandi, *"Catching MPC Cheaters:
  Identification and Openability"*, ePrint 2016/611 (locally identifiable secret sharing); also
  Ishai–Ostrovsky–Zikas (TCC 2012) locally identifiable secret sharing. For a cryptography-only
  exposition: "Concretely efficient secure MPC protocols" survey (D. Feng et al., 2022),
  sandbox.edpsciences.org, Sec. on IT-MACs.
- **Problem it solves vs plain Shamir.** Authenticated secret sharing (ASS) protects *share
  integrity* during storage and reconstruction using information-theoretic MACs instead of
  public-key schemes: a $t$-corrupt adversary who tampers with a share is detected with
  probability $1 - 1/|\mathbb{F}|$ per check, and **any** party (or an honest majority) can
  run a batch MAC-check that catches the misbehaver — with *no* number-theoretic assumptions.
  Plain Shamir gives shares zero integrity; the Rabin–Ben-Or route needs $O(m)$ extra values per
  share; ASS needs only one MAC per value and supports fast opens. It is the workhorse of
  dishonest-majority MPC online phases and of lightweight VSS/AVSS variants (Shoup–Smart 2024).
- **Construction.** Let $x \in \mathbb{F}$ be a field element. Distribute a global MAC key
  $(\Delta) \in \mathbb{K}$ (larger extension field) replicated/additively shared so that no
  one party knows it (SPDZ: each $P_i$ holds additive share $\Delta_i$, $\Delta = \sum_i
  \Delta_i$). To share $x$: compute the tag $M = \Delta \cdot x$, then additively share both:
  each $P_i$ holds $(x_i, M_i)$ with $x = \sum_i x_i$, $M = \sum_i M_i$. Homomorphic: local
  addition gives a sharing of $x{+}y$ with MAC $\Delta(x{+}y)$; multiplying by a public scalar
  works too. To *open to a party* (or all): parties broadcast/send their shares; the opener
  computes $\hat x = \sum x_i$, $\hat M = \sum M_i$ and accepts iff
  $\hat M = \Delta \cdot \hat x$ (knowing $\Delta$ for the recipient). *Batch check:* to verify
  $L$ shares at once, parties pick a random linear combination $c_1,\dots,c_L \in \mathbb{F}$
  (coin-flipping) and check $\widehat{\sum_j c_j M_j} = \Delta \cdot \widehat{\sum_j c_j x_j}$ —
  sound because forging along a random direction requires solving for $\Delta$. Application to
  VSS/cheating detection: each reconstructing share is delivered as an *authenticated* share;
  after aggregation the MAC check either passes (share correct) or the culprit is
  identified/locally — this is exactly the "share authentication + pairwise share-checking"
  pattern generalized: pairwise checks are replaced by tag sharing + a single random-linear
  MAC check, and per-party MAC keys give identify-and-abort.
- **Cost vs Shamir.** Storage: $2\times$ per share (value + one MAC over the extension field),
  roughly the same rate as double sharing but with $O(1)$ message opens: opening a share needs
  the shares broadcast plus a batch MAC-check amortized across many values. The heavyweight
  generation of authenticated shares (shared random values, beaver triples) happens in a
  *preprocessing* phase using OT/HE — offline. Vs plain Shamir: +$|K|$ bits per share, but you
  get detect-any-cheat with overwhelming probability and publicly safe reconstruction, again
  without public-key math online.
- **Composability.** *Composes* into dishonest-majority MPC (SPDZ family), *robust
  reconstruction* for Shamir-style sharings, *proactive refresh* that carries MACs over
  (refresh under the same global key requires key stays randomized every epoch), and the
  *lightweight AVSS* line (Shoup–Smart uses hash/PRF-based MACs). *Incompatibility/note:*
  authenticating *additive* shares does not, by itself, make shares secretly "verifiable" at
  share time against a lying *dealer* — the dealer must also be committed/checked (use with a
  commitment round, or a VSS layer). MAC keys must be refreshed/stored bootstrapped under
  secrecy or the whole MAC hierarchy collapses; identify-abort gives you *accountability* not
  necessarily *fairness* (no recovery).
- **Implementation pitfalls.** Field size must satisfy $|\mathbb{F}| > 2^\lambda$, else the MAC
  forgery odds are not negligible — a common mismatch in ported code. Batch MAC-check needs a
  secure coin for the random coefficients (don't reuse a public fixed $c$). Additive-share +
  MAC must stay in the same party-to-party pairing; mixing which party holds which $\Delta_i$ is
  a disaster. Use a *fresh* $\Delta$ per execution domain (or per epoch) to avoid correlation
  across sharings.

---

## 6. Publicly checkable reconstruction (anyone can verify reconstructed shares)

- **Reference foci.** (a) Schoenmakers PVSS (Section 3) — reconstruction is inherently public
  (Y_i-checkable + in-exponent Lagrange). (b) S. Das, Z. Xiang, L. Ren, VSSR/CHURP companion,
  and CHURP (S. Maram, F. Zhang, L. Wang, A. Low, Y. Zhang, A. Juels, D. Song, ACM CCS 2019,
  ePrint 2019/017) — *StateVerif* gives an O(n) on-chain, KZG-free public check that the
  committee's reconstruction data still spans the secret. (c) J. Groth, NI-VSS/NI-DKG
  (ePrint 2021/339); A. Kate et al. cgVSS (ePrint 2023/451) — formalize "strong public
  verifiability" where even corrupt recipients can't break a public-verification transcript.
  (d) I. Cascudo, B. David, SCRAPE (FC 2017) — public verification of reconstruction for
  randomness-beacon style reconstruct (g-shares checks with RS codes). (e) Recent generic +
  post-quantum PVSS: "Publicly Verifiable Generalized Secret Sharing" (PVGSS), ePrint 2025/664;
  Kihong Whang et al., lattice PVSS in the standard model, arXiv 2504.14381; AB-PVSS
  (J. Crypto & Cybersecurity 2026); also the YOLO/YOSO/HEPVSS constructions for P2P
  committees.
- **Problem it solves vs plain Shamir.** In plain Shamir, reconstruction is a private
  computation: nothing stops a corrupt shareholder from submitting garbage that interpolates a
  wrong secret, and an outsider cannot tell. Publicly checkable reconstruction demands that
  **any verifier without any secret** can: (1) check each opened share is *on* the committed
  polynomial, and (2) check the final reconstructed value is the only value compatible with the
  valid shares. This converts secret sharing into an auditable primitive — essential for DRNG
  beacons, DAO randomness, blockchains, e-voting, and for holding misbehaving nodes accountable
  on a public ledger.
- **Construction.** The general recipe: **commitment-in-the-exponent over a public group**.
  Dealer shares $s$ and, for reconstruction, shareholders *publish* $y_i = g^{s_i}$ (not
  $s_i$); anyone verifies $y_i = \prod_j C_j^{i^j}$ (powers of the public coefficient
  commitments) and recovers $Y = g^s = \prod_i y_i^{\lambda_i}$ in the exponent — a public,
  soundable computation (Schoenmakers). For *field-element* secrets, CCA-secure encryption +
  NIZKs replace it: each shareholder publicly proves $Dec_{sk_i}(E_i) = s_i$ lands on the
  committed polynomial via a NIZK (Groth 2021/339; the generic PVGSS/lattice-PVSS
  constructions do the same with Schnorr/DLEQ proofs and standard-model NIZKs). CHURP's
  StateVerif is a nice lightweight folklore check: after any committee/refresh step, publish
  $g^{s_i}$ for each member and check $g^s = \prod_i (g^{s_i})^{\lambda_i}$ (Inv-Secret) and, by
  a random linear combination of shares, that the degree of the reduced shares is $t$
  (Inv-State) — both checks run on-chain over a public transcript with O(n) cost and no KZG.
- **Cost vs Shamir.** Public verification replaces "n shares + private interpolation" by
  "$n$ group elements broadcast + $O(n)$ exponentiations/pairings + public interpolation".
  Communication is $O(n)$ group elements (times $\log p$), same order as Shamir but now all
  public data that any party can audit; computation $O(n)$ exponent ops. For KZG-based field
  reconstruction (Groth), per-share proofs make the ledger transcript $O(n)$ proofs — some
  constructions optimize to $O(n \log n)$ aggregate verification. DRNG-style (SCRAPE) cost is
  $O(n)$ verifier work vs $O(n^2)$ for naive pair-checks.
- **Composability.** *Composes* with PVSS (native), KZG-VSS (native), proactive refresh and
  dynamic committees (CHURP's Invariance checks exist exactly to survive
  committee-evanescence), DRNGs (SCRAPE is built for beacons), and DKG (public audited
  transcripts in Groth/cgVSS/ADKG). *Note:* public checkability forces *computational*
  hiding wherever it uses public groups (the exponent is public); so IT-hiding schemes
  (Pedersen-style, Rabin–Ben-Or) do **not** get free public reconstruction of the *secret* —
  only of $g^s$. For truly public-reconstruction + IT-hiding simultaneously, you need MAC-based
  ASS-style auditing (Section 5.2) instead of exponent commitments; that pairing is the subject
  of ongoing work (e.g. lightweight hatches).
- **Implementation pitfalls.** Never reconstruct the *in-exponent* version from interpolated
  coefficients over the wrong modulus; exponents interpolate mod $q$, group ops mod $p$. When
  using NIZKs for decryption, bind the proof to the ciphertext, the public key, and the
  commitment — replaying a decryption proof against another $C$ invalidates soundness. For
  on-chain verification keep the transcript minimal and deterministic (hash all inputs) or an
  auditor can disagree on ordering. SCRAPE-style RS checks need the evaluation set structured
  (roots of unity) for the $O(n)$ algorithm. Verify group membership of every opened $g^{s_i}$
  (subgroup check) to avoid small-subgroup forgery of the public shares.

---

## Variants covered (summary)

1. **Feldman VSS (1987)** — FOCS; DL-binding non-interactive commit-witness VSS over
   $\mathbb{Z}_p^*$, $g^{a_j}$ commitments, per-share check $g^{s_i} = \prod C_j^{i^j}$.
2. **Pedersen VSS (1991)** — CRYPTO; IT-hiding + DL-binding via $g^{a_j}h^{b_j}$ commitments,
   share pairs $(s_i, t_i)$; the DKG-standard commitment phase.
3. **Schoenmakers PVSS (1999)** — CRYPTO; publicly verifiable ElGamal-encrypted shares,
   Schnorr/FS correctness proof, in-exponent public reconstruction; Stadler/FO precedents.
4. **KZG/eVSS polynomial-commitment VSS (2010-2023)** — KZG'10, VSSR'19, Tomescu+'20,
   Zhang+'22, Momose-Das-Ren'23; O(1) broadcast + proofs, powers-of-tau SRS.
5. **Groth NI-VSS/NI-DKG (2021)** + **cgVSS (2023)** — CCA-secure encrypted-field-shares,
   non-interactive DKG/resharing, strong public verifiability (Internet Computer).
6. **MVSS — moderated VSS (Katz-Koo 2006)** and the multi-party/joint-VSS (DKG) interpretation
   (Pedersen/GJKR), gradecast-simulated broadcast.
7. **Asynchronous VSS** — CKLS 2002 (bivariate, $O(n^2)$ messages), Patra-Choudhary-Rangan
   2010/2012, Das-Xiang-Ren ADD'21, Alhaddad-Varia-Zhang high-threshold'21, Abraham et al.
   packed VSS'22 + linear-comm asynch MPC'24, Shoup-Smart lightweight'23, Cheng et al. HAVSS'24,
   PC-based eAVSS/Bingo/FRISS.
8. **Synchronous VSS with optimal round complexity** — GIKR'01 (3-round lower bound),
   Fitzi-Garay-Gollakota-Rangan-Srinathan'06 (efficient 3-round), Patra et al.'09 (statistical 2
   -round), Applebaum-Kachlon-Patra'23 (3-round at $t<n/2$).
9. **Hierarchical VSS** — Tassa'04 (Birkhoff derivative shares, conjunctive), Tassa&Dyn bivariate,
   Traverso et al. dynamic verifiable hierarchical (ePrint 2017/724), dual/disjunctive
   multi-level (ePrint 2008/018); PVGSS (ePrint 2025/664) for generalized access + public
   verifiability.
10. **Information-theoretic / pairwise-check VSS** — Rabin-Ben-Or'89 IC-signatures + WSS +
    zero-knowledge expose-phase; the perfectly-secure VSS survey (ePrint 2021/445).
11. **IT-MAC authenticated share checking** — SPDZ'12, BDOZ'11, MASCOT, SPDZ2k'18, CESS
    cheater-identification (ePrint 2016/611); batch MAC checks for public share audit.
12. **Publicly checkable reconstruction** — Schoenmakers'99 (in-exponent), CHURP StateVerif'19,
    Groth'21/cgVSS'23 strong public verifiability, SCRAPE'17 DRNG checks, PVGSS'25, lattice
    PVSS'25 (standard model), AB-PVSS (2026, attribute-based CP-ABE+NIZK).

Related-but-out-of-scope (flagged for completeness): Graded VSS (Feldman-Micali STOC'88),
packed VSS (Franklin-Yung; Abraham et al. TCC'22 for broadcast), dual-threshold VSS
(Alhaddad et al.), proactive secret sharing (Herzberg-Jarecki-Krawczyk-Yung CRYPTO'95),
GJKR DKG (Eurocrypt'03 / JoC'07), and the AVSS-as-a-subroutine ACSS/ADKG constructions listed
under item 7.