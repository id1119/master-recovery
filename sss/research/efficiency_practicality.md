# Efficiency and Practicality Improvements over Basic Shamir Secret Sharing

Research survey covering eight families of improvements to the basic Shamir
secret-sharing scheme (Shamir, "How to share a secret", CACM 22(11), 1979):
hybrid/knowledge-based sharing, field and arithmetic choices, Reed-Solomon
duality and error correction, multi-secret sharing, weighted thresholds,
hierarchical thresholds, production share formats, and dealer-side
optimization. Every entry documents: name, authors, year, venue; a summary;
implementable algorithm detail; cost comparison against baseline Shamir;
composability notes; and pitfalls. No code is included; algorithms are
described operationally so that an implementer can reproduce them.

Baseline for all comparisons: Shamir (t, n) over GF(p) or GF(2^m), share size
equal to the secret size, dealer computation of n evaluations of a degree
(t-1) polynomial, reconstruction by Lagrange interpolation using t points,
perfect security (t-1 shares give zero information).

---

## 1. Hybrid Secret Sharing: Krawczyk "Secret Sharing Made Short"

### Identity
- Name: Secret Sharing Made Short (hybrid / knowledge-based secret sharing).
- Authors: Hugo Krawczyk.
- Year / venue: 1994, Crypto '94, Springer LNCS 839, pp. 136-146. DOI
  10.1007/3-540-48329-2_12. Also published as "Secret sharing made short" in
  ACM CCS 1993.

### Summary
The share size of any perfect (t, n) secret-sharing scheme is at least the
secret size (the information rate cannot exceed 1 for perfect schemes, since
the entropy bound forces |share| >= |secret|). Krawczyk's scheme bypasses this
bound by giving up perfect secrecy in exchange for computational secrecy: the
dealer picks a random key, shares *only the key* with a perfect scheme such as
Shamir, encrypts the bulk secret with a symmetric cipher under that key, and
distributes the ciphertext publicly. Share size becomes ciphertext_size / n
plus one field element (the key share). Each participant stores a piece of the
ciphertext and a share of the key. Reconstruction requires any t participants,
combining the key shares and decrypting.

### Implementation algorithm
1. Dealer generates a random symmetric key K (e.g., 256-bit AES key).
2. The secret S is encrypted under K with a symmetric cipher (block cipher
   with an authenticated mode, or XOR with a keystream) producing ciphertext C.
3. C is split into n chunks C_1..C_n (equal length, last chunk padded).
4. K is shared with plain Shamir (t, n) into key-shares k_1..k_n.
5. Participant i receives (k_i, C_i).
6. Reconstruction: any t participants pool key-shares, Lagrange-interpolate K,
   reassemble C_1..C_n from the t chunks present, decrypt to recover S.
Size per participant: |C|/n + |K|, so total storage is (n/t)·|S|_chunks + |K|
times t in the worst case, versus n·|S| for plain Shamir.

### Cost comparison
- Per-share size: |S|/n + |K| vs |S| in Shamir. For a large secret this is
  roughly a factor n (i.e., n times smaller per share) better.
- Dealer work: one symmetric encryption (fast) plus one Shamir sharing of a
  256-bit key instead of a Shamir sharing of the whole secret (which in GF(p)
  is O(n·t) multiplications on the full secret size).
- Reconstruction: symmetric decryption plus a Lagrange interpolation on field
  elements the size of K, independent of |S|. Interpolation cost drops from
  O(t^2) operations on |S|-sized field elements to O(t^2) on 256-bit elements.
- Network cost: participants exchange only key shares; the ciphertext chunks
  can be transferred in parallel.

### Composability
- Orthogonal to the field choice (GF(p) or GF(2^m)); the key-sharing layer can
  be swapped for any of the variants in sections 2-8.
- Composes with verifiability: the symmetric encryption can be replaced by
  authenticated encryption (GCM/ChaCha20-Poly1305), giving integrity of the
  reassembled secret.
- Composes with error correction (section 3) if the ciphertext chunks are
  redundancy-coded, though that reintroduces storage overhead.
- Used in practice: ssss (Schneier-adjacent community tool) combines passphrase
  encryption with Shamir; several threshold storage products share an envelope
  key this way.

### Pitfalls
- Security is computational, not perfect: the attacker who holds t-1 key
  shares and all ciphertext chunks can brute-force the key; the entropy bound
  argument no longer applies. Key length must therefore be chosen to outlast
  the data's secrecy horizon (256-bit AES is the safe default).
- The dealer must not reuse a key across multiple secrets; key reuse
  destroys the scheme.
- If the symmetric cipher is used in a streaming mode without authentication,
  tampering with a ciphertext chunk is undetectable until decryption, and can
  produce garbage silently.
- Requires a trustworthy RNG at the dealer (same as Shamir) but additionally
  the key must be genuinely random; deterministic derivation from the secret
  weakens it.
- Chunking must be even; a long ciphertext needs a padding/ciphertext-stealing
  strategy to keep chunks equal length.
- Verification of secret integrity requires an authenticated mode; many
  descriptions of the scheme omit this.

---

## 2. Field Choice and Arithmetic Acceleration: GF(2^m) vs GF(p), Bitslicing, CLMUL

### Identity
- Name: Finite-field choices for Shamir; constant-time GF(2^8) arithmetic
  tables; SSE/AVX/CLMUL polynomial arithmetic; bitsliced sharing.
- Authors: historical lineage from the AES field (Rijndael: Daemen and
  Rijmen, 1998-2001) to secret sharing; practical implementations by the
  libgfshare authors (kinnison, djpohly), HashiCorp Vault
  (shamir/shamir.go), and ssss (Mark D. Wooding's catacomb arithmetic).
- Year / venue: GF(2^m) Shamir is folklore from the 1990s; the definitive
  production codification is in libgfshare (2006-2016), Vault (2015-), and
  the ssss "diffusion layer" tool (2005-2015).

### Summary
Shamir works over any finite field. Two families matter for speed: GF(p) for
large primes p (share size = bit length of p) and GF(2^m), especially m = 8
(byte arithmetic, AES field) and larger m for word-sized shares. GF(2^m)
replaces big-integer modular multiplication with table lookups (log/exp
tables) or CLMUL-based carry-less multiplication, giving 10-100x speedups and
constant-time behavior. Choosing m = share bit length makes shares exactly the
byte length of the secret with no prime-search cost.

### Implementation algorithm
1. Choose GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1
   (0x11B, the AES polynomial) and primitive element 0x03.
2. Precompute exponentiation table exp[0..510] and discrete-log table log[0..255]
   (the standard GF(2^8) trick: every nonzero element is a power of 0x03).
3. Field multiply of a,b: if either is 0, result 0; else
   exp[log[a] + log[b]] (tables sized to avoid mod 255 wrapping).
4. Division is exp[log[a] - log[b]]; this makes Lagrange coefficients cheap.
5. Vault-style alternative (constant-time, no tables): a loop over bits of a,
   shifting and conditionally XOR-reducing by 0x1B when the carry bit is set.
6. Share computation: Horner evaluation of P(x) = S + a_1 x + ... +
   a_(t-1) x^(t-1) at the n distinct nonzero x-points (Vault uses x values
   drawn from a random permutation of 1..255).
7. Word-size variant: use GF(2^m) with m equal to the secret's byte length
   (e.g., GF(2^128) for 16-byte secrets) so that the secret is one field
   element and shares are exactly one field element; arithmetic via CLMUL
   (PCLMULQDQ) reduction.
8. Bitsliced variant: process 64/128 secrets in parallel by bit-slicing the
   field operations (each secret's field arithmetic mapped onto bit planes),
   amortizing the table-lookup or CLMUL cost.

### Cost comparison
- GF(2^8) table-based multiply: ~2-5 ns/op vs 100+ ns for a 256-bit GF(p)
  modular multiply (typical numbers for 2010s CPUs; the gap has narrowed but
  the constant-time property of table-free loops matters).
- CLMUL-based GF(2^128) multiply: ~10-30 ns, comparable to GF(p) 256-bit but
  with no reduction priming and constant time.
- Dealer: n Horner steps of t-1 multiplies each — O(n·t) field multiplies.
  At t=5, n=10, GF(2^8): ~45 multiplies total (nanoseconds); GF(1024):
  ~45 big-integer operations.
- Prime-search cost: GF(p) requires finding a prime of given size once;
  GF(2^m) requires none.
- Table memory: 2x256 bytes for the tables (cache-resident); bitsliced
  versions trade registers for wider parallelism.

### Composability
- The field layer is the base of every other construction: multi-secret,
  weighted, hierarchical, and error-correcting variants all accept GF(2^m).
- Composes with Lagrange-coefficient caching (section 8): in GF(2^8) division
  is a table subtraction, making coefficient recomputation cheap.
- Vault's exact polynomial (0x1B, primitive 0x03, random-permutation x-points)
  is a de facto standard; shares generated by different implementations of the
  same conventions are interchangeable.
- Composes with x-value conventions: secrets.js uses x = 1..n, Vault uses
  random nonzero x; interop requires matching conventions.

### Pitfalls
- GF(2^m) addition is XOR; subtraction equals addition; newcomers confuse
  share recombination signs (Lagrange coefficients are still well-defined).
- The reduction polynomial must be irreducible over GF(2) and the element
  used for tables must be primitive; choosing 0x02 with the wrong polynomial
  silently produces a non-field.
- Table-based multiply is variable-time if not masked; secrets in shared
  contexts can leak through cache timing (less relevant for cold-storage
  tools, critical for online services).
- Random-permutation x-points (Vault) mean the dealer must track which x each
  share used; fixed x = 1..n is simpler and standard in educational and
  browser-based tools.
- GF(2^8) limits n to 255 participants; larger n requires GF(2^16) or GF(p).
- Bitslicing requires careful layout; a bug in plane assignment corrupts all
  parallel secrets at once.

---

## 3. Reed-Solomon Equivalence: Error Correction of Shares (McEliece-Sarwate)

### Identity
- Name: "On sharing secrets and Reed-Solomon codes"; also known as the
  McEliece-Sarwate scheme; strong-security proof by Nishiara-Takizawa.
- Authors: Robert J. McEliece and Dilip V. Sarwate.
- Year / venue: Communications of the ACM, vol. 24, no. 9, pp. 583-584, 1981.
  The strong (all-subsets) security claim is proven by Y. Nishiara and
  S. Takizawa, "Strong Security of the McEliece-Sarwate Secret Sharing
  Scheme", IEICE Transactions on Fundamentals, vol. J92-A, no. 12,
  pp. 1009-1013, Dec 2009 (per Tassa's and Matsumoto's surveys).

### Summary
A (t, n) Shamir scheme is exactly a Reed-Solomon (RS) code [n, t] with the
shares as codeword symbols: the polynomial P of degree < t is the message, the
n shares are its evaluations at n points. The weight of the RS code is d = n-t+1.
Consequence: the t-th share is redundant; even with corrupted shares,
Berlekamp-Massey / Euclid decoding recovers P from any t + 2e shares with e
errors (or any t + f with f erasures), because RS decoders correct e errors and
f erasures as long as 2e + f <= d-1 = n-t. This turns "reconstruct or fail"
into "reconstruct despite malicious/corrupted shares". A second consequence:
the ramp variant shares L secret symbols in one degree-(k-1) polynomial,
supporting up to n = q - L participants in GF(q).

### Implementation algorithm
1. Represent shares as (x_i, y_i) for distinct x_i in GF(q), q > n.
2. Identify corrupted shares: use the RS viewpoint. Form the polynomial
   (implicitly) of degree < t through any t of the points.
3. Reconstruct with error correction: run Berlekamp-Massey (or the
   Sugiyama-Euclid algorithm) on the received words — the standard decoder for
   RS codes — returning the unique polynomial P of degree < t consistent with
   all but e of the shares, where 2e + f <= n - t.
4. Alternatively detect-only: evaluate P through t shares, verify all n shares
   match; if not, use majority/voting over subsets (taken combinatorially).
5. Erasure handling: if up to f shares are missing but the rest are trusted,
   t points suffice — interpolation handles erasures for free (that is the
   classic Shamir property; the new part is handling active corruption).
6. Ramp variant: choose P of degree k-1 with the first L coefficients equal to
   the L secret symbols S_1..S_L; share = evaluation point; any k evaluations
   determine P and hence all L secrets. The information rate becomes L/(k+1)
   instead of 1/t, and q must satisfy q > n + L (n <= q - L).
7. Strong security (Nishiara-Takizawa): any set of participants smaller than
   threshold learns nothing about the secret, including the case where the
   adversary sees the polynomial's leading structure — the IEICE proof covers
   this stronger formulation that the 1981 note only sketched.

### Cost comparison
- Interpolation cost unchanged when no corruption (t points, O(t^2) field ops).
- Error correction: Berlekamp-Massey is O((n-t)·t) field operations — cheap,
   comparable to one extra interpolation.
- Storage: identical to Shamir for the (t,n) form; the ramp form trades
   security threshold (k < t for the same n) for L-fold secret capacity.
- Detection-only approaches that try all C(n,t) subsets cost C(n,t)·t^2 —
   only feasible for small n; the algebraic decoder is the efficient path.

### Composability
- The same GF(q) and the same share format as Shamir: drop-in, shares are
   interchangeable.
- Composes with the dealer-side optimization (section 8): Lagrange coefficient
   computation is shared between the two paths.
- Composes with verification (trusted dealer or commitments): if shares can be
   checked, erasure correction suffices and the decoder is even cheaper.
- Ramp variant composes with multi-secret sharing (section 4) — it is the
   simplest multi-secret construction.
- In the binary-field world, GF(2^m) RS decoders are widely implemented
   (error-correcting libraries), so implementations can borrow code.

### Pitfalls
- The error-correction capability is n-t (the redundancy in the share count),
   not t-1; a decoder that assumes larger correction radius fails.
- Corruption detection requires redundancy: with exactly t shares there is no
   way to tell which share is wrong — the decoder needs n > t.
- The Nishiara-Takizawa proof assumes specific algebraic conditions; citing
   the 1981 note alone for "all-subsets security" is an overstatement that
   reviewers may flag.
- Berlekamp-Massey needs the field's discrete structure; over GF(p) with huge
   primes the Euclidean decoder is preferred.
- The ramp scheme leaks: k-1 shares of a ramp with L secrets leak k-1-L
   combinations' worth — the threshold for "zero information" is k, not t.
- Chosen-ciphertext-style attacks: an adversary who can influence which shares
   are fed to the decoder can force expensive decoding; cap the number of
   shares processed.

---

## 4. Multi-Secret Sharing: Yang-Chang-Hwang, Pang-Liao, and the Linear View

### Identity
- Name: Multi-secret sharing schemes (MSS); main references:
  - C.-C. Yang, T.-Y. Chang, M.-S. Hwang, "A (t, n) multi-secret sharing
    scheme", Applied Mathematics and Computation, 151(2):483-490, 2004.
  - S.-J. Wang, Y.-R. Tsai, C.-C. Shen, "Verifiable threshold scheme in
    multi-secret sharing..." variants and their cryptanalyses (Hao-Yu-Song
    2011; Yu-Hao-Cheng 2013).
  - L.-J. Pang and Y.-M. Wang, "A new (t, n) multi-secret sharing scheme based
    on Shamir's secret sharing", Applied Mathematics and Computation,
    167(2):840-848, 2005.
  - A. Beimel, "Secret-Sharing Schemes: A Survey", 2011 (cs.bgu.ac.il),
    framing multi-secret schemes as linear secret sharing / monotone span
    programs.
- Year / venue: 2004-2011; survey 2011.

### Summary
Classic Shamir shares one secret per polynomial instance. Multi-secret
schemes share p > 1 secrets so that any t participants recover *all* p secrets
in one round. The Yang-Chang-Hwang (YCH) scheme: for p <= t, build a
polynomial h(x) of degree t-1 whose first p coefficients are the secrets
S_1..S_p and the remaining coefficients are random; give each participant a
private pseudo-share y_i = h(f(r, x_i)) where f is a two-variable one-way
function, x_i public; publish r and f(r, x_i); t participants interpolate h at
the pseudo-points (f(r,x_i), y_i) and recover all coefficients. Pang-Liao
(2005) is a widely-cited but broken variant (reconstruction reveals only one
secret; the p>1 claim fails), showing why one must validate MSS schemes.
Beimel's survey gives the correct general lens: a scheme sharing p secrets is
a linear secret sharing scheme, i.e., a monotone span program; polynomial-time
constructions exist for any access structure but share sizes can be
super-polynomial.

### Implementation algorithm (YCH, p <= t case, the sound version)
1. Choose a large prime q, p secrets S_1..S_p in GF(q), t > p.
2. Dealer chooses random b_p..b_(t-1) in GF(q) and forms
   h(x) = S_1 + S_2 x + ... + S_p x^(p-1) + b_p x^p + ... + b_(t-1) x^(t-1).
3. Pick a two-variable one-way function f (e.g., a keyed hash or exponentiation
   map) and a random public r.
4. For participant i with public identity x_i: publish f(r, x_i); secretly
   deliver y_i = h(f(r, x_i)).
5. Reconstruction: any t participants pool their y_i, compute f(r, x_i)
   (public), solve the interpolation system of t equations in the t unknowns
   S_1..S_p, b_p..b_(t-1); all p secrets come out.
6. The p > t case requires a degree-(p-1) polynomial h with the same secret
   placement and a modified share transform (y_i = h(f(r,x_i)) - x_i trick);
   this case is where published variants are most often broken — treat with
   caution.
7. Verifiable variants add commitments/checksums so participants can confirm
   the pseudo-share lies on the polynomial before pooling.

### Cost comparison
- One round of t shares yields p secrets: share-efficiency ratio p·t/(n·t) =
   p (for the same participant count), i.e., p-fold capacity gain over
   running Shamir p times.
- Dealer cost: t-1 random coefficients + n evaluations of h (same complexity
   as one Shamir run), instead of p Shamir runs (p·t random coefficients).
- The one-way function evaluation f(r, x_i) adds one hash/exponentiation per
   participant — negligible compared to interpolation.
- Beimel's survey warns: "more secrets" is not free in general; the linear
   span program view shows share size must grow with the complexity of the
   access structure, and super-polynomial lower bounds exist for
   non-threshold structures (Babai-Gal-Linial-Nikolov; Pitassi-Robere;
   Gal-Hansen).

### Composability
- The polynomial coefficients-as-secrets trick composes with the ramp variant
   of section 3 (same construction family).
- Composes with any of sections 2's fields; YCH needs a field with at least
   n + p distinct elements.
- The verifiable variants compose with commitment schemes (section 8-adjacent
   verification).
- YCH composes with threshold hierarchy only with care: the pseudo-share
   transformation interacts badly with derivative-based hierarchical shares.

### Pitfalls
- Many published MSS schemes are broken; Pang-Liao's widely-cited 2005 scheme
   and several "verifiable" variants were shown to reveal only one secret or
   to fail verification (Yu-Hao-Cheng 2013). Cite with the cryptanalysis.
- The p <= t case is sound; the p > t case is where subtle leaks appear; do
   not implement the p > t variant without independent verification.
- f must really be one-way in the right sense: publishing r and f(r, x_i)
   must not let t-1 participants compute h at a usable point.
- Beimel's linear view: if the access structure isn't a pure threshold, share
   sizes blow up; MSS doesn't escape that.
- Reuse of r across different secrets within one scheme instance leaks
   structure.

---

## 5. Weighted Threshold Secret Sharing

### Identity
- Name: Weighted threshold secret sharing.
- Authors: Shamir (1979) already suggested weights via multiple shares;
  formal treatments: A. Beimel, T. Tassa, E. Weinreb, "Characterizing Ideal
  Weighted Threshold Secret Sharing", Theory of Cryptography Conference
  (TCC 2005) / SIAM J. Discrete Mathematics 22(1):360-397, 2008; S. Garg,
  et al., "Cryptography with Weights: MPC, Encryption and Signatures",
  CRYPTO 2023, LNCS 14084 (eprint 2022/1632); weighted-RS variants in
  Iftene-Boureanu and Harn-Lin CRT-based constructions (2014).
- Year / venue: 1979 through 2023.

### Summary
Weighted threshold access: participants get weights w_i, a subset qualifies
iff the sum of weights of its members reaches a quota W. Shamir's original
trick (give w_i ordinary sub-shares per participant) is correct but
expensive: share size grows with weight. Beimel-Tassa-Weinreb show that not
every weighted threshold structure is "ideal" (achieving share size = secret
size) — the characterization is via the weights' additive structure — so
small-share weighted schemes necessarily pay in some dimension. Garg et al.
(2023) construct weighted ramp secret sharing with share size O(w) — linear
in the participant's weight — and derive weighted MPC, encryption, and
signatures from it, proving the primitive is compatible with modern
cryptography rather than just a storage feature.

### Implementation algorithm
1. Sub-share (virtualization) route: give participant with weight w_i
   w_i independent ordinary Shamir shares of the same (t'=W, N) scheme, where
   N = sum of all w_i; any coalition with total weight >= W holds >= W
   sub-shares and reconstructs. Storage = w_i field elements per participant.
2. Quota-field route (ideal when the structure is ideal): when the weights
   admit an ideal characterization (Beimel-Tassa-Weinreb conditions), use a
   single field element per participant with a carefully chosen evaluation
   point/derivative assignment; no general formula exists — check the
   characterization first.
3. Ramp-weighted route (Garg et al.): construct a weighted ramp scheme whose
   share size is O(w_i); the construction works over a vector space where
   each participant's share is a short vector proportional to their weight,
   giving threshold-with-quota recovery without the n-fold virtualization
   blowup.
4. CRT route (Iftene-Boureanu; Harn-Lin): choose pairwise coprime moduli
   m_1..m_n with weights; secret s mod M = product of moduli of qualifying
   subsets; participants get s mod m_i; CRT reconstruction works when the
   qualifying subset's moduli product reaches the secret's size bound.
5. Verification: Garg et al. include NIZK-style verification of share
   membership in the weighted setting (see also arXiv 2505.24289,
   "Verifiable Weighted Secret Sharing").

### Cost comparison
- Virtualization: share size w_i·|secret|; total storage = W·|secret| (sum of
  all weights must reach W), vs n·|secret| in unweighted Shamir when weights
  are 1.
- Garg et al. WRSS: O(w_i) share size, which is asymptotically optimal for
  weighted schemes and much better than w_i·|secret| when the field element
  is larger than a bit.
- Ideal cases (Beimel-Tassa-Weinreb): one field element per participant,
  matching plain Shamir.
- Beimel-Weinreb (IPL 2006) also show monotone circuits for weighted
  threshold functions have complexity linear in the number of weights,
  bounding how cheaply evaluation can be done.

### Composability
- Weighted schemes compose with hierarchical ones only when the access
  structure is a chain of weighted conditions — not generally.
- The Garg et al. WRSS composes with their weighted MPC/encryption/signature
  constructions, useful for threshold-key-management products.
- Virtualization composes trivially with any base scheme (just run it with
  larger n'), at the price of the storage blowup.
- CRT routes compose with parallel secrets (multi-secret, section 4).

### Pitfalls
- The naive "evaluate at one point per participant, weight = multiplicity of
  x" trick does NOT work: a participant with two shares at the same x gains
  nothing (interpolation needs distinct points). The correct virtualization
  uses distinct x values per sub-share.
- Ideal weighted schemes exist only for a restricted class of weight
  vectors; shipping a non-ideal weighted scheme with one-element shares is
  impossible — the Beimel-Tassa-Weinreb characterization must be consulted.
- Quota W must be the actual threshold; choosing W > sum of weights makes the
  scheme useless silently.
- CRT schemes leak partial information if the moduli are small relative to s;
  the secret's size bound must be respected.

---

## 6. Hierarchical Secret Sharing: Tassa's Birkhoff Interpolation Scheme

### Identity
- Name: "Hierarchical Threshold Secret Sharing".
- Authors: Tamir Tassa.
- Year / venue: Journal of Cryptology 20(2):237-264, 2007 (DOI
  10.1007/s00145-006-0334-8); earlier version in the proceedings of TCC 2004
  (LNCS 2951). Follow-ups: Tassa-Dyn (SISC 2009) on "hierarchical secret
  sharing schemes with lower bounds"; Belenkiy (2008) and others on
  "extended hierarchical" variants.

### Summary
Hierarchical access structure (levels U_0..U_m, thresholds k_0 < k_1 < ...
< k_m): a subset qualifies iff for every level i, it contains at least k_i
participants drawn from levels 0..i combined. Tassa's scheme is perfect,
ideal (each participant stores exactly one field element), and matches this
access structure exactly. The trick: the secret is the constant term of a
polynomial P of degree k_m - 1, and a participant in level U_i receives the
*i-th derivative* P^(i)(u) evaluated at their identity u (lower derivatives
carry more information). Reconstruction is a Birkhoff (lacunary Hermite)
interpolation problem; identities must be assigned so that all authorized
interpolation problems are well posed, and so that unauthorized subsets'
problems remain underdetermined. Tassa proves that the scheme realizes the
access structure and is perfectly secure.

### Implementation algorithm
1. Fix field F of characteristic not dividing the factorial orders; choose
   distinct identities u in F for participants (identities must satisfy
   the paper's well-posedness conditions — typically spread out, avoiding
   degenerate clusters).
2. Dealer picks random a_2..a_(k_m-1) and forms
   P(x) = S + a_2 x + ... + a_(k_m-1) x^(k_m-1).
3. Participant u in level i receives share = P^(i)(u) (the i-th derivative
   evaluated at u; for i=0 this is the ordinary Shamir value).
4. Reconstruction: t = k_m participants from an authorized set pool their
   (u, P^(i)(u)) pairs; solve the Birkhoff interpolation system (a
   Vandermonde-like system with derivative rows) for the coefficients; read
   off S.
5. The well-posedness condition: for each derivative order j, the number of
   given values of derivative order <= j must be at least j+1 (a necessary
   condition; Tassa's theorems give sufficient assignments).
6. Identities must be chosen in F with q large enough; the paper discusses
   field-size requirements for the assigned identities (q > number of
   participants, with margins for the interpolation constraints).

### Cost comparison
- Share size: one field element per participant (ideal), same as Shamir —
   versus Shamir-with-multiple-shares for hierarchy (rate 1/w_0) and versus
   Simmons'/Brickell's vector-space constructions (rate 1/k_m).
- Dealer cost: O(k_m) random coefficients + n derivative evaluations — each
   derivative evaluation is O(k_m) field ops, so O(n·k_m) total, same order
   as n runs of polynomial evaluation.
- Reconstruction: Birkhoff system solution is O(k_m^2) field ops, comparable
   to Lagrange interpolation.
- Identity assignment requires an offline search to satisfy well-posedness —
   one-time, polynomial-time in the paper's construction.

### Composability
- The scheme is a monotone span program realization of the hierarchical
   access structure; it composes with the linear view of section 4.
- Compose with verification: derivative shares can be committed with the
   same commitments used for ordinary shares.
- Not directly composable with the weighted constructions (different access
   structure algebra).
- Compose with multi-secret only by running independent instances.

### Pitfalls
- The naive "Shamir with per-level thresholds on one polynomial" fails; the
   derivative orders are what make it work.
- Birkhoff interpolation is not automatically well posed — ill-posed
   instances (no solution or multiple solutions) must be avoided by identity
   selection; blindly picking random identities can produce an ill-posed
   reconstruction for authorized sets.
- Field characteristic: derivatives require division by factorials; a field
   of characteristic dividing k_m! breaks the scheme.
- The scheme is ideal only for the hierarchical (chain) structure; variants
   with additional constraints (e.g., lower bounds per level) need the
   extended constructions and are no longer ideal.

---

## 7. Production Share Formats and Packing (Vault, secrets.js, libgfshare, ssss)

### Identity
- Name: Encodings and packaging of Shamir shares in production systems.
- Implementations: HashiCorp Vault shamir/shamir.go (IBM-licensed code by
  Brian Vohaska / HashiCorp, 2015-); secrets.js and its grempe fork
  (Alexander Kolarov / Greg Ruppe, audited by Cure53 2019); libgfshare
  (kinnison, djpohly fork); ssss (pointat / osresearch fork).
- Year / venue: 2005-present, ongoing.

### Summary
The academic Shamir algorithm leaves the share encoding open. Production
systems standardized: (a) share data layout, (b) how the x-coordinate is
stored, (c) checksums for tamper detection, (d) interop between
implementations, (e) packaging for humans (hex, base36, word lists). Vault:
shares are 32-byte groups, x drawn from a random permutation of 1..255, share
= x || y_1..y_5 (grouped), no checksum/version byte in the current format.
secrets.js: header `<bits><id><value>` — bits in base36 (3..20), id random,
value per-symbol with base-2/3/36 encoding; newShare(id, shares) derives an
extra share via Lagrange recomputation without the secret (partial
reconstruction). libgfshare: binary format designed for reuse of shares with
new (t', n') parameters (reusing shares across schemes with different
thresholds). ssss: hex-encoded shares with an optional passphrase
(encryption layer) and a "diffusion layer" that mixes the key before
splitting.

### Implementation algorithm
1. Choose a group size (Vault: 32 bytes per symbol), field GF(2^8), reduction
   constant 0x1B, primitive element 0x03.
2. Split the secret into groups; for each group evaluate the polynomial at n
   distinct nonzero x's (Vault: x from mathrand.Perm(255)+1, stored first in
   each share).
3. Compose each share as: x byte + one y byte per group. Vault returns
   `[[x, y_1..y_g], ...]` or `[x, y_1..y_g]` as a flat byte slice
   (ShareOverhead = 1).
4. secrets.js: build header `<bits><id>`, then for each share index 1..n and
   each symbol, encode the field value in the configured radix; reconstruction
   parses the header, uses bits to select the field, and interpolates.
5. newShare: to produce a new (n+1)th share, Lagrange-compute P(n+1) from any
   t existing shares (requires recombining shares, allowed when the caller
   legitimately holds t shares).
6. Checksums: where included, append a checksum per share (e.g., a simple
   hash or parity group) so that corrupted shares are detectable before
   interpolation; note: Vault's format currently has none.
7. Passphrase mode (ssss): derive an encryption key from the passphrase,
   encrypt the secret's split material, then share; decryption requires the
   passphrase plus t shares.

### Cost comparison
- Overhead: Vault's ShareOverhead = 1 byte per group of 32 (3.1% storage
   overhead for 256-bit secrets); secrets.js: base36 header adds ~1-3 chars
   per share.
- Encoding/decoding costs are linear in share size; the dominant cost remains
   interpolation.
- Checksums add a hash per share: negligible.
- Interop: matching field conventions makes shares portable; mismatched
   conventions produce garbage silently.

### Composability
- Share formats are the interop layer: a fixed format composes with any
   field/algorithm variant from sections 2-6, as long as conventions are
   published.
- Vault's unseal pipeline: threshold 1 -> raw key; else shamir.Combine on the
   unseal parts; the barrier then uses AES-GCM keyring encryption. The
   shamir layer and the encryption layer are cleanly separable.
- secrets.js's newShare composes with partial-reconstruction workflows
   (e.g., adding a member without dealer re-issuance).

### Pitfalls
- Vault's format has no checksum/version; corrupting one byte of a Vault
   unseal share produces a wrong key with no error — detectable only by
   decryption failure downstream.
- Random-permutation x's (Vault) vs fixed x = 1..n (secrets.js) are
   incompatible encodings of the same math.
- secrets.js uses `bits` for the field size: bits must match the share
   format or shares fail to parse; the header is text, the payload is
   number-encoded, both must be regenerated consistently.
- libgfshare's share-reuse across different (t', n') is convenient but
   weakens security in the original instance (the reused shares leak
   information about the earlier polynomial).
- ssss passphrase mode: passphrase entropy caps the security of the whole
   system; a dictionary passphrase defeats the scheme.

---

## 8. Dealer-Side Optimization: Lagrange Coefficients, Batched Evaluation, Re-Sharing

### Identity
- Name: Precomputed Lagrange coefficients; batched polynomial evaluation;
  share re-issuance without revealing the secret.
- Authors: folklore (evaluation is Horner's rule; coefficient reuse is
  standard in RS decoders); documented in secrets.js (newShare) and in
  general secret-sharing libraries; the "share renewal without secret
  exposure" protocol appears in the threshold cryptography literature
  (e.g., Herzberg et al., "Proactive Secret Sharing", CRYPTO '95).
- Year / venue: 1995 (Herzberg et al.) and folklore.

### Summary
The dealer's cost for n shares of a (t, n) scheme is n Horner evaluations of
a degree-(t-1) polynomial = n·(t-1) multiplications. Two optimizations:
(a) batch evaluation of the same polynomial at many points (divide-and-
conquer / multi-point evaluation, O(n log^2 n) with fast polynomial
arithmetic; in practice, Horner with cached coefficient powers);
(b) when re-sharing the same secret at a new threshold or to new
participants, precompute the Lagrange coefficients relating the old shares to
the new ones (for the reconstruction side, a participant holding t shares
computes P at a new x with O(t) field multiplications using the cached
coefficients lambda_i(x) = prod_{j != i} (x - x_j)/(x_i - x_j)). Proactive
resilience (Herzberg et al.) uses this to periodically re-share the secret
without any participant learning it.

### Implementation algorithm
1. Dealer: pick random a_1..a_(t-1); P(x) = S + a_1 x + ... .
2. Evaluate at x_1..x_n by Horner: O(n·t) field ops; no faster generic
   method is needed for n <= 1000; for very large n use multi-point
   evaluation (subproduct tree).
3. For re-share to a new participant: given t old shares (x_i, y_i), compute
   lambda_i for each old point at the new x and sum y_i·lambda_i — O(t) field
   multiplications per new share, no secret material touched.
4. Proactive reshare: dealer (or the t participants jointly) chooses a random
   degree-(t-1) polynomial R with R(0) = 0, computes new shares
   y'_i = y_i + R(i), and each participant adds R(i); old shares are
   discarded; an adversary learning shares from two different periods gains
   nothing (the sum of R-evaluations is a fresh random polynomial).
5. Verification (commitments): dealer publishes commitments to coefficients;
   participants verify their share satisfies the commitment; this catches
   dealer misbehavior (Feldman's VSS) and composes with all sections above.

### Cost comparison
- Dealer: O(n·t) vs O(n·t) baseline — the gain is in avoiding re-generation
   of coefficients for repeated evaluations (re-share case: O(t) per new
   share vs O(n·t) for a fresh sharing).
- Reconstruction with cached coefficients: O(t) per evaluation vs O(t^2) for
   full Lagrange per evaluation.
- Multi-point evaluation: asymptotically O(n log^2 n) but with a large
   constant; wins only for n >= 10^4.
- Proactive reshare: adds one random polynomial per period; per-share
   communication is one field element.

### Composability
- The lambda precomputation is the connective tissue of every variant in
   sections 3-6 (they all reduce to polynomial evaluation/interpolation).
- Composes with weighted virtualization (section 5): reshare handles weight
   changes by adding/removing sub-shares.
- Proactive reshare composes with the Vault-style deployment: unseal shares
   can be renewed periodically without changing the master key.
- Feldman commitments give a cheap verifiability layer independent of the
   field choice.

### Pitfalls
- Cached Lagrange coefficients are only valid for the same x-set; changing
   the participant set invalidates all caches.
- Proactive reshare requires a secure channel to distribute R(i); doing it
   over the shares' own channel leaks R.
- Multi-point evaluation's subproduct tree needs memory O(n) and careful
   modular arithmetic; a naive implementation is slower than Horner.
- Feldman commitments reveal information (the committed polynomial's
   structure) — fine for dealer honesty, but combined with the ramp or
   multi-secret variants the leaked structure may cross thresholds.
- Re-share at a lower threshold (t' < t) increases leakage: old shares are
   still valid under the lower threshold; thresholds must only be raised.

---

## Cross-cutting remarks

1. Perfect versus computational: Krawczyk (section 1) trades perfect secrecy
   for share-size reduction; everything else preserves perfect secrecy.
2. Share size lower bounds: perfect (t,n) schemes need |share| >= |secret|
   (entropy argument); ramp, multi-secret, and hybrid schemes trade the bound
   away in controlled ways (sections 1, 3, 4).
3. The Reed-Solomon duality (section 3) is the deepest single fact: almost
   every optimization in sections 2, 4, 6, 8 is a polynomial-interpolation
   fact in disguise; designing with the code-theoretic view in mind avoids
   re-deriving results.
4. Field choice (section 2) is the highest-leverage, lowest-risk improvement:
   GF(2^8) with the AES polynomial gives constant-time, table-fast
   arithmetic, byte-aligned shares, and instant interop with Vault and
   libgfshare.
5. Production reality (section 7): checksum/versioning gaps in Vault's share
   format and the fixed-vs-random x convention are the two most common
   integration bugs; any new implementation should publish its conventions.
6. Security of the "published" variants: multi-secret schemes (section 4)
   are a minefield of broken constructions (Pang-Liao and many verifiable
   variants were cryptanalyzed); prefer either the YCH p <= t construction,
   the ramp/RS construction (section 3), or independent verification.

Sources consulted: Krawczyk (Crypto '94); McEliece-Sarwate (CACM 1981);
Nishiara-Takizawa (IEICE Trans. J92-A, 2009); Yang-Chang-Hwang (AMC 2004);
Pang-Wang (AMC 2005); Yu-Hao-Cheng (2013) and Hao-Yu-Song (2011)
cryptanalyses; Beimel (2011 survey); Beimel-Tassa-Weinreb (SIAM JDM 2008);
Beimel-Weinreb (IPL 2006); Garg et al. (CRYPTO 2023, eprint 2022/1632);
Tassa (J. Cryptology 2007, full text openu.ac.il); Herzberg et al.
(CRYPTO '95); HashiCorp Vault shamir/shamir.go and barrier_aes_gcm.go
(main and v1.15.6); secrets.js/grempe fork README; libgfshare (kinnison,
djpohly); ssss (pointat, osresearch); arXiv 2505.24289; eprint 2023/1534;
arXiv 2502.02774.
