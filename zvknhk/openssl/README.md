#   Zvknhk in OpenSSL

How `vkeccak.vi` is wired into OpenSSL by
[`scripts/apply-openssl-patch.sh`](../scripts/apply-openssl-patch.sh).

`demo/openssl/` is a pristine upstream OpenSSL checkout, exactly as
`riscv-isa-sim/` is for Spike and `qemu-src/` is for QEMU. The patch script
layers the instruction onto it at build time. The editable source is the one
file here in `openssl/`; everything else the script does is two small
insertions into upstream files.

```bash
make openssl            # -> demo/openssl/build/apps/openssl
make patch-openssl      # apply the patch only
make unpatch-openssl    # restore demo/openssl to pristine upstream
make test-openssl       # run the checks under QEMU
make test-openssl-all   # ... at every VLEN QEMU supports
make openssl-clean      # remove demo/openssl/build
```

This is the consumer-facing end of the extension. Spike and QEMU answer *does
the instruction work*; this answers *does real software use it*.


##  The one file that holds the instruction

| File | Copied to | Pulled in by |
|---|---|---|
| `keccak1600_zvknhk.c.inc` | `crypto/sha/` | `#include` just above `SHA3_absorb()` in `keccak1600.c` |

It contains the permutation — `KeccakF1600_zvknhk()`, one `.insn` plus the
loads and stores around it — and the runtime dispatch that chooses between it
and the generic C.


##  The two insertion sites

Both edits are *pure insertions* anchored on a nearby upstream line, and both
are guarded by a token that only the patch introduces. That makes the script
idempotent: an already-patched file is skipped, so it is safe to re-run on
every build.

| File | What goes in |
|---|---|
| `include/crypto/riscv_arch.def` | `RISCV_DEFINE_CAP(ZVKNHK, 0, 24, -1, 0)` |
| `crypto/sha/keccak1600.c` | `#include "keccak1600_zvknhk.c.inc"` |

That really is the whole patch. Two lines of upstream change, because the
interesting decision was *where* to put them.


##  Why `KeccakF1600()` and not the provider

OpenSSL's per-architecture SHA-3 hook is `PROV_SHA3_METHOD` in
`providers/implementations/digests/sha3_prov.c` — a struct of `absorb`,
`final` and `squeeze` pointers, chosen at digest-init time from capability
bits. s390x installs a KIMD/KLMD version there, ARMv8.2 an SHA3-extension one.
It is the obvious place to hook, and it is the wrong one here, for two
reasons.

**It covers only half the work.** Look at what the ARM branch actually
installs:

```c
static PROV_SHA3_METHOD shake_ARMSHA3_md = {
    armsha3_sha3_absorb,
    ossl_sha3_final_default,
    ossl_shake_squeeze_default     /* generic KeccakF1600 */
};
```

Absorb is accelerated; squeeze is not. For hashing that is a reasonable
trade, because absorb is where the bytes are. For ML-KEM it is backwards. A
measured ML-KEM-768 keygen runs 44 permutations, and only the *first* rate
block of each hash reaches `SHA3_absorb()` — everything past it comes out of
`SHA3_squeeze()`. The nine matrix polynomials each need three SHAKE128 blocks,
so 18 of those 44 permutations are squeeze-side. Hooking absorb alone would
leave a large share of the Keccak on the table.

**It covers only the digest provider.** `KeccakF1600()` is one level below:
absorb, final and squeeze all funnel through it. Patching there puts the
instruction under SHA-3, SHAKE, KMAC, ML-KEM, ML-DSA and SLH-DSA in a single
site — and `crypto/sha/build.info` lists this code as `SOURCE` for both
`libcrypto` and `providers/libfips.a`, so the FIPS provider gets it too.

The cost is that a drop-in `KeccakF1600()` reloads and restores the 200-byte
state around every permutation, because between calls the state lives in
`KECCAK1600_CTX.A` in memory. Keeping it in the vector registers across a
whole absorb or squeeze would mean hooking `SHA3_absorb()`/`SHA3_squeeze()`
instead, and writing the padding and rate handling to go with it. This patch
deliberately takes the simple route: it is the smallest change that makes
every SHA-3 consumer in the library use the instruction.


##  How the include redirects the call sites

`KeccakF1600()` is `static` in `keccak1600.c`, defined once (under several
mutually exclusive `#if` variants) and called from exactly two places —
`SHA3_absorb()` and `SHA3_squeeze()`. The `.c.inc` ends with

```c
#define KeccakF1600 KeccakF1600_zvknhk_dispatch
```

and the `#include` is anchored so that it lands after every definition and
before both calls. Preprocessing is sequential, so the `KeccakF1600(A)` call
written *inside* the dispatcher — above the `#define` — is not itself
replaced, and the software fallback does not recurse.

That is what lets the change be a one-line insertion rather than an edit of
the call sites. The anchor is the prose of the comment block that opens
`SHA3_absorb()`, using the script's `after_term` mode to land after the
comment closes; anchoring on the function signature would not work, because
`size_t SHA3_absorb(uint64_t A[5][5], ...` appears twice in the file and the
first occurrence is the forward declaration at the top — inserting there would
put the `#define` above the definitions and make the fallback recurse.


##  The capability, and how to turn it on

`RISCV_DEFINE_CAP(ZVKNHK, 0, 24, -1, 0)` is one line in
`include/crypto/riscv_arch.def`. Word 0 bit 24 is the first free slot after
`ZVKSH`. `riscv_arch.h` derives everything else from it by re-including the
`.def` under different macro definitions: the `RISCV_HAS_ZVKNHK()` inline, the
sizing of `OPENSSL_riscvcap_P[]`, and the `RISCV_capabilities[]` entry that
carries the name.

The hwprobe key is `-1`, meaning "no hwprobe key", exactly as `ZKR` does.
Zvknhk is not an upstream extension, so the kernel has no bit for it. That
leaves the environment override in `crypto/riscvcap.c`:

```c
if ((e = getenv("OPENSSL_riscvcap")))
    parse_env(e);
else
    hwprobe_to_cap();
```

`parse_env()` uppercases the string and searches it for `_<EXTNAME>`. So:

```bash
OPENSSL_riscvcap=rv64gc_v_zvknhk qemu-riscv64 -cpu rv64,zvknhk=true,vlen=256 ...
```

**`_v_` has to be spelled with its own underscore.** `rv64gcv_zvknhk` contains
no literal `_V`, so `RISCV_HAS_V()` stays false; `riscv_vlen()` is only probed
under `if (RISCV_HAS_V())`, VLEN reads back as 0, and the dispatch correctly
declines. This is easy to get wrong and fails silently — silently *correct*,
but on the software path.

The dispatch is `RISCV_HAS_ZVKNHK() && riscv_vlen() >= 128`, matching the
precedent at `crypto/sha/sha_riscv.c:25` and `crypto/modes/gcm128.c:528`, and
matching the `Zvl128b` requirement in `zvknhk.adoc`.


##  Element layout

`KECCAK1600_CTX.A` is `uint64_t[5][5]`, and `SHA3_absorb()` already treats it
as flat — `A_flat = (uint64_t *)A` — so lane `i` sits at byte offset `8*i`.

That is exactly the order `zvknhk.adoc` defines for the fixed element group:
registers concatenated in increasing register-number order using the standard
element layout. The state therefore needs no marshalling at all; `vle64.v`
from `&A[0][0]` lands each lane where the instruction expects it.

`vl` and `LMUL` matter only to the surrounding `vle64`/`vse64` that move the
25 live words. At `LMUL=8` the largest usable `vl` is `VLMAX = 8*VLEN/64`,
which is at least 25 for `VLEN >= 256` but only 16 at `VLEN = 128` — so there
the transfer is split in two, elements 0..15 into `v0`..`v7` and 16..24 into
`v8`..`v12`. Both halves stay inside the 16-register group that `vd=v0` spans
at that VLEN. This is the same split as
[`test/keccak_insn.c`](../test/keccak_insn.c), and it is why the test sweep
covers 128 explicitly.


##  Two assembler details

`.option push` / `.option arch, +v` / `.option pop` wraps each block. OpenSSL
passes no `-march` when cross-building RISC-V, so whether the assembler
accepts `vle64.v` depends entirely on how the toolchain was configured. The
option makes it assemble either way and costs nothing when V is already on.

The clobber list is not optional. When the toolchain's default `-march` does
include V — which it does for a `riscv64-unknown-linux-gnu` GCC built for
`rv64gcv` — GCC auto-vectorises the surrounding C. `SHA3_absorb()` compiles to
VLA vector code, `csrr vlenb` and all, in the *unpatched* tree. So vector state
can be live across the asm once the permutation is inlined into it, and `vl`
and `vtype` have to be declared too, because GCC tracks `vtype` to elide
redundant `vsetvli` and the `vsetivli` here invalidates that. The list covers
`v0`–`v15`, the widest element group (`NREG = ceil(2048/VLEN) = 16` at the
`VLEN=128` floor); larger VLEN spans fewer registers, so one list is safe for
both paths.


##  What actually picks it up

ML-KEM and ML-DSA reach Keccak through fetched digests, not through internal
calls:

```c
crypto/ml_kem/ml_kem.c:1686   key->shake128_md = EVP_MD_fetch(libctx, "SHAKE128",  properties);
                     :1687   key->shake256_md = EVP_MD_fetch(libctx, "SHAKE256",  properties);
                     :1688   key->sha3_256_md = EVP_MD_fetch(libctx, "SHA3-256",  properties);
                     :1689   key->sha3_512_md = EVP_MD_fetch(libctx, "SHA3-512",  properties);

crypto/ml_dsa/ml_dsa_key.c:98 ret->shake128_md = EVP_MD_fetch(libctx, "SHAKE-128", propq);
                          :99 ret->shake256_md = EVP_MD_fetch(libctx, "SHAKE-256", propq);
```

Those handles are the only Keccak in either implementation — there is no
internal fallback — and they resolve to the default provider's SHA-3, which is
the code this patch sits underneath. Note the two spellings: ML-KEM asks for
`SHAKE128`, ML-DSA for `SHAKE-128`. That inconsistency would matter to anyone
writing a *provider*; it does not matter here, because the patch is below the
name lookup entirely. Which is the other argument for hooking where it does.


##  Testing

`make test-openssl` runs sixteen checks in [`../demo/`](../demo/):

- six known answers — SHA3-256, SHA3-512, and SHAKE128/256 at both 32 and 200
  bytes of output — with the capability **on**, so the instruction is doing
  the work;
- the same six with the capability **off** *and on a CPU model without
  `zvknhk`*, so the software fallback is genuinely the code that ran. Running
  those on a CPU that has the instruction would let a regression that ignored
  the capability pass unnoticed;
- an ML-KEM-768 keygen/encap/decap round trip and an ML-DSA-65
  keygen/sign/verify;
- a fingerprint comparison across both backends;
- a negative test.

**Why 200 bytes.** Output shorter than the rate — 168 for SHAKE128, 136 for
SHAKE256 — is copied straight out of the state after the padding permutation,
so it only ever reaches the `KeccakF1600()` call in `SHA3_absorb()`. The one in
`SHA3_squeeze()` is never executed. Counted directly with
`contrib/plugins/libhowvec.so`: `xoflen` 32 and 168 execute `vkeccak.vi` once,
200 executes it twice, 400 three times. Without a vector past the rate, half
the patch is untested.

**Why a fingerprint.** The round trips are self-consistency checks — encap
against decap, sign against verify — so a uniformly wrong Keccak would still
pass them. `pqcbench fingerprint` grows both keys from a fixed seed and signs
deterministically, then prints SHA-256 (not Keccak) digests of the ML-KEM
public key, the ML-DSA public key and the ML-DSA signature. Requiring those to
agree between the two backends cross-checks `vkeccak.vi` against the
FIPS-202-validated software path across matrix expansion, CBD and rejection
sampling, and the signing loop.

**Why the exit status.** The negative test runs the same binary with the same
`OPENSSL_riscvcap` against a QEMU CPU *without* `zvknhk`, and requires exit
status exactly **132** — 128 + SIGILL. Accepting any nonzero status would also
accept a bad QEMU option, a loader failure or an unrelated crash, none of which
prove the instruction ever executed. Without this check the whole suite proves
nothing: falling back to the C code produces identical digests.

`make test-openssl-all` repeats all of it at VLEN 128, 256, 512 and 1024.


##  Measuring

Two targets, because emulators and hardware have to be measured differently.

```bash
make -C demo count     # instructions removed per operation (emulator)
make -C demo cycles    # rdcycle / rdinstret, best of N runs (hardware)
```

**On an emulator, count instructions.** QEMU has no timing model, and its
in-guest counters are worse than useless: in user mode it answers every counter
CSR — `cycle`, `instret` and the `hpmcounter`s alike — from
`read_hpmcounter()` → `get_ticks()` → `cpu_get_host_ticks()`, the *host* CPU's
tick counter (`target/riscv/tcg/csr.c`). A 1M-iteration loop measured as
76,301,877 "instructions" inside a process the TCG plugin counted at 5,149,196
in total, with `cycle` returning 76,301,718 — the same quantity, read twice
from the same source. What QEMU does do exactly is count executed
instructions, via `tests/tcg/plugins/libinsn.so`. `make count` uses that, and
runs each operation at *n* and 2*n* so that process startup differences out —
without which the numbers describe OpenSSL's CLI rather than the algorithm.

**On hardware, count cycles.** `pqcbench <op> <n> <reps>` reads `rdcycle` and
`rdinstret` around the loop and reports the best of `<reps>`, along with CPI
and wall-clock ns. Run it natively on the target, no emulator:

```bash
./pqcbench all 100 5                                   # software path
OPENSSL_riscvcap=rv64gc_v_zvknhk ./pqcbench all 100 5  # vkeccak path
```

`make -C demo cycles` runs exactly that, with **no emulator**; on a build host
it stops and says to copy `demo/pqcbench` to the board. `make -C demo
cycles-qemu` exercises the same code path under QEMU, where the numbers are
host ticks rather than cycles — for checking the code, not for results.

`cycle` and `instret` are only readable from user mode if `mcounteren` grants
it, so the tool probes with a `SIGILL` handler first and falls back to wall
clock rather than dying — verified under Linux and `qemu-riscv64`, where an
unassigned CSR is caught and the process survives. That cannot help under Spike
behind `pk`, which does not permit `rdcycle` and aborts on the trap instead of
raising `SIGILL`; use the two-argument form there.

Before the table it prints a **counter check**: `instret` measured over a probe
of exactly known length. A retirement counter reports ×1.00; anything else is
called out. This deliberately replaced an earlier test that treated
`cycle == instret` as proof of emulation — a simple in-order core can retire a
tight ALU loop at CPI 1.0, so that test would have libelled real hardware.

Everything is deterministic: keys are grown from a fixed seed and ML-DSA
signatures taken in deterministic mode. Without that, hedged signing plus
rejection sampling makes two runs do genuinely different amounts of Keccak —
enough that measured deltas came out negative.

**The seed is single use.** Both providers erase it once the key exists —
`ml_kem_kmgmt.c` "Erase the single-use seed", and `ml_dsa_kmgmt.c` cleansing
`gctx->entropy` — so a generation context that is seeded once and then reused
yields one deterministic key followed by random ones. That is not a subtle
effect: before it was fixed, measured ML-KEM keygen moved from 2,093,960
instructions per operation at N=2 to 508,318 at N=41, because the second
generation is the one that pays to initialise the DRBG. `pqcbench` re-applies
the seed before every generation, and the figures are now flat to ±2
instructions across N.

**Nothing is calibrated by hand.** `count.sh` derives instructions-per-
permutation on every run, with the same binary at the same VLEN, by hashing
1 MiB with SHA3-256 — whose permutation count follows from the 136-byte rate as
`floor(S/136) + 1 = 7711`. It matters: the figure is VLEN-dependent, 5951/5788
at VLEN=128 against 5907/5795 at VLEN=256. Every process's exit status is
checked and exactly one `total insns` record is required, so a crashed run or a
mistyped operation fails loudly instead of being reported as a sample of zero.

One caveat when comparing against another harness: the Keccak *share* depends
on how much EVP plumbing is counted as part of the operation. The permutation
count is the stable quantity; the percentage is a ratio against whatever
denominator the harness chose.


##  Limits

Upstream moves these files. In 4.0.2 the capability table is
`include/crypto/riscv_arch.def`; on master it has moved to
`include/arch/riscv_arch.def`, and `sha3_prov.c.in` has been split into
`sha3_prov.c` and `sha3_prov.inc.in`. Every anchor in the script is checked
before use and the script fails loudly if one is gone, which is the intended
way to find out that a bump moved something.

Only the 24-round form is reachable. `imm5` is always 0 here, because SHA-3,
SHAKE and KMAC are all Keccak-f[1600]. The 12-round selector exists for
TurboSHAKE and KangarooTwelve, which OpenSSL has no consumer for.
