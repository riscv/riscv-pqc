# Zvknhk — reference implementations and tests

Reference implementations and tests for **`Zvknhk`**, the RISC-V Vector Keccak
extension, and its instruction `vkeccak.vi` — a vector-immediate multi-round
Keccak-_p_[1600] permutation.

The normative definition is [`../src/zvknhk.adoc`](../src/zvknhk.adoc), a
chapter of the PQC specification built by the Makefile at the repository root.
Nothing in this directory is needed to build that document, and nothing here is
normative: where an implementation and the specification disagree, the
specification wins.

There are three implementations, in ascending order of distance from the spec:

| | What it is | Source of truth |
|---|---|---|
| **Spike** | the instruction's semantics in the RISC-V ISA simulator | [`spike/vkeccak_vi.h`](spike/vkeccak_vi.h) |
| **QEMU** | the same semantics for TCG | [`qemu/`](qemu/README.md) |
| **OpenSSL** | a consumer — SHA-3/SHAKE/ML-KEM/ML-DSA running on the instruction | [`openssl/`](openssl/README.md) |

Each upstream is a pristine submodule that `scripts/apply-*-patch.sh` layers the
change onto at build time; the editable sources live here. The round body in
`qemu/vkeccak_vi.c.inc` is character-for-character the one in
`spike/vkeccak_vi.h`, so the two reference implementations cannot drift apart.

## License

This directory is BSD 3-Clause — see [`LICENSE`](LICENSE) — not CC-BY-4.0 like
the specification text in `../src/`. Every file carries an
`SPDX-License-Identifier` tag.

BSD-3-Clause is the deliberate choice: this code is written to be copied into
QEMU (GPL-2.0-or-later), OpenSSL (Apache-2.0) and Spike (BSD-3-Clause), and it
is the license compatible with all three. Apache-2.0 would not be — it cannot
be combined with QEMU, which is GPLv2 as a whole.

## Getting the submodules

```bash
git submodule update --init --recursive zvknhk/riscv-isa-sim zvknhk/qemu-src zvknhk/demo/openssl
```

They track pristine upstream, pinned to a stable release wherever upstream
publishes one:

| Submodule | Upstream | Pinned at |
|---|---|---|
| `riscv-isa-sim` | `github.com/riscv-software-src/riscv-isa-sim` | `master` |
| `qemu-src` | `gitlab.com/qemu-project/qemu` | `v11.1.1` |
| `demo/openssl` | `github.com/openssl/openssl` | `openssl-4.0.2` |

Spike is the exception: its most recent tag, `v1.1.0`, is from December 2021 and
sits 2260 commits behind, well before the Zvk vector-crypto support this builds
on. Upstream develops on `master` and so does everyone consuming it, so that is
what is pinned. The exact commits are recorded in the superproject; `git
submodule status` prints them.

When moving a pin, re-run the patch for that upstream before recording it. The
scripts are anchor-based, and a hunk that inserts into a long, churning list is
the first thing to break — the script fails loudly naming the file rather than
applying a half-patch.

Keep them pointed at upstream. If one is repointed at a fork and pinned to a
fork-only commit, `git clone --recurse-submodules` breaks for everyone else: the
URL in `.gitmodules` still resolves to upstream, where that commit does not
exist.

## Build — the Spike simulator

`riscv-isa-sim` is a pristine upstream Spike checkout;
`scripts/apply-spike-patch.sh` layers the Zvknhk instruction onto it. `make
spike` runs the patch, configures once, and builds:

```bash
make spike           # -> riscv-isa-sim/build/spike
make patch-spike     # apply the patch only
make spike-clean     # remove riscv-isa-sim/build
```

The build needs a C++20 compiler, Boost (`libboost-dev`, regex + system),
`device-tree-compiler` and autotools — the same dependencies as upstream Spike;
see its README. `make spike` builds with `-j$(nproc)`; override with `NPROC=`.

The patch adds one extension, `zvknhk`, which gates the instruction. Enable it
in the ISA string:

```bash
riscv-isa-sim/build/spike --isa=rv64gcv_zvl256b_zvknhk_zicntr_zihpm pk <binary>
```

Per the specification, `Zvknhk` depends on `Zve64x` and needs `VLEN >= 128`, so
the registration declares both as implied and `--isa=rv64i_zvknhk` pulls them in
rather than being accepted as a vector-less string. An explicitly requested
`zvl` still wins, since the implied `zvl128b` only raises `VLEN`. Note this
makes `zvknhk` stricter than upstream's other `zvk*` extensions, which declare
no implications.

### What the patch does

`spike/vkeccak_vi.h` is the instruction semantics and the thing to edit. The
rest is glue that the script inserts into five upstream files: the `EXT_ZVKNHK`
extension id, the `"zvknhk"` ISA-string name, the `MATCH`/`MASK` encoding and
its `DECLARE_INSN`, a `riscv_insn_ext_zvknhk` build-system entry, and the
disassembler entry.

Because the specification defines the state as a single fixed element group that
is not strip-mined, the implementation needs neither the Zvk element-group loop
macros nor a new element-group type. `riscv/vector_unit.h`,
`riscv/zvk_ext_macros.h` and `riscv/zvkned_ext_macros.h` are therefore left
untouched, which keeps the footprint on upstream small.

If you change *what* the script inserts, reset the simulator sources first —
each site is guarded by a token that only the patch introduces, so an
already-patched file is skipped and would keep the old insertion:

```bash
make unpatch-spike && make spike
```

### Conformance to the specification

The implementation follows `../src/zvknhk.adoc` rather than the original fork,
which predates the current spec text and differs from it in several ways: it
treated `imm5` as a literal round count, strip-mined the permutation across
`vl`, and placed the fixed encoding field at `0b10001` instead of `0b10010`.
What the patched simulator now implements:

- the state is one fixed element group designated by `vd`, with
  `EMUL=NREG=ceil(EGW/VLEN)`, independent of `vl` and `LMUL`;
- `imm5` is a selector — `0` gives 24 rounds, `1` gives 12 rounds using
  `RC[12..23]`, and every other value is reserved;
- `SEW != 64`, `vm=0`, a nonzero `vstart`, a reserved `imm5` and a misaligned
  `vd` all raise an illegal-instruction exception;
- elements 25..31 and all bits outside the fixed group are preserved.

Each insertion is anchored on a nearby upstream line and guarded by a token that
only this patch introduces, so the script is idempotent and re-runs cleanly. It
deliberately does **not** use a unified diff: the change originated as a nine-hunk
diff against a Spike fork, and two of those hunks already failed to apply against
upstream two months later, because they insert lines into long, churning lists.
If an anchor ever disappears, the script fails loudly naming the file — update
the anchor rather than force the patch.

## Build — QEMU

`qemu-src` is a pristine upstream QEMU checkout, and
`scripts/apply-qemu-patch.sh` layers the Zvknhk instruction onto it in exactly
the same anchor-based way as the Spike patch. `make qemu` runs the patch,
configures once, and builds:

```bash
make qemu            # -> qemu-src/build/qemu-riscv64
                     #    qemu-src/build/qemu-system-riscv64
make patch-qemu      # apply the patch only
make unpatch-qemu    # restore qemu-src to pristine upstream
make qemu-clean      # remove qemu-src/build
```

Two targets are built: `riscv64-linux-user`, which runs RISC-V Linux binaries
directly — static and dynamically linked alike, no proxy kernel — and
`riscv64-softmmu` for full-system emulation. Override `QEMU_TARGETS` to build
just one. The build needs QEMU's own dependencies (a C compiler, Python, Ninja,
glib); it bootstraps Meson itself into a private venv.

Because `zvknhk` implies `zve64x`, it is enough on its own in the CPU string:

```bash
qemu-src/build/qemu-riscv64 -cpu rv64,zvknhk=true,vlen=256 test/xtest
```

**[`qemu/README.md`](qemu/README.md) is the writeup of how the instruction is
wired in** — the two `.c.inc` files that hold it, the nine insertion sites, why
none of QEMU's strip-mining scaffolding applies to a fixed element group, and
where each reserved encoding is enforced.

Note that QEMU caps VLEN at `RV_VLEN_MAX`, currently 1024, so the `VLEN >= 2048`
row of the specification's table cannot be exercised there; Spike has no such
cap.

## Build — OpenSSL

The third target is not a simulator but a consumer. `demo/openssl` is a pristine
upstream OpenSSL checkout, and `scripts/apply-openssl-patch.sh` layers a
`vkeccak.vi` Keccak backend onto it in the same anchor-based way as the other
two patches. `make openssl` runs the patch, configures once, and cross-builds:

```bash
make openssl            # -> demo/openssl/build/apps/openssl
make patch-openssl      # apply the patch only
make unpatch-openssl    # restore demo/openssl to pristine upstream
make openssl-clean      # remove demo/openssl/build
```

It is a two-line patch: a `ZVKNHK` capability bit in the RISC-V capability
table, and one `#include` in `crypto/sha/keccak1600.c` that redirects
`KeccakF1600()`. Hooking the permutation rather than the digest provider is what
makes it two lines instead of a rewrite — and it is what puts the instruction
under SHA-3, SHAKE, KMAC, ML-KEM, ML-DSA and SLH-DSA at once, in both the
default and the FIPS provider.

Zvknhk is not an upstream extension, so the kernel has no hwprobe bit for it.
OpenSSL's `OPENSSL_riscvcap` override is therefore how it is switched on, which
suits an emulator exactly:

```bash
OPENSSL_riscvcap=rv64gc_v_zvknhk \
    qemu-src/build/qemu-riscv64 -L $RISCV/sysroot \
    -cpu rv64,v=true,vlen=256,elen=64,zvknhk=true \
    demo/openssl/build/apps/openssl dgst -sha3-256 /dev/null
```

`_v_` needs its own underscore — OpenSSL's parser looks for a literal `_V`, and
without it `VLEN` reads back as 0 and the backend silently declines to the C
path.

**[`openssl/README.md`](openssl/README.md) is the writeup of how the instruction
is wired in** — the two insertion sites, why `KeccakF1600()` and not
`PROV_SHA3_METHOD`, how one `#include` redirects both call sites, and why the
vector clobbers are not optional.

The cross build needs the same `riscv64-unknown-linux-gnu` toolchain as `test/`.
It is configured `no-shared`, so `apps/openssl` carries OpenSSL statically; libc
is still dynamic, hence the `-L $RISCV/sysroot` above.

## Tests

`test/` holds the instruction test suite. It builds a static RISC-V binary and
runs it under the Spike built above. Both round counts the instruction defines
are covered:

| Suite | `imm5` | Rounds | Vectors from |
|---|---|---|---|
| SHA-3, SHAKE128/256 | `0` | 24 | FIPS 202 |
| TurboSHAKE128/256 | `1` | 12 | [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861) §5 |

Each suite also checks the bare permutation on its own, so a failure in the
instruction is distinguishable from one in the sponge padding. 39 vectors in
total.

```bash
make test            # builds spike if needed, then builds and runs the tests
make test-all        # the same, at every VLEN the spec tabulates (128..2048)
```

The same suite runs under QEMU instead of Spike, plus a full-system smoke test
that boots with no proxy kernel and no firmware:

```bash
make test-qemu       # the suite under user-mode QEMU
make test-qemu-all   # at every VLEN QEMU supports (128..1024)
make boot-qemu       # system-mode: boot test/system/ on qemu-system-riscv64
make boot-qemu-all   # the same, at every VLEN QEMU supports
make -C test run-qemu-dyn   # a dynamically linked build of the same suite
```

`demo/` checks the same instruction from the other end — through OpenSSL, where
nothing knows it exists:

```bash
make test-openssl      # sixteen checks at VLEN=256
make test-openssl-all  # at every VLEN QEMU supports (128..1024)
make -C demo count      # instructions removed per operation (emulator)
make -C demo cycles     # rdcycle/rdinstret, best of N runs -- run on the target
make -C demo cycles-qemu # the same code path under QEMU (host ticks, not cycles)
```

Those are SHA-3 and SHAKE known answers with the capability on and off — the
SHAKE vectors run to 200 bytes, past the rate, because shorter output never
reaches the permutation in `SHA3_squeeze()` — an ML-KEM-768 and an ML-DSA-65
round trip, a fingerprint comparison that cross-checks both backends over the
whole PQC path, and a negative test that runs the same binary with the same
`OPENSSL_riscvcap` against a QEMU CPU *without* `zvknhk` and requires exit
status 132 (SIGILL). Without that last one a passing suite would prove nothing:
falling back to the C code produces identical digests.

The fixed element group spans `NREG = ceil(2048/VLEN)` registers, so both its
extent and the set of legal `vd` change with `VLEN`. The tests are built for the
smallest supported `VLEN` and run unmodified at 128, 256, 512, 1024 and 2048;
see [`test/README.md`](test/README.md) for how.

They need a `riscv64-unknown-linux-gnu` toolchain and `$RISCV` pointing at its
install prefix (the proxy kernel `pk` is taken from
`$RISCV/riscv64-unknown-linux-gnu/bin/pk`). Both the simulator and the proxy
kernel can be overridden:

```bash
make -C test run SPIKE=/path/to/spike PK=/path/to/pk
```

Expected output ends with every vector passing:

```
[PASS]	SHA3-256 64537B87892835FF0963EF9AD5145AB4CFCE5D303A0CB0415B3B03F9D16E7D6B
...
[PASS]	TurboSHAKE128 1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C
...
[INFO] fail= 0
```

`test/Makefile` defaults `SPIKE` and `PK` to this directory's builds rather than
whatever is on `PATH`, and selects the runtime `VLEN`.

Spike parallelises well: a from-scratch build is ~80 s at `-j20`.

## Cleaning

```bash
make clean   # remove the Spike, QEMU, OpenSSL and test build artifacts
```

## Directory structure

- **`spike/vkeccak_vi.h`** — the instruction's reference semantics for Spike;
  the source of truth for the simulator, edit it here
- **`qemu/`** — the instruction's reference semantics for QEMU, and
  [`qemu/README.md`](qemu/README.md), the writeup of how it is wired in
- **`openssl/`** — the Keccak backend for OpenSSL, and
  [`openssl/README.md`](openssl/README.md), the writeup of how it is wired in
- `test/` — instruction tests: SHA-3 / SHAKE (24 rounds) and TurboSHAKE
  (12 rounds) known-answer vectors
- `test/system/` — a full-system smoke test booted on `qemu-system-riscv64`
- `demo/` — checks that OpenSSL's SHA-3, ML-KEM and ML-DSA really run on the
  instruction, including a negative test that proves the fallback isn't hiding.
  `pqcbench.c` drives one operation at a time for measurement, and `count.sh`
  counts instructions under QEMU with the per-permutation figures calibrated on
  each run rather than hardcoded
- `scripts/apply-spike-patch.sh` — layers the instruction onto upstream Spike
- `scripts/apply-qemu-patch.sh` — layers the instruction onto upstream QEMU
- `scripts/apply-openssl-patch.sh` — layers the Keccak backend onto upstream
  OpenSSL
- `riscv-isa-sim/` — pristine upstream Spike / RISC-V ISA simulator (submodule)
- `qemu-src/` — pristine upstream QEMU (submodule)
- `demo/openssl/` — pristine upstream OpenSSL (submodule)
