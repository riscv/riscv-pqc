#   Zvknhk instruction tests

Tests for `vkeccak.vi`, the single-instruction Keccak-_p_[1600] permutation
defined by the [`Zvknhk`](../../src/zvknhk.adoc) extension. They run known-answer
vectors against the instruction as implemented by
[`spike/vkeccak_vi.h`](../spike/vkeccak_vi.h), executing on the Spike built by
this repository. Both round counts the instruction offers are covered: 24
rounds via SHA-3 and SHAKE, and 12 rounds via TurboSHAKE.

Original code by Markku-Juhani O. Saarinen; the instruction itself is credited
to Nicolas Brunie.


##  Running

From `zvknhk/`:

```bash
make test
```

That builds Spike with the Zvknhk patch if needed, compiles the test binary,
and runs it. To run just the tests, from this directory:

```bash
make run
```

You need:

- a `riscv64-unknown-linux-gnu` toolchain, with `$RISCV` pointing at its
  install prefix,
- the proxy kernel `pk`, taken from `$RISCV/riscv64-unknown-linux-gnu/bin/pk`,
- a patched Spike, built by `make spike` in `zvknhk/`.

Both the simulator and the proxy kernel can be pointed elsewhere:

```bash
make run SPIKE=/path/to/spike PK=/path/to/pk
```

The `zvknhk` extension added by the patch is what enables the instruction, so it
has to appear in the ISA string. The Makefile builds one from `VLEN`:

```
--isa=rv64gcv_zvl$(VLEN)b_zvknhk_zicntr_zihpm
```

`zvknhk` implies `zve64x` and `zvl128b`, so those need not be spelled out.

### VLEN configurations

The fixed element group is `EGW=2048` bits, so it spans
`NREG = ceil(2048/VLEN)` registers and `vd` must be `NREG`-aligned. Both the
number of registers and the set of legal `vd` therefore change with `VLEN`
(`zvknhk.adoc`):

| `VLEN` | `NREG` | Valid `vd` |
|---|---|---|
| 128 | 16 | `v0`, `v16` |
| 256 | 8 | `v0`, `v8`, `v16`, `v24` |
| 512 | 4 | `v0`, `v4`, ..., `v28` |
| 1024 | 2 | `v0`, `v2`, ..., `v30` |
| >= 2048 | 1 | any `vd` |

The tests run at all of these. Pick one with `VLEN=`, or sweep them all:

```bash
make run VLEN=512     # a single configuration
make run-all          # 128, 256, 512, 1024, 2048
```

`run-all` reports one line per configuration and fails the build if any of them
does. For each it checks the simulator's exit status (`test_main` returns the
failure count, and a trap exits 255), that the run really happened at the
requested `VLEN`, that the reported failure count is zero, and that vectors
actually ran — the last so that an empty or truncated run cannot pass
silently:

```
VLEN=128 ok: 39 vectors
VLEN=256 ok: 39 vectors
...
```

`make test-all` in `zvknhk/` does the same thing, building Spike
first if needed.

The binary is compiled for `rv64gcv_zvl128b` — the smallest supported `VLEN`,
so that one binary is valid at every configuration — and the simulator is then
told the actual `VLEN` at run time.

Two details make `keccak_insn.c` VLEN-generic:

- It uses `vd=v0`, which is an `NREG`-aligned group start at every `VLEN`.
- The instruction ignores `vl`, but the surrounding `vle64.v`/`vse64.v` that
  move the 25 active state words do not. At `LMUL=8` the largest usable `vl`
  is `VLMAX = 8*VLEN/64`, which is comfortably above 25 for `VLEN >= 256` but
  only 16 at `VLEN=128`. There the transfer is split in two — elements 0..15
  into `v0..v7`, then 16..24 into `v8..v12` — both halves landing inside the
  16-register group that `v0` spans at that `VLEN`.

##  What is tested

Each suite first checks the bare permutation, then the sponge constructions
built on it. The sponge layers in `sha3_api.c` and `turbo_api.c` are ordinary
portable C; only the two wrappers in `keccak_insn.c` use the instruction, so a
failure in the sponge vectors but not in the bare-permutation ones points at
the glue rather than at the instruction.

`test_sha3.c` — 24 rounds (`imm5 = 0`), vectors from FIPS 202:

| Test | Covers |
|---|---|
| `KECCAK-P` | the permutation itself, on a known input state |
| `SHA3-224/256/384/512` | fixed-length hashing |
| `SHAKE128/256` | extendable output, several lengths |

`test_turbo.c` — 12 rounds (`imm5 = 1`), vectors from
[RFC 9861](https://www.rfc-editor.org/rfc/rfc9861) Section 5:

| Test | Covers |
|---|---|
| `KECCAK-P12` | the reduced-round permutation on its own |
| `TurboSHAKE128` | 14 vectors |
| `TurboSHAKE256` | 13 vectors |

The TurboSHAKE vectors span every domain separation byte the RFC tabulates
(`01`, `06`, `07`, `0B`, `1F`, `30`, `7F`), the empty message, messages of
`ptn(17**k)` for k in 0..4, and a 10032-byte squeeze checked on its final 32
bytes — so they exercise multi-block absorption and repeated squeezing, not
just a single permutation call.

Two RFC vectors per function are omitted: `ptn(17**5)` and `ptn(17**6)` are
1.4 MB and 24 MB, which take minutes to absorb byte-at-a-time under a
simulator. Everything else in Section 5 that applies to TurboSHAKE is present.
`KECCAK-P12` is not from the RFC, which has no bare-permutation vector; it uses
the same input as the 24-round `KECCAK-P` test and was cross-checked against an
independent implementation of Keccak-_p_[1600,12].


##  How the instruction is invoked

The assembler does not know `vkeccak.vi` yet, so `keccak_insn.c` emits it with
`.insn`:

```C
    __asm volatile (
        "vsetivli x0, 25, e64, m8, tu, mu\n"
        "vle64.v v0, 0(%[s])\n"
        //  vkeccak.vi v0, 0   -- imm5 = 0 selects 24 rounds (Keccak-f[1600])
        //  .insn r opc, func3, func7, rd, rs1, rs2
        ".insn r 0x77, 0x2, 0x53, x0, x18, x0\n"
        "vse64.v v0, 0(%[s])\n"
        :
        : [s]"r"(state)
        : "memory"
    );
```

That is the `VLEN >= 256` arm of the `KECCAK_INSN` macro; the `VLEN = 128` arm
splits the transfer in two, as described above. The 25 state lanes are loaded
into `v0`, the permutation runs in place, and the lanes are stored back. The
state is a single fixed element group of `EGW=2048` bits designated by `vd`,
independent of `vl` and `LMUL`, so `vl` only has to be large enough for the
surrounding `vle64.v` / `vse64.v` of the 25 active words.

Reading the operands of that `.insn` needs care, because only two of the five
R-type fields are actually operands:

| Field | In the example | Meaning |
|---|---|---|
| `opc`, `func3`, `func7` | `0x77`, `0x2`, `0x53` | fixed opcode bits |
| `rd` | `x0` | `vd` — the vector register holding the state, here `v0` |
| `rs1` | `x18` | **not an operand**; `0b10010` is a fixed part of the encoding |
| `rs2` | `x0` | `imm5`, the round-count selector |

`imm5` is a *selector*, not a round count. `keccak_insn.c` provides a wrapper
for each of the two defined values:

| `imm5` | Rounds | Permutation |
|---|---|---|
| `0b00000` | 24 | Keccak-_p_[1600,24] = Keccak-_f_[1600] — SHA-3, SHAKE |
| `0b00001` | 12 | Keccak-_p_[1600,12] — TurboSHAKE, KangarooTwelve |

All other values are reserved and raise an illegal-instruction exception, as do
`SEW != 64`, `vm=0`, a nonzero `vstart`, and a `vd` that is not aligned to an
`NREG`-register boundary.

`keccak_f1600()` uses `imm5 = 0` and `keccak_p1600_12()` uses `imm5 = 1`; both
are covered by the vectors above.

Assembled, the example above is `0xa6092077`, and a patched Spike disassembles
it as:

```
core   0: 0x000000000001047c (0xa6092077) vkeccak.vi v0, 0
```

##  Expected output

A successful run ends with every vector passing and `fail= 0`:

```
[INFO]	=== SHA3 ===
[PASS]	KECCAK-P 1581ED5252B07483009456B676A6F71D7D79518A4B1965F7450576D1437B4720...
[PASS]	SHA3-224 6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7
[PASS]	SHA3-256 64537B87892835FF0963EF9AD5145AB4CFCE5D303A0CB0415B3B03F9D16E7D6B
...
[PASS]	SHAKE256 6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB
[INFO]	=== TurboSHAKE ===
[PASS]	KECCAK-P12 FECCEEE8FEB6CC31E742D7A8CC3DBF572DFDD5008E3CC2337D9913C2858B4027...
[PASS]	TurboSHAKE128 1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C
...
[PASS]	TurboSHAKE256 ABE569C1F77EC340F02705E7D37C9AB7E155516E4A6A150021D70B6FAC0BB40C069F9A9828A0D575CD99F9BAE435AB1ACF7ED9110BA97CE0388D074BAC768776
[INFO] fail= 0
```

That is 39 `[PASS]` lines in all: 11 for SHA-3 and SHAKE, 28 for TurboSHAKE.

The run is preceded by a platform dump from `plat_local.h` (word sizes,
endianness, `vlen`, cycle and instruction counts). `vlen = 256` there confirms
the ISA string took effect.

If `vkeccak.vi` is not recognised — a Spike without the patch, or an ISA string
without `zvknhk` — the run traps on an illegal instruction instead of printing
`[PASS]` lines.


##  Files

| File | |
|---|---|
| `keccak_insn.c` | the `vkeccak.vi` wrappers — the only file using the instruction |
| `sha3_api.c`, `sha3_api.h` | SHA-3 / SHAKE built on `keccak_f1600()` |
| `turbo_api.c`, `turbo_api.h` | TurboSHAKE built on `keccak_p1600_12()` |
| `test_sha3.c` | FIPS 202 known-answer vectors |
| `test_turbo.c` | RFC 9861 known-answer vectors |
| `test_main.c` | entry point and platform dump |
| `test_rvkat_sio.c`, `test_rvkat.h` | minimal self-contained I/O and hex helpers |
| `plat_local.h` | platform detection, cycle/instret counters |
| `Makefile` | build and run against this repository's Spike |


##  Notes

The SHA-3 and SHAKE sponge code in `sha3_api.c` and the test scaffolding
(`test_rvkat*`, `plat_local.h`) are deliberately plain, unoptimised C: they
exist to exercise the instruction, not to be fast. `turbo_api.c` follows the
same shape for TurboSHAKE.

`keccak_insn.c` is the only file that emits `vkeccak.vi`; the sponges, the
vectors and the scaffolding above it are portable C. That is what makes the
`KECCAK-P` / `KECCAK-P12` checks useful: if those pass but the SHA-3 or
TurboSHAKE vectors fail, the fault is in the padding code rather than in the
instruction.
