#   Zvknhk in QEMU

How `vkeccak.vi` is wired into QEMU by
[`scripts/apply-qemu-patch.sh`](../scripts/apply-qemu-patch.sh).

`qemu-src/` is a pristine upstream QEMU checkout, exactly as `riscv-isa-sim/`
is for Spike. The patch script layers the instruction onto it at build time.
The editable sources are the two files here in `qemu/`; everything else the
script does is nine small insertions into upstream files.

```bash
make qemu            # -> qemu-src/build/qemu-riscv64
                     #    qemu-src/build/qemu-system-riscv64
make patch-qemu      # apply the patch only
make unpatch-qemu    # restore qemu-src to pristine upstream
make qemu-clean      # remove qemu-src/build
```


##  The two files that hold the instruction

| File | Copied to | Pulled in by |
|---|---|---|
| `vkeccak_vi.c.inc` | `target/riscv/tcg/` | `#include` at the end of `vcrypto_helper.c` |
| `trans_vkeccak_vi.c.inc` | `target/riscv/tcg/insn_trans/` | `#include` at the end of `trans_rvvk.c.inc` |

`vkeccak_vi.c.inc` is the permutation — `HELPER(vkeccak_vi)`.
`trans_vkeccak_vi.c.inc` is the translator — `trans_vkeccak_vi()` and the
reserved-encoding checks.

Splitting them this way is what keeps the upstream footprint at two `#include`
lines instead of two large hunks: both are `.c.inc` files, the same mechanism
QEMU already uses for `trans_rvvk.c.inc` itself, and a `""` include resolves
relative to the including file, so each lands in the right compilation unit
without touching the build system.

The round body in `vkeccak_vi.c.inc` is character-for-character the one in
[`spike/vkeccak_vi.h`](../spike/vkeccak_vi.h) — it is extracted from that file
rather than retyped, so the two reference implementations cannot drift.


##  The nine insertion sites

Every edit is a *pure insertion* anchored on a nearby upstream line, and every
site is guarded by a token that only the patch introduces. That makes the
script idempotent: an already-patched file is skipped, so it is safe to re-run
on every build.

| File | What goes in |
|---|---|
| `target/riscv/insn32.decode` | the decode pattern |
| `target/riscv/helper.h` | `DEF_HELPER_3(vkeccak_vi, void, ptr, env, i32)` |
| `target/riscv/tcg/vcrypto_helper.c` | `#include "vkeccak_vi.c.inc"` |
| `target/riscv/tcg/insn_trans/trans_rvvk.c.inc` | `#include "trans_vkeccak_vi.c.inc"` |
| `target/riscv/cpu_cfg_fields.h.inc` | `BOOL_FIELD(ext_zvknhk)` |
| `target/riscv/cpu.c` | `ISA_EXT_DATA_ENTRY(zvknhk, ...)` |
| `target/riscv/cpu.c` | `ZVKNHK_IMPLIED` rule (implies `zve64x`) |
| `target/riscv/cpu.c` | `&ZVKNHK_IMPLIED` in the implied-rules array |
| `target/riscv/tcg/tcg-cpu.c` | validation: `zve64x`, and `VLEN >= 128` |

Two things worth noting about that list.

**One table gives both the ISA string and the CPU property.** QEMU builds the
`zvknhk=on` property from `isa_edata_arr[]`, the same array that produces the
ISA string, so `ISA_EXT_DATA_ENTRY` is the only registration needed — there is
no separate property to declare. The entry goes in after `zvknhb`, which also
keeps the array alphabetical.

**`Zvl128b` cannot be an implied extension here.** `zvknhk.adoc` says Zvknhk
depends on `Zve64x` and requires `VLEN >= 128` (`Zvl128b`). QEMU has no `zvl*`
extension booleans — VLEN is the `vlen` CPU property — so only the `Zve64x`
half is expressible as an implication. The VLEN floor becomes a validation
check in `tcg-cpu.c` instead:

```
$ qemu-riscv64 -cpu rv64,zve64x=true,vlen=64,zvknhk=true ./xtest
qemu-riscv64: Zvknhk extension requires VLEN to be at least 128
```

That check is a separate `if` block rather than an extra clause bolted onto
upstream's existing `Zvbc || Zvknhb` condition, so that every site stays a pure
insertion and nothing has to be edited in place.


##  Encoding

Straight out of the specification: `funct6=101001`, `vm=1`, `imm5` in the
`vs2` field, `10010` fixed in the `vs1` field, `funct3=OPMVV`, `opcode=OP-VE`.

```
vkeccak_vi  101001 1 ..... 10010 010 ..... 1110111 @r2_vm_1
```

`@r2_vm_1` is upstream's existing format for "vd and vs2, unmasked". It is the
right one here precisely *because* it ignores the `vs1` field — `10010` is a
fixed part of the opcode, not an operand, so nothing should decode it. Using
`@r_vm_1` instead would work but would misleadingly extract an `rs1`.

The pattern does not collide with anything: within `funct6=101001` upstream
uses `vs1` values `00000`–`00011`, `00111` (the `vaes*.vs` family) and `10000`
(`vsm4r.vs`); `10010` is free.

Fixing `vm=1` in the pattern also gets one reserved encoding for free — a
masked encoding simply fails to match any pattern and raises an illegal
instruction, with no explicit check anywhere.


##  Why none of QEMU's Zvk scaffolding is used

This is the part that is not mechanical, and it is the same thing that had to
be unwound in Spike.

QEMU's vector helpers are built around strip-mining: a helper loops from
`env->vstart / EGS` to `env->vl / EGS`, then fixes up the tail according to
`vta`. The shared Zvk translator macros — `GEN_V_UNMASKED_TRANS()` and
`GEN_VI_UNMASKED_TRANS()` — emit `gen_helper_egs_check()`, which raises an
illegal instruction unless *both* `vl` and `vstart` are multiples of `EGS`, and
they pass `LMUL`, `VTA` and `VMA` down in the descriptor.

None of that applies. `zvknhk.adoc` makes `vkeccak.vi` an explicit exception:
the state is a *single fixed element group* designated by `vd`, with
`EMUL = NREG = ceil(EGW/VLEN)` independent of `LMUL`, and its operation is
independent of `vl` — *every* value of `vl` is permitted, including `vl=0`.
Running it through `egs_check` would reject legal programs. So
`trans_vkeccak_vi()` spells the sequence out instead: no `egs_check`, no
descriptor, no `VDATA` fields. It passes a pointer to `vd` and the immediate,
and that is all the helper needs.

For the same reason the helper does not use `VSTART_CHECK_EARLY_EXIT()`, the
macro every other vector helper opens with. That macro treats `vstart >= vl`
as an already-completed instruction and returns; for an operation that ignores
`vl` entirely, it would silently skip the permutation whenever `vl` happened to
be small.


##  Element layout, and why the helper needs no NREG

The one genuinely convenient thing about QEMU here: it stores the vector
register file as a single flat, contiguous byte array, with register `n`
occupying `vlenb` bytes at offset `n * vlenb`. `vreg_ofs(s, a->rd)` gives the
base of the group, and from there element `i` is just `vd[i]`.

That is exactly the layout the specification defines. Byte offset `i * 8` lands
in register `vd + floor(i*8/vlenb)` at element position `i mod (vlenb/8)` —
which is the spec's "registers concatenated in increasing register-number order
using the standard vector element layout". So the helper reads elements 0..24,
writes elements 0..24, and never needs to know `NREG`, `VLEN` or which register
boundary it is crossing. `H8()` is the identity on both host endiannesses; it
is spelled out only for consistency with the surrounding helpers.

Elements 25..31 — the *state tail* — and every bit outside the fixed group are
preserved by the simplest possible mechanism: they are never written. The state
tail is not the architectural vector tail, so `vta` correctly plays no part.


##  Where each reserved encoding is enforced

Everything that is static in `vtype` or the encoding is rejected at
*translation* time, where `vkeccak_vi_check()` returning false makes the
instruction fail to decode and raise an illegal instruction. Only `vstart` is
dynamic, so only `vstart` is checked in the helper.

| Reserved encoding | Enforced |
|---|---|
| `SEW != 64` | translate — `s->sew == MO_64` |
| reserved `imm5` (not 0 or 1) | translate — `a->rs2 == 0 \|\| a->rs2 == 1` |
| `vd` not `NREG`-aligned | translate — `(a->rd % nreg) == 0` |
| group extends past `v31` | translate — `(a->rd + nreg) <= 32` |
| `vm=0` | decode — the pattern fixes bit 25 |
| `vstart != 0` | helper — `riscv_raise_exception(..., ILLEGAL_INST, GETPC())` |

`trans_vkeccak_vi()` emits `decode_save_opc()` before the helper only when
`s->vstart_eq_zero` is false, i.e. only when the helper could actually raise.

Two checks that the other Zvk instructions perform are *deliberately absent*,
because `zvknhk.adoc` exempts this instruction from them:
`require_align(a->rd, s->lmul)` — alignment follows `NREG`, not `LMUL` — and
`MAXSZ(s) >= egw_bytes`, since `EGS > VLMAX` is explicitly not reserved here.


##  Running it

Because `zvknhk` implies `zve64x`, it is enough on its own — no vector
extension has to be spelled out:

```bash
qemu-src/build/qemu-riscv64 -cpu rv64,zvknhk=true,vlen=256 ./test/xtest
```

**Static binaries** — the default; `make test-qemu` runs the full known-answer
suite this way, and `make test-qemu-all` sweeps every VLEN.

**Dynamically linked binaries** — user-mode QEMU needs an interpreter prefix so
the loader and libc resolve:

```bash
make -C test run-qemu-dyn      # -L $(RISCV)/sysroot
```

**Full-system boot** — `make boot-qemu` builds a freestanding payload and boots
it on the `virt` machine with no firmware and no proxy kernel, so the vector
unit is enabled by the payload itself in M-mode:

```bash
qemu-system-riscv64 -M virt -bios none -nographic \
    -cpu rv64,v=true,vlen=256,elen=64,zvknhk=true -kernel test/system/boot.elf
```

`make boot-qemu-all` boots it at every VLEN. See
[`../test/system/`](../test/system/).


##  Limits

QEMU caps VLEN at `RV_VLEN_MAX`, which upstream currently sets to **1024**
(`target/riscv/cpu.h`). The specification tabulates VLEN up to 2048, so the
`NREG = 1` row — where the whole element group fits in a single register and
any `vd` is legal — cannot be reached under QEMU. Spike has no such cap, and
`make test-all` covers 2048 there. The QEMU sweeps therefore run 128, 256, 512
and 1024.
