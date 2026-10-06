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


##  Element-group execution

At `VLEN >= 256`, `vd` is an ordinary `LMUL` register group. The translator
requires `LMUL*VLEN >= 2048` and normal `LMUL` alignment. The helper checks
that `vl` and `vstart` are multiples of 32, then permutes each 32-word group
from `vstart/32` through `vl/32 - 1`. It leaves each group's seven state-tail
words unchanged and resets `vstart` on completion. A `vl` of zero does no work.

At `VLEN=128`, `vd` is the special fixed 16-register group (`v0` or `v16`).
The instruction ignores `vl`; a nonzero `vstart` is illegal. The translator
passes this mode in bit 8 of the helper's immediate argument, outside the
architectural five-bit selector.

QEMU stores vector registers contiguously. A 32-word group begins at offset
`group*32` from the `vd` pointer, so the same lane indexing works at every
supported `VLEN`. The state tail is part of an active element group and is
preserved. Architectural tail elements are also left undisturbed, a permitted
result under tail-agnostic policy.

The translator checks `SEW`, `imm5`, vector state, group size and alignment.
The decode pattern rejects `vm=0`. The helper checks `vl` and `vstart`, which
can change at runtime. The translator saves the opcode when those checks may
raise an illegal-instruction exception.

QEMU's optional `rvv_vl_half_avl` policy can select a `vl` that is not a
multiple of `EGSMAX=32`. CPU validation disables that policy when Zvknhk is
enabled and warns if the policy was requested, so `vsetvl` chooses `VLMAX`
when AVL exceeds it. This choice meets
the element-group constraint, including when `VLMAX<32`.

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
