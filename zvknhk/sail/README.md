<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Zvknhk Sail operation and tests

[`zvknhk_insts.sail`](zvknhk_insts.sail) is the executable Sail operation
listing used by [the specification](../../src/zvknhk.adoc). The AsciiDoc
chapter includes its `operation` tag directly, so the document and tests use
the same source. Building the document does not require the Sail compiler.

The `*_insts.sail` name follows the
[vector-crypto instruction files in sail-riscv](https://github.com/riscv/sail-riscv/tree/master/model/extensions/vector_crypto).
The [ratified ISA manual's Vector Cryptography chapter
(v20260120)](https://docs.riscv.org/reference/isa/v20260120/unpriv/vector-crypto.html)
uses `[source,sail]` listings and refers to that separate formal model.
For integration into the manual, the operation can be included from a relocated
file or embedded in the chapter without any test code or custom build tools.

## Run

Requires [Sail](https://github.com/rems-project/sail) (tested with 0.20.1),
GNU Make, a host C compiler, and GMP and zlib development libraries.
No RISC-V cross compiler, emulator, or `sail-riscv` checkout is needed.

From the repository root:

```sh
make -C zvknhk/sail check   # Parse and type-check
make -C zvknhk/sail test    # Generate C, compile it, and run assertions
```

`make -C zvknhk test-sail` is a convenience alias for the second command.
Override `SAIL`, `SAILFLAGS`, `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`,
or `LDLIBS` as needed. `SAIL_LIB_DIR` defaults to the `lib` directory under
`sail --dir`. Generated files and the SMT cache stay in the ignored `build/`
directory; `make -C zvknhk/sail clean` removes them.

## Source and test boundary

- `zvknhk_insts.sail` defines the Keccak permutation and iterates over active
  32-word element groups. `get_lmul_pow()` supplies the signed LMUL exponent.
- `tests/model.sail` provides a standalone vector register file, `VLEN`,
  `get_sew()`, `get_lmul_pow()`, `vl`, `vstart`, and element accessors.
- `tests/test_vkeccak.sail` checks both round counts, independent groups,
  state tails, restart at group boundaries, `vl=0`, reserved immediates,
  and the `VLEN=128` exception.

The surrounding RISC-V model must supply vector state, the instruction and
execute declarations, and `get_eg_elem`/`set_eg_elem` accessors using standard
vector element layout. The execution listing checks `SEW=64`; decoder checks
for `vm` and vector availability remain part of integration into `sail-riscv`.

The Sail source and tests use the BSD-3-Clause license in
[`../LICENSE`](../LICENSE).
