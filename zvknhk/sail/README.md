<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Zvknhk Sail operation and tests

[`zvknhk_insts.sail`](zvknhk_insts.sail) is the executable Sail operation
listing used by [the specification](../../src/zvknhk.adoc). The AsciiDoc
chapter includes its `operation` tag directly, so the document and tests use
the same source. Building the document does not require the Sail compiler.

The `*_insts.sail` name follows the
[vector-crypto instruction files in sail-riscv](https://github.com/riscv/sail-riscv/tree/master/model/extensions/vector_crypto).
The [ISA manual's vector-crypto chapter](https://github.com/riscv/riscv-isa-manual/blob/main/src/unpriv/zvk.adoc)
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

- `zvknhk_insts.sail`: Keccak round constants, rho/pi recurrence, permutation,
  instruction constructor, and execution clause. This is the code to carry
  into the specification and formal model.
- `tests/prelude.sail`: a small standalone implementation of the prelude
  interfaces used by the listing, backed by Sail's installed libraries.
- `tests/model.sail`: test-only instruction/retirement types, `vstart`,
  and one logical fixed group at `vd=v0`.
- `tests/test_vkeccak.sail`: 24- and 12-round all-zero known-answer tests
  for all 25 words, preservation of all seven state-tail words, all 30
  reserved immediates, and nonzero `vstart` for both round counts.
  Illegal-instruction cases check that the whole group and `vstart`
  remain unchanged. Expected permutation outputs are also used by
  [the system-mode test](../test/system/boot.c).

The operation expects the surrounding RISC-V model to provide `instruction`,
`execute`, `vregidx`, `ExecutionResult`, `RETIRE_SUCCESS`, `vstart`, and
`set_vstart`, plus these instruction-specific interfaces:

```sail
val get_fixed_eg : vregidx -> vector(32, bits(64))
val set_fixed_eg_elem : (vregidx, range(0, 24), bits(64)) -> unit
```

The test environment represents a logical group, not a full vector register
file or decoder. Integration into `sail-riscv` still needs extension
registration, encoding/assembly mappings, the remaining legality checks
(`SEW`, `vm`, vector state, and group alignment), and fixed-group accessors
implementing the specified `VLEN` layout independently of `vl` and `LMUL`.
The tests here do not establish those properties; the simulator tests in
[`../test/`](../test/README.md) exercise the implemented instruction.

The Sail source and tests use the BSD-3-Clause license in
[`../LICENSE`](../LICENSE).
