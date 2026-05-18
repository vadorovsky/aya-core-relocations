# aya-core-relocations

Example of an eBPF project based on [Aya][aya] that uses
[BTF CO-RE (Compile Once, Run Everywhere) relocations][btf-core].

It uses the `#[btf]` procedural macro from the [aya-btf][aya-btf] crate that
marks a `struct` in a way that bpf-linker (with the experimental CO-RE support)
is able to emit BTF relocation for all field accesses that are done to it.

This macro allows to define a kernel data structure with fields that a
developer is interested in, e.g.:

```rust
#[btf]
#[repr(C)]
struct task_struct {
    pid: i32,
    tgid: i32,
}
```

Then the fields can be accessed in the following way:

```rust
let pid = unsafe { bpf_probe_read_kernel(&(*task).pid)? };
let tgid = unsafe { bpf_probe_read_kernel(&(*task).tgid)? };
```

During the bitcode linking phase of the Rust build for the BPF target,
bpf-linker is going to detect these field accesses and wrap them in the
appropriate LLVM intrinsic (`@llvm.preserve.struct.access.index`). In effect,
the BPF backend in LLVM will emit a BTF relocation in the `.BTF.ext` ELF
section of the program object.

## Prerequisites

### Rust toolchain

Use [rustup][rustup] to install the:

1. Stable toolchain: `rustup toolchain install stable`
1. Nightly toolchains: `rustup toolchain install nightly --component rust-src`
1. (If cross-compiling) Linux target: `rustup target add ${ARCH}-unknown-linux-musl`

### bpf-linker

This example requires a custom [bpf-linker][bpf-linker] from a **development
branch**:

https://github.com/vadorovsky/bpf-linker/tree/btf-relocations

There are two ways of installing it:

#### Binaries (recommended)

TODO

#### Building from source (not recommended)

On Linux x86_64 with glibc (`x86_64-unknown-linux-gnu`):

```
cargo install --git https://github.com/vadorovsky/bpf-linker bpf-linker --branch btf-relocations
```

On any other platform:

```
cargo install --git https://github.com/vadorovsky/bpf-linker bpf-linker --branch btf-relocations --no-default-features
```

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package aya-core-relocations --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/aya-core-relocations` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, aya-core-relocations is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[aya]: https://aya-rs.dev
[btf-core]: https://nakryiko.com/posts/bpf-portability-and-co-re
[aya-btf]: https://github.com/vadorovsky/aya-btf
[rustup]: https://rustup.rs
[bpf-linker]: https://github.com/aya-rs/bpf-linker
[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
