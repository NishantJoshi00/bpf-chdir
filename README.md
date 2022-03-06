# Tracking `chdir` in Linux Machines

## Requirements

## Pre-build requirements

`LLVM` is required in your build system to compile BPF bytecode using RedBPF.

- **LLVM 13**  
  It is needed to compile BPF bytecode.

- One of the followings:
  
  1. The Linux kernel headers
  2. `vmlinux`, the Linux kernel image that contains `.BTF` section
  3. Raw BTF data i.e. `/sys/kernel/btf/vmlinux`  
     These are needed to generate Rust bindings of the data structures of the Linux kernel.

### On Ubuntu 20.04 LTS

Install LLVM 13 and the Linux kernel headers

```bash
# apt-get update \
  && apt-get -y install \
       wget \
       build-essential \
       software-properties-common \
       lsb-release \
       libelf-dev \
       linux-headers-generic \
       pkg-config \
  && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 13 && rm -f ./llvm.sh
# llvm-config-13 --version | grep 13
```

### On Fedora 35

Install LLVM 13 and the Linux kernel headers

```bash
# dnf install -y \
    clang-13.0.0 \
    llvm-13.0.0 \
    llvm-libs-13.0.0 \
    llvm-devel-13.0.0 \
    llvm-static-13.0.0 \
    kernel \
    kernel-devel \
    elfutils-libelf-devel \
    make \
    pkg-config \
    zstd
# llvm-config --version | grep 13
```

### On Arch Linux

Install LLVM 13 and the Linux kernel headers

```bash
# pacman --noconfirm -Syu \
  && pacman -S --noconfirm \
       llvm \
       llvm-libs \
       libffi \
       clang \
       make \
       pkg-config \
       linux-headers \
       linux
# llvm-config --version | grep -q '^13'
```

### Building LLVM from source

If your Linux distro does not support the latest LLVM as pre-built packages
yet, you may build LLVM from the LLVM source code.

```bash
$ tar -xaf llvm-13.0.0.src.tar.xz
$ mkdir -p llvm-13.0.0.src/build
$ cd llvm-13.0.0.src/build
$ cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/llvm-13-release -DCMAKE_BUILD_TYPE=Release
$ cmake --build . --target install
```

Then you can use your LLVM by specifying the custom installation path when
installing `cargo-bpf` or building RedBPF like this:

```bash
$ LLVM_SYS_130_PREFIX=$HOME/llvm-13-release/ cargo install cargo-bpf
$ LLVM_SYS_130_PREFIX=$HOME/llvm-13-release/ cargo build
```

Make sure correct `-DCMAKE_BUILD_TYPE` is specified. Typically `Debug` type is
not recommended if you are not going to debug LLVM itself.

## Installing `cargo-bpf`

`cargo-bpf` is a command line tool for compiling BPF program written in Rust
into BPF bytecode.

```bash
$ cargo install cargo-bpf --no-default-features --features=llvm13,command-line
$ cargo bpf --version
```

You can learn how to use this from [tutorial](TUTORIAL.md).

## Building RedBPF from source

If you want to build RedBPF from source to fix something, you can do as follows:

```bash
$ git clone https://github.com/foniod/redbpf.git
$ cd redbpf
$ git submodule sync
$ git submodule update --init
$ cargo build
$ cargo build --examples
```





## Building

To build the application simple run the `./build.sh` in the current directory to build the eBPF program as well as the userspace handling program

```bash
$ chmod u+x ./build.sh
$ ./build.sh
```



While running the program `$ sudo` is required check the `run.sh` file for more information

```bash
# While running the program
$ sudo ./run.sh
```
