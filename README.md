<div align="center">
    <h1>Awesome Rust Security</h1>
    <p>Curated list of awesome projects and resources related to Rust and computer security</p>
</div>
<br/>

# Table of Contents

- [Tools](#tools)
    - [Web and Cloud Security](#web-and-cloud-security)
    - [Vulnerability Assessment](#vulnerability-assessment)
    - [Offensive Security and Red Teaming](#offensive-security-and-red-teaming)
    - [Malware and Threat Detection](#malware-and-threat-detection)
    - [Cryptography](#cryptography)
- [Educational](#educational)
    - [Books](#books)
    - [Articles](#articles)
    - [Talks](#talks)
- [Similar Lists](#similar-lists)
- [Contributing](#contributing)

<br/>
<br/>

# Tools

## Web and Cloud Security

### Pentesting

- [sn0int](https://github.com/kpcyrd/sn0int) - OSINT framework and package manager
- [sniffglue](https://github.com/kpcyrd/sniffglue) - secure multithreaded packet sniffer
- [badtouch](https://github.com/kpcyrd/badtouch) - scriptable network authentication cracker
- [rshijack](https://github.com/kpcyrd/rshijack) - TCP connection hijacker
- [feroxbuster](https://github.com/epi052/feroxbuster) - fast, simple and recursive content discovery tool
- [rustbuster](https://github.com/phra/rustbuster) - web fuzzer and content discovery tool

### Authorization & Authentication Frameworks

- [biscuit](https://github.com/CleverCloud/biscuit) - delegated, decentralized, capabilities based authorization token
- [paseto.rs](https://github.com/instructure/paseto) - PASETO Rust implementation
- [webauthn.rs](https://github.com/kanidm/webauthn-rs) - WebAuthn implementation in Rust
- [OpenSK](https://github.com/google/OpenSK) - open-source implementation for security keys written in Rust 

### Cloud and Infrastructure

- [firecracker](https://github.com/firecracker-microvm/firecracker) - secure and fast microVMs for serverless computing
- [boringtun](https://github.com/cloudflare/boringtun) - CloudFlare's Rust implementation of WireGuard
- [innernet](https://github.com/tonarino/innernet) - private network based on WireGuard
- [vaultwarden](https://github.com/dani-garcia/vaultwarden) - unofficial BitWarden implementation in Rust

### Software Supply Chain

- [rebuilderd](https://github.com/kpcyrd/rebuilderd) - independent verification of binary packages
- [rust-tuf](https://github.com/heartsucker/rust-tuf) - Rust implementation of [the Update Framework](https://theupdateframework.io/)

### Other Frameworks

- [adblock-rust](https://github.com/brave/adblock-rust) - Brave's Rust-based adblock engine
- [libinjection](https://github.com/arvancloud/libinjection-rs) - Rust bindings to libinjection

<br/>

## Vulnerability Assessment

### Static Code Auditing

- [RustSec](https://github.com/RustSec) - organization supporting vulnerability disclosure for Rust packages, audit Cargo.lock files for dependencies
- [cargo-geiger](https://github.com/rust-secure-code/cargo-geiger) - detect usage of unsafe Rust
- [siderophile](https://github.com/trailofbits/siderophile) - find ideal fuzz targets in a Rust codebase
- [cargo-crev](https://github.com/crev-dev/cargo-crev) - cryptographically verifiable code review for cargo
- [arch-audit](https://github.com/ilpianista/arch-audit) - audit installed Arch packages for vulnerabilities
- [ripgrep](https://github.com/BurntSushi/ripgrep) - recursively search directories with regexes

### Fuzzing

- [rust-fuzz](https://github.com/rust-fuzz) - organization implementing cargo plugins for AFL, libFuzzer, and honggfuzz
- [LibAFL](https://github.com/AFLplusplus/LibAFL) - slot fuzzers together in Rust
- [fuzzcheck.rs](https://github.com/loiclec/fuzzcheck-rs) - structure-aware, in-process, coverage-guided, evolutionary fuzzing engine for Rust functions.
- [onefuzz](https://github.com/microsoft/onefuzz) - self-hosted Fuzzing-As-A-Service platform 
- [lain](https://github.com/microsoft/lain) - fuzzer framework implemented in Rust
- [fzero](https://github.com/gamozolabs/fzero_fuzzer) - fast grammar-based fuzz generator implementation
- [nautilus](https://github.com/RUB-SysSec/nautilus) - grammar-based feedback fuzzer from RUB's Systems Security Lab
- [sidefuzz](https://github.com/phayes/sidefuzz) - fuzzer for side-channel vulnerabilities
- [arbitrary](https://github.com/rust-fuzz/arbitrary) - trait for generating structured input from raw bytes, helpful for structure-aware fuzzing
- [rust-san](https://github.com/japaric/rust-san) - sanitizers for Rust code
- [lidiffuzz](https://github.com/Shnatsel/libdiffuzz) - memory allocator drop-in to test for uninitialized memory reads

### Binary Analysis & Reversing

- [goblin](https://github.com/m4b/goblin) - binary parsing crate for Rust
- [unicorn.rs](https://github.com/unicorn-rs/unicorn-rs) - Rust bindings to the Unicorn framework
- [cargo-call-stack](https://github.com/japaric/cargo-call-stack) - whole program stack analysis
- [xori](https://github.com/endgameinc/xori) - disassembly library for PE32, 32+ and shellcode
- [rd](https://github.com/sidkshatriya/rd) - record/replay debugger implemented in Rust
- [binsec](https://github.com/ex0dus-0x/binsec) - Swiss Army Knife for Binary (In)Security
- [radeco](https://github.com/radareorg/radeco) - Radare2-based decompiler and symbol executor
- [falcon](https://github.com/falconre/falcon) - Binary Analysis Framework in Rust
- [mesos](https://github.com/gamozolabs/mesos) - binary coverage tool without modification for Windows
- [guerilla](https://github.com/mehcode/guerrilla) - monkey patching Rust functions

### Property-Based Testing

- [quickcheck](https://github.com/BurntSushi/quickcheck) - property-based testing for Rust
- [proptest](https://github.com/AltSysrq/proptest) - Hypothesis-like property testing for Rust
- [bughunt-rust](https://github.com/blt/bughunt-rust) - example of using fuzzing QuickCheck models for bughunting
- [mutagen](https://github.com/llogiq/mutagen) - mutation testing framework for Rust

### Symbolic Execution

- [seer](https://github.com/dwrensha/seer) - symbolic execution engine for Rust
- [haybale](https://github.com/PLSysSec/haybale) - LLVM IR-based symbolic execution engine from the USCD System Security Lab

### Formal Verification

- [MIRAI](https://github.com/facebookexperimental/MIRAI) - abstract interpreter for Rust's MIR from Facebook
- [elecrolysis](https://github.com/Kha/electrolysis) - formal verification of Rust programs with the Lean theorem prover

<br/>

## Offensive Security and Red Teaming

> TODO: need contributions!

### Command-and-Control Frameworks

### Defense Evasion

### Packing, Obfuscation, Encryption

- [obfstr](https://github.com/CasualX/obfstr) - string obfuscation for Rust
- [Linux.Fe2O3](https://github.com/guitmz/Fe2O3) - Simple ELF prepender virus / in-memory loader written in Rust

<br/>

## Malware and Threat Detection

- [yara-rust](https://github.com/Hugal31/yara-rust) - Rust bindings to YARA
- [BONOMEN](https://github.com/0xcpu/bonomen) - hunt for malware critical process impersonation
- [confine](https://github.com/ex0dus-0x/confine) - sandbox for threat detection
- [redbpf](https://github.com/foniod/redbpf) - crate for writing BPF/eBPF modules
- [cernan](https://github.com/postmates/cernan) - telemtry aggregation and shipping

<br/>

## Cryptography

### Frameworks

- [secrets](https://github.com/stouset/secrets) - secure storage for cryptographic secrets in Rust
- [mundane](https://github.com/google/mundane) - BoringSSL-backed cryptography library
- [rust-threshold-secret-sharing](https://github.com/snipsco/rust-threshold-secret-sharing) - Rust implementation of threshold-based secret sharing
- [molasses](https://github.com/trailofbits/molasses) - Rust implementation of the MLS group messaging protocol
- [rust-security-framework](https://github.com/kornelski/rust-security-framework) - Rust bindings to the macOS `Security.framework`
- [microkv](https://github.com/ex0dus-0x/microkv) - minimal and secure key-value storage for Rust

### Applications

- [ripasso](https://github.com/cortex/ripasso/) - password manager written in Rust
- [sekey](https://github.com/sekey/sekey) - TouchID / Secure Enclave for SSH authentication
- [Mullvad VPN Client](https://github.com/mullvad/mullvadvpn-app) - Mullvad VPN app written in Rust

<br/>

# Educational

## Books

- [Black Hat Rust](https://github.com/skerkour/black-hat-rust)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [Secure Rust Guidelines](https://anssi-fr.github.io/rust-guide/)

## Articles

- [str::repeat wildcopy exploit writeup](https://saaramar.github.io/str_repeat_exploit/)
- [Basic Guide to Linux Exploit Mitigations and Building a Security Detector with Rust](https://codemuch.tech/2019/05/01/elf-security-rust/)

## Talks

> TODO: need contributions!

<br/>

# Similar Lists

- [awesome-rust](https://github.com/rust-unofficial/awesome-rust)
- [rust-secure-code/projects](https://github.com/rust-secure-code/projects)
- [analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis)
- [analysis-tools-dev/dynamic-analysis](https://github.com/analysis-tools-dev/dynamic-analysis)
- [awesome-go-security](https://github.com/Binject/awesome-go-security)

<br/>

# Contributing

Make a pull request if you are interested in adding more to this list!
