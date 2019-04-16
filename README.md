# WAVE Proof Verification Library in C/C++
This is a C/C++ library for verifying [WAVE](https://github.com/immesys/wave) proofs. It provides a Go interface as well, mainly used for ease of testing. This library is compatible with WAVE v0.4.1, excluding the unimplemented features listed in the TODO section.

## Using this Library
First, clone the repository into the appropriate directory in your Go source tree (`src/github.com/ddreyer/wave-verify`). Then, run `git submodule init` and then `git submodule update` to clone the submodules. Finally, run `make` to produce the `verify.a` file.

## Testing
A Go testing suite can be run via the command `go test` in the `lang/go` directory. The testing suite requires that the WAVE daemon be running. WAVE releases can be found [here](https://github.com/immesys/wave/releases)

## Credits
The code uses two third party libraries as Git submodules: an [ED25519 library](https://github.com/orlp/ed25519) and a [Keccak hashing library](https://github.com/brainhub/SHA3IUF).

## Intel SGX Support
The sgx branch of this repository allows this library to interface as a Git submodule with a parent [library](https://github.com/ddreyer/wave-verify-sgx) that provides a C API for verifying WAVE proofs inside an Intel SGX enclave.

## Other Notes
* The files in the `src/asn1c` directory were generated using the command `asn1c -fcompound-names objects-lite.asn`. The code uses a forked [branch](https://github.com/velichkov/asn1c/tree/external_vlm_master) of the open source ASN.1 to C compiler. 

## TODOS
- [ ] write a C testing suite such that valgrind can be run
- [ ] implement expiry checks for attestations and entities
- [ ] implement revocation checks
- [ ] provide a better C interface