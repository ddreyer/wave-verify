# WAVE Proof Verification Library in C/C++
This is a C/C++ library for verifying [WAVE](https://github.com/immesys/wave) proofs. It provides a Go interface as well, mainly used for ease of testing. The code uses a forked [branch](https://github.com/velichkov/asn1c/tree/external_vlm_master) of the open source ASN.1 to C compiler. 

This library is compatible with WAVE v0.4.1, excluding the unimplemented features listed in the TODO section.

## Using this Library
First, clone the repository into the appropriate directory in your Go source tree (`src/github.com/ddreyer/wave-verify`). Then, run `make` to produce the `verify.a` file.

## Testing
A Go test suite can be run using the command `go test` in the `lang/go` directory.

## Credits
The code uses two third party libraries: an [ED25519 library](https://github.com/orlp/ed25519) and a [Keccak hashing library](https://github.com/brainhub/SHA3IUF).

asn1c_files were generated using the command `asn1c -fcompound-names objects-lite.asn`

## Intel SGX Support
This library interfaces with a parent [library](https://github.com/ddreyer/wave-verify-sgx) that provides a C API for verifying WAVE proofs inside an enclave. However, to interface with Intel SGX, some of the files in this library must be modified. Running the provided ____ script copies the following files in the sgxfiles folder into their corresponding locations for Intel SGX compatability.

* utils.hpp
* verify.cpp
* GeneralizedTime.h
* GeneralizedTime.c

## TODOS
- [ ]