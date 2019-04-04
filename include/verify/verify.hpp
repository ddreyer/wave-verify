#ifndef __VERIFY_H_INCLUDED__
#define __VERIFY_H_INCLUDED__

#include <openssl/evp.h>

#include "ed25519/src/ed25519.h"
#include "hash-library/keccak.h"

#include "WaveEntity.h"
#include "WaveEntitySecret.h"
#include "WaveAttestation.h"
#include "AttestationVerifierBody.h"
#include "AttestationBody.h"
#include "WaveWireObject.h"
#include "WaveExplicitProof.h"
#include "Public-Ed25519.h"
#include "Public-Curve25519.h"
#include "Params-BLS12381-IBE.h"
#include "Params-BLS12381-OAQUE.h"
#include "Public-BLS12381-IBE.h"
#include "Public-OAQUE.h"
#include "AVKeyAES128-GCM.h"
#include "HashKeccak-256.h"
#include "HashSha3-256.h"
#include "WR1BodyCiphertext.h"
#include "WR1VerifierBody.h"
#include "SignedOuterKey.h"
#include "LocationURL.h"
#include "HashKeccak-256.h"
#include "HashSha3-256.h"
#include "Ed25519OuterSignature.h"
#include "RTreePolicy.h"
#include "RTreeStatement.h"
#include "TrustLevel.h"

#include <string>
#include "Enclave_t.h"

// toggle this to enable/disable debug print output
#define verify_print(...) ocall_print(__VA_ARGS__)
// #define verify_print(...)

long verifyProof(char *proofDER, size_t proofDERSize, char *subject, size_t subj_size, 
                char *policyDER, size_t policyDER_size);

#endif
