#ifndef __ASN_H_INCLUDED__
#define __ASN_H_INCLUDED__

#include <WaveEntity.h>
#include <WaveEntitySecret.h>
#include <WaveAttestation.h>
#include <AttestationVerifierBody.h>
#include <AttestationBody.h>
#include <WaveWireObject.h>
#include <WaveExplicitProof.h>
#include <Public-Ed25519.h>
#include <Public-Curve25519.h>
#include <Params-BLS12381-IBE.h>
#include <Params-BLS12381-OAQUE.h>
#include <Public-BLS12381-IBE.h>
#include <Public-OAQUE.h>
#include <AVKeyAES128-GCM.h>
#include <HashKeccak-256.h>
#include <HashSha3-256.h>
#include <WR1BodyCiphertext.h>
#include <WR1VerifierBody.h>
#include <SignedOuterKey.h>
#include <LocationURL.h>
#include <HashKeccak-256.h>
#include <HashSha3-256.h>
#include <Ed25519OuterSignature.h>
#include <RTreePolicy.h>
#include <RTreeStatement.h>
#include <TrustLevel.h>
#include <WaveEncryptedMessage.h>

#include "utils.h"

using namespace std;

const string WaveObjectIdentifier("1.3.6.1.4.1.51157");
const string EntityKeyScheme("11");
const string Ed25519Id("1");
const string Curve25519Id("2");
const string OaqueBLS12381S20AttributesetId("7");
const string OaqueBLS12381S20ParamsId("8");
const string IbeBLS12381ParamsId("9");
const string IbeBLS12381PublicId("10");
const string AttestationBodyScheme("3");
const string UnencryptedBodyScheme("1");
const string WR1BodySchemeV1("2");
const string HashScheme("9");
const string Sha3256Id("1");
const string Keccak256Id("2");
const string OuterSignatureScheme("5");
const string EphemeralEd25519("1");
const string PolicyScheme("12");
const string TrustLevel("1");
const string ResourceTree("2");

typedef struct enc_buffer {
    uint8_t *buffer;
    size_t buffer_size;
    size_t buffer_filled;
} enc_buffer_t;

void * unmarshal(uint8_t *derEncodedData, size_t size, void *decodePtr, asn_TYPE_descriptor_t *asnType);

void init_enc_buffer(enc_buffer_t* buffer);

void free_enc_buffer(enc_buffer_t* buffer);

static int print2buf_cb(const void *buffer, size_t size, void *app_key);

int encode_to_buffer(enc_buffer_t* xb, asn_TYPE_descriptor_t *td, void *sptr);

string idJoiner(string scheme, string id);

string getTypeId(asn_TYPE_descriptor_t *td);

string marshal(void *obj, asn_TYPE_descriptor_t *asnType);

#endif
