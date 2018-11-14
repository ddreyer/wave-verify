#include "asn.h"

void * unmarshal(uint8_t *derEncodedData, size_t size, void *decodePtr, asn_TYPE_descriptor_t *asnType) {
    asn_dec_rval_t rval;
    rval = ber_decode(0, asnType, (void **) &decodePtr, derEncodedData, size);
    if (rval.code != RC_OK) {
        asnType->op->free_struct(asnType, decodePtr, ASFM_FREE_EVERYTHING);
        decodePtr = nullptr;
    } else {
        char errbuf[128];
        size_t errlen = sizeof(errbuf);
        if (asn_check_constraints(asnType, decodePtr, errbuf, &errlen)) {
            ocall_print("constraint check on unmarshalled object failed");
            return nullptr;
        }
    }
    return decodePtr;
}

/* Following is adapted from https://stackoverflow.com/questions/11075886/encode-xer-to-buffer-with-asn1c
 * except I fixed a bug (sigh) in the callback by adding a return 1;
 */

void init_enc_buffer(enc_buffer_t* buffer) {
    buffer->buffer = (uint8_t *) malloc(1024);
    assert(buffer->buffer != NULL);
    buffer->buffer_size = 1024;
    buffer->buffer_filled = 0;
}

void free_enc_buffer(enc_buffer_t* buffer) {
    free(buffer->buffer);
    buffer->buffer_size = 0;
    buffer->buffer_filled = 0;
}

static int print2buf_cb(const void *buffer, size_t size, void *app_key) {
    enc_buffer_t* xb = (enc_buffer_t*) app_key;
    while (xb->buffer_size - xb->buffer_filled <= size+1) {
        xb->buffer_size *= 2;
        xb->buffer_size += 1;
        xb->buffer = (uint8_t *) realloc(xb->buffer, xb->buffer_size);
        assert(xb->buffer != NULL);
    }
    memcpy(xb->buffer+xb->buffer_filled, buffer, size);
    xb->buffer_filled += size;
    *(xb->buffer+xb->buffer_filled) = '\0';
    return 1;
}

int encode_to_buffer(enc_buffer_t* xb, asn_TYPE_descriptor_t *td, void *sptr) {
    asn_enc_rval_t er;
    if (!td || !sptr) return -1;
    /* if object identifier, xer encode only the body to view type id string
     * else, der encode whole object to marshal 
     */
    if (td == &asn_DEF_OBJECT_IDENTIFIER) {
        er = td->op->xer_encoder(td, sptr, 1, XER_F_BASIC, print2buf_cb, xb);
    } else {
        er = der_encode(td, sptr, print2buf_cb, xb);
    }
    if (er.encoded == -1) return -1;
    return 0;
}

/* joins type id substrings together, assuming WaveObjectIdentifier is always the the base */
string idJoiner(string scheme, string id) {
    return WaveObjectIdentifier + "." + scheme + "." + id;
}

/* takes in an asn type descriptor and returns the object identifier as an
 * XER encoded string for the type 
 */
string getTypeId(asn_TYPE_descriptor_t *td) {
    /* WaveObjectIdentifier is always the the base string */
    if (td == &asn_DEF_Public_Ed25519) {
        return idJoiner(EntityKeyScheme, Ed25519Id);
    } else if (td == &asn_DEF_Public_Curve25519) {
        return idJoiner(EntityKeyScheme, Curve25519Id);
    } else if (td == &asn_DEF_Params_BN256_IBE) {
        return idJoiner(EntityKeyScheme, IbeBn256ParamsId);
    } else if (td == &asn_DEF_Public_BN256_IBE) {
        return idJoiner(EntityKeyScheme, IbeBn256PublicId);
    } else if (td == &asn_DEF_Params_BN256_OAQUE) {
        return idJoiner(EntityKeyScheme, OaqueBn256S20ParamsId);
    } else if (td == &asn_DEF_Public_OAQUE) {
        return idJoiner(EntityKeyScheme, OaqueBn256S20AttributesetId);
    } else if (td == &asn_DEF_AttestationBody) {
        return idJoiner(AttestationBodyScheme, UnencryptedBodyScheme);
    } else if (td == &asn_DEF_WR1BodyCiphertext) {
        return idJoiner(AttestationBodyScheme, WR1BodySchemeV1);
    } else if (td == &asn_DEF_HashKeccak_256) {
        return idJoiner(HashScheme, Keccak256Id);
    } else if (td == &asn_DEF_HashSha3_256) {
        return idJoiner(HashScheme, Sha3256Id);
    } else if (td == &asn_DEF_Ed25519OuterSignature) {
        return idJoiner(OuterSignatureScheme, EphemeralEd25519);
    } else if (td == &asn_DEF_TrustLevel) {
        return idJoiner(PolicyScheme, TrustLevel);
    } else if (td == &asn_DEF_RTreePolicy) {
        return idJoiner(PolicyScheme, ResourceTree);
    } else {
        verify_rtree_error("Could not find a match for a type id");
    }
}

/* Marshals a given struct and returns encoded string (used for a couple purposes in the program) */
string marshal(void *obj, asn_TYPE_descriptor_t *asnType) {
    char errbuf[128];
    size_t errlen = sizeof(errbuf);
    if (asn_check_constraints(asnType, obj, errbuf, &errlen)) {
        verify_rtree_error("constraint check on object to be marshalled failed");
    }
    enc_buffer_t enc_buf;
    init_enc_buffer(&enc_buf);
    encode_to_buffer(&enc_buf, asnType, obj);
    string enc((char *) enc_buf.buffer, enc_buf.buffer_filled);
    return enc;
}
