#include <fstream>
#include <streambuf>
#include <sstream>
#include <stdio.h>
#include <algorithm>
#include <list>
#include <unordered_map>
#include <vector>

#include "verify.hpp"

using namespace std;

const int CapCertification = 1;
const int PermittedCombinedStatements = 1000;

/* asn1 stuff */

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
            verify_print("constraint check on unmarshalled object failed");
            return nullptr;
        }
    }
    return decodePtr;
}

/* The following is adapted from https://stackoverflow.com/questions/11075886/encode-xer-to-buffer-with-asn1c
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
    } else if (td == &asn_DEF_Params_BLS12381_IBE) {
        return idJoiner(EntityKeyScheme, IbeBLS12381ParamsId);
    } else if (td == &asn_DEF_Public_BLS12381_IBE) {
        return idJoiner(EntityKeyScheme, IbeBLS12381PublicId);
    } else if (td == &asn_DEF_Params_BLS12381_OAQUE) {
        return idJoiner(EntityKeyScheme, OaqueBLS12381S20ParamsId);
    } else if (td == &asn_DEF_Public_OAQUE) {
        return idJoiner(EntityKeyScheme, OaqueBLS12381S20AttributesetId);
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
        verify_print("Could not find a match for a type id");
    }
}

/* Marshals a given struct and returns encoded string (used for a couple purposes in the program) */
string marshal(void *obj, asn_TYPE_descriptor_t *asnType) {
    char errbuf[128];
    size_t errlen = sizeof(errbuf);
    if (asn_check_constraints(asnType, obj, errbuf, &errlen)) {
        verify_print("constraint check on object to be marshalled failed");
        return "";
    }
    enc_buffer_t enc_buf;
    init_enc_buffer(&enc_buf);
    encode_to_buffer(&enc_buf, asnType, obj);
    string enc((char *) enc_buf.buffer, enc_buf.buffer_filled);
    free_enc_buffer(&enc_buf);
    return enc;
}

/* verify helper functions */

class EntityItem {
private:
    WaveEntity_t *entity;
    string entityDer;
public:
    EntityItem(WaveEntity_t *entity, string entityDer);
    WaveEntity_t * get_entity();
    string get_der();
};

class AttestationItem {
private:
    WaveAttestation_t *attestation;
    AttestationVerifierBody_t *decryptedBody;
public:
    AttestationItem(WaveAttestation_t *att, AttestationVerifierBody_t *dBody);
    WaveAttestation_t * get_att();
    AttestationVerifierBody_t * get_body();
};

class RTreeStatementItem {
private:
    EntityHash_t *permissionSet;
    list<string> permissions;
    string intersectionResource;
public:
    RTreeStatementItem(EntityHash_t *pSet, list<string> perms, string iResource);
    EntityHash_t * get_permissionSet();
    list<string> get_permissions();
    string get_interResource();
};

EntityItem::EntityItem(WaveEntity_t *ent, string entDer) {
    entity = ent;
    entityDer = entDer;
}

WaveEntity_t * EntityItem::get_entity() {
    return entity;
}

string EntityItem::get_der() {
    return entityDer;
}

AttestationItem::AttestationItem(WaveAttestation_t *att, AttestationVerifierBody_t *dBody) {
    attestation = att;
    decryptedBody = dBody;
}

WaveAttestation_t * AttestationItem::get_att() {
    return attestation;
}
    
AttestationVerifierBody_t * AttestationItem::get_body() {
    return decryptedBody;
}

RTreeStatementItem::RTreeStatementItem(EntityHash_t *pSet, list<string> perms, string iResource) {
    permissionSet = pSet;
    permissions = perms;
    intersectionResource = iResource;
}

EntityHash_t * RTreeStatementItem::get_permissionSet() {
    return permissionSet;
}

list<string> RTreeStatementItem::get_permissions() {
    return permissions;
}

string RTreeStatementItem::get_interResource() {
    return intersectionResource;
}

bool HasCapability(WaveEntity_t *entity) {
    EntityPublicKey_t::EntityPublicKey__capabilityFlags caps = entity->tbs.verifyingKey.capabilityFlags;
    int capIndex = 0;
    while (capIndex < caps.list.count) {
        long capInt = *caps.list.array[capIndex];
        if (capInt == CapCertification) {
            return true;
        }
        capIndex++;
    }
    return false;
}

OCTET_STRING_t * HashSchemeInstanceFor(EntityHash_t *hash) {
    ANY_t type = hash->encoding.choice.single_ASN1_type;
    string id = marshal(hash->direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (id == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *hash = 0;
        hash = (HashKeccak_256_t *) unmarshal(type.buf, type.size, hash, &asn_DEF_HashKeccak_256);
        if (hash == nullptr) {
            verify_print("HASHSCHEMEINSTANCEFOR ERROR #1");
        }
        if (hash->size != 32) {
            verify_print("HASHSCHEMEINSTANCEFOR ERROR #2");
        }
        return hash;
    } else if (id == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *hash = 0;
        hash = (HashSha3_256_t *) unmarshal(type.buf, type.size, hash, &asn_DEF_HashSha3_256);
        if (hash == nullptr) {
            verify_print("HASHSCHEMEINSTANCEFOR ERROR #3");
        }
        if (hash->size != 32) {
            verify_print("HASHSCHEMEINSTANCEFOR ERROR #4");
        }
        return hash;
    } else {
        verify_print("HASHSCHEMEINSTANCEFOR ERROR #5");
        return nullptr;
    }
}

LocationURL_t * LocationSchemeInstanceFor(Location_t *loc) {
    ANY_t type = loc->encoding.choice.single_ASN1_type;
    LocationURL_t *lsurl = 0;
    lsurl = (LocationURL_t *) unmarshal(type.buf, type.size, lsurl, &asn_DEF_LocationURL);
    if (lsurl == nullptr) {
        verify_print("subject location is unsupported");
        return nullptr;
    }
    return lsurl;
}

RTreePolicy_t * PolicySchemeInstanceFor(AttestationVerifierBody_t *attVerBody) {
    RTreePolicy_t *policy = 0;
    ANY_t type = attVerBody->policy.encoding.choice.single_ASN1_type;
    string currBodyId = marshal(attVerBody->policy.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (currBodyId == getTypeId(&asn_DEF_TrustLevel)) {
        TrustLevel_t *tp = 0;
        tp = (TrustLevel_t *) unmarshal(type.buf, type.size, tp, &asn_DEF_TrustLevel);
        verify_print("not supporting trust level policy right now");
        return nullptr;
    } else if (currBodyId == getTypeId(&asn_DEF_RTreePolicy)) {
        policy = (RTreePolicy_t *) unmarshal(type.buf, type.size, policy, &asn_DEF_RTreePolicy);
        if (policy == nullptr) {
            verify_print("unexpected policy error");
        }
        return policy;
    } else {
        verify_print("unsupported policy scheme");
        return nullptr;
    }
}

vector<string> split(string s, string delimiter) {
    size_t pos = 0;
    string token;
    vector<string> splitStr;
    while ((pos = s.find(delimiter)) != string::npos) {
        token = s.substr(0, pos);
        splitStr.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    splitStr.push_back(s);
    return splitStr;
}

string emit(vector<string> *bout, vector<string> *fout) {
    for (int i = 0; i < bout->size(); i++) {
        fout->push_back(bout->at(bout->size()-i-1));
    }
    string ss("");
    for (size_t i = 0; i < fout->size(); ++i) {
        if (i != 0) {
            ss.append("/");
        }
        ss.append(fout->at(i));
    }
    return ss;
}

string RestrictBy(string from, string by) {
    vector<string> fp = split(from, "/");
    vector<string> bp = split(by, "/");
    vector<string> fout;
    vector<string> bout;
    string intersectionResource;
    // phase 1: emit matching prefix
    int fi = 0, bi = 0;
    int fni = fp.size() - 1, bni = bp.size() - 1;
    for (; fi < fp.size() && bi < bp.size(); fi++, bi++) {
        if (fp[fi] != "*" && (fp[fi] == bp[bi] || (bp[bi] == "+" && fp[fi] != "*"))) {
            fout.push_back(fp[fi]);
        } else if (fp[fi] == "+" && bp[bi] != "*") {
            fout.push_back(bp[bi]);
        } else {
            break;
        }
    }
    //phase 2
    //emit matching suffix
    for (; fni >= fi && bni >= bi; fni--, bni--) {
        if (bp[bni] != "*" && (fp[fni] == bp[bni] || (bp[bni] == "+" && fp[fni] != "*"))) {
            bout.push_back(fp[fni]);
        } else if (fp[fni] == "+" && bp[bni] != "*") {
            bout.push_back(bp[bni]);
        } else {
            break;
        }
    }
    //phase 3
    //emit front
    if (fi < fp.size() && fp[fi] == "*") {
        for (; bi < bp.size() && bp[bi] != "*" && bi <= bni; bi++) {
            fout.push_back(bp[bi]);
        }
    } else if (bi < bp.size() && bp[bi] == "*") {
        for (; fi < fp.size() && fp[fi] != "*" && fi <= fni; fi++) {
            fout.push_back(fp[fi]);
        }
    }
    //phase 4
    //emit back
    if (fni >= 0 && fp[fni] == "*") {
        for (; bni >= 0 && bp[bni] != "*" && bni >= bi; bni--) {
            bout.push_back(bp[bni]);
        }
    } else if (bni >= 0 && bp[bni] == "*") {
        for (; fni >= 0 && fp[fni] != "*" && fni >= fi; fni--) {
            bout.push_back(fp[fni]);
        }
    }
    //phase 5
    //emit star if they both have it
    if (fi == fni && fp[fi] == "*" && bi == bni && bp[bi] == "*") {
        fout.push_back("*");
        intersectionResource = emit(&bout, &fout);
    }
    //Remove any stars
    if (fi < fp.size() && fp[fi] == "*") {
        fi++;
    }
    if (bi < bp.size() && bp[bi] == "*") {
        bi++;
    }
    if ((fi == fni+1 || fi == fp.size()) && (bi == bni+1 || bi == bp.size())) {
        intersectionResource = emit(&bout, &fout);
    }
    return intersectionResource;
}

bool isStatementSupersetOf(RTreeStatementItem *subset, RTreeStatementItem *superset) {
    OCTET_STRING_t *lhs_ps = HashSchemeInstanceFor(subset->get_permissionSet());
    OCTET_STRING_t *rhs_ps = HashSchemeInstanceFor(superset->get_permissionSet());
    if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, lhs_ps, rhs_ps)) {
        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ps, ASFM_FREE_EVERYTHING);
        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ps, ASFM_FREE_EVERYTHING);
        return false;
    }
    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ps, ASFM_FREE_EVERYTHING);
    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ps, ASFM_FREE_EVERYTHING);
    unordered_map<string, bool> superset_perms;
    for (auto perm : superset->get_permissions()) {
        superset_perms[perm] = true;
    }
    for (auto perm : subset->get_permissions()) {
        if (!superset_perms[perm]) {
            return false;
        }
    }
    // gofunc: RestrictBy
    string inter_uri = RestrictBy(subset->get_interResource(), superset->get_interResource());
    if (inter_uri.empty()) {
        return false;
    }
    return !inter_uri.compare(subset->get_interResource());
}

void freeStatementItem(RTreeStatementItem *statement) {
    asn_DEF_EntityHash.op->free_struct(&asn_DEF_EntityHash, statement->get_permissionSet(), ASFM_FREE_EVERYTHING);
    delete statement;
}

void computeStatements(vector<RTreeStatementItem *> *statements, vector<RTreeStatementItem *> *dedup_statements) {
    for (int orig_idx = 0; orig_idx < statements->size(); orig_idx++) {
        next:
        for (int chosen_idx = 0; chosen_idx < dedup_statements->size(); chosen_idx++) {
            if (isStatementSupersetOf(statements->at(orig_idx), dedup_statements->at(chosen_idx))) {
                freeStatementItem(statements->at(orig_idx));
                goto next;
            }
            if (isStatementSupersetOf(dedup_statements->at(chosen_idx), statements->at(orig_idx))) {
                RTreeStatementItem *item = dedup_statements->at(chosen_idx);
                dedup_statements->at(chosen_idx) = statements->at(orig_idx);
                freeStatementItem(item);
                goto next;
            }
        }
        dedup_statements->push_back(statements->at(orig_idx));
    }
}

RTreeStatementItem * statementToItem(RTreeStatement_t *statement) {
    RTreeStatement_t::RTreeStatement__permissions perms = statement->permissions;
    int i = 0;
    list<string> permList;
    while (i < perms.list.count) {
        UTF8String_t *str = perms.list.array[i];
        permList.push_back(string((const char *) str->buf, str->size));
        i++;
    }
    string rsource((const char *) statement->resource.buf, statement->resource.size);
    return new RTreeStatementItem(&statement->permissionSet, permList, rsource);
}

void appendStatements(vector<RTreeStatementItem *> *statements, RTreePolicy_t::RTreePolicy__statements *policyStments) {
    int index = 0;
    while (index < policyStments->list.count) {
        statements->push_back(statementToItem(policyStments->list.array[index]));
        index++;
    }
}

long expiry_to_long(OCTET_STRING_t expiryStr) {
    string temp = string((const char *) expiryStr.buf, expiryStr.size);
    return stol(temp, nullptr);
}

tuple<OCTET_STRING_t *, OCTET_STRING_t *, vector<RTreeStatementItem *> *, long, vector<RTreePolicy_t *> *> verify_rtree_proof(char *proof, size_t proofSize) {
    string decodedProof(proof, proofSize);
    // dynamically allocated memory and return variables
    list<EntityItem> entList;
    vector<AttestationItem> attestationList;
    vector<OCTET_STRING_t *> pathEndEntities;
    vector<RTreePolicy_t *> *pathpolicies = new vector<RTreePolicy_t *>();
    vector<RTreeStatementItem *> *dedup_statements = new vector<RTreeStatementItem *>();
    WaveExplicitProof_t *exp = 0;
    OCTET_STRING_t *finalsubject = 0;
    OCTET_STRING_t *lhs_ns = 0;
    long expiry = LONG_MAX;
    string errorMessage = string("\nverify_rtree_proof succeeded\n");

    WaveWireObject_t *wwoPtr = 0;
    wwoPtr = (WaveWireObject_t *) unmarshal((uint8_t *) (decodedProof.c_str()), decodedProof.length(), wwoPtr, &asn_DEF_WaveWireObject);	/* pointer to decoded data */
    if (wwoPtr == nullptr) {
        errorMessage = string("failed to unmarshal proof wire object");
        goto errorReturn;
    }

    {
        ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
        exp = (WaveExplicitProof_t *) unmarshal(type.buf, type.size, exp, &asn_DEF_WaveExplicitProof);	/* pointer to decoded data */
        asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
        if (exp == nullptr) {
            errorMessage = string("failed to unmarshal explicit proof");
            goto errorReturn;
        }
    }
    
    {
        // parse entities
        WaveExplicitProof_t::WaveExplicitProof__entities ents = exp->entities;
        int entIndex = 0;
        while (entIndex < ents.list.count) {
            verify_print("\nParsing entity");
            OCTET_STRING_t *ent = ents.list.array[entIndex];
            string entStr((const char *) ent->buf, ent->size);
            entIndex++;

            // gofunc: ParseEntity
            WaveWireObject_t *wwoPtr = nullptr;
            wwoPtr = (WaveWireObject_t *) unmarshal(ent->buf, ent->size, wwoPtr, &asn_DEF_WaveWireObject);
            if (wwoPtr == nullptr) {
                errorMessage = string("failed to unmarshal");
                goto errorReturn;
            }

            WaveEntity_t *entity = 0;
            ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
            entity = (WaveEntity_t *) unmarshal(type.buf, type.size, entity, &asn_DEF_WaveEntity);	/* pointer to decoded data */

            if (entity == nullptr) {
                // maybe this is an entity secret
                WaveEntitySecret_t *es = 0;
                es = (WaveEntitySecret_t *) unmarshal(type.buf, type.size, es, &asn_DEF_WaveEntitySecret);
                if (es == nullptr) {
                    asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
                    errorMessage = string("DER is not a wave entity");
                    goto errorReturn;
                }
                entity = &(es->entity);
            }
            asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
            EntityItem e(entity, entStr);
            entList.push_back(e);

            // gofunc: parseEntityFromObject
            // check the signature
            EntityPublicKey_t entKey = entity->tbs.verifyingKey;
            type = entKey.key.encoding.choice.single_ASN1_type;
            string entKeyId = marshal(entKey.key.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);

            if (entKeyId == getTypeId(&asn_DEF_Public_Ed25519)) {
                Public_Ed25519_t *ks = 0;
                ks = (Public_Ed25519_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Ed25519);
                if (ks->size != 32) {
                    asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
                    errorMessage = string("key length is incorrect");
                    goto errorReturn;
                }

                // gofunc: VerifyCertify
                // gofunc: HasCapability
                if (!HasCapability(entity)) {
                    asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
                    errorMessage = string("this key cannot perform certifications");
                    goto errorReturn;
                }

                // gofunc: Verify
                string eData = marshal(&entity->tbs, &asn_DEF_WaveEntityTbs);
                string entSig((const char *) entity->signature.buf, entity->signature.size);
                string ksStr((const char *) ks->buf, ks->size);

                asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
                
                if (!ed25519_verify((const unsigned char *) entSig.c_str(), 
                    (const unsigned char *) eData.c_str(), eData.length(), 
                    (const unsigned char *) ksStr.c_str())) {
                    errorMessage = string("entity ed25519 signature invalid");
                    goto errorReturn;
                }
                verify_print("valid entity signature");
            } else if (entKeyId == getTypeId(&asn_DEF_Public_Curve25519)) {
                errorMessage = string("this key cannot perform certifications");
                goto errorReturn;
            } else if (entKeyId == getTypeId(&asn_DEF_Params_BLS12381_IBE)) {
                errorMessage = string("this key cannot perform certifications");
                goto errorReturn;
            } else if (entKeyId == getTypeId(&asn_DEF_Public_BLS12381_IBE)) {
                errorMessage = string("this key cannot perform verification");
                goto errorReturn;
            } else if (entKeyId == getTypeId(&asn_DEF_Params_BLS12381_OAQUE)) {
                errorMessage = string("this key cannot perform verification");
                goto errorReturn;
            } else if (entKeyId == getTypeId(&asn_DEF_Public_OAQUE)) {
                errorMessage = string("this key cannot perform verification");
                goto errorReturn;
            } else {
                errorMessage = string("entity uses unsupported key scheme");
                goto errorReturn;
            }

            // Entity appears ok, let's unpack it further
            WaveEntityTbs_t::WaveEntityTbs__keys tbsKeys = entity->tbs.keys;
            int tbsIndex = 0;
            while (tbsIndex < tbsKeys.list.count) {
                EntityPublicKey_t *tbsKey = tbsKeys.list.array[tbsIndex];
                tbsIndex++;
                EXTERNAL_t lkey = tbsKey->key;
                ANY_t type = lkey.encoding.choice.single_ASN1_type;
                string lkeyId = marshal(lkey.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
                // gofunc: EntityKeySchemeInstanceFor
                if (lkeyId == getTypeId(&asn_DEF_Public_Ed25519)) {
                    Public_Ed25519_t *ks = 0;
                    ks = (Public_Ed25519_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Ed25519);
                    if (ks == nullptr) {
                        errorMessage = string("tbs key is null");
                        goto errorReturn;
                    }
                    if (ks->size != 32) {
                        asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
                        errorMessage = string("key length is incorrect");
                        goto errorReturn;
                    }
                    asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
                } else if (lkeyId == getTypeId(&asn_DEF_Public_Curve25519)) {
                    Public_Curve25519_t *ks = 0;
                    ks = (Public_Curve25519_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Curve25519);
                    if (ks == nullptr) {
                        errorMessage = string("tbs key is null");
                        goto errorReturn;
                    }
                    if (ks->size != 32) {
                        asn_DEF_Public_Curve25519.op->free_struct(&asn_DEF_Public_Curve25519, ks, ASFM_FREE_EVERYTHING);
                        errorMessage = string("key length is incorrect");
                        goto errorReturn;
                    }
                    asn_DEF_Public_Curve25519.op->free_struct(&asn_DEF_Public_Curve25519, ks, ASFM_FREE_EVERYTHING);
                } else if (lkeyId == getTypeId(&asn_DEF_Params_BLS12381_IBE)) {
                    Params_BLS12381_IBE_t *ks = 0;
                    ks = (Params_BLS12381_IBE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BLS12381_IBE);
                    if (ks == nullptr) {
                        errorMessage = string("tbs key is null");
                        goto errorReturn;
                    }
                    asn_DEF_Params_BLS12381_IBE.op->free_struct(&asn_DEF_Params_BLS12381_IBE, ks, ASFM_FREE_EVERYTHING);
                } else if (lkeyId == getTypeId(&asn_DEF_Public_BLS12381_IBE)) {
                    Public_BLS12381_IBE *ks = 0;
                    ks = (Public_BLS12381_IBE *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_BLS12381_IBE);
                    if (ks == nullptr) {
                        errorMessage = string("tbs key is null");
                        goto errorReturn;
                    }
                    asn_DEF_Public_BLS12381_IBE.op->free_struct(&asn_DEF_Public_BLS12381_IBE, ks, ASFM_FREE_EVERYTHING);
                } else if (lkeyId == getTypeId(&asn_DEF_Params_BLS12381_OAQUE)) {
                    Params_BLS12381_OAQUE_t *ks = 0;
                    ks = (Params_BLS12381_OAQUE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BLS12381_OAQUE);
                    if (ks == nullptr) {
                        errorMessage = string("tbs key is null");
                        goto errorReturn;
                    }
                    asn_DEF_Params_BLS12381_OAQUE.op->free_struct(&asn_DEF_Params_BLS12381_OAQUE, ks, ASFM_FREE_EVERYTHING);
                } else if (lkeyId == getTypeId(&asn_DEF_Public_OAQUE)) {
                    Public_OAQUE_t *ks = 0;
                    ks = (Public_OAQUE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_OAQUE);
                    if (ks == nullptr) {
                        errorMessage = string("tbs key is null");
                        goto errorReturn;
                    }
                    asn_DEF_Public_OAQUE.op->free_struct(&asn_DEF_Public_OAQUE, ks, ASFM_FREE_EVERYTHING);
                } else {
                    errorMessage = string("tbs key uses unsupported key scheme");
                    goto errorReturn;
                }
            }

            long currExp = expiry_to_long(entity->tbs.validity.notAfter);
            if (currExp < expiry) {
                expiry = currExp;
            }
        }
    }

    {
        // retrieve attestations
        WaveExplicitProof_t::WaveExplicitProof__attestations atsts = exp->attestations;
        int attIndex = 0;
        while (attIndex < atsts.list.count) {
            verify_print("\nParsing attestation");
            AttestationReference_t *atst = atsts.list.array[attIndex];
            attIndex++;

            AttestationReference_t::AttestationReference__keys keys = atst->keys;
            AVKeyAES128_GCM_t *vfk = 0;
            string verifierBodyKey;
            string verifierBodyNonce;
            int vfkLen = 0;
            if (keys.list.count == 0) {
                verify_print("atst has no keys");
            }

            int keyIndex = 0;
            while (keyIndex < keys.list.count) {
                /* casting is needed due to some weirdness with the asn1c compiler
                * https://github.com/vlm/asn1c/issues/296
                */
                AttestationVerifierKey_t *key = (AttestationVerifierKey_t *) keys.list.array[keyIndex];
                ANY_t type = key->encoding.choice.single_ASN1_type;
                vfk = (AVKeyAES128_GCM_t *) unmarshal(type.buf, type.size, vfk, &asn_DEF_AVKeyAES128_GCM);
                int vfkLen = 0;
                if (vfk == nullptr) {
                    verify_print("atst key was not aes");
                } else {
                    vfkLen = vfk->size;
                    string verifierKey(vfk->buf, vfk->buf + vfkLen);
                    asn_DEF_AVKeyAES128_GCM.op->free_struct(&asn_DEF_AVKeyAES128_GCM, vfk, ASFM_FREE_EVERYTHING);  
                    verifierBodyKey = verifierKey.substr(0, 16);
                    verifierBodyNonce = verifierKey.substr(16, verifierKey.length());
                    break;
                }
                keyIndex++;
            }

            // gofunc: ParseAttestation
            // parse attestation
            OCTET_STRING_t *derEncodedData = atst->content;
            WaveWireObject_t *wwoPtr = 0;
            wwoPtr = (WaveWireObject_t *) unmarshal(derEncodedData->buf, derEncodedData->size, wwoPtr, &asn_DEF_WaveWireObject);
            if (wwoPtr == nullptr) {
                errorMessage = string("failed to unmarshal atst content");
                goto errorReturn;
            }
            WaveAttestation_t *att = 0;
            ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
            att = (WaveAttestation_t *) unmarshal(type.buf, type.size, att, &asn_DEF_WaveAttestation);	/* pointer to decoded data */
            asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
            if (att == nullptr) {
                errorMessage = string("failed to unmarshal into Wave Attestation");
                goto errorReturn;
            }

            // gofunc: DecryptBody
            AttestationVerifierBody_t *decryptedBody;
            string schemeID = marshal(att->tbs.body.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
            if (schemeID == getTypeId(&asn_DEF_AttestationBody)) {
                asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                errorMessage = string("unencrypted body scheme, currently not supported");
                goto errorReturn;
            } else if (schemeID == getTypeId(&asn_DEF_WR1BodyCiphertext)) {
                verify_print("this is a wr1 body scheme");
                // decrypt body
                type = att->tbs.body.encoding.choice.single_ASN1_type;
                WR1BodyCiphertext_t *wr1body = 0;
                wr1body = (WR1BodyCiphertext_t *) unmarshal(type.buf, type.size, wr1body, &asn_DEF_WR1BodyCiphertext);
                if (wr1body == nullptr) {
                    asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                    errorMessage = string("getting body ciphertext failed");
                    goto errorReturn;
                }
                verify_print("got wr1 body");
                // checking subject HI instance
                OCTET_STRING_t *ret = HashSchemeInstanceFor(&att->tbs.subject);
                asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, ret, ASFM_FREE_EVERYTHING);

                if (vfk != nullptr) {
                    verify_print("decrypting attestation");
                    OCTET_STRING_t vbodyCipher = wr1body->verifierBodyCiphertext;
                    int bodyLen = vbodyCipher.size;
                    unsigned char verifierBodyDER[bodyLen];

                    EVP_CIPHER_CTX *ctx;
                    int outlen, ret;
                    if(!(ctx = EVP_CIPHER_CTX_new())) {
                        asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                        asn_DEF_WR1BodyCiphertext.op->free_struct(&asn_DEF_WR1BodyCiphertext, wr1body, ASFM_FREE_EVERYTHING);
                        errorMessage = string("Could not initialize decryption context");
                        goto errorReturn;
                    }
                    /* Select cipher, key, and IV */
                    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL,
                                (const unsigned char *) verifierBodyKey.c_str(), 
                                (const unsigned char *) verifierBodyNonce.c_str())) {
                        asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                        asn_DEF_WR1BodyCiphertext.op->free_struct(&asn_DEF_WR1BodyCiphertext, wr1body, ASFM_FREE_EVERYTHING);
                        errorMessage = string("Error setting aes decryption fields");
                        goto errorReturn;
                    }
                    /* Decrypt ciphertext */
                    if (1 != EVP_DecryptUpdate(ctx, verifierBodyDER, &outlen, 
                        vbodyCipher.buf, bodyLen)) {
                        asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                        asn_DEF_WR1BodyCiphertext.op->free_struct(&asn_DEF_WR1BodyCiphertext, wr1body, ASFM_FREE_EVERYTHING);
                        errorMessage = string("aes decryption failed");
                        goto errorReturn;
                    }
                    EVP_CIPHER_CTX_free(ctx);
                    unsigned char *hah = verifierBodyDER;
                    string v((const char *)hah, bodyLen-16);
                    verify_print("aes decryption succeeded");

                    asn_DEF_WR1BodyCiphertext.op->free_struct(&asn_DEF_WR1BodyCiphertext, wr1body, ASFM_FREE_EVERYTHING);

                    //unmarshal into WR1VerifierBody
                    WR1VerifierBody_t *vbody = 0;
                    vbody = (WR1VerifierBody_t *) unmarshal((uint8_t *) verifierBodyDER, bodyLen-16, vbody, &asn_DEF_WR1VerifierBody);
                    if (vbody == nullptr) {
                        asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                        errorMessage = string("could not unmarshal into WR1VerifierBody");
                        goto errorReturn;
                    }        
                    decryptedBody = &vbody->attestationVerifierBody;
                }
            } else {
                errorMessage = string("unsupported body scheme");
                asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att, ASFM_FREE_EVERYTHING);
                goto errorReturn;
            }

            AttestationItem aItem(att, decryptedBody);
            attestationList.push_back(aItem);

            LocationURL_t *attesterLoc = 0;
            type = decryptedBody->attesterLocation.encoding.choice.single_ASN1_type;
            attesterLoc = (LocationURL_t *) unmarshal(type.buf, type.size, attesterLoc, &asn_DEF_LocationURL);
            if (attesterLoc == nullptr) {
                errorMessage = string("could not get attester loc");
                goto errorReturn;
            }
            asn_DEF_LocationURL.op->free_struct(&asn_DEF_LocationURL, attesterLoc, ASFM_FREE_EVERYTHING);

            WaveEntity_t *attester = 0;
            string attestId = marshal(decryptedBody->attester.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
            type = decryptedBody->attester.encoding.choice.single_ASN1_type;
            // gofunc: EntityByHashLoc
            if (attestId == getTypeId(&asn_DEF_HashKeccak_256)) {
                HashKeccak_256_t *attesterHash = 0;
                attesterHash = (HashKeccak_256_t *) unmarshal(type.buf, type.size, attesterHash, &asn_DEF_HashKeccak_256);
                if (attesterHash == nullptr) {
                    errorMessage = string("could not get attester hash");
                    goto errorReturn;
                }
                if (attesterHash->size != 32) {
                    asn_DEF_HashKeccak_256.op->free_struct(&asn_DEF_HashKeccak_256, attesterHash, ASFM_FREE_EVERYTHING);
                    errorMessage = string("attester hash not valid");
                    goto errorReturn;
                }

                // loop through entities
                for (list<EntityItem>::iterator it=entList.begin(); it != entList.end(); ++it) {
                    char eHash[32];
                    if (sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, it->get_der().c_str(), it->get_der().size(), eHash, 32)) {
                        asn_DEF_HashKeccak_256.op->free_struct(&asn_DEF_HashKeccak_256, attesterHash, ASFM_FREE_EVERYTHING);
                        errorMessage = string("could not take hash of entity");
                        goto errorReturn;
                    }
                    if (!memcmp(attesterHash->buf, eHash, 32)) {
                        verify_print("found matching entity for attester");
                        attester = it->get_entity();
                        break;
                    }
                }
                asn_DEF_HashKeccak_256.op->free_struct(&asn_DEF_HashKeccak_256, attesterHash, ASFM_FREE_EVERYTHING);
            } else if (attestId == getTypeId(&asn_DEF_HashSha3_256)) {
                HashSha3_256_t *attesterHash = 0;
                attesterHash = (HashSha3_256_t *) unmarshal(type.buf, type.size, attesterHash, &asn_DEF_HashSha3_256);
                if (attesterHash == nullptr) {
                    errorMessage = string("could not get attester hash");
                    goto errorReturn;
                }
                if (attesterHash->size != 32) {
                    asn_DEF_HashSha3_256.op->free_struct(&asn_DEF_HashSha3_256, attesterHash, ASFM_FREE_EVERYTHING);
                    errorMessage = string("attester hash not valid");
                    goto errorReturn;
                }
                asn_DEF_HashSha3_256.op->free_struct(&asn_DEF_HashSha3_256, attesterHash, ASFM_FREE_EVERYTHING);
            } else {
                errorMessage = string("unsupported attester hash scheme id");
                goto errorReturn;
            }

            // gofunc: VerifyBinding
            // At this time we only know how to extract the key from an ed25519 outer signature
            if (attester == nullptr) {
                errorMessage = string("no attester");
                goto errorReturn;
            }

            // gofunc: VerifyCertify
            // gofunc: HasCapability
            if (!HasCapability(attester)) {
                errorMessage = string("this key cannot perform certifications");
                goto errorReturn;
            }

            SignedOuterKey_t *binding = 0;
            type = decryptedBody->outerSignatureBinding.encoding.choice.single_ASN1_type;
            binding = (SignedOuterKey_t *) unmarshal(type.buf, type.size, binding, &asn_DEF_SignedOuterKey);
            if (binding == nullptr) {
                errorMessage = string("outer signature binding not supported/this is not really a signed outer key");
                goto errorReturn;
            }

            // gofunc: Verify
            string encodedData = marshal(&binding->tbs, &asn_DEF_SignedOuterKeyTbs);
            Public_Ed25519_t *attesterKey = 0;
            type = attester->tbs.verifyingKey.key.encoding.choice.single_ASN1_type;
            attesterKey = (Public_Ed25519_t *) unmarshal(type.buf, type.size, attesterKey, &asn_DEF_Public_Ed25519);
            if (attesterKey == nullptr) {
                asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
                errorMessage = string("couldn't unmarshal attesterKey");
                goto errorReturn;
            }
            string bindingSig((const char *) binding->signature.buf, binding->signature.size);
            string attKey((const char *) attesterKey->buf, attesterKey->size);
            asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, attesterKey, ASFM_FREE_EVERYTHING);

            if (!ed25519_verify((const unsigned char *) bindingSig.c_str(), 
                (const unsigned char *) encodedData.c_str(), encodedData.length(), 
                (const unsigned char *) attKey.c_str())) {
                asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
                errorMessage = string("outer signature binding invalid");
                goto errorReturn;
            }
            verify_print("valid outer signature binding" );

            // Now we know the binding is valid, check the key is the same
            if (marshal(&binding->tbs.outerSignatureScheme, &asn_DEF_OBJECT_IDENTIFIER) 
                != getTypeId(&asn_DEF_Ed25519OuterSignature)) {
                asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
                errorMessage = string("outer signature scheme invalid");
                goto errorReturn;
            }

            Ed25519OuterSignature_t *osig = 0;
            type = att->outerSignature.encoding.choice.single_ASN1_type;
            osig = (Ed25519OuterSignature_t *) unmarshal(type.buf, type.size, osig, &asn_DEF_Ed25519OuterSignature);
            if (osig == nullptr) {
                asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
                errorMessage = string("unknown outer signature type/signature scheme not supported");
                goto errorReturn;
            }

            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, &binding->tbs.verifyingKey, &osig->verifyingKey)) {
                asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
                asn_DEF_Ed25519OuterSignature.op->free_struct(&asn_DEF_Ed25519OuterSignature, osig, ASFM_FREE_EVERYTHING);
                errorMessage = string("bound key does not match");
                goto errorReturn;
            }
            // check signature
            // gofunc: VerifySignature
            string encData = marshal(&att->tbs, &asn_DEF_WaveAttestationTbs);
            OCTET_STRING_t vKey = osig->verifyingKey;
            OCTET_STRING_t sig = osig->signature;
            string s((const char *) sig.buf, sig.size);
            string v((const char *) vKey.buf, vKey.size);
            asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
            asn_DEF_Ed25519OuterSignature.op->free_struct(&asn_DEF_Ed25519OuterSignature, osig, ASFM_FREE_EVERYTHING);
            /* verify the signature */
            if (!ed25519_verify((const unsigned char *) s.c_str(), 
                    (const unsigned char *) encData.c_str(), encData.length(), 
                    (const unsigned char *) v.c_str())) {
                errorMessage = string("invalid outer signature");
                goto errorReturn;
            }
            verify_print("valid outer signature");
            long currExp = expiry_to_long(decryptedBody->validity.notAfter);
            if (currExp < expiry) {
                expiry = currExp;
            }
        }
    }

    {
        // now verify the paths
        WaveExplicitProof_t::WaveExplicitProof__paths paths = exp->paths;
        verify_print("\nPaths retrieved");
        int pathIndex = 0;
        while (pathIndex < paths.list.count) {
            WaveExplicitProof__paths__Member *p = paths.list.array[pathIndex];
            pathIndex++;
            int pIndex = 0;
            if (p->list.count == 0) {
                errorMessage = string("path of length 0");
                goto errorReturn;
            }
            long *pathNum = p->list.array[pIndex];
            pIndex++;
            try {
                attestationList.at(*pathNum); 
            } catch (...) {
                errorMessage = string("proof refers to non-included attestation");
                goto errorReturn;
            }

            AttestationItem currAttItem = attestationList.at(*pathNum);
            WaveAttestation_t *currAtt = currAttItem.get_att();

            // gofunc: Subject
            // gofunc: HashSchemeInstanceFor
            OCTET_STRING_t *cursubj = HashSchemeInstanceFor(&currAtt->tbs.subject);
            // gofunc: LocationSchemeInstanceFor
            LocationURL_t *cursubloc = LocationSchemeInstanceFor(&currAtt->tbs.subjectLocation);

            // gofunc: PolicySchemeInstanceFor
            AttestationVerifierBody_t *currBody = currAttItem.get_body();
            RTreePolicy_t *policy = PolicySchemeInstanceFor(currBody);

            while (pIndex < p->list.count) {
                pathNum = p->list.array[pIndex];
                pIndex++;
                try {
                    attestationList.at(*pathNum); 
                } catch (...) {
                    errorMessage = string("proof refers to non-included attestation");
                    goto errorReturn;
                }
                AttestationItem nextAttItem = attestationList.at(*pathNum);
                WaveAttestation_t *nextAtt = nextAttItem.get_att();
                
                // gofunc: Attester
                // gofunc: HashSchemeInstanceFor
                OCTET_STRING_t *nextAttest = HashSchemeInstanceFor(&nextAttItem.get_body()->attester);
                // gofunc: LocationSchemeInstanceFor
                LocationURL_t *nextAttLoc = LocationSchemeInstanceFor(&nextAttItem.get_body()->attesterLocation);

                if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, cursubj, nextAttest)) {
                    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, cursubj, ASFM_FREE_EVERYTHING);
                    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, nextAttest, ASFM_FREE_EVERYTHING);
                    errorMessage = string("path has broken links");
                    goto errorReturn;
                }
                asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, cursubj, ASFM_FREE_EVERYTHING);
                asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, nextAttest, ASFM_FREE_EVERYTHING);

                // gofunc: PolicySchemeInstanceFor
                AttestationVerifierBody_t *nextBody = nextAttItem.get_body();
                RTreePolicy_t *nextPolicy = PolicySchemeInstanceFor(nextBody);

                // gofunc: Intersect
                OCTET_STRING_t *rhs_ns = HashSchemeInstanceFor(&nextPolicy->Namespace);
                OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(&policy->Namespace);
                // not doing multihash
                if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, rhs_ns, lhs_ns)) {
                    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ns, ASFM_FREE_EVERYTHING);
                    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);
                    errorMessage = string("different authority domain");
                    goto errorReturn;
                }
                asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ns, ASFM_FREE_EVERYTHING);
                asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);
                
                // gofunc: intersectStatement
                vector<RTreeStatementItem *> statements;
                RTreePolicy_t::RTreePolicy__statements policyStatements = policy->statements;
                int lhs_index = 0;
                while (lhs_index < policyStatements.list.count) {
                    RTreeStatement_t *leftStatement = policyStatements.list.array[lhs_index];
                    lhs_index++;
                    RTreePolicy_t::RTreePolicy__statements nextPolicyStatements = nextPolicy->statements;
                    int rhs_index = 0;
                    while (rhs_index < nextPolicyStatements.list.count) {
                        RTreeStatement_t *rightStatement = nextPolicyStatements.list.array[rhs_index];
                        rhs_index++;
                        OCTET_STRING_t *lhs_ps = HashSchemeInstanceFor(&leftStatement->permissionSet);
                        OCTET_STRING_t *rhs_ps = HashSchemeInstanceFor(&rightStatement->permissionSet);
                        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, lhs_ps, rhs_ps)) {
                            asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ps, ASFM_FREE_EVERYTHING);
                            asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ps, ASFM_FREE_EVERYTHING);
                            continue;
                        }
                        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ps, ASFM_FREE_EVERYTHING);
                        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ps, ASFM_FREE_EVERYTHING);
                        
                        unordered_map <string, bool> lhs_perms;
                        int lpermIdx = 0;
                        while (lpermIdx < leftStatement->permissions.list.count) {
                            UTF8String_t *lperm = leftStatement->permissions.list.array[lpermIdx];
                            lpermIdx++;
                            lhs_perms[string((const char *) lperm->buf, lperm->size)] = true;
                        }
                        list<string> intersectionPerms;
                        int rpermIdx = 0;
                        while (rpermIdx < rightStatement->permissions.list.count) {
                            UTF8String_t *rperm = rightStatement->permissions.list.array[rpermIdx];
                            rpermIdx++;
                            string rpermStr = string((const char *) rperm->buf, rperm->size);
                            if (lhs_perms[rpermStr]) {
                                intersectionPerms.push_back(rpermStr);
                            }
                        }
                        if (intersectionPerms.size() == 0) {
                            continue;
                        }
                        // gofunc: RestrictBy
                        string from = string((const char *) leftStatement->resource.buf, leftStatement->resource.size);
                        string by = string((const char *) rightStatement->resource.buf, rightStatement->resource.size);
                        string intersectionResource = RestrictBy(from, by);

                        if (intersectionResource.empty()) {
                            RTreeStatementItem *item = new RTreeStatementItem(&leftStatement->permissionSet, intersectionPerms, intersectionResource);
                            statements.push_back(item);
                        }
                    }   
                }

                vector<RTreeStatementItem *> dedup_statements;
                computeStatements(&statements, &dedup_statements);
                int indirections;
                if (policy->indirections < nextPolicy->indirections) {
                    indirections = policy->indirections - 1;
                } else {
                    indirections = nextPolicy->indirections - 1;
                }
                asn_DEF_RTreePolicy.op->free_struct(&asn_DEF_RTreePolicy, nextPolicy, ASFM_FREE_EVERYTHING);
                
                // Check errors
                if (indirections < 0) {
                    errorMessage = string("insufficient permitted indirections");
                    goto errorReturn;
                }
                if (dedup_statements.size() > PermittedCombinedStatements) {
                    errorMessage = string("statements form too many combinations");
                    goto errorReturn;
                }
                // gofunc: Subject
                // gofunc: HashSchemeInstanceFor
                cursubj = HashSchemeInstanceFor(&nextAtt->tbs.subject);
            }
            pathpolicies->push_back(policy);
            pathEndEntities.push_back(cursubj);
        }
    }

    {
        // Now combine the policies together
        verify_print("Paths verified, now combining the policies");
        RTreePolicy_t *aggregatepolicy = pathpolicies->at(0);
        lhs_ns = HashSchemeInstanceFor(&aggregatepolicy->Namespace);
        appendStatements(dedup_statements, &(aggregatepolicy->statements));
        finalsubject = pathEndEntities.at(0);
        for (int idx = 1; idx < pathpolicies->size(); idx++) {
            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, finalsubject, pathEndEntities.at(idx))) {
                errorMessage = string("paths don't terminate at same entity");
                goto errorReturn;
            }
            // gofunc: Union
            OCTET_STRING_t *rhs_ns = HashSchemeInstanceFor(&pathpolicies->at(idx)->Namespace);
            // not doing multihash
            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, rhs_ns, lhs_ns)) {
                asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ns, ASFM_FREE_EVERYTHING);
                errorMessage = string("different authority domain");
                goto errorReturn;
            }
            asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ns, ASFM_FREE_EVERYTHING);
            
            vector<RTreeStatementItem *> statements;
            RTreePolicy_t::RTreePolicy__statements *rhsStatements = &(pathpolicies->at(idx)->statements);
            appendStatements(&statements, rhsStatements);
            computeStatements(&statements, dedup_statements);
            if (dedup_statements->size() > PermittedCombinedStatements) {
                errorMessage = string("statements form too many combinations");
                goto errorReturn;
            }
        }
        goto Return;
    }

errorReturn:
    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, finalsubject, ASFM_FREE_EVERYTHING);
	asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);
	for (int i = 0; i < pathpolicies->size(); i++) {
        asn_DEF_RTreePolicy.op->free_struct(&asn_DEF_RTreePolicy, pathpolicies->at(i), ASFM_FREE_EVERYTHING);
    }
	delete pathpolicies;
	for (int i = 0; i < dedup_statements->size(); i++) {
		delete dedup_statements->at(i);
	}
	delete dedup_statements;
    expiry = -1;
Return:
    verify_print(errorMessage.c_str());
    asn_DEF_WaveExplicitProof.op->free_struct(&asn_DEF_WaveExplicitProof, exp, ASFM_FREE_EVERYTHING);
    for (auto & ent: entList) {
        asn_DEF_WaveEntity.op->free_struct(&asn_DEF_WaveEntity, ent.get_entity(), ASFM_FREE_EVERYTHING);
    }
    for (auto & att: attestationList) {
        asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att.get_att(), ASFM_FREE_EVERYTHING);
        asn_DEF_AttestationVerifierBody.op->free_struct(&asn_DEF_AttestationVerifierBody, att.get_body(), ASFM_FREE_EVERYTHING);
    }
    for (int i = 1; i < pathEndEntities.size(); i++) {
        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, pathEndEntities.at(i), ASFM_FREE_EVERYTHING);
    }
    return {finalsubject, lhs_ns, dedup_statements, expiry, pathpolicies};
}

long verifyProof(char *proofDER, size_t proofDERSize, char *subject, size_t subj_size, 
                char *policyDER, size_t policyDER_size) {
    auto [finalsubject, superset_ns, supersetStatements, expiry, pathpolicies] = 
		verify_rtree_proof((char *) proofDER, proofDERSize);
	if (expiry == -1) {
		verify_print("\nerror in verify rtree proof");
		return -1;
	}

    string returnStr = string("verifying proof succeeded");
	// Check that proof policy is a superset of required policy
	// gofunc: IsSubsetOf
	RTreePolicy_t *policy = 0;
	if (policyDER != nullptr) {
		verify_print("comparing proof policy to required policy");
		WaveWireObject_t *wwoPtr = 0;
    	wwoPtr = (WaveWireObject_t *) unmarshal((uint8_t *) policyDER, policyDER_size, wwoPtr, &asn_DEF_WaveWireObject);
		if (wwoPtr == nullptr) {
			returnStr = string("failed to unmarshal wave wire object");
			goto errorReturn;
		}
		ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
		policy = (RTreePolicy_t *) unmarshal(type.buf, type.size, policy, &asn_DEF_RTreePolicy);
		asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
		if (policy == nullptr) {
           	returnStr = string("unexpected error unmarshaling policy");
			goto errorReturn;
        }

		OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(&policy->Namespace);
		// not doing multihash
		if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, superset_ns, lhs_ns)) {
			asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);
			returnStr = string("proof is well formed but namespaces don't match");
			goto errorReturn;
		}
		asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, lhs_ns, ASFM_FREE_EVERYTHING);

		RTreePolicy_t::RTreePolicy__statements policyStatements = policy->statements;
		int lhs_index = 0;
		while (lhs_index < policyStatements.list.count) {
			RTreeStatementItem *leftStatement = statementToItem(policyStatements.list.array[lhs_index]);
			lhs_index++;
			int superset_index = 0;
			bool superset = false;
			while (superset_index < supersetStatements->size()) {
				RTreeStatementItem *supersetStatement = supersetStatements->at(superset_index);
				superset_index++;
				if (isStatementSupersetOf(leftStatement, supersetStatement)) {
					superset = true;
					break;
				}
			}
			delete leftStatement;
			if (!superset) {
				returnStr = string("proof is well formed but grants insufficient permissions");
				goto errorReturn;
			}
		}
	}
	verify_print("proof grants sufficient permissions\n");

	// Check subject
	if (memcmp(subject, finalsubject->buf, subj_size)) {
		returnStr = string("proof is well formed but subject does not match");
		goto errorReturn;
	}
	verify_print("subjects match\n");
	goto Return;

errorReturn:
	expiry = -1;
Return:
	verify_print(returnStr.c_str());
    asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, finalsubject, ASFM_FREE_EVERYTHING);
    asn_DEF_RTreePolicy.op->free_struct(&asn_DEF_RTreePolicy, policy, ASFM_FREE_EVERYTHING);
	asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, superset_ns, ASFM_FREE_EVERYTHING);
	for (int i = 0; i < pathpolicies->size(); i++) {
        asn_DEF_RTreePolicy.op->free_struct(&asn_DEF_RTreePolicy, pathpolicies->at(i), ASFM_FREE_EVERYTHING);
    }
	delete pathpolicies;
	for (int i = 0; i < supersetStatements->size(); i++) {
		delete supersetStatements->at(i);
	}
	delete supersetStatements;
	return expiry;
}
