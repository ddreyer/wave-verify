#include "verify.h"

const int CapCertification = 1;
const int PermittedCombinedStatements = 1000;

using namespace std;

const string WaveObjectIdentifier("1.3.6.1.4.1.51157");
const string EntityKeyScheme("11");
const string Ed25519Id("1");
const string Curve25519Id("2");
const string OaqueBn256S20AttributesetId("3");
const string OaqueBn256S20ParamsId("4");
const string IbeBn256ParamsId("5");
const string IbeBn256PublicId("6");
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

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

static const string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


string base64_decode(string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string ret;

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
        for (i = 0; i <4; i++)
            char_array_4[i] = base64_chars.find(char_array_4[i]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (i = 0; (i < 3); i++)
            ret += char_array_3[i];
        i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
        char_array_4[j] = 0;

        for (j = 0; j <4; j++)
        char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

string string_to_hex(const std::string& input) {
    static const char* const lut = "0123456789abcdef";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

void verifyError(string errMessage) {
    cerr << errMessage << "\n";
    exit(-1);
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

auto unmarshal(uint8_t *derEncodedData, size_t size, auto decodePtr, asn_TYPE_descriptor_t *asnType) {
    asn_dec_rval_t rval;
    rval = ber_decode(0, asnType, (void **) &decodePtr, derEncodedData, size);
    if (rval.code != RC_OK) {
        // printf("%d %d\n", rval.code == RC_FAIL, rval.consumed);
        // printf("%d\n", rval.code == RC_WMORE);
        asnType->op->free_struct(asnType, decodePtr, ASFM_FREE_EVERYTHING);
        decodePtr = nullptr;
    }
    return decodePtr;
}

/* Following is adapted from https://stackoverflow.com/questions/11075886/encode-xer-to-buffer-with-asn1c
 * except I fixed a bug (sigh) in the callback by adding a return 1;
 */
typedef struct enc_buffer {
    uint8_t *buffer;
    size_t buffer_size;
    size_t buffer_filled;
} enc_buffer_t;

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
        verifyError("Could not find a match for a type id");
    }
}

/* Marshals a given struct and returns encoded string (used for a couple purposes in the program) */
string marshal(void *body, asn_TYPE_descriptor_t *asnType) {
    enc_buffer_t enc_buf;
    init_enc_buffer(&enc_buf);
    encode_to_buffer(&enc_buf, asnType, body);
    string enc((char *) enc_buf.buffer);
    return enc;
}

OCTET_STRING_t * HashSchemeInstanceFor(WaveAttestation_t *att) {
    ANY_t type = att->tbs.subject.encoding.choice.single_ASN1_type;
    string subId = marshal(att->tbs.subject.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (subId == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *attest = 0;
        attest = unmarshal(type.buf, type.size, attest, &asn_DEF_HashKeccak_256);
        if (attest == nullptr) {
            verifyError("problem with hash");
        }
        if (attest->size != 32) {
            verifyError("problem with hash");
        }
        return attest;
    } else if (subId == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *attest = 0;
        attest = unmarshal(type.buf, type.size, attest, &asn_DEF_HashSha3_256);
        if (attest == nullptr) {
            verifyError("problem with hash");
        }
        if (attest->size != 32) {
            verifyError("problem with hash");
        }
        return attest;
    } else {
        verifyError("problem with hash");
    }
}

OCTET_STRING_t * HashSchemeInstanceFor(RTreePolicy_t *policy) {
    ANY_t type = policy->Namespace.encoding.choice.single_ASN1_type;
    string id = marshal(policy->Namespace.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (id == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *hash = 0;
        hash = unmarshal(type.buf, type.size, hash, &asn_DEF_HashKeccak_256);
        if (hash == nullptr) {
            verifyError("problem with hash");
        }
        if (hash->size != 32) {
            verifyError("problem with hash");
        }
        return hash;
    } else if (id == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *hash = 0;
        hash = unmarshal(type.buf, type.size, hash, &asn_DEF_HashSha3_256);
        if (hash == nullptr) {
            verifyError("problem with hash");
        }
        if (hash->size != 32) {
            verifyError("problem with hash");
        }
        return hash;
    } else {
        verifyError("problem with hash");
    }
}

OCTET_STRING_t * HashSchemeInstanceFor(EntityHash_t *pSet) {
    ANY_t type = pSet->encoding.choice.single_ASN1_type;
    string id = marshal(pSet->direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (id == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *hash = 0;
        hash = unmarshal(type.buf, type.size, hash, &asn_DEF_HashKeccak_256);
        if (hash == nullptr) {
            verifyError("problem with hash");
        }
        if (hash->size != 32) {
            verifyError("problem with hash");
        }
        return hash;
    } else if (id == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *hash = 0;
        hash = unmarshal(type.buf, type.size, hash, &asn_DEF_HashSha3_256);
        if (hash == nullptr) {
            verifyError("problem with hash");
        }
        if (hash->size != 32) {
            verifyError("problem with hash");
        }
        return hash;
    } else {
        verifyError("problem with hash");
    }
}

LocationURL_t * LocationSchemeInstanceFor(WaveAttestation_t *att) {
    ANY_t type = att->tbs.subjectLocation.encoding.choice.single_ASN1_type;
    LocationURL_t *lsurl = 0;
    lsurl = unmarshal(type.buf, type.size, lsurl, &asn_DEF_LocationURL);
    if (lsurl == nullptr) {
        verifyError("subject location is unsupported");
    }
    return lsurl;
}

RTreePolicy_t * PolicySchemeInstanceFor(AttestationVerifierBody_t *attVerBody) {
    RTreePolicy_t *policy = 0;
    ANY_t type = attVerBody->policy.encoding.choice.single_ASN1_type;
    string currBodyId = marshal(attVerBody->policy.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (currBodyId == getTypeId(&asn_DEF_TrustLevel)) {
        TrustLevel_t *tp = 0;
        tp = unmarshal(type.buf, type.size, tp, &asn_DEF_TrustLevel);
        verifyError("not supporting trust level policy right now");
    } else if (currBodyId == getTypeId(&asn_DEF_RTreePolicy)) {
        policy = unmarshal(type.buf, type.size, policy, &asn_DEF_RTreePolicy);
        if (policy == nullptr) {
            verifyError("unexpected policy error");
        }
        return policy;
    } else {
        verifyError("unsupported policy scheme");
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
        fout->push_back((*bout)[bout->size()-i-1]);
    }
    stringstream ss;
    for (size_t i = 0; i < fout->size(); ++i) {
        if (i != 0) {
            ss << ",";
        }
        ss << (*fout)[i];
    }
    return ss.str();
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
    for (; fi < fp.size() && bi < bp.size(); fi, bi = fi+1, bi+1) {
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
    for (; fni >= fi && bni >= bi; fni, bni = fni-1, bni-1) {
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
        return false;
    }
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

void computeStatements(vector<RTreeStatementItem> *statements, vector<RTreeStatementItem> *dedup_statements) {
    next:
    for (int orig_idx = 0; orig_idx < statements->size(); orig_idx++) {
        for (int chosen_idx = 0; chosen_idx < dedup_statements->size(); chosen_idx++) {
            if (isStatementSupersetOf(&(*statements)[orig_idx], &(*dedup_statements)[chosen_idx])) {
                goto next;
            }
            if (isStatementSupersetOf(&(*dedup_statements)[chosen_idx], &(*statements)[orig_idx])) {
                dedup_statements[chosen_idx] = statements[orig_idx];
                goto next;
            }
        }
        dedup_statements->push_back((*statements)[orig_idx]);
    }
}

void appendStatements(vector<RTreeStatementItem> *statements, RTreePolicy_t::RTreePolicy__statements *policyStments) {
    int index = 0;
    while (index < policyStments->list.count) {
        RTreeStatement_t *s = policyStments->list.array[index];
        RTreeStatement_t::RTreeStatement__permissions perms = s->permissions;
        int i = 0;
        list<string> permList;
        while (i < perms.list.count) {
            UTF8String_t *str = perms.list.array[i];
            permList.push_back(string((const char *) str->buf, str->size));
            i++;
        }
        string rsource((const char *) s->resource.buf, s->resource.size);
        RTreeStatementItem item(&s->permissionSet, permList, rsource);
        statements->push_back(item);
        index++;
    }
}

int verify(string pemContent) {
    string derEncodedData(base64_decode(pemContent));

    printf("Binary size: %lu\n", derEncodedData.length());
    if (derEncodedData.length() == 0) {
    	verifyError("could not decode proof from DER format");
    }

    WaveWireObject_t *wwoPtr = 0;
    wwoPtr = unmarshal((uint8_t *) (derEncodedData.c_str()), derEncodedData.length(), wwoPtr, &asn_DEF_WaveWireObject);	/* pointer to decoded data */
    if (wwoPtr == nullptr) {
        verifyError("failed to unmarshal");
    }

    WaveExplicitProof_t *exp = 0;
    ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
    exp = unmarshal(type.buf, type.size, exp, &asn_DEF_WaveExplicitProof);	/* pointer to decoded data */
    if (exp == nullptr) {
        verifyError("failed to unmarshal");
    }

    // parse entities
    WaveExplicitProof_t::WaveExplicitProof__entities ents = exp->entities;

    cout << "entities retrieved\n";
    list<EntityItem> entList;
    int entIndex = 0;
    while (entIndex < ents.list.count) {
        OCTET_STRING_t *ent = exp->entities.list.array[entIndex];
        string entStr((const char *) ent->buf, ent->size);
        entIndex++;

        // gofunc: ParseEntity
        WaveWireObject_t *wwoPtr = nullptr;
        wwoPtr = unmarshal(ent->buf, ent->size, wwoPtr, &asn_DEF_WaveWireObject);
        if (exp == nullptr) {
            verifyError("failed to unmarshal");
        }

        WaveEntity_t *entity = 0;
        ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
        entity = unmarshal(type.buf, type.size, entity, &asn_DEF_WaveEntity);	/* pointer to decoded data */
        if (entity == nullptr) {
            // maybe this is an entity secret
            WaveEntitySecret_t *es = 0;
            es = unmarshal(type.buf, type.size, es, &asn_DEF_WaveEntitySecret);
            if (es == nullptr) {
                verifyError("DER is not a wave entity");
            }
            entity = &(es->entity);
        }

        // gofunc: parseEntityFromObject
        // check the signature
        EntityPublicKey_t entKey = entity->tbs.verifyingKey;
        type = entKey.key.encoding.choice.single_ASN1_type;
        string entKeyId = marshal(entKey.key.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);

        if (entKeyId == getTypeId(&asn_DEF_Public_Ed25519)) {
            Public_Ed25519_t *ks = 0;
            ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Ed25519);
            if (ks->size != 32) {
                verifyError("key length is incorrect");
            }

            // gofunc: VerifyCertify
            // gofunc: HasCapability
            if (!HasCapability(entity)) {
                verifyError("this key cannot perform certifications");
            }

            // gofunc: Verify
            // string eData = marshal(&entity->tbs, &asn_DEF_WaveEntityTbs);
            // cout << "len: " << eData.length() << "\n";
            // string entSig((const char *) entity->signature.buf, entity->signature.size);
            // string ksStr((const char *) ks->buf, ks->size);
            // if (!ed25519_verify((const unsigned char *) entSig.c_str(), 
            //     (const unsigned char *) eData.c_str(), eData.length(), 
            //     (const unsigned char *) ksStr.c_str())) {
            //     cerr << "\nsig: " << string_to_hex(entSig);
            //     cerr << "\nkey: " << string_to_hex(ksStr);
            //     cerr << "\ndata: " << string_to_hex(eData) << "\n";
            //     verifyError("entity ed25519 signature invalid");
            // }
            // cout << "valid entity signature\n";
        } else if (entKeyId == getTypeId(&asn_DEF_Public_Curve25519)) {
            Public_Curve25519_t *ks = 0;
            ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Curve25519);
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            if (ks->size != 32) {
                verifyError("key length is incorrect");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Params_BN256_IBE)) {
            Params_BN256_IBE_t *ks = 0;
            ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_IBE);
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Public_BN256_IBE)) {
            Public_BN256_IBE_t *ks = 0;
            ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_BN256_IBE);
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Params_BN256_IBE)) {
            Params_BN256_OAQUE_t *ks = 0;
            ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_OAQUE);
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Public_OAQUE)) {
            Public_OAQUE_t *ks = 0;
            ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_OAQUE);
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else {
            verifyError("entity uses unsupported key scheme");
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
            if (lkeyId == getTypeId(&asn_DEF_Public_Ed25519)) {
                Public_Ed25519_t *ks = 0;
                ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Ed25519);
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
                if (ks->size != 32) {
                    verifyError("key length is incorrect");
                }
            } else if (lkeyId == getTypeId(&asn_DEF_Public_Curve25519)) {
                Public_Curve25519_t *ks = 0;
                ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Curve25519);
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
                if (ks->size != 32) {
                    verifyError("key length is incorrect");
                }
            } else if (lkeyId == getTypeId(&asn_DEF_Params_BN256_IBE)) {
                Params_BN256_IBE_t *ks = 0;
                ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_IBE);
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else if (lkeyId == getTypeId(&asn_DEF_Public_BN256_IBE)) {
                Public_BN256_IBE_t *ks = 0;
                ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_BN256_IBE);
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else if (lkeyId == getTypeId(&asn_DEF_Params_BN256_OAQUE)) {
                Params_BN256_OAQUE_t *ks = 0;
                ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_OAQUE);
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else if (lkeyId == getTypeId(&asn_DEF_Public_OAQUE)) {
                Public_OAQUE_t *ks = 0;
                ks = unmarshal(type.buf, type.size, ks, &asn_DEF_Public_OAQUE);
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else {
                verifyError("tbs key uses unsupported key scheme");
            }
        }
        EntityItem e(entity, entStr);
        entList.push_back(e);
    }

    // retrieve attestations
    WaveExplicitProof_t::WaveExplicitProof__attestations atsts = exp->attestations;
    cout << "attestations retrieved\n";
    vector<AttestationItem> attestationList;
    int attIndex = 0;
    while (attIndex < atsts.list.count) {
        AttestationReference_t *atst = atsts.list.array[attIndex];
        attIndex++;

        AttestationReference_t::AttestationReference__keys keys = atst->keys;
        char *vfk;
        string verifierBodyKey;
        string verifierBodyNonce;
        int vfkLen = 0;
        if (keys.list.count == 0) {
            cout << "atst has no keys\n";
        }

        int keyIndex = 0;
        while (keyIndex < keys.list.count) {
            /* casting is needed due to some weirdness with the asn1c compiler
             * https://github.com/vlm/asn1c/issues/296
             */
            AttestationVerifierKey_t *key = (AttestationVerifierKey_t *) keys.list.array[keyIndex];
            ANY_t type = key->encoding.choice.single_ASN1_type;
            AVKeyAES128_GCM_t *vfk = 0;
            vfk = unmarshal(type.buf, type.size, vfk, &asn_DEF_AVKeyAES128_GCM);
            int vfkLen = 0;
            if (vfk == nullptr) {
                cout << "atst key was not aes\n";
            } else {
                vfkLen = vfk->size;
                string verifierKey(vfk->buf, vfk->buf + vfkLen);
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
        wwoPtr = unmarshal(derEncodedData->buf, derEncodedData->size, wwoPtr, &asn_DEF_WaveWireObject);
        if (wwoPtr == nullptr) {
            verifyError("failed to unmarshal atst content");
        }
        WaveAttestation_t *att = 0;
        ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
        att = unmarshal(type.buf, type.size, att, &asn_DEF_WaveAttestation);	/* pointer to decoded data */
        if (att == nullptr) {
            verifyError("failed to unmarshal into Wave Attestation");
        }

        // gofunc: DecryptBody
        AttestationVerifierBody_t *decryptedBody;
        string schemeID = marshal(att->tbs.body.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
        if (schemeID == getTypeId(&asn_DEF_AttestationBody)) {
            cout << "unencrypted body scheme, currently not supported\n";
        } else if (schemeID == getTypeId(&asn_DEF_WR1BodyCiphertext)) {
            cout << "this is a wr1 body scheme\n";
            // decrypt body
            type = att->tbs.body.encoding.choice.single_ASN1_type;
            WR1BodyCiphertext_t *wr1body = 0;
            wr1body = unmarshal(type.buf, type.size, wr1body, &asn_DEF_WR1BodyCiphertext);
            if (wr1body == nullptr) {
                verifyError("getting body ciphertext failed");
            }
            cout << "got wr1 body\n";
            // checking subject HI instance
            HashSchemeInstanceFor(att);

            if (vfk) {
                cout << "decrypting attestation\n";
                mbedtls_gcm_context ctx;
                mbedtls_gcm_init( &ctx );
                int ret = 0;
                ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, 
                    (const unsigned char *) verifierBodyKey.c_str(), verifierBodyKey.length()*8);
                if (ret) {
                    verifyError("aes set key failed");
                }
        
                OCTET_STRING_t vbodyCipher = wr1body->verifierBodyCiphertext;
                const unsigned char additional[] = {};
                int bodyLen = vbodyCipher.size;
                unsigned char verifierBodyDER[bodyLen];
                unsigned char tag_buf[16];
                
                string s((const char *) vbodyCipher.buf, bodyLen);
                string t(verifierBodyNonce.c_str(), 12);
                ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, bodyLen, (const unsigned char *) verifierBodyNonce.c_str(), 
                    verifierBodyNonce.length(), additional, 0, (const unsigned char *) s.c_str(), verifierBodyDER, 16, tag_buf);
                if (ret) {
                    cerr << "ciphertext:\n" << string_to_hex(s) << "\n\n";
                    cerr << "nonce:\n" << string_to_hex(t) << "\n\n";
                    cerr << "key:\n" << string_to_hex(verifierBodyKey) << "\n";
                    verifyError("aes decryption failed");
                } else {
                    unsigned char *hah = verifierBodyDER;
                    string v((const char *)hah, bodyLen-16);
                    cout << "aes decryption succeeded\n";
                }
                mbedtls_gcm_free(&ctx);

                //unmarshal into WR1VerifierBody
                WR1VerifierBody_t *vbody = 0;
                vbody = unmarshal((uint8_t *) verifierBodyDER, bodyLen-16, vbody, &asn_DEF_WR1VerifierBody);
                if (vbody == nullptr) {
                    verifyError("could not unmarshal into WR1VerifierBody");
                }        
                decryptedBody = &vbody->attestationVerifierBody;
            }
        } else {
            verifyError("unsupported body scheme");
        }

        LocationURL_t *attesterLoc = 0;
        type = decryptedBody->attesterLocation.encoding.choice.single_ASN1_type;
        attesterLoc = unmarshal(type.buf, type.size, attesterLoc, &asn_DEF_LocationURL);
        if (attesterLoc == nullptr) {
            verifyError("could not get attester loc");
        }

        WaveEntity_t *attester = 0;
        string attestId = marshal(decryptedBody->attester.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
        type = decryptedBody->attester.encoding.choice.single_ASN1_type;
        // gofunc: EntityByHashLoc
        if (attestId == getTypeId(&asn_DEF_HashKeccak_256)) {
            HashKeccak_256_t *attesterHash = 0;
            attesterHash = unmarshal(type.buf, type.size, attesterHash, &asn_DEF_HashKeccak_256);
            if (attesterHash == nullptr) {
                verifyError("could not get attester hash");
            }
            if (attesterHash->size != 32) {
                verifyError("attester hash not valid");
            }
            // convert attestation hash to hex
            string attesterHashStr((const char *) attesterHash->buf, attesterHash->size);
            string attHashHex = string_to_hex(attesterHashStr);
            // loop through entities
            for (list<EntityItem>::iterator it=entList.begin(); it != entList.end(); ++it) {
                Keccak k(Keccak::Keccak256);
                string entityHash = k(it->get_der());
                cout << "\natt hash: " << attHashHex;
                cout << "\nentity hash: " << entityHash;
                if (attHashHex == entityHash) {
                    cout << "\nfound matching entity for attester\n";
                    attester = it->get_entity();
                    break;
                }
            }
        } else if (attestId == getTypeId(&asn_DEF_HashSha3_256)) {
            HashSha3_256_t *attesterHash = 0;
            attesterHash = unmarshal(type.buf, type.size, attesterHash, &asn_DEF_HashSha3_256);
            if (attesterHash == nullptr) {
                verifyError("could not get attester hash");
            }
            if (attesterHash->size != 32) {
                verifyError("attester hash not valid");
            }
        } else {
            verifyError("unsupported attester hash scheme id");
        }

        SignedOuterKey_t *binding = 0;
        type = decryptedBody->outerSignatureBinding.encoding.choice.single_ASN1_type;
        binding = unmarshal(type.buf, type.size, binding, &asn_DEF_SignedOuterKey);
        if (binding == nullptr) {
            verifyError("outer signature binding not supported/this is not really a signed outer key");
        }

        // gofunc: VerifyBinding
        // At this time we only know how to extract the key from an ed25519 outer signature
        Ed25519OuterSignature_t *osig = 0;
        type = att->outerSignature.encoding.choice.single_ASN1_type;
        osig = unmarshal(type.buf, type.size, osig, &asn_DEF_Ed25519OuterSignature);
        if (osig == nullptr) {
            verifyError("unknown outer signature type/signature scheme not supported");
        }

        if (attester == nullptr) {
            verifyError("no attester");
        }

        // gofunc: VerifyCertify
        // gofunc: HasCapability
        if (!HasCapability(attester)) {
            verifyError("this key cannot perform certifications");
        }

        // gofunc: Verify
        string encodedData = marshal(&binding->tbs, &asn_DEF_SignedOuterKeyTbs);

        Public_Ed25519_t *attesterKey = 0;
        type = attester->tbs.verifyingKey.key.encoding.choice.single_ASN1_type;
        attesterKey = unmarshal(type.buf, type.size, attesterKey, &asn_DEF_Public_Ed25519);
        string bindingSig((const char *) binding->signature.buf, binding->signature.size);
        string attKey((const char *) attesterKey->buf, attesterKey->size);
        if (!ed25519_verify((const unsigned char *) bindingSig.c_str(), 
            (const unsigned char *) encodedData.c_str(), encodedData.length(), 
            (const unsigned char *) attKey.c_str())) {
            cerr << "signature: " << string_to_hex(bindingSig);
            cerr << "\nkey: " << string_to_hex(attKey) << "\n";
            verifyError("outer signature binding invalid");
        }
        cout << "valid outer signature binding\n";

        // Now we know the binding is valid, check the key is the same
        if (marshal(&binding->tbs.outerSignatureScheme, &asn_DEF_OBJECT_IDENTIFIER) 
            != getTypeId(&asn_DEF_Ed25519OuterSignature)) {
            verifyError("outer signature scheme invalid");
        }

        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, &binding->tbs.verifyingKey, &osig->verifyingKey)) {
            verifyError("bound key does not match");
        }
        // check signature
        // gofunc: VerifySignature
        string encData = marshal(&att->tbs, &asn_DEF_WaveAttestationTbs);

        OCTET_STRING_t vKey = osig->verifyingKey;
        OCTET_STRING_t sig = osig->signature;
        string s((const char *) sig.buf, sig.size);
        string v((const char *) vKey.buf, vKey.size);
        /* verify the signature */
        // if (!ed25519_verify((const unsigned char *) s.c_str(), 
        //         (const unsigned char *) encData.c_str(), encData.length(), 
        //         (const unsigned char *) v.c_str())) {
        //     verifyError("invalid outer signature");
        // }
        // cout << "valid outer signature\n";
        AttestationItem aItem(att, decryptedBody);
        attestationList.push_back(aItem);
    }

    cout << "Finished parsing attestations\n";

    // now verify the paths
    vector<RTreePolicy_t *> pathpolicies;
    vector<OCTET_STRING_t *> pathEndEntities;
    WaveExplicitProof_t::WaveExplicitProof__paths paths = exp->paths;
    cout << "paths retrieved\n";
    int pathIndex = 0;
    while (pathIndex < paths.list.count) {
        WaveExplicitProof__paths__Member *p = paths.list.array[pathIndex];
        pathIndex++;
        int pIndex = 0;
        // len(path) == 0
        if (p->list.count == 0) {
            verifyError("path of length 0");
        }
        // path[0]
        long *pathNum = p->list.array[pIndex];
        pIndex++;
        try {
            attestationList.at(*pathNum); 
        } catch (...) {
            verifyError("proof refers to non-included attestation");
        }

        AttestationItem currAttItem = attestationList.at(*pathNum);
        WaveAttestation_t *currAtt = currAttItem.get_att();
        // gofunc: Subject
        // gofunc: HashSchemeInstanceFor
        OCTET_STRING_t *cursubj = HashSchemeInstanceFor(currAtt);

        // gofunc: LocationSchemeInstanceFor
        LocationURL_t *cursubloc = LocationSchemeInstanceFor(currAtt);

        // gofunc: PolicySchemeInstanceFor
        AttestationVerifierBody_t *currBody = currAttItem.get_body();
        RTreePolicy_t *policy = PolicySchemeInstanceFor(currBody);

        while (pIndex < p->list.count) {
            pathNum = p->list.array[pIndex];
            pIndex++;
            try {
                attestationList.at(*pathNum); 
            } catch (...) {
                verifyError("proof refers to non-included attestation");
            }

            AttestationItem nextAttItem = attestationList.at(*pathNum);
            WaveAttestation_t *nextAtt = currAttItem.get_att();
            // gofunc: HashSchemeInstanceFor
            OCTET_STRING_t *nextAttest = HashSchemeInstanceFor(nextAtt);

            // gofunc: LocationSchemeInstanceFor
            LocationURL_t *nextAttLoc = LocationSchemeInstanceFor(nextAtt);

            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, cursubj, nextAttest)) {
                verifyError("path has broken links");
            }

            // gofunc: PolicySchemeInstanceFor
            AttestationVerifierBody_t *nextBody = nextAttItem.get_body();
            RTreePolicy_t *nextPolicy = PolicySchemeInstanceFor(nextBody);

            // gofunc: Intersect
            OCTET_STRING_t *rhs_ns = HashSchemeInstanceFor(nextPolicy);
            OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(policy);
            // // not doing multihash
            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, rhs_ns, lhs_ns)) {
                verifyError("different authority domain");
            }
            // gofunc: intersectStatement
            vector<RTreeStatementItem> statements;
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
                        continue;
                    }

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
                        RTreeStatementItem item(&leftStatement->permissionSet, intersectionPerms, intersectionResource);
                        statements.push_back(item);
                    }
                }   
            }

            vector<RTreeStatementItem> dedup_statements;
            computeStatements(&statements, &dedup_statements);
            int indirections;
            if (policy->indirections < nextPolicy->indirections) {
                indirections = policy->indirections - 1;
            } else {
                indirections = nextPolicy->indirections - 1;
            }

            // Check errors
            if (indirections < 0) {
                verifyError("insufficient permitted indirections");
            }
            if (dedup_statements.size() > PermittedCombinedStatements) {
                verifyError("statements form too many combinations");
            }
            cursubj = nextAttest;
            LocationURL_t *cursubloc = nextAttLoc;
        }
        pathpolicies.push_back(policy);
        pathEndEntities.push_back(cursubj);
        LocationURL_t *subjectLocation = cursubloc;
    }

    // Now combine the policies together
    cout << "paths verified, now combining the policies\n";
    RTreePolicy_t *aggregatepolicy = pathpolicies[0];
    OCTET_STRING_t *finalsubject = pathEndEntities[0];
    vector<RTreePolicy_t *> v(pathpolicies.begin()+1, pathpolicies.end());
    for (int idx = 0; idx < pathpolicies.size(); idx++) {
        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, finalsubject, pathEndEntities[idx])) {
            verifyError("paths don't terminate at same entity");
        }
        // gofunc: Union
        OCTET_STRING_t *rhs_ns = HashSchemeInstanceFor(pathpolicies[idx]);
        OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(aggregatepolicy);
        // not doing multihash
        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, rhs_ns, lhs_ns)) {
            verifyError("different authority domain");
        }
        vector<RTreeStatementItem> statements;
        RTreePolicy_t::RTreePolicy__statements *lhsStatements = &aggregatepolicy->statements;
        appendStatements(&statements, lhsStatements);
        RTreePolicy_t::RTreePolicy__statements *rhsStatements = &pathpolicies[idx]->statements;
        appendStatements(&statements, rhsStatements);
        vector<RTreeStatementItem> dedup_statements;
        computeStatements(&statements, &dedup_statements);
        int indirections;
        if (pathpolicies[idx]->indirections < aggregatepolicy->indirections) {
            indirections = pathpolicies[idx]->indirections;
        }
        if (dedup_statements.size() > PermittedCombinedStatements) {
            verifyError("statements form too many combinations");
        }
    }
    return 0;
}
