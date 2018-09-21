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

EntityItem::EntityItem(WaveEntity *ent, string entDer) {
    entity = ent;
    entityDer = entDer;
}

WaveEntity * EntityItem::get_entity() {
    return entity;
}

string EntityItem::get_der() {
    return entityDer;
}

AttestationItem::AttestationItem(WaveAttestation *att, AttestationVerifierBody dBody) {
    attestation = att;
    decryptedBody = dBody;
}

WaveAttestation * AttestationItem::get_att() {
    return attestation;
}
    
AttestationVerifierBody AttestationItem::get_body() {
    return decryptedBody;
}

// RTreeStatementItem::RTreeStatementItem(RTreeStatement::permissionSet pSet, list<string> perms, string iResource) {
//     permissionSet = pSet;
//     permissions = perms;
//     intersectionResource = iResource;
// }

// RTreeStatement::permissionSet RTreeStatementItem::get_permissionSet() {
//     return permissionSet;
// }

// list<string> RTreeStatementItem::get_permissions() {
//     return permissions;
// }

// string RTreeStatementItem::get_interResource() {
//     return intersectionResource;
// }

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

// string HashSchemeInstanceFor(RTreePolicy policy) {
//     OssEncOID id = policy.get_RTreePolicy_namespace().get_type_id();
//     if (id == keccak_256_id) {
//         HashKeccak_256 *hash = policy.get_RTreePolicy_namespace().get_value().get_HashKeccak_256();
//         if (hash == nullptr) {
//             verifyError("problem with hash");
//         }
//         if (hash->length() != 32) {
//             verifyError("problem with hash");
//         }
//         return string(hash->get_buffer(), hash->length());
//     } else if (id == sha3_256_id) {
//         HashSha3_256 *hash = policy.get_RTreePolicy_namespace().get_value().get_HashSha3_256();
//         if (hash == nullptr) {
//             verifyError("problem with hash");
//         }
//         if (hash->length() != 32) {
//             verifyError("problem with hash");
//         }
//         return string(hash->get_buffer(), hash->length());
//     } else {
//         verifyError("problem with hash");
//     }
// }

// string HashSchemeInstanceFor(RTreeStatement::permissionSet pSet) {
//     OssEncOID id = pSet.get_type_id();
//     if (id == keccak_256_id) {
//         HashKeccak_256 *hash = pSet.get_value().get_HashKeccak_256();
//         if (hash == nullptr) {
//             verifyError("problem with hash");
//         }
//         if (hash->length() != 32) {
//             verifyError("problem with hash");
//         }
//         return string(hash->get_buffer(), hash->length());
//     } else if (id == sha3_256_id) {
//         HashSha3_256 *hash = pSet.get_value().get_HashSha3_256();
//         if (hash == nullptr) {
//             verifyError("problem with hash");
//         }
//         if (hash->length() != 32) {
//             verifyError("problem with hash");
//         }
//         return string(hash->get_buffer(), hash->length());
//     } else {
//         verifyError("problem with hash");
//     }
// }

LocationURL_t * LocationSchemeInstanceFor(WaveAttestation_t *att) {
    ANY_t type = att->tbs.subject.encoding.choice.single_ASN1_type;
    LocationURL_t *lsurl = 0;
    lsurl = unmarshal(type.buf, type.size, lsurl, &asn_DEF_LocationURL);
    if (lsurl == nullptr) {
        verifyError("subject location is unsupported");
    }
    return lsurl;
}

// vector<string> split(string s, string delimiter) {
//     size_t pos = 0;
//     string token;
//     vector<string> splitStr;
//     while ((pos = s.find(delimiter)) != string::npos) {
//         token = s.substr(0, pos);
//         splitStr.push_back(token);
//         s.erase(0, pos + delimiter.length());
//     }
//     splitStr.push_back(s);
//     return splitStr;
// }

// string emit(vector<string> *bout, vector<string> *fout) {
//     for (int i = 0; i < bout->size(); i++) {
//         fout->push_back((*bout)[bout->size()-i-1]);
//     }
//     stringstream ss;
//     for (size_t i = 0; i < fout->size(); ++i) {
//         if (i != 0) {
//             ss << ",";
//         }
//         ss << (*fout)[i];
//     }
//     return ss.str();
// }

// string RestrictBy(string from, string by) {
//     vector<string> fp = split(from, "/");
//     vector<string> bp = split(by, "/");
//     vector<string> fout;
//     vector<string> bout;
//     string intersectionResource;
//     // phase 1: emit matching prefix
//     int fi = 0, bi = 0;
//     int fni = fp.size() - 1, bni = bp.size() - 1;
//     for (; fi < fp.size() && bi < bp.size(); fi, bi = fi+1, bi+1) {
//         if (fp[fi] != "*" && (fp[fi] == bp[bi] || (bp[bi] == "+" && fp[fi] != "*"))) {
//             fout.push_back(fp[fi]);
//         } else if (fp[fi] == "+" && bp[bi] != "*") {
//             fout.push_back(bp[bi]);
//         } else {
//             break;
//         }
//     }
//     //phase 2
//     //emit matching suffix
//     for (; fni >= fi && bni >= bi; fni, bni = fni-1, bni-1) {
//         if (bp[bni] != "*" && (fp[fni] == bp[bni] || (bp[bni] == "+" && fp[fni] != "*"))) {
//             bout.push_back(fp[fni]);
//         } else if (fp[fni] == "+" && bp[bni] != "*") {
//             bout.push_back(bp[bni]);
//         } else {
//             break;
//         }
//     }
//     //phase 3
//     //emit front
//     if (fi < fp.size() && fp[fi] == "*") {
//         for (; bi < bp.size() && bp[bi] != "*" && bi <= bni; bi++) {
//             fout.push_back(bp[bi]);
//         }
//     } else if (bi < bp.size() && bp[bi] == "*") {
//         for (; fi < fp.size() && fp[fi] != "*" && fi <= fni; fi++) {
//             fout.push_back(fp[fi]);
//         }
//     }
//     //phase 4
//     //emit back
//     if (fni >= 0 && fp[fni] == "*") {
//         for (; bni >= 0 && bp[bni] != "*" && bni >= bi; bni--) {
//             bout.push_back(bp[bni]);
//         }
//     } else if (bni >= 0 && bp[bni] == "*") {
//         for (; fni >= 0 && fp[fni] != "*" && fni >= fi; fni--) {
//             bout.push_back(fp[fni]);
//         }
//     }
//     //phase 5
//     //emit star if they both have it
//     if (fi == fni && fp[fi] == "*" && bi == bni && bp[bi] == "*") {
//         fout.push_back("*");
//         intersectionResource = emit(&bout, &fout);
//     }
//     //Remove any stars
//     if (fi < fp.size() && fp[fi] == "*") {
//         fi++;
//     }
//     if (bi < bp.size() && bp[bi] == "*") {
//         bi++;
//     }
//     if ((fi == fni+1 || fi == fp.size()) && (bi == bni+1 || bi == bp.size())) {
//         intersectionResource = emit(&bout, &fout);
//     }
//     return intersectionResource;
// }

// bool isStatementSupersetOf(RTreeStatementItem *subset, RTreeStatementItem *superset) {
//     string lhs_ps = HashSchemeInstanceFor(subset->get_permissionSet());
//     string rhs_ps = HashSchemeInstanceFor(superset->get_permissionSet());
//     if (lhs_ps.compare(rhs_ps) != 0) {
//         return false;
//     }
//     unordered_map<string, bool> superset_perms;
//     for (auto perm : superset->get_permissions()) {
//         superset_perms[perm] = true;
//     }
//     for (auto perm : subset->get_permissions()) {
//         if (!superset_perms[perm]) {
//             return false;
//         }
//     }
//     // gofunc: RestrictBy
//     string inter_uri = RestrictBy(subset->get_interResource(), superset->get_interResource());
//     if (inter_uri.empty()) {
//         return false;
//     }
//     return !inter_uri.compare(subset->get_interResource());
// }

// void computeStatements(vector<RTreeStatementItem> *statements, vector<RTreeStatementItem> *dedup_statements) {
//     next:
//     for (int orig_idx = 0; orig_idx < statements->size(); orig_idx++) {
//         for (int chosen_idx = 0; chosen_idx < dedup_statements->size(); chosen_idx++) {
//             if (isStatementSupersetOf(&(*statements)[orig_idx], &(*dedup_statements)[chosen_idx])) {
//                 goto next;
//             }
//             if (isStatementSupersetOf(&(*dedup_statements)[chosen_idx], &(*statements)[orig_idx])) {
//                 dedup_statements[chosen_idx] = statements[orig_idx];
//                 goto next;
//             }
//         }
//         dedup_statements->push_back((*statements)[orig_idx]);
//     }
// }

// void appendStatements(vector<RTreeStatementItem> *statements, RTreePolicy::statements *policyStments) {
//     OssIndex index = policyStments->first();
//     while (index != OSS_NOINDEX) {
//         RTreeStatement *s = policyStments->at(index);
//         RTreeStatement::permissions perms = s->get_permissions();
//         OssIndex i = perms.first();
//         list<string> permList;
//         while (i != OSS_NOINDEX) {
//             OssString *str = perms.at(i);
//             permList.push_back(string(str->get_buffer(), str->length()));
//             i = perms.next(i);
//         }
//         string rsource(s->get_resource().get_buffer(), s->get_resource().length());
//         RTreeStatementItem item(s->get_permissionSet(), permList, rsource);
//         statements->push_back(item);
//         index = policyStments->next(index);
//     }
// }

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

    // investigate asn_check_constraint segfault

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
                cout << "got atst key of length " << vfkLen << "\n";
                string verifierKey(vfk->buf, vfk->buf + vfkLen);
                verifierBodyKey = verifierKey.substr(0, 16);
                verifierBodyNonce = verifierKey.substr(16, verifierKey.length());
                cout << "key:\n" << string_to_hex(verifierBodyKey) << "\n";
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
            WR1BodyCiphertext *wr1body = 0;
            wr1body = unmarshal(type.buf, type.size, wr1body, &asn_DEF_WR1BodyCiphertext);
            if (wr1body == nullptr) {
                verifyError("getting body ciphertext failed");
            }
            cout << "got wr1 body\n";
            // checking subject HI instance
            HashSchemeInstanceFor(att);

            // if (vfk) {
            //     cout << "decrypting attestation\n";
            //     mbedtls_gcm_context ctx;
            //     mbedtls_gcm_init( &ctx );
            //     int ret = 0;
            //     ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, 
            //         (const unsigned char *) verifierBodyKey.c_str(), verifierBodyKey.length()*8);
            //     if (ret) {
            //         verifyError("aes set key failed");
            //     }
        
//                 WR1BodyCiphertext::verifierBodyCiphertext vbodyCipher = wr1body->get_verifierBodyCiphertext();
//                 const unsigned char additional[] = {};
//                 int bodyLen = vbodyCipher.length();
//                 unsigned char verifierBodyDER[bodyLen];
//                 unsigned char tag_buf[16];
                
//                 cout << "key:\n" << string_to_hex(verifierBodyKey) << "\n";
//                 char *temp = vbodyCipher.get_buffer();
//                 string s(temp, bodyLen);
//                 string t(verifierBodyNonce.c_str(), 12);
//                 cout << "ciphertext:\n" << string_to_hex(s) << "\n\n";
//                 cout << "nonce:\n" << string_to_hex(t) << "\n\n";
//                 ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, bodyLen, (const unsigned char *) verifierBodyNonce.c_str(), 
//                     verifierBodyNonce.length(), additional, 0, (const unsigned char *) s.c_str(), verifierBodyDER, 16, tag_buf);
//                 if (ret) {
//                     verifyError("aes decrypt failed");
//                 } else {
//                     unsigned char *hah = verifierBodyDER;
//                     string v((const char *)hah, bodyLen-16);
//                     cout << "object:\n" << string_to_hex(v) << "\n\n";
//                     cout << "decryption succeeded\n";
//                 }
//                 mbedtls_gcm_free(&ctx);

//                 //unmarshal into WR1VerifierBody
//                 char *vBodyPtr = (char *) verifierBodyDER;
//                 WR1VerifierBody *vbody = nullptr;
//                 WR1VerifierBody_PDU pdu;
//                 vbody = unmarshal(string(vBodyPtr, bodyLen-16), vbody, pdu);
        
//                 decryptedBody = vbody->get_attestationVerifierBody();
//                 delete vbody;
            // }
        } else {
            verifyError("unsupported body scheme");
        }

//         LocationURL *attesterLoc = 
//             decryptedBody.get_attesterLocation().get_value().get_LocationURL();
//         if (attesterLoc == nullptr) {
//             verifyError("could not get attester loc");
//         }

//         OssEncOID attestId = decryptedBody.get_attester().get_type_id();
//         WaveEntity *attester = nullptr;
//         // gofunc: EntityByHashLoc
//         if (attestId == keccak_256_id) {
//             HashKeccak_256 *attesterHash = decryptedBody.get_attester().get_value().get_HashKeccak_256();
//             if (attesterHash == nullptr) {
//                 verifyError("could not get attester hash");
//             }
//             if (attesterHash->length() != 32) {
//                 verifyError("attester hash not valid");
//             }
//             // convert attestation hash to hex
//             string attesterHashStr(attesterHash->get_buffer(), attesterHash->length());
//             string attHashHex = string_to_hex(attesterHashStr);
//             // loop through entities
//             for (list<EntityItem>::iterator it=entList.begin(); it != entList.end(); ++it) {
//                 Keccak k(Keccak::Keccak256);
//                 string entityHash = k(it->get_der());
//                 cout << "\natt hash: " << attHashHex;
//                 cout << "\nentity hash: " << entityHash;
//                 if (strcmp(attHashHex.c_str(), entityHash.c_str()) == 0) {
//                     cout << "\nfound matching entity for attester\n";
//                     attester = it->get_entity();
//                     break;
//                 }
//             }
//         } else if (attestId == sha3_256_id) {
//             HashSha3_256 *attesterHash = decryptedBody.get_attester().get_value().get_HashSha3_256();
//             if (attesterHash == nullptr) {
//                 verifyError("could not get attester hash");
//             }
//             if (attesterHash->length() != 32) {
//                 verifyError("attester hash not valid");
//             }
//         } else {
//             verifyError("unsupported attester hash scheme id");
//         }

//         SignedOuterKey *_ = decryptedBody.get_outerSignatureBinding().get_value().get_SignedOuterKey();
//         if (_ == nullptr) {
//             verifyError("outer signature binding not supported");
//         }
//         // gofunc: VerifyBinding
//         // At this time we only know how to extract the key from an ed25519 outer signature
//         Ed25519OuterSignature *osig = att->get_outerSignature().get_value().get_Ed25519OuterSignature();
//         if (osig == nullptr) {
//             verifyError("unknown outer signature type/signature scheme not supported");
//         }

//         SignedOuterKey *binding = 
//             decryptedBody.get_outerSignatureBinding().get_value().get_SignedOuterKey();
//         if (binding == nullptr) {
//             verifyError("this is not really a signed outer key");
//             return -1;
//         }

//         if (attester == nullptr) {
//             verifyError("no attester");
//         }

//         // gofunc: VerifyCertify
//         // gofunc: HasCapability
//         if (!HasCapability(attester)) {
//             verifyError("this key cannot perform certifications");
//         }

//         // gofunc: Verify
//         SignedOuterKeyTbs_PDU keypdu;		/* coding container for binding TBS value */
//         string encodedData = marshal(binding->get_tbs(), keypdu);

//         Public_Ed25519 *attesterKey = 
//             attester->get_tbs().get_verifyingKey().get_key().get_value().get_Public_Ed25519();
//         string bindingSig(binding->get_signature().get_buffer(), binding->get_signature().length());
//         string attKey(attesterKey->get_buffer(), attesterKey->length());
//         if (!ed25519_verify((const unsigned char *) bindingSig.c_str(), 
//             (const unsigned char *) encodedData.c_str(), encodedData.length(), 
//             (const unsigned char *) attKey.c_str())) {
//             cerr << "signature: " << string_to_hex(bindingSig);
//             cerr << "\nkey: " << string_to_hex(attKey) << "\n";
//             verifyError("outer signature binding invalid");
//         }
//         cout << "valid outer signature binding\n";

//         // Now we know the binding is valid, check the key is the same
//         if (binding->get_tbs().get_outerSignatureScheme() != ephemeral_ed25519) {
//             verifyError("outer signature scheme invalid");
//         }

//         if (binding->get_tbs().get_verifyingKey() != osig->get_verifyingKey()) {
//             verifyError("bound key does not match");
//         }
//         // check signature
//         // gofunc: VerifySignature
//         WaveAttestationTbs_PDU apdu;
//         string encData = marshal(att->get_tbs(), apdu);

//         Ed25519OuterSignature::verifyingKey vKey = osig->get_verifyingKey();
//         Ed25519OuterSignature::signature sig = osig->get_signature();
//         string s(sig.get_buffer(), sig.length());
//         string v(vKey.get_buffer(), vKey.length());
//         /* verify the signature */
//         if (!ed25519_verify((const unsigned char *) s.c_str(), 
//                 (const unsigned char *) encData.c_str(), encData.length(), 
//                 (const unsigned char *) v.c_str())) {
//             verifyError("invalid outer signature");
//         }
//         cout << "valid outer signature\n";
//         AttestationItem aItem(att, decryptedBody);
//         attestationList.push_back(aItem);
    }

//     cout << "Finished parsing attestations\n";

//     // now verify the paths
//     vector<RTreePolicy> pathpolicies;
//     vector<OssString *> pathEndEntities;
//     WaveExplicitProof::paths paths = exp->get_paths();
//     delete wwoPtr;
//     cout << "paths retrieved\n";
//     OssIndex pathIndex = paths.first();
//     while (pathIndex != OSS_NOINDEX) {
//         WaveExplicitProof::paths::component *p = paths.at(pathIndex);
//         pathIndex = paths.next(pathIndex);
//         OssIndex pIndex = p->first();
//         // len(path) == 0
//         if (pIndex == OSS_NOINDEX) {
//             verifyError("path of length 0");
//         }
//         // path[0]
//         int *pathNum = p->at(pIndex);
//         pIndex = p->next(pIndex);
//         try {
//             attestationList.at(*pathNum); 
//         } catch (...) {
//             verifyError("proof refers to non-included attestation");
//         }

//         AttestationItem currAttItem = attestationList.at(*pathNum);
//         WaveAttestation *currAtt = currAttItem.get_att();
//         // gofunc: Subject
//         OssEncOID subId = currAtt->get_tbs().get_subject().get_type_id();
//         // gofunc: HashSchemeInstanceFor
//         OssString *cursubj = HashSchemeInstanceFor(currAtt);

//         // gofunc: LocationSchemeInstanceFor
//         LocationURL *cursubloc = LocationSchemeInstanceFor(currAtt);

//         // gofunc: PolicySchemeInstanceFor
//         AttestationVerifierBody currBody = currAttItem.get_body();
//         RTreePolicy *policy;
//         if (currBody.get_policy().get_type_id() == trust_level) {
//             TrustLevel *tp = currBody.get_policy().get_value().get_TrustLevel();
//             verifyError("not supporting trust level policy right now");
//         } else if (currBody.get_policy().get_type_id() == resource_tree) {
//             policy = currBody.get_policy().get_value().get_RTreePolicy();
//             if (policy == nullptr) {
//                 verifyError("unexpected policy error");
//             }
//         } else {
//             verifyError("unsupported policy scheme");
//         }

//         while (pIndex != OSS_NOINDEX) {
//             pathNum = p->at(pIndex);
//             pIndex = p->next(pIndex);
//             try {
//                 attestationList.at(*pathNum); 
//             } catch (...) {
//                 verifyError("proof refers to non-included attestation");
//             }

//             AttestationItem nextAttItem = attestationList.at(*pathNum);
//             WaveAttestation *nextAtt = currAttItem.get_att();
//             // gofunc: HashSchemeInstanceFor
//             OssString *nextAttest = HashSchemeInstanceFor(nextAtt);

//             // gofunc: LocationSchemeInstanceFor
//             LocationURL *nextAttLoc = LocationSchemeInstanceFor(nextAtt);

//             if (memcmp(cursubj->get_buffer(), nextAttest->get_buffer(), cursubj->length())) {
//                 verifyError("path has broken links");
//             }

//             // gofunc: PolicySchemeInstanceFor
//             AttestationVerifierBody nextBody = nextAttItem.get_body();
//             RTreePolicy *nextPolicy;
//             if (nextBody.get_policy().get_type_id() == trust_level) {
//                 TrustLevel *tp = nextBody.get_policy().get_value().get_TrustLevel();
//                 verifyError("not supporting trust level policy right now");
//             } else if (nextBody.get_policy().get_type_id() == resource_tree) {
//                 nextPolicy = nextBody.get_policy().get_value().get_RTreePolicy();
//                 if (nextPolicy == nullptr) {
//                     verifyError("unexpected policy error");
//                 }
//             } else {
//                 verifyError("unsupported policy scheme");
//             }

//             // gofunc: Intersect
//             string rhs_ns = HashSchemeInstanceFor(*nextPolicy);
//             string lhs_ns = HashSchemeInstanceFor(*policy);
//             // not doing multihash
//             if (rhs_ns.compare(lhs_ns) != 0) {
//                 verifyError("different authority domain");
//             }
//             // gofunc: intersectStatement
//             vector<RTreeStatementItem> statements;
//             RTreePolicy::statements policyStatements = policy->get_statements();
//             OssIndex lhs_index = policyStatements.first();
//             while (lhs_index != OSS_NOINDEX) {
//                 RTreeStatement *leftStatement = policyStatements.at(lhs_index);
//                 lhs_index = policyStatements.next(lhs_index);
//                 RTreePolicy::statements nextPolicyStatements = nextPolicy->get_statements();
//                 OssIndex rhs_index = nextPolicyStatements.first();
//                 while (rhs_index != OSS_NOINDEX) {
//                     RTreeStatement *rightStatement = nextPolicyStatements.at(rhs_index);
//                     rhs_index = nextPolicyStatements.next(rhs_index);
//                     string lhs_ps = HashSchemeInstanceFor(leftStatement->get_permissionSet());
//                     string rhs_ps = HashSchemeInstanceFor(rightStatement->get_permissionSet());
//                     if (lhs_ps.compare(rhs_ps) != 0) {
//                         continue;
//                     }

//                     unordered_map <string, bool> lhs_perms;
//                     OssIndex lpermIdx = leftStatement->get_permissions().first();
//                     while (lpermIdx != OSS_NOINDEX) {
//                         OssString *lperm = leftStatement->get_permissions().at(lpermIdx);
//                         lpermIdx = leftStatement->get_permissions().next(lpermIdx);
//                         lhs_perms[string(lperm->get_buffer(), lperm->length())] = true;
//                     }
//                     list<string> intersectionPerms;
//                     OssIndex rpermIdx = rightStatement->get_permissions().first();
//                     while (rpermIdx != OSS_NOINDEX) {
//                         OssString *rperm = rightStatement->get_permissions().at(rpermIdx);
//                         rpermIdx = rightStatement->get_permissions().next(rpermIdx);
//                         string rpermStr = string(rperm->get_buffer(), rperm->length());
//                         if (lhs_perms[rpermStr]) {
//                             intersectionPerms.push_back(rpermStr);
//                         }
//                     }
//                     if (intersectionPerms.size() == 0) {
//                         continue;
//                     }
//                     // gofunc: RestrictBy
//                     string from = string(leftStatement->get_resource().get_buffer(), 
//                         leftStatement->get_resource().length());
//                     string by = string(rightStatement->get_resource().get_buffer(), 
//                         rightStatement->get_resource().length());
//                     string intersectionResource = RestrictBy(from, by);

//                     if (intersectionResource.empty()) {
//                         RTreeStatementItem item(leftStatement->get_permissionSet(), intersectionPerms, intersectionResource);
//                         statements.push_back(item);
//                     }
//                 }   
//             }

//             vector<RTreeStatementItem> dedup_statements;
//             computeStatements(&statements, &dedup_statements);
//             int indirections;
//             if (policy->get_indirections() < nextPolicy->get_indirections()) {
//                 indirections = policy->get_indirections() - 1;
//             } else {
//                 indirections = nextPolicy->get_indirections() - 1;
//             }

//             //Check errors
//             if (indirections < 0) {
//                 verifyError("insufficient permitted indirections");
//             }
//             if (dedup_statements.size() > PermittedCombinedStatements) {
//                 verifyError("statements form too many combinations");
//             }
//             cursubj = nextAttest;
//             LocationURL *cursubloc = nextAttLoc;
//         }
//         pathpolicies.push_back(*policy);
//         pathEndEntities.push_back(cursubj);
//         LocationURL *subjectLocation = cursubloc;
//     }
//     // Now combine the policies together
//     RTreePolicy aggregatepolicy = pathpolicies[0];
//     OssString *finalsubject = pathEndEntities[0];
//     vector<RTreePolicy> v(pathpolicies.begin()+1, pathpolicies.end());
//     for (int idx = 0; idx < pathpolicies.size(); idx++) {
//         if (memcmp(finalsubject->get_buffer(), pathEndEntities[idx]->get_buffer(), finalsubject->length())) {
//             verifyError("paths don't terminate at same entity");
//         }
//         // gofunc: Union
//         string rhs_ns = HashSchemeInstanceFor(pathpolicies[idx]);
//         string lhs_ns = HashSchemeInstanceFor(aggregatepolicy);
//         // not doing multihash
//         if (rhs_ns.compare(lhs_ns) != 0) {
//             verifyError("different authority domain");
//         }
//         vector<RTreeStatementItem> statements;
//         RTreePolicy::statements lhsStatements = aggregatepolicy.get_statements();
//         appendStatements(&statements, &lhsStatements);
//         RTreePolicy::statements rhsStatements = pathpolicies[idx].get_statements();
//         appendStatements(&statements, &rhsStatements);
//         vector<RTreeStatementItem> dedup_statements;
//         computeStatements(&statements, &dedup_statements);
//         int indirections;
//         if (pathpolicies[idx].get_indirections() < aggregatepolicy.get_indirections()) {
//             indirections = pathpolicies[idx].get_indirections();
//         }
//         if (dedup_statements.size() > PermittedCombinedStatements) {
//             verifyError("statements form too many combinations");
//         }
//     }
//     return 0;
}
