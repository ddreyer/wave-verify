#include "verify.h"

const int CapCertification = 1;
const int PermittedCombinedStatements = 1000;

using namespace std;

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

OCTET_STRING_t * HashSchemeInstanceFor(WaveAttestation_t *att) {
    ANY_t type = att->tbs.subject.encoding.choice.single_ASN1_type;
    string subId = marshal(att->tbs.subject.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (subId == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *attest = 0;
        attest = (HashKeccak_256_t *) unmarshal(type.buf, type.size, attest, &asn_DEF_HashKeccak_256);
        if (attest == nullptr) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #1");
        }
        if (attest->size != 32) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #2");
        }
        return attest;
    } else if (subId == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *attest = 0;
        attest = (HashSha3_256_t *) unmarshal(type.buf, type.size, attest, &asn_DEF_HashSha3_256);
        if (attest == nullptr) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #3");
        }
        if (attest->size != 32) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #4");
        }
        return attest;
    } else {
        ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #5");
        return nullptr;
    }
}

OCTET_STRING_t * HashSchemeInstanceFor(RTreePolicy_t *policy) {
    ANY_t type = policy->Namespace.encoding.choice.single_ASN1_type;
    string id = marshal(policy->Namespace.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (id == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *hash = 0;
        hash = (HashKeccak_256_t *) unmarshal(type.buf, type.size, hash, &asn_DEF_HashKeccak_256);
        if (hash == nullptr) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #6");
        }
        if (hash->size != 32) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #7");
        }
        return hash;
    } else if (id == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *hash = 0;
        hash = (HashSha3_256_t *) unmarshal(type.buf, type.size, hash, &asn_DEF_HashSha3_256);
        if (hash == nullptr) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #8");
        }
        if (hash->size != 32) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #9");
        }
        return hash;
    } else {
        ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #10");
        return nullptr;
    }
}

OCTET_STRING_t * HashSchemeInstanceFor(EntityHash_t *pSet) {
    ANY_t type = pSet->encoding.choice.single_ASN1_type;
    string id = marshal(pSet->direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
    if (id == getTypeId(&asn_DEF_HashKeccak_256)) {
        HashKeccak_256_t *hash = 0;
        hash = (HashKeccak_256_t *) unmarshal(type.buf, type.size, hash, &asn_DEF_HashKeccak_256);
        if (hash == nullptr) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #11");
        }
        if (hash->size != 32) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #12");
        }
        return hash;
    } else if (id == getTypeId(&asn_DEF_HashSha3_256)) {
        HashSha3_256_t *hash = 0;
        hash = (HashSha3_256_t *) unmarshal(type.buf, type.size, hash, &asn_DEF_HashSha3_256);
        if (hash == nullptr) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #13");
        }
        if (hash->size != 32) {
            ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #14");
        }
        return hash;
    } else {
        ocall_print("HASHSCHEMEINSTANCEFOR ERROR: problem with hash #15");
        return nullptr;
    }
}

LocationURL_t * LocationSchemeInstanceFor(WaveAttestation_t *att) {
    ANY_t type = att->tbs.subjectLocation.encoding.choice.single_ASN1_type;
    LocationURL_t *lsurl = 0;
    lsurl = (LocationURL_t *) unmarshal(type.buf, type.size, lsurl, &asn_DEF_LocationURL);
    if (lsurl == nullptr) {
        ocall_print("subject location is unsupported");
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
        ocall_print("not supporting trust level policy right now");
        return nullptr;
    } else if (currBodyId == getTypeId(&asn_DEF_RTreePolicy)) {
        policy = (RTreePolicy_t *) unmarshal(type.buf, type.size, policy, &asn_DEF_RTreePolicy);
        if (policy == nullptr) {
            ocall_print("unexpected policy error");
        }
        return policy;
    } else {
        ocall_print("unsupported policy scheme");
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

void appendStatements(vector<RTreeStatementItem *> *statements, RTreePolicy_t::RTreePolicy__statements *policyStments) {
    int index = 0;
    while (index < policyStments->list.count) {
        statements->push_back(statementToItem(policyStments->list.array[index]));
        index++;
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

void freeStatementItem(RTreeStatementItem *statement) {
    asn_DEF_EntityHash.op->free_struct(&asn_DEF_EntityHash, statement->get_permissionSet(), ASFM_FREE_EVERYTHING);
    delete statement;
}

long expiry_to_long(OCTET_STRING_t expiryStr) {
    string temp = string((const char *) expiryStr.buf, expiryStr.size);
    return stol(temp, nullptr);
}

tuple<OCTET_STRING_t *, OCTET_STRING_t *, vector<RTreeStatementItem *> *, long, vector<RTreePolicy_t *> *> verify_rtree_error(string message) {
    ocall_print(message.c_str());
    return {nullptr};
}

tuple<OCTET_STRING_t *, OCTET_STRING_t *, vector<RTreeStatementItem *> *, long, vector<RTreePolicy_t *> *> verify_rtree_proof(char *proof, size_t proofSize) {
    string decodedProof(proof, proofSize);
    long expiry = LONG_MAX;
    WaveWireObject_t *wwoPtr = 0;
    wwoPtr = (WaveWireObject_t *) unmarshal((uint8_t *) (decodedProof.c_str()), decodedProof.length(), wwoPtr, &asn_DEF_WaveWireObject);	/* pointer to decoded data */
    if (wwoPtr == nullptr) {
        return verify_rtree_error("failed to unmarshal");
    }

    WaveExplicitProof_t *exp = 0;
    ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
    exp = (WaveExplicitProof_t *) unmarshal(type.buf, type.size, exp, &asn_DEF_WaveExplicitProof);	/* pointer to decoded data */
    asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
    if (exp == nullptr) {
        return verify_rtree_error("failed to unmarshal");
    }
    
    // parse entities
    WaveExplicitProof_t::WaveExplicitProof__entities ents = exp->entities;
    list<EntityItem> entList;
    int entIndex = 0;
    while (entIndex < ents.list.count) {
        ocall_print("\nParsing entity");
        OCTET_STRING_t *ent = exp->entities.list.array[entIndex];
        string entStr((const char *) ent->buf, ent->size);
        entIndex++;

        // gofunc: ParseEntity
        WaveWireObject_t *wwoPtr = nullptr;
        wwoPtr = (WaveWireObject_t *) unmarshal(ent->buf, ent->size, wwoPtr, &asn_DEF_WaveWireObject);
        if (wwoPtr == nullptr) {
            return verify_rtree_error("failed to unmarshal");
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
                return verify_rtree_error("DER is not a wave entity");
            }
            entity = &(es->entity);
        }
        asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);

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
                return verify_rtree_error("key length is incorrect");
            }

            // gofunc: VerifyCertify
            // gofunc: HasCapability
            if (!HasCapability(entity)) {
                return verify_rtree_error("this key cannot perform certifications");
            }

            // gofunc: Verify
            string eData = marshal(&entity->tbs, &asn_DEF_WaveEntityTbs);
            string entSig((const char *) entity->signature.buf, entity->signature.size);
            string ksStr((const char *) ks->buf, ks->size);

            asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
            
            if (!ed25519_verify((const unsigned char *) entSig.c_str(), 
                (const unsigned char *) eData.c_str(), eData.length(), 
                (const unsigned char *) ksStr.c_str())) {
                return verify_rtree_error("entity ed25519 signature invalid");
            }
            ocall_print("valid entity signature");
        } else if (entKeyId == getTypeId(&asn_DEF_Public_Curve25519)) {
            Public_Curve25519_t *ks = 0;
            ks = (Public_Curve25519_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Curve25519);
            if (ks == nullptr) {
                return verify_rtree_error("entity key is null");
            }
            if (ks->size != 32) {
                asn_DEF_Public_Curve25519.op->free_struct(&asn_DEF_Public_Curve25519, ks, ASFM_FREE_EVERYTHING);
                return verify_rtree_error("key length is incorrect");
            }
            asn_DEF_Public_Curve25519.op->free_struct(&asn_DEF_Public_Curve25519, ks, ASFM_FREE_EVERYTHING);
            return verify_rtree_error("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Params_BN256_IBE)) {
            Params_BN256_IBE_t *ks = 0;
            ks = (Params_BN256_IBE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_IBE);
            if (ks == nullptr) {
                return verify_rtree_error("entity key is null");
            }
            asn_DEF_Params_BN256_IBE.op->free_struct(&asn_DEF_Params_BN256_IBE, ks, ASFM_FREE_EVERYTHING);
            return verify_rtree_error("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Public_BN256_IBE)) {
            Public_BN256_IBE_t *ks = 0;
            ks = (Public_BN256_IBE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_BN256_IBE);
            if (ks == nullptr) {
                return verify_rtree_error("entity key is null");
            }
            asn_DEF_Public_BN256_IBE.op->free_struct(&asn_DEF_Public_BN256_IBE, ks, ASFM_FREE_EVERYTHING);
            return verify_rtree_error("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Params_BN256_IBE)) {
            Params_BN256_OAQUE_t *ks = 0;
            ks = (Params_BN256_OAQUE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_OAQUE);
            if (ks == nullptr) {
                return verify_rtree_error("entity key is null");
            }
            asn_DEF_Params_BN256_OAQUE.op->free_struct(&asn_DEF_Params_BN256_OAQUE, ks, ASFM_FREE_EVERYTHING);
            return verify_rtree_error("this key cannot perform certifications");
        } else if (entKeyId == getTypeId(&asn_DEF_Public_OAQUE)) {
            Public_OAQUE_t *ks = 0;
            ks = (Public_OAQUE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_OAQUE);
            if (ks == nullptr) {
                return verify_rtree_error("entity key is null");
            }
            asn_DEF_Public_OAQUE.op->free_struct(&asn_DEF_Public_OAQUE, ks, ASFM_FREE_EVERYTHING);
            return verify_rtree_error("this key cannot perform certifications");
        } else {
            return verify_rtree_error("entity uses unsupported key scheme");
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
                ks = (Public_Ed25519_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Ed25519);
                if (ks == nullptr) {
                    return verify_rtree_error("tbs key is null");
                }
                if (ks->size != 32) {
                    asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
                    return verify_rtree_error("key length is incorrect");
                }
                asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, ks, ASFM_FREE_EVERYTHING);
            } else if (lkeyId == getTypeId(&asn_DEF_Public_Curve25519)) {
                Public_Curve25519_t *ks = 0;
                ks = (Public_Curve25519_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_Curve25519);
                if (ks == nullptr) {
                    return verify_rtree_error("tbs key is null");
                }
                if (ks->size != 32) {
                    asn_DEF_Public_Curve25519.op->free_struct(&asn_DEF_Public_Curve25519, ks, ASFM_FREE_EVERYTHING);
                    return verify_rtree_error("key length is incorrect");
                }
                asn_DEF_Public_Curve25519.op->free_struct(&asn_DEF_Public_Curve25519, ks, ASFM_FREE_EVERYTHING);
            } else if (lkeyId == getTypeId(&asn_DEF_Params_BN256_IBE)) {
                Params_BN256_IBE_t *ks = 0;
                ks = (Params_BN256_IBE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_IBE);
                if (ks == nullptr) {
                    return verify_rtree_error("tbs key is null");
                }
                asn_DEF_Params_BN256_IBE.op->free_struct(&asn_DEF_Params_BN256_IBE, ks, ASFM_FREE_EVERYTHING);
            } else if (lkeyId == getTypeId(&asn_DEF_Public_BN256_IBE)) {
                Public_BN256_IBE_t *ks = 0;
                ks = (Public_BN256_IBE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_BN256_IBE);
                if (ks == nullptr) {
                    return verify_rtree_error("tbs key is null");
                }
                asn_DEF_Public_BN256_IBE.op->free_struct(&asn_DEF_Public_BN256_IBE, ks, ASFM_FREE_EVERYTHING);
            } else if (lkeyId == getTypeId(&asn_DEF_Params_BN256_OAQUE)) {
                Params_BN256_OAQUE_t *ks = 0;
                ks = (Params_BN256_OAQUE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Params_BN256_OAQUE);
                if (ks == nullptr) {
                    return verify_rtree_error("tbs key is null");
                }
                asn_DEF_Params_BN256_OAQUE.op->free_struct(&asn_DEF_Params_BN256_OAQUE, ks, ASFM_FREE_EVERYTHING);
            } else if (lkeyId == getTypeId(&asn_DEF_Public_OAQUE)) {
                Public_OAQUE_t *ks = 0;
                ks = (Public_OAQUE_t *) unmarshal(type.buf, type.size, ks, &asn_DEF_Public_OAQUE);
                if (ks == nullptr) {
                    return verify_rtree_error("tbs key is null");
                }
                asn_DEF_Public_OAQUE.op->free_struct(&asn_DEF_Public_OAQUE, ks, ASFM_FREE_EVERYTHING);
            } else {
                return verify_rtree_error("tbs key uses unsupported key scheme");
            }
        }

        long currExp = expiry_to_long(entity->tbs.validity.notAfter);
        if (currExp < expiry) {
            expiry = currExp;
        }

        EntityItem e(entity, entStr);
        entList.push_back(e);
    }

    // retrieve attestations
    WaveExplicitProof_t::WaveExplicitProof__attestations atsts = exp->attestations;
    vector<AttestationItem> attestationList;
    int attIndex = 0;
    while (attIndex < atsts.list.count) {
        ocall_print("\nParsing attestation");
        AttestationReference_t *atst = atsts.list.array[attIndex];
        attIndex++;

        AttestationReference_t::AttestationReference__keys keys = atst->keys;
        AVKeyAES128_GCM_t *vfk = 0;
        string verifierBodyKey;
        string verifierBodyNonce;
        int vfkLen = 0;
        if (keys.list.count == 0) {
            ocall_print("atst has no keys");
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
                ocall_print("atst key was not aes");
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
            return verify_rtree_error("failed to unmarshal atst content");
        }
        WaveAttestation_t *att = 0;
        ANY_t type = wwoPtr->encoding.choice.single_ASN1_type;
        att = (WaveAttestation_t *) unmarshal(type.buf, type.size, att, &asn_DEF_WaveAttestation);	/* pointer to decoded data */
        asn_DEF_WaveWireObject.op->free_struct(&asn_DEF_WaveWireObject, wwoPtr, ASFM_FREE_EVERYTHING);
        if (att == nullptr) {
            return verify_rtree_error("failed to unmarshal into Wave Attestation");
        }

        // gofunc: DecryptBody
        AttestationVerifierBody_t *decryptedBody;
        string schemeID = marshal(att->tbs.body.direct_reference, &asn_DEF_OBJECT_IDENTIFIER);
        if (schemeID == getTypeId(&asn_DEF_AttestationBody)) {
            ocall_print("unencrypted body scheme, currently not supported");
        } else if (schemeID == getTypeId(&asn_DEF_WR1BodyCiphertext)) {
            ocall_print("this is a wr1 body scheme");
            // decrypt body
            type = att->tbs.body.encoding.choice.single_ASN1_type;
            WR1BodyCiphertext_t *wr1body = 0;
            wr1body = (WR1BodyCiphertext_t *) unmarshal(type.buf, type.size, wr1body, &asn_DEF_WR1BodyCiphertext);
            if (wr1body == nullptr) {
                return verify_rtree_error("getting body ciphertext failed");
            }
            ocall_print("got wr1 body");
            // checking subject HI instance
            OCTET_STRING_t *ret = HashSchemeInstanceFor(att);
            asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, ret, ASFM_FREE_EVERYTHING);

            if (vfk != nullptr) {
                ocall_print("decrypting attestation");
                OCTET_STRING_t vbodyCipher = wr1body->verifierBodyCiphertext;
                int bodyLen = vbodyCipher.size;
                unsigned char verifierBodyDER[bodyLen];

                EVP_CIPHER_CTX *ctx;
                int outlen, ret;
                if(!(ctx = EVP_CIPHER_CTX_new())) {
                    return verify_rtree_error("Could not initialize decryption context");
                }
                /* Select cipher, key, and IV */
                if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL,
                            (const unsigned char *) verifierBodyKey.c_str(), 
                            (const unsigned char *) verifierBodyNonce.c_str())) {
                    return verify_rtree_error("Error setting aes decryption fields");
                }
                /* Decrypt ciphertext */
                if (1 != EVP_DecryptUpdate(ctx, verifierBodyDER, &outlen, 
                    vbodyCipher.buf, bodyLen)) {
                    return verify_rtree_error("aes decryption failed");
                }
                EVP_CIPHER_CTX_free(ctx);
                unsigned char *hah = verifierBodyDER;
                string v((const char *)hah, bodyLen-16);
                ocall_print("aes decryption succeeded");

                asn_DEF_WR1BodyCiphertext.op->free_struct(&asn_DEF_WR1BodyCiphertext, wr1body, ASFM_FREE_EVERYTHING);

                //unmarshal into WR1VerifierBody
                WR1VerifierBody_t *vbody = 0;
                vbody = (WR1VerifierBody_t *) unmarshal((uint8_t *) verifierBodyDER, bodyLen-16, vbody, &asn_DEF_WR1VerifierBody);
                if (vbody == nullptr) {
                    return verify_rtree_error("could not unmarshal into WR1VerifierBody");
                }        
                decryptedBody = &vbody->attestationVerifierBody;
            }
        } else {
            return verify_rtree_error("unsupported body scheme");
        }

        LocationURL_t *attesterLoc = 0;
        type = decryptedBody->attesterLocation.encoding.choice.single_ASN1_type;
        attesterLoc = (LocationURL_t *) unmarshal(type.buf, type.size, attesterLoc, &asn_DEF_LocationURL);
        if (attesterLoc == nullptr) {
            return verify_rtree_error("could not get attester loc");
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
                return verify_rtree_error("could not get attester hash");
            }
            if (attesterHash->size != 32) {
                asn_DEF_HashKeccak_256.op->free_struct(&asn_DEF_HashKeccak_256, attesterHash, ASFM_FREE_EVERYTHING);
                return verify_rtree_error("attester hash not valid");
            }
            // convert attestation hash to hex
            string attesterHashStr((const char *) attesterHash->buf, attesterHash->size);
            asn_DEF_HashKeccak_256.op->free_struct(&asn_DEF_HashKeccak_256, attesterHash, ASFM_FREE_EVERYTHING);

            string attHashHex = string_to_hex(attesterHashStr);
            // loop through entities
            for (list<EntityItem>::iterator it=entList.begin(); it != entList.end(); ++it) {
                Keccak k(Keccak::Keccak256);
                string entityHash = k(it->get_der());
                if (attHashHex == entityHash) {
                    ocall_print("found matching entity for attester");
                    attester = it->get_entity();
                    break;
                }
                asn_DEF_WaveEntity.op->free_struct(&asn_DEF_WaveEntity, it->get_entity(), ASFM_FREE_EVERYTHING);
            }
        } else if (attestId == getTypeId(&asn_DEF_HashSha3_256)) {
            HashSha3_256_t *attesterHash = 0;
            attesterHash = (HashSha3_256_t *) unmarshal(type.buf, type.size, attesterHash, &asn_DEF_HashSha3_256);
            if (attesterHash == nullptr) {
                return verify_rtree_error("could not get attester hash");
            }
            if (attesterHash->size != 32) {
                asn_DEF_HashSha3_256.op->free_struct(&asn_DEF_HashSha3_256, attesterHash, ASFM_FREE_EVERYTHING);
                return verify_rtree_error("attester hash not valid");
            }
            asn_DEF_HashSha3_256.op->free_struct(&asn_DEF_HashSha3_256, attesterHash, ASFM_FREE_EVERYTHING);
        } else {
            return verify_rtree_error("unsupported attester hash scheme id");
        }

        SignedOuterKey_t *binding = 0;
        type = decryptedBody->outerSignatureBinding.encoding.choice.single_ASN1_type;
        binding = (SignedOuterKey_t *) unmarshal(type.buf, type.size, binding, &asn_DEF_SignedOuterKey);
        if (binding == nullptr) {
            return verify_rtree_error("outer signature binding not supported/this is not really a signed outer key");
        }

        // gofunc: VerifyBinding
        // At this time we only know how to extract the key from an ed25519 outer signature
        Ed25519OuterSignature_t *osig = 0;
        type = att->outerSignature.encoding.choice.single_ASN1_type;
        osig = (Ed25519OuterSignature_t *) unmarshal(type.buf, type.size, osig, &asn_DEF_Ed25519OuterSignature);
        if (osig == nullptr) {
            return verify_rtree_error("unknown outer signature type/signature scheme not supported");
        }

        if (attester == nullptr) {
            return verify_rtree_error("no attester");
        }

        // gofunc: VerifyCertify
        // gofunc: HasCapability
        if (!HasCapability(attester)) {
            return verify_rtree_error("this key cannot perform certifications");
        }

        // gofunc: Verify
        string encodedData = marshal(&binding->tbs, &asn_DEF_SignedOuterKeyTbs);

        Public_Ed25519_t *attesterKey = 0;
        type = attester->tbs.verifyingKey.key.encoding.choice.single_ASN1_type;
        attesterKey = (Public_Ed25519_t *) unmarshal(type.buf, type.size, attesterKey, &asn_DEF_Public_Ed25519);
        if (attesterKey == nullptr) {
            return verify_rtree_error("couldn't unmarshal attesterKey");
        }
        string bindingSig((const char *) binding->signature.buf, binding->signature.size);
        string attKey((const char *) attesterKey->buf, attesterKey->size);
        asn_DEF_Public_Ed25519.op->free_struct(&asn_DEF_Public_Ed25519, attesterKey, ASFM_FREE_EVERYTHING);

        if (!ed25519_verify((const unsigned char *) bindingSig.c_str(), 
            (const unsigned char *) encodedData.c_str(), encodedData.length(), 
            (const unsigned char *) attKey.c_str())) {
            return verify_rtree_error("outer signature binding invalid");
        }
        ocall_print("valid outer signature binding" );

        // Now we know the binding is valid, check the key is the same
        if (marshal(&binding->tbs.outerSignatureScheme, &asn_DEF_OBJECT_IDENTIFIER) 
            != getTypeId(&asn_DEF_Ed25519OuterSignature)) {
            return verify_rtree_error("outer signature scheme invalid");
        }

        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, &binding->tbs.verifyingKey, &osig->verifyingKey)) {
            return verify_rtree_error("bound key does not match");
        }
        // check signature
        // gofunc: VerifySignature
        string encData = marshal(&att->tbs, &asn_DEF_WaveAttestationTbs);
        OCTET_STRING_t vKey = osig->verifyingKey;
        OCTET_STRING_t sig = osig->signature;
        string s((const char *) sig.buf, sig.size);
        string v((const char *) vKey.buf, vKey.size);
        /* verify the signature */
        if (!ed25519_verify((const unsigned char *) s.c_str(), 
                (const unsigned char *) encData.c_str(), encData.length(), 
                (const unsigned char *) v.c_str())) {
            return verify_rtree_error("invalid outer signature");
        }
        ocall_print("valid outer signature");

        long currExp = expiry_to_long(decryptedBody->validity.notAfter);
        if (currExp < expiry) {
            expiry = currExp;
        }

        asn_DEF_SignedOuterKey.op->free_struct(&asn_DEF_SignedOuterKey, binding, ASFM_FREE_EVERYTHING);
        asn_DEF_Ed25519OuterSignature.op->free_struct(&asn_DEF_Ed25519OuterSignature, osig, ASFM_FREE_EVERYTHING);
        AttestationItem aItem(att, decryptedBody);
        attestationList.push_back(aItem);
    }

    // now verify the paths
    vector<RTreePolicy_t *> *pathpolicies = new vector<RTreePolicy_t *>();
    vector<OCTET_STRING_t *> *pathEndEntities = new vector<OCTET_STRING_t *>();
    WaveExplicitProof_t::WaveExplicitProof__paths paths = exp->paths;
    ocall_print("\nPaths retrieved");
    int pathIndex = 0;
    while (pathIndex < paths.list.count) {
        WaveExplicitProof__paths__Member *p = paths.list.array[pathIndex];
        pathIndex++;
        int pIndex = 0;
        if (p->list.count == 0) {
            return verify_rtree_error("path of length 0");
        }
        long *pathNum = p->list.array[pIndex];
        pIndex++;
        try {
            attestationList.at(*pathNum); 
        } catch (...) {
            return verify_rtree_error("proof refers to non-included attestation");
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
                return verify_rtree_error("proof refers to non-included attestation");
            }

            AttestationItem nextAttItem = attestationList.at(*pathNum);
            WaveAttestation_t *nextAtt = currAttItem.get_att();
            // gofunc: HashSchemeInstanceFor
            OCTET_STRING_t *nextAttest = HashSchemeInstanceFor(nextAtt);

            // gofunc: LocationSchemeInstanceFor
            LocationURL_t *nextAttLoc = LocationSchemeInstanceFor(nextAtt);

            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, cursubj, nextAttest)) {
                return verify_rtree_error("path has broken links");
            }
            asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, cursubj, ASFM_FREE_EVERYTHING);

            // gofunc: PolicySchemeInstanceFor
            AttestationVerifierBody_t *nextBody = nextAttItem.get_body();
            RTreePolicy_t *nextPolicy = PolicySchemeInstanceFor(nextBody);

            // gofunc: Intersect
            OCTET_STRING_t *rhs_ns = HashSchemeInstanceFor(nextPolicy);
            OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(policy);
            // not doing multihash
            if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, rhs_ns, lhs_ns)) {
                return verify_rtree_error("different authority domain");
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
                return verify_rtree_error("insufficient permitted indirections");
            }
            if (dedup_statements.size() > PermittedCombinedStatements) {
                return verify_rtree_error("statements form too many combinations");
            }
            cursubj = nextAttest;
            LocationURL_t *cursubloc = nextAttLoc;
        }
        pathpolicies->push_back(policy);
        pathEndEntities->push_back(cursubj);
        LocationURL_t *subjectLocation = cursubloc;
    }

    // Now combine the policies together
    ocall_print("Paths verified, now combining the policies");
    RTreePolicy_t *aggregatepolicy = pathpolicies->at(0);
    OCTET_STRING_t *lhs_ns = HashSchemeInstanceFor(aggregatepolicy);
    vector<RTreeStatementItem *> *dedup_statements = new vector<RTreeStatementItem *>();
    appendStatements(dedup_statements, &(aggregatepolicy->statements));
    OCTET_STRING_t *finalsubject = pathEndEntities->at(0);
    for (int idx = 1; idx < pathpolicies->size(); idx++) {
        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, finalsubject, pathEndEntities->at(idx))) {
            return verify_rtree_error("paths don't terminate at same entity");
        }
        // gofunc: Union
        OCTET_STRING_t *rhs_ns = HashSchemeInstanceFor(pathpolicies->at(idx));
        // not doing multihash
        if (OCTET_STRING_compare(&asn_DEF_OCTET_STRING, rhs_ns, lhs_ns)) {
            return verify_rtree_error("different authority domain");
        }
        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, rhs_ns, ASFM_FREE_EVERYTHING);
        
        vector<RTreeStatementItem *> statements;
        RTreePolicy_t::RTreePolicy__statements *rhsStatements = &(pathpolicies->at(idx)->statements);
        appendStatements(&statements, rhsStatements);
        computeStatements(&statements, dedup_statements);
        if (dedup_statements->size() > PermittedCombinedStatements) {
            return verify_rtree_error("statements form too many combinations");
        }
    }

    asn_DEF_WaveExplicitProof.op->free_struct(&asn_DEF_WaveExplicitProof, exp, ASFM_FREE_EVERYTHING);
    for (int i = 1; i < pathEndEntities->size(); i++) {
        asn_DEF_OCTET_STRING.op->free_struct(&asn_DEF_OCTET_STRING, pathEndEntities->at(i), ASFM_FREE_EVERYTHING);
    }
    delete pathEndEntities;
    for (auto & att: attestationList) {
        asn_DEF_WaveAttestation.op->free_struct(&asn_DEF_WaveAttestation, att.get_att(), ASFM_FREE_EVERYTHING);
        asn_DEF_AttestationVerifierBody.op->free_struct(&asn_DEF_AttestationVerifierBody, att.get_body(), ASFM_FREE_EVERYTHING);
    }
    return {finalsubject, lhs_ns, dedup_statements, expiry, pathpolicies};
}
