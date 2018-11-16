#ifndef __VERIFY_H_INCLUDED__
#define __VERIFY_H_INCLUDED__

#include <fstream>
#include <streambuf>
#include <sstream>
#include <stdio.h>
#include <algorithm>
#include <list>
#include <unordered_map>
#include <vector>

#include "asn.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "ed25519/src/ed25519.h"
#include "hash-library/keccak.h"

using namespace std;

class RVerifyRTreeProof {
private:
    OCTET_STRING_t subject;
    RTreePolicy_t policy;
public:
    RVerifyRTreeProof(OCTET_STRING_t subj, RTreePolicy_t policy);
    OCTET_STRING_t get_subject();
    RTreePolicy_t get_policy();
};

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

OCTET_STRING_t * HashSchemeInstanceFor(RTreePolicy_t *policy);

bool isStatementSupersetOf(RTreeStatementItem *subset, RTreeStatementItem *superset);

RVerifyRTreeProof * verify_rtree_proof(char *proof, size_t proofSize);

#endif
