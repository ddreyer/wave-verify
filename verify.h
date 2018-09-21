#ifndef __VERIFY_H_INCLUDED__
#define __VERIFY_H_INCLUDED__

#include <fstream>
#include <streambuf>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <list>
#include <unordered_map>
#include <vector>

#include <WaveEntity.h>
#include <WaveEntitySecret.h>
#include <WaveAttestation.h>
#include <AttestationVerifierBody.h>
#include <AttestationBody.h>
#include <RTreeStatement.h>
#include <WaveWireObject.h>
#include <WaveExplicitProof.h>
#include <Public-Ed25519.h>
#include <Public-Curve25519.h>
#include <Params-BN256-IBE.h>
#include <Params-BN256-OAQUE.h>
#include <Public-BN256-IBE.h>
#include <Public-OAQUE.h>
#include <AVKeyAES128-GCM.h>
#include <HashKeccak-256.h>
#include <HashSha3-256.h>
#include <WR1BodyCiphertext.h>
#include <LocationURL.h>
#include <HashKeccak-256.h>
#include <HashSha3-256.h>

#include "aes-gcm/gcm.h"
#include "ed25519/src/ed25519.h"
#include "hash-library/keccak.h"

class EntityItem {
private:
    WaveEntity_t *entity;
    std::string entityDer;
public:
    EntityItem(WaveEntity_t *entity, std::string entityDer);
    WaveEntity_t * get_entity();
    std::string get_der();
};

class AttestationItem {
private:
    WaveAttestation_t *attestation;
    AttestationVerifierBody_t decryptedBody;
public:
    AttestationItem(WaveAttestation_t *att, AttestationVerifierBody_t dBody);
    WaveAttestation_t * get_att();
    AttestationVerifierBody_t get_body();
};

// class RTreeStatementItem {
// private:
//     struct RTreeStatement_t rTreeStatement;
//     std::list<std::string> permissions;
//     std::string intersectionResource;
// public:
//     RTreeStatementItem(RTreeStatement::permissionSet pSet, std::list<std::string> perms, std::string iResource);
//     RTreeStatement::permissionSet get_permissionSet();
//     std::list<std::string> get_permissions();
//     std::string get_interResource();
// };

int verify(std::string pemContent);

#endif