#ifndef __VERIFY_H_INCLUDED__
#define __VERIFY_H_INCLUDED__

#include <fstream>
#include <streambuf>
#include <iostream>
#include <stdio.h>
#include <algorithm>
#include <string>
#include <list>
#include <vector>
#include "objects.h"
#include "aes-gcm/gcm.h"
#include "ed25519/src/ed25519.h"
#include "hash-library/keccak.h"

class EntityItem {
private:
    WaveEntity *entity;
    std::string entityDer;
public:
    EntityItem(WaveEntity *entity, std::string entityDer);
    WaveEntity * get_entity();
    std::string get_der();
};

class ASN1Exception {
private:
    int code;
public:
    ASN1Exception(int asn1_code);
    ASN1Exception(const ASN1Exception & that);
    int get_code() const;
};

int verify(std::string pemContent);

#endif