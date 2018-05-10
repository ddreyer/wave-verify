#include "verify.h"

const int CapCertification = 1;

using namespace std;

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

ASN1Exception::ASN1Exception(int asn1_code) {
    code = asn1_code;
}

ASN1Exception::ASN1Exception(const ASN1Exception & that) {
    code = that.code;
}

int ASN1Exception::get_code() const {
    return code;
}

/*
 * The ASN.1/C++ error reporting function.
 */

void throw_error(int code) {
    throw ASN1Exception(code);
}

static int report_error(OssControl *ctl, const char *where, ASN1Exception &exc) {
    int code = exc.get_code();
    const char *msg;

    if (!code)
	/* success */
	return 0;

    printf("\nAn error happened\n  Error origin: %s\n  Error code: %d\n",
	     where, code);

    if (ctl) {
	msg = ctl->getErrorMsg();
    	if (msg && *msg)
	    printf("  Error text: '%s'\n", msg);
    }

    return code;
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
    cout << "\nlength of input: " << len << "\n";

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

int verifyError(string errMessage) {
    cerr << errMessage << "\n";
    exit(-1);
}
    
OssString * HashSchemeInstanceFor(WaveAttestation *nextAtt) {
    OssEncOID subId = nextAtt->get_tbs().get_subject().get_type_id();
    if (subId == keccak_256_id) {
        HashKeccak_256 *nextAttest = nextAtt->get_tbs().get_subject().get_value().get_HashKeccak_256();
        if (nextAttest == nullptr) {
            verifyError("problem with next attestation subject");
        }
        if (nextAttest->length() != 32) {
            verifyError("problem with next attestation subject");
        }
        return nextAttest;
    } else if (subId == sha3_256_id) {
        HashSha3_256 *nextAttest = nextAtt->get_tbs().get_subject().get_value().get_HashSha3_256();
        if (nextAttest == nullptr) {
            verifyError("problem with next attestation subject");
        }
        if (nextAttest->length() != 32) {
            verifyError("problem with next attestation subject");
        }
        return nextAttest;
    } else {
        verifyError("problem with next attestation subject");
    }
}

LocationURL * LocationSchemeInstanceFor(WaveAttestation *att) {
    LocationURL *lsurl = att->get_tbs().get_subjectLocation().get_value().get_LocationURL();
    if (lsurl == nullptr) {
        verifyError("subject location is unsupported");
    }
    return lsurl;
}

bool HasCapability(WaveEntity *entity) {
    EntityPublicKey::capabilityFlags caps = 
        entity->get_tbs().get_verifyingKey().get_capabilityFlags();
    OssIndex capIndex = caps.first();
    while (capIndex != OSS_NOINDEX) {
        int *capInt = caps.at(capIndex);
        capIndex = caps.next(capIndex);
        if (*capInt == CapCertification) {
            return true;
        }
    }
    return false;
}

auto unmarshal(string derEncodedData, auto decodePtr, auto pdu) {
    int code = 0;		/* return code */
    decodePtr = NULL;	/* pointer to decoded data */

    /*
     * Handle ASN.1/C++ runtime errors with C++ exceptions.
     */
    asn1_set_error_handling(throw_error, TRUE);

    try {
	objects_Control ctl;	/* ASN.1/C++ control object */

	try {
	    EncodedBuffer encodedData;	/* encoded data */
	    int encRule;	/* default encoding rules */

	    ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU | AUTOMATIC_ENCDEC);
	    ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU | AUTOMATIC_ENCDEC);
        ctl.setDebugFlags(PRINT_DECODER_OUTPUT | PRINT_DECODING_DETAILS);

	    /*
	     * Do decoding. Note that API is the same for any encoding method.
	     * Get encoding rules which were specified on the ASN.1 compiler
	     * command line.
	     */
	    encRule = ctl.getEncodingRules();

	    /*
	     * Set the decoder's input.
	     */
	    if (encRule == OSS_DER) {
            cout << "encoding rule is OSS_DER\n";
		    encodedData.set_buffer(derEncodedData.length(), (char *)derEncodedData.c_str());
	    } else {
	    	cout << "can't find encoding rule\n";
	    }

	    /*
	     * Decode the encoded PDU whose encoding is in "encodedData".
	     * An exception will be thrown on any error.
         * Trace messages are turned on by using SOED
	     */
	    pdu.decode(ctl, encodedData);

	    /*
	     * Read decoded data.
	     */
	    decodePtr = pdu.get_data();
	} catch (ASN1Exception &exc) {
	    /*
	     * An error occurred during decoding.
	     */
	    code = report_error(&ctl, "decode", exc);
	}
    } catch (ASN1Exception &exc) {
	/*
	 * An error occurred during control object initialization.
	 */
	code = report_error(NULL, "initialization", exc);
    } catch (...) {
	/*
	 * An unexpected exception is caught.
	 */


	printf("Unexpected exception caught.\n");
	code = -1;
    }

    if (code) {
        verifyError("failed to unmarshal");
    }
    return decodePtr;
}

string marshal(auto body) {
    const char *where = "initialization";
    int code = 0;
    EncodedBuffer eData;	/* encoded data */
    try {
    objects_Control ctl;	/* ASN.1/C++ control object */

    try {
        WaveEntityTbs_PDU pdu;		/* coding container for entity TBS value */
        ossEncodingRules encRule;	/* default encoding rules */

        where = "initial settings";

        ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU | AUTOMATIC_ENCDEC);
        ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

        /*
        * Get the encoding rule, which is set currently.
        */
        encRule = ctl.getEncodingRules();

        /*
        * Set the data to the coding container.
        */
        pdu.set_data(body);

        /*
        * Encode the object.
        */
        printf("\nThe encoder's trace messages (only for SOED)...\n\n");
        where = "encoding";
        pdu.encode(ctl, eData);
        printf("\nPDU encoded successfully.\n");
    } catch (ASN1Exception &exc) {
        /*
        * An error occurred during decoding.
        */
        code = report_error(&ctl, where, exc);
    }
    } catch (ASN1Exception &exc) {
    /*
    * An error occurred during control object initialization.
    */
    code = report_error(NULL, where, exc);
    } catch (...) {
    /*
    * An unexpected exception is caught.
    */
    printf("Unexpected exception caught.\n");
    code = -1;
    }
    if (code) {
        verifyError("failed to marshal");
    }
    return string(eData.get_data(), eData.get_length());
}

int verify(string pemContent) {
    string derEncodedData(base64_decode(pemContent));

    printf("Binary size: %lu\n", derEncodedData.length());
    if (derEncodedData.length() == 0) {
    	verifyError("could not decode proof from DER format");
    }

    WaveWireObject *wwoPtr = nullptr;
    WaveWireObject_PDU pdu;
    wwoPtr = unmarshal(derEncodedData, wwoPtr, pdu);	/* pointer to decoded data */

    WaveExplicitProof *exp = wwoPtr->get_value().get_WaveExplicitProof();
    if (exp == nullptr) {
        verifyError("cannot get wave explicit proof from wave wire object");
    }

    // parse entities
    WaveExplicitProof::entities ents = exp->get_entities();
    cout << "entities retrieved\n";
    list<EntityItem> entList;
    OssIndex entIndex = ents.first();
    while (entIndex != OSS_NOINDEX) {
        OssString *ent = ents.at(entIndex);
        string entStr(ent->get_buffer(), ent->length());
        // retrieve next entity to parse
        entIndex = ents.next(entIndex);

        // gofunc: ParseEntity
        WaveWireObject *wwoPtr = nullptr;
        WaveWireObject_PDU pdu;
        wwoPtr = unmarshal(entStr, wwoPtr, pdu);

        WaveEntity *entity = wwoPtr->get_value().get_WaveEntity();
        if (entity == nullptr) {
            // maybe this is an entity secret
            WaveEntitySecret *es = wwoPtr->get_value().get_WaveEntitySecret();
            if (es == nullptr) {
                verifyError("DER is not a wave entity");
            }
            entity = &(es->get_entity());
        }
        // gofunc: parseEntityFromObject
        // check the signature
        EntityPublicKey::key entKey = entity->get_tbs().get_verifyingKey().get_key();
        OssEncOID entKeyId = entKey.get_type_id();
        if (entKeyId == ed25519_id) {
            Public_Ed25519 *ks = entKey.get_value().get_Public_Ed25519();
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            if (ks->length() != 32) {
                verifyError("key length is incorrect");
            }
            // gofunc: VerifyCertify
            // gofunc: HasCapability
            if (!HasCapability(entity)) {
                verifyError("this key cannot perform certifications");
            }

            // gofunc: Verify
            string eData = marshal(entity->get_tbs());

            string entSig(entity->get_signature().get_buffer(), entity->get_signature().length());
            string ksStr(ks->get_buffer(), ks->length());
            // TODO: checking signature currently fails
            // if (!ed25519_verify((const unsigned char *) entSig.c_str(), 
            //     (const unsigned char *) eData.c_str(), eData.length(), 
            //     (const unsigned char *) ksStr.c_str())) {
            //     cerr << "\nsig: " << string_to_hex(entSig);
            //     cerr << "\nkey: " << string_to_hex(ksStr) << "\n";
            //     string d(eData.c_str(), eData.length());
            //     cerr << "\ndata: " << string_to_hex(d);
            //     verifyError("entity ed25519 signature invalid");
            // }
            cout << "valid entity signature\n";
        } else if (entKeyId == curve25519_id) {
            Public_Curve25519 *ks = entKey.get_value().get_Public_Curve25519();
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            if (ks->length() != 32) {
                verifyError("key length is incorrect");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == ibe_bn256_params_id) {
            Params_BN256_IBE *ks = entKey.get_value().get_Params_BN256_IBE();
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == ibe_bn256_public_id) {
            Public_BN256_IBE *ks = entKey.get_value().get_Public_BN256_IBE();
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == oaque_bn256_s20_params_id) {
            Params_BN256_OAQUE *ks = entKey.get_value().get_Params_BN256_OAQUE();
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else if (entKeyId == oaque_bn256_s20_attributeset_id) {
            Public_OAQUE *ks = entKey.get_value().get_Public_OAQUE();
            if (ks == nullptr) {
                verifyError("entity key is null");
            }
            verifyError("this key cannot perform certifications");
        } else {
            verifyError("entity uses unsupported key scheme");
        }

        // Entity appears ok, let's unpack it further
        // TODO: rv.revocations
        // TODO: rv.extensions

        WaveEntity::tbs::keys tbsKeys = entity->get_tbs().get_keys();
        OssIndex tbsIndex = tbsKeys.first();
        while (tbsIndex != OSS_NOINDEX) {
            EntityPublicKey *tbsKey = tbsKeys.at(tbsIndex);
            // retrieve next TBS key
            tbsIndex = tbsKeys.next(tbsIndex);
            EntityPublicKey::key lkey = tbsKey->get_key();
            OssEncOID lkeyId = lkey.get_type_id();
            if (lkeyId == ed25519_id) {
                Public_Ed25519 *ks = lkey.get_value().get_Public_Ed25519();
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
                if (ks->length() != 32) {
                    verifyError("key length is incorrect");
                }
            } else if (lkeyId == curve25519_id) {
                Public_Curve25519 *ks = lkey.get_value().get_Public_Curve25519();
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
                if (ks->length() != 32) {
                    verifyError("key length is incorrect");
                }
            } else if (lkeyId == ibe_bn256_params_id) {
                Params_BN256_IBE *ks = lkey.get_value().get_Params_BN256_IBE();
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else if (lkeyId == ibe_bn256_public_id) {
                Public_BN256_IBE *ks = lkey.get_value().get_Public_BN256_IBE();
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else if (lkeyId == oaque_bn256_s20_params_id) {
                Params_BN256_OAQUE *ks = lkey.get_value().get_Params_BN256_OAQUE();
                if (ks == nullptr) {
                    verifyError("tbs key is null");
                }
            } else if (lkeyId == oaque_bn256_s20_attributeset_id) {
                Public_OAQUE *ks = lkey.get_value().get_Public_OAQUE();
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
    WaveExplicitProof::attestations atsts = exp->get_attestations();
    cout << "attestations retrieved\n";
    vector<AttestationItem> attestationList;
    OssIndex attIndex = atsts.first();
    while (attIndex != OSS_NOINDEX) {
        AttestationReference *atst = atsts.at(attIndex);
        // retrieve next attestation to parse
        attIndex = atsts.next(attIndex);

        AttestationReference::keys keys = atst->get_keys();
        char *vfk;
        string verifierBodyKey;
        string verifierBodyNonce;
        int vfkLen = 0;
        if (keys.empty()) {
            cout << "atst has no keys\n";
        }
        OssIndex keyIndex = keys.first();
        while (keyIndex != OSS_NOINDEX) {
            AttestationVerifierKey *key = keys.at(keyIndex);
            AttestationVerifierKeySchemes_Type vf = key->get_value();
            vfk = vf.get_AVKeyAES128_GCM()->get_buffer();
            if (vfk == nullptr) {
                cout << "atst key was not aes\n";
            } else {
                vfkLen = vf.get_AVKeyAES128_GCM()->length();
                cout << "got atst key of length " << vfkLen << "\n";
                string verifierKey(vfk, vfk + vfkLen);
                verifierBodyKey = verifierKey.substr(0, 16);
                verifierBodyNonce = verifierKey.substr(16, verifierKey.length());
                cout << "key:\n" << string_to_hex(verifierBodyKey) << "\n";
                break;
            }
            keyIndex = keys.next(keyIndex);
        }
        // gofunc: ParseAttestation
        // parse attestation
        AttestationReference::content *derEncodedData = atst->get_content();
        WaveWireObject *wwoPtr = nullptr;
        WaveWireObject_PDU pdu;
        wwoPtr = unmarshal(string(derEncodedData->get_buffer(), derEncodedData->length()), wwoPtr, pdu);

        WaveAttestation *att = wwoPtr->get_value().get_WaveAttestation();
        if (att == nullptr) {
            verifyError("DER is not a wave attestation");
        }

        // gofunc: DecryptBody
        AttestationVerifierBody decryptedBody;
        OssEncOID schemeID = att->get_tbs().get_body().get_type_id();
        if (schemeID == unencrypted_body_scheme) {
            cout << "unencrypted body scheme, currently not supported\n";
        } else if (schemeID == wr1_body_scheme_v1) {
            cout << "wr1 body scheme\n";
            // decrypt body
            WR1BodyCiphertext *wr1body = att->get_tbs().get_body()
                    .get_value().get_WR1BodyCiphertext();
            cout << "got wr1 body\n";
            if (wr1body == nullptr) {
                verifyError("getting body ciphertext failed");
            }

            // checking subject HI instance
            HashSchemeInstanceFor(att);
            
            // check subject location scheme
            LocationSchemeInstanceFor(att);

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
        
                WR1BodyCiphertext::verifierBodyCiphertext vbodyCipher = wr1body->get_verifierBodyCiphertext();
                const unsigned char additional[] = {};
                int bodyLen = vbodyCipher.length();
                unsigned char verifierBodyDER[bodyLen];
                unsigned char tag_buf[16];
                
                cout << "key:\n" << string_to_hex(verifierBodyKey) << "\n";
                char *temp = vbodyCipher.get_buffer();
                string s(temp, bodyLen);
                string t(verifierBodyNonce.c_str(), 12);
                cout << "ciphertext:\n" << string_to_hex(s) << "\n\n";
                cout << "nonce:\n" << string_to_hex(t) << "\n\n";
                ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, bodyLen, (const unsigned char *) verifierBodyNonce.c_str(), 
                    verifierBodyNonce.length(), additional, 0, (const unsigned char *) s.c_str(), verifierBodyDER, 16, tag_buf);
                if (ret) {
                    verifyError("aes decrypt failed");
                } else {
                    unsigned char *hah = verifierBodyDER;
                    string v((const char *)hah, bodyLen-16);
                    cout << "object:\n" << string_to_hex(v) << "\n\n";
                    cout << "decryption succeeded\n";
                }
                mbedtls_gcm_free(&ctx);

                //unmarshal into WR1VerifierBody
                char *vBodyPtr = (char *) verifierBodyDER;
                WR1VerifierBody *vbody = nullptr;
                WR1VerifierBody_PDU pdu;
                vbody = unmarshal(string(vBodyPtr, bodyLen-16), vbody, pdu);
        
                decryptedBody = vbody->get_attestationVerifierBody();
            }
        } else {
            verifyError("unsupported body scheme");
        }

        LocationURL *attesterLoc = 
            decryptedBody.get_attesterLocation().get_value().get_LocationURL();
        if (attesterLoc == nullptr) {
            verifyError("could not get attester loc");
        }

        OssEncOID attestId = decryptedBody.get_attester().get_type_id();
        WaveEntity *attester = nullptr;
        // gofunc: EntityByHashLoc
        if (attestId == keccak_256_id) {
            HashKeccak_256 *attesterHash = decryptedBody.get_attester().get_value().get_HashKeccak_256();
            if (attesterHash == nullptr) {
                verifyError("could not get attester hash");
            }
            if (attesterHash->length() != 32) {
                verifyError("attester hash not valid");
            }
            // convert attestation hash to hex
            string attesterHashStr(attesterHash->get_buffer(), attesterHash->length());
            string attHashHex = string_to_hex(attesterHashStr);
            // loop through entities
            for (list<EntityItem>::iterator it=entList.begin(); it != entList.end(); ++it) {
                Keccak k(Keccak::Keccak256);
                string entityHash = k(it->get_der());
                cout << "\natt hash: " << attHashHex;
                cout << "\nentity hash: " << entityHash;
                if (strcmp(attHashHex.c_str(), entityHash.c_str()) == 0) {
                    cout << "\nfound matching entity for attester\n";
                    attester = it->get_entity();
                    break;
                }
            }
        } else if (attestId == sha3_256_id) {
            HashSha3_256 *attesterHash = decryptedBody.get_attester().get_value().get_HashSha3_256();
            if (attesterHash == nullptr) {
                verifyError("could not get attester hash");
            }
            if (attesterHash->length() != 32) {
                verifyError("attester hash not valid");
            }
            //TODO: support non-keccak schemes
        } else {
            verifyError("unsupported attester hash scheme id");
        }

        SignedOuterKey *_ = decryptedBody.get_outerSignatureBinding().get_value().get_SignedOuterKey();
        if (_ == nullptr) {
            verifyError("outer signature binding not supported");
        }
        // gofunc: VerifyBinding
        // At this time we only know how to extract the key from an ed25519 outer signature
        Ed25519OuterSignature *osig = att->get_outerSignature().get_value().get_Ed25519OuterSignature();
        if (osig == nullptr) {
            verifyError("unknown outer signature type/signature scheme not supported");
        }

        SignedOuterKey *binding = 
            decryptedBody.get_outerSignatureBinding().get_value().get_SignedOuterKey();
        if (binding == nullptr) {
            verifyError("this is not really a signed outer key");
            return -1;
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
        const char *where = "initialization";
        int code = 0;
        EncodedBuffer encodedData;	/* encoded data */
        try {
        objects_Control ctl;	/* ASN.1/C++ control object */

        try {
            SignedOuterKeyTbs_PDU pdu;		/* coding container for binding TBS value */
            ossEncodingRules encRule;	/* default encoding rules */

            where = "initial settings";

            ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
            ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

            /*
            * Get the encoding rule, which is set currently.
            */
            encRule = ctl.getEncodingRules();

            /*
            * Set the data to the coding container.
            */
            pdu.set_data(binding->get_tbs());

            /*
            * Print the input to the encoder.
            */
            printf("The input to the encoder...\n\n");
            where = "printing";
            pdu.print(ctl);

            /*
            * Encode the object.
            */
            printf("\nThe encoder's trace messages (only for SOED)...\n\n");
            where = "encoding";
            pdu.encode(ctl, encodedData);
            printf("\nPDU encoded successfully.\n");

            /*
            * Printing the encoded PDU.
            */
            printf("\n%s-Encoded PDU...\n\n",
                encRule == OSS_BER ? "BER": "PER");
            where = "printing";
            encodedData.print_hex(ctl);
            
        } catch (ASN1Exception &exc) {
            /*
            * An error occurred during decoding.
            */
            code = report_error(&ctl, where, exc);
        }
        } catch (ASN1Exception &exc) {
        /*
        * An error occurred during control object initialization.
        */
        code = report_error(NULL, where, exc);
        } catch (...) {
        /*
        * An unexpected exception is caught.
        */
        printf("Unexpected exception caught.\n");
        code = -1;
        }

        Public_Ed25519 *attesterKey = 
            attester->get_tbs().get_verifyingKey().get_key().get_value().get_Public_Ed25519();
        string bindingSig(binding->get_signature().get_buffer(), binding->get_signature().length());
        string attKey(attesterKey->get_buffer(), attesterKey->length());
        if (!ed25519_verify((const unsigned char *) bindingSig.c_str(), 
            (const unsigned char *) encodedData.get_data(), encodedData.get_length(), 
            (const unsigned char *) attKey.c_str())) {
            cerr << "signature: " << string_to_hex(bindingSig);
            cerr << "\nkey: " << string_to_hex(attKey) << "\n";
            verifyError("outer signature binding invalid");
        }
        cout << "valid outer signature binding\n";

        // Now we know the binding is valid, check the key is the same
        if (binding->get_tbs().get_outerSignatureScheme() != ephemeral_ed25519) {
            verifyError("outer signature scheme invalid");
        }

        if (binding->get_tbs().get_verifyingKey() != osig->get_verifyingKey()) {
            verifyError("bound key does not match");
        }
        // check signature
        // gofunc: VerifySignature
        where = "initialization";
        EncodedBuffer encData;	/* encoded data */
        try {
        objects_Control ctl;	/* ASN.1/C++ control object */

        try {
            WaveAttestationTbs_PDU pdu;		/* coding container for attestation TBS value */
            ossEncodingRules encRule;	/* default encoding rules */

            where = "initial settings";

            ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU | AUTOMATIC_ENCDEC);
            ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

            /*
            * Get the encoding rule, which is set currently.
            */
            encRule = ctl.getEncodingRules();

            /*
            * Set the data to the coding container.
            */
            pdu.set_data(att->get_tbs());

            /*
            * Print the input to the encoder.
            */
            printf("The input to the encoder...\n\n");
            where = "printing";
            pdu.print(ctl);

            /*
            * Encode the object.
            */
            printf("\nThe encoder's trace messages (only for SOED)...\n\n");
            where = "encoding";
            pdu.encode(ctl, encData);
            printf("\nPDU encoded successfully.\n");

        } catch (ASN1Exception &exc) {
            /*
            * An error occurred during decoding.
            */
            code = report_error(&ctl, where, exc);
        }
        } catch (ASN1Exception &exc) {
        /*
        * An error occurred during control object initialization.
        */
        code = report_error(NULL, where, exc);
        } catch (...) {
        /*
        * An unexpected exception is caught.
        */
        printf("Unexpected exception caught.\n");
        code = -1;
        }
        if (code) {
            verifyError("code #4 failed");
        }

        Ed25519OuterSignature::verifyingKey vKey = osig->get_verifyingKey();
        Ed25519OuterSignature::signature sig = osig->get_signature();
        string s(sig.get_buffer(), sig.length());
        string v(vKey.get_buffer(), vKey.length());
        /* verify the signature */
        if (!ed25519_verify((const unsigned char *) s.c_str(), 
                (const unsigned char *) encData.get_data(), encData.get_length(), 
                (const unsigned char *) v.c_str())) {
            verifyError("invalid outer signature");
        }
        cout << "valid outer signature\n";
        AttestationItem aItem(att, decryptedBody);
        attestationList.push_back(aItem);
    }

    cout << "Finished parsing attestations\n";

    //TODO revocation checks
    //todo check end to end and check all paths have same subject
    //now verify the paths
    WaveExplicitProof::paths paths = exp->get_paths();
    cout << "paths retrieved\n";
    OssIndex pathIndex = paths.first();
    while (pathIndex != OSS_NOINDEX) {
        WaveExplicitProof::paths::component *p = paths.at(pathIndex);
        pathIndex = paths.next(pathIndex);
        OssIndex pIndex = p->first();
        // len(path) == 0
        if (pIndex == OSS_NOINDEX) {
            verifyError("path of length 0");
        }
        // path[0]
        int *pathNum = p->at(pIndex);
        pIndex = p->next(pIndex);
        try {
            attestationList.at(*pathNum); 
        } catch (...) {
            verifyError("proof refers to non-included attestation");
        }

        AttestationItem currAttItem = attestationList.at(*pathNum);
        WaveAttestation *currAtt = currAttItem.get_att();
        // gofunc: Subject
        OssEncOID subId = currAtt->get_tbs().get_subject().get_type_id();
        // gofunc: HashSchemeInstanceFor
        OssString *cursubj = HashSchemeInstanceFor(currAtt);

        // gofunc: LocationSchemeInstanceFor
        LocationURL *cursubloc = 
            currAtt->get_tbs().get_subjectLocation().get_value().get_LocationURL();
        if (cursubloc == nullptr) {
            verifyError("problem with attestation location");
        }

        // gofunc: PolicySchemeInstanceFor
        AttestationVerifierBody currBody = currAttItem.get_body();
        if (currBody.get_policy().get_type_id() == trust_level) {
            currBody.get_policy().get_value().get_TrustLevel();
        } else if (currBody.get_policy().get_type_id() == resource_tree) {
            currBody.get_policy().get_value().get_RTreePolicy();
        } else {
            verifyError("unsupported policy scheme");
        }

        while (pIndex != OSS_NOINDEX) {
            pathNum = p->at(pIndex);
            pIndex = p->next(pIndex);
            try {
                attestationList.at(*pathNum); 
            } catch (...) {
                verifyError("proof refers to non-included attestation");
            }

            AttestationItem nextAttItem = attestationList.at(*pathNum);
            WaveAttestation *nextAtt = currAttItem.get_att();
            // gofunc: HashSchemeInstanceFor
            OssString *nextAttest = HashSchemeInstanceFor(nextAtt);

            // gofunc: LocationSchemeInstanceFor
            LocationURL *nextAttLoc = 
                nextAtt->get_tbs().get_subjectLocation().get_value().get_LocationURL();
            if (nextAttLoc == nullptr) {
                verifyError("problem with next attestation location");
            }


        }
    }
    return 0;
}
