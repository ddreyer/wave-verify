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
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    cout << "\nlength of hex: " << len << "\n";

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

int verify(string pemContent) {
    string derEncodedData(base64_decode(pemContent));

    printf("Binary size: %lu\n", derEncodedData.length());
    if (derEncodedData.length() == 0) {
    	cerr << "could not decode proof from DER format\n";
        return -1;
    }

    // unmarshal into WaveWireObject
    int code = 0;		/* return code */
    WaveWireObject *wwoPtr = NULL;	/* pointer to decoded data */

    /*
     * Handle ASN.1/C++ runtime errors with C++ exceptions.
     */
    asn1_set_error_handling(throw_error, TRUE);

    try {
	objects_Control ctl;	/* ASN.1/C++ control object */

	try {
	    EncodedBuffer encodedData;	/* encoded data */
	    WaveWireObject_PDU pdu;	 /* coding container for a WWO value */ 
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
	    wwoPtr = pdu.get_data();
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
        cerr << "code #1 failed to decode\n";
        return -1;
    }

    WaveExplicitProof *exp = wwoPtr->get_value().get_WaveExplicitProof();
    if (exp == nullptr) {
        cerr << "cannot get wave explicit proof from wave wire object\n";
        return -1;
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
        WaveWireObject *wwoPtr = NULL;	/* pointer to decoded data */

        try {
            objects_Control ctl;	/* ASN.1/C++ control object */

            try {
                EncodedBuffer encodedData;	/* encoded data */
                WaveWireObject_PDU pdu;	 /* coding container for a WWO value */
                int encRule;	/* default encoding rules */

                ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
                ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU | AUTOMATIC_ENCDEC);
                ctl.setDebugFlags(PRINT_DECODER_OUTPUT | PRINT_DECODING_DETAILS | PRINT_DECODER_INPUT | PRINT_HEX_WITH_ASCII);

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
                    encodedData.set_buffer(ent->length(),
                                           ent->get_buffer());
                } else {
                    cout << "can't find encoding rule\n";
                }

                /*
                 * Decode the encoded PDU whose encoding is in "encodedData".
                 * An exception will be thrown on any error.
                 */
                pdu.decode(ctl, encodedData);

                /*
                 * Read decoded data.
                 */
                wwoPtr = pdu.get_data();
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
            cerr << "failed to decode entity\n";
            return -1;
        }

        WaveEntity *entity = wwoPtr->get_value().get_WaveEntity();
        if (entity == nullptr) {
            // maybe this is an entity secret
            WaveEntitySecret *es = wwoPtr->get_value().get_WaveEntitySecret();
            if (es == nullptr) {
                cerr << "DER is not a wave entity\n";
                return -1;
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
                cerr << "entity key is null\n";
                return -1;
            }
            if (ks->length() != 32) {
                cerr << "key length is incorrect\n";
                return -1;
            }
            // gofunc: VerifyCertify
            // gofunc: HasCapability
            EntityPublicKey::capabilityFlags caps = 
                entity->get_tbs().get_verifyingKey().get_capabilityFlags();
            OssIndex capIndex = caps.first();
            bool hasCapability = false;
            while (capIndex != OSS_NOINDEX) {
                int *capInt = caps.at(capIndex);
                capIndex = caps.next(capIndex);
                if (*capInt == CapCertification) {
                    hasCapability = true;
                    break;
                }
            }

            if (!hasCapability) {
                cerr << "this key cannot perform certifications\n";
                return -1;
            }

            // gofunc: Verify
            // TODO: figure out ent.TBS.Raw
            // if (!ed25519_verify((const unsigned char *) (entity->get_signature().get_buffer()), 
            //     (const unsigned char *) "temp", 4, (const unsigned char *) (ks->get_buffer()))) {
            //     cerr << "entity ed25519 signature invalid\n";
            //     return -1;
            // }
            cout << "valid entity signature\n";
        } else if (entKeyId == curve25519_id) {
            Public_Curve25519 *ks = entKey.get_value().get_Public_Curve25519();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
            if (ks->length() != 32) {
                cerr << "key length is incorrect\n";
                return -1;
            }
            cerr << "this key cannot perform certifications\n";
            return -1;
        } else if (entKeyId == ibe_bn256_params_id) {
            Params_BN256_IBE *ks = entKey.get_value().get_Params_BN256_IBE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
            cerr << "this key cannot perform certifications\n";
            return -1;
        } else if (entKeyId == ibe_bn256_public_id) {
            Public_BN256_IBE *ks = entKey.get_value().get_Public_BN256_IBE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
            cerr << "this key cannot perform certifications\n";
            return -1;
        } else if (entKeyId == oaque_bn256_s20_params_id) {
            Params_BN256_OAQUE *ks = entKey.get_value().get_Params_BN256_OAQUE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
            cerr << "this key cannot perform certifications\n";
            return -1;
        } else if (entKeyId == oaque_bn256_s20_attributeset_id) {
            Public_OAQUE *ks = entKey.get_value().get_Public_OAQUE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
            cerr << "this key cannot perform certifications\n";
            return -1;
        } else {
            cerr << "entity uses unsupported key scheme\n";
            return -1;
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
                    cerr << "tbs key is null\n";
                    return -1;
                }
                if (ks->length() != 32) {
                    cerr << "key length is incorrect\n";
                    return -1;
                }
            } else if (lkeyId == curve25519_id) {
                Public_Curve25519 *ks = lkey.get_value().get_Public_Curve25519();
                if (ks == nullptr) {
                    cerr << "tbs key is null\n";
                    return -1;
                }
                if (ks->length() != 32) {
                    cerr << "key length is incorrect\n";
                    return -1;
                }
            } else if (lkeyId == ibe_bn256_params_id) {
                Params_BN256_IBE *ks = lkey.get_value().get_Params_BN256_IBE();
                if (ks == nullptr) {
                    cerr << "tbs key is null\n";
                    return -1;
                }
            } else if (lkeyId == ibe_bn256_public_id) {
                Public_BN256_IBE *ks = lkey.get_value().get_Public_BN256_IBE();
                if (ks == nullptr) {
                    cerr << "tbs key is null\n";
                    return -1;
                }
            } else if (lkeyId == oaque_bn256_s20_params_id) {
                Params_BN256_OAQUE *ks = lkey.get_value().get_Params_BN256_OAQUE();
                if (ks == nullptr) {
                    cerr << "tbs key is null\n";
                    return -1;
                }
            } else if (lkeyId == oaque_bn256_s20_attributeset_id) {
                Public_OAQUE *ks = lkey.get_value().get_Public_OAQUE();
                if (ks == nullptr) {
                    cerr << "tbs key is null\n";
                    return -1;
                }
            } else {
                cerr << "tbs key uses unsupported key scheme\n";
                return -1;
            }
        }
        EntityItem e(entity, entStr);
        entList.push_back(e);
    }

    // retrieve attestations
    WaveExplicitProof::attestations atsts = exp->get_attestations();
    cout << "attestations retrieved\n";
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
        int code = 0;		/* return code */
        AttestationReference::content *derEncodedData = atst->get_content();
        WaveWireObject *wwoPtr = NULL;	/* pointer to decoded data */

        try {
            objects_Control ctl;	/* ASN.1/C++ control object */

            try {
                EncodedBuffer encodedData;	/* encoded data */
                WaveWireObject_PDU pdu;	 /* coding container for a WWO value */
                int encRule;	/* default encoding rules */

                ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
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
                    encodedData.set_buffer(derEncodedData->length(),
                                           (char *)derEncodedData->get_buffer());
                } else {
                    cout << "can't find encoding rule\n";
                }

                /*
                 * Decode the encoded PDU whose encoding is in "encodedData".
                 * An exception will be thrown on any error.
                 */
                pdu.decode(ctl, encodedData);

                /*
                 * Read decoded data.
                 */
                wwoPtr = pdu.get_data();
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
            cerr << "code #2 failed\n";
            return -1;
        }

        WaveAttestation *att = wwoPtr->get_value().get_WaveAttestation();
        if (att == nullptr) {
            cerr << "DER is not a wave attestation\n";
            return -1;
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
                cerr << "getting body ciphertext failed\n";
            }

            // checking subject HI instance
            OssEncOID hashSchemeID = att->get_tbs().get_subject().get_type_id();
            if (hashSchemeID == keccak_256_id) {
                HashKeccak_256 *subjectHI = att->get_tbs().get_subject().get_value().get_HashKeccak_256();
            } else if (hashSchemeID == sha3_256_id) {
                HashSha3_256 *subjectHI = att->get_tbs().get_subject().get_value().get_HashSha3_256();
            } else {
                cerr << "subject hash is unsupported\n";
                return -1;
            }

            // check subject location scheme
            LocationURL *lsurl = 
                att->get_tbs().get_subjectLocation().get_value().get_LocationURL();
            if (lsurl == nullptr) {
                cerr << "subject location is unsupported\n";
                return -1;
            }

            if (vfk) {
                cout << "decrypting attestation\n";
                mbedtls_gcm_context ctx;
                mbedtls_gcm_init( &ctx );
                int ret = 0;
                ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, 
                    (const unsigned char *) verifierBodyKey.c_str(), verifierBodyKey.length()*8);
                if (ret) {
                    cerr << "aes set key failed\n";
                    return -1;
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
                    cerr << "aes decrypt failed\n";
                    return -1;
                } else {
                    unsigned char *hah = verifierBodyDER;
                    string v((const char *)hah, bodyLen-16);
                    cout << "object:\n" << string_to_hex(v) << "\n\n";
                    cout << "decryption succeeded\n";
                }
                mbedtls_gcm_free(&ctx);

                //unmarshal into WR1VerifierBody
                code = 0;		/* return code */
                WR1VerifierBody *vbody = NULL;	/* pointer to decoded data */

                try {
                objects_Control ctl;	/* ASN.1/C++ control object */

                try {
                    EncodedBuffer encodedData;	/* encoded data */
                    WR1VerifierBody_PDU pdu;	 /* coding container for a WWO value */ 
                    int encRule;	/* default encoding rules */

                    ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
                    ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU | AUTOMATIC_ENCDEC);
                    ctl.setDebugFlags(PRINT_DECODER_OUTPUT | PRINT_DECODING_DETAILS | PRINT_DECODER_INPUT | PRINT_HEX_WITH_ASCII);

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
                        encodedData.set_buffer(bodyLen-16, (char *) verifierBodyDER);
                    } else {
                        cout << "can't find encoding rule\n";
                    }

                    /*
                    * Decode the encoded PDU whose encoding is in "encodedData".
                    * An exception will be thrown on any error.
                    */
                    pdu.decode(ctl, encodedData);

                    /*
                    * Read decoded data.
                    */
                    vbody = pdu.get_data();
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
                    cerr << "code #3 failed\n";
                    return -1;
                }
                decryptedBody = vbody->get_attestationVerifierBody();
            }

        } else {
            cerr << "unsupported body scheme\n";
            return -1;
        }

        LocationURL *attesterLoc = 
            decryptedBody.get_attesterLocation().get_value().get_LocationURL();
        if (attesterLoc == nullptr) {
            cerr << "could not get attester loc\n";
            return -1;
        }

        OssEncOID attestId = decryptedBody.get_attester().get_type_id();
        WaveEntity *attester = nullptr;
        // gofunc: EntityByHashLoc
        if (attestId == keccak_256_id) {
            HashKeccak_256 *attesterHash = decryptedBody.get_attester().get_value().get_HashKeccak_256();
            if (attesterHash == nullptr) {
                cerr << "could not get attester hash\n";
                return -1;
            }
            if (attesterHash->length() != 32) {
                cerr << "attester hash not valid\n";
                return -1;
            }
            // convert attestation has to hex and then to lower case
            string attesterHashStr(attesterHash->get_buffer(), attesterHash->length());
            string attHashHex = string_to_hex(attesterHashStr);
            transform(attHashHex.begin(), attHashHex.end(), attHashHex.begin(), ::tolower);
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
                cerr << "could not get attester hash\n";
                return -1;
            }
            if (attesterHash->length() != 32) {
                cerr << "attester hash not valid\n";
                return -1;
            }
            //TODO: support non-keccak schemes
        } else {
            cerr << "unsupported attester hash scheme id\n";
            return -1;
        }

        SignedOuterKey *_ = decryptedBody.get_outerSignatureBinding().get_value().get_SignedOuterKey();
        if (_ == nullptr) {
            cerr << "outer signature binding not supported\n";
            return -1;
        }
        // gofunc: VerifyBinding
        // At this time we only know how to extract the key from an ed25519 outer signature
        Ed25519OuterSignature *osig = att->get_outerSignature().get_value().get_Ed25519OuterSignature();
        if (osig == nullptr) {
            cerr << "unknown outer signature type/signature scheme not supported\n";
            return -1;
        }

        SignedOuterKey *binding = 
            decryptedBody.get_outerSignatureBinding().get_value().get_SignedOuterKey();
        if (binding == nullptr) {
            cerr << "this is not really a signed outer key\n";
            return -1;
        }

        if (attester == nullptr) {
            cerr << "no attester\n";
            return -1;
        }

        // gofunc: VerifyCertify
        // gofunc: HasCapability
        EntityPublicKey::capabilityFlags caps = 
            attester->get_tbs().get_verifyingKey().get_capabilityFlags();
        OssIndex capIndex = caps.first();
        bool hasCapability = false;
        while (capIndex != OSS_NOINDEX) {
            int *capInt = caps.at(capIndex);
            capIndex = caps.next(capIndex);
            if (*capInt == CapCertification) {
                hasCapability = true;
                break;
            }
        }

        if (!hasCapability) {
            cerr << "this key cannot perform certifications\n";
            return -1;
        }

        // gofunc: Verify
        const char *where = "initialization";
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
            cerr << "outer signature binding invalid\n";
            return -1;
        }
        cout << "valid outer signature binding\n";

        // Now we know the binding is valid, check the key is the same
        if (binding->get_tbs().get_outerSignatureScheme() != ephemeral_ed25519) {
            cerr << "outer signature scheme invalid\n";
            return -1;
        }

        if (binding->get_tbs().get_verifyingKey() != osig->get_verifyingKey()) {
            cerr << "bound key does not match\n";
            return -1;
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
            cerr << "code #4 failed\n";
            return -1;
        }

        Ed25519OuterSignature::verifyingKey vKey = osig->get_verifyingKey();
        Ed25519OuterSignature::signature sig = osig->get_signature();
        string s(sig.get_buffer(), sig.length());
        string v(vKey.get_buffer(), vKey.length());
        /* verify the signature */
        if (ed25519_verify((const unsigned char *) s.c_str(), 
                (const unsigned char *) encData.get_data(), encData.get_length(), 
                (const unsigned char *) v.c_str())) {
            cout << "valid outer signature\n";
        } else {
            cerr << "invalid outer signature\n";
            return -1;
        }

    }

    cout << "Finished verifying proof\n";
    return 0;
}
