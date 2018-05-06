#include <fstream>
#include <streambuf>
#include <iostream>
#include <stdio.h>
#include <algorithm>
#include <string>
#include <list>

#include "objects.h"
#include "aes-gcm/gcm.h"
#include "ed25519/src/ed25519.h"

const int CapCertification = 1;

using namespace std;

class ASN1Exception {
private:
    int code;
public:
    ASN1Exception(int asn1_code);
    ASN1Exception(const ASN1Exception & that);
    int get_code() const;
};

ASN1Exception::ASN1Exception(int asn1_code)
{
    code = asn1_code;
}

ASN1Exception::ASN1Exception(const ASN1Exception & that)
{
    code = that.code;
}

int ASN1Exception::get_code() const
{
    return code;
}

/*
 * The ASN.1/C++ error reporting function.
 */

void throw_error(int code)
{
    throw ASN1Exception(code);
}

static int report_error(OssControl *ctl, const char *where, ASN1Exception &exc) 
{
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

std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    cout << "THIS IS LEN: " << len << "\n";

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

int main() {
    string str("Reading in PEM file");
    cout << str << "\n";

    ifstream t("proof.pem");
    string pemStr((istreambuf_iterator<char>(t)),
                             istreambuf_iterator<char>());

    // extract proof content from .pem file
    pemStr.erase(0, pemStr.find("\n") + 1);
    int idx = pemStr.find("-----END WAVE");
    pemStr.erase(idx, pemStr.find("\n", idx));
    pemStr.erase(remove(pemStr.begin(), pemStr.end(), '\n'), pemStr.end());
    string derEncodedData(base64_decode(pemStr));

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
    list<WaveEntity*> entList;
    OssIndex entIndex = ents.first();
    while (entIndex != OSS_NOINDEX) {
        OssString *ent = ents.at(entIndex);
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
            entity = &es->get_entity();
        }
        // gofunc: parseEntityFromObject
        // check the signature
        // TODO: finish some of these if statements
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
            EntityPublicKey::capabilityFlags caps = 
                entity->get_tbs().get_verifyingKey().get_capabilityFlags();
            OssIndex capIndex = caps.first();
            bool hasCapability = false;
            while (capIndex != OSS_NOINDEX) {
                int *capInt = caps.at(capIndex);
                // retrieve next entity to parse
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

            // TODO: figure out ent.TBS.Raw
            // if (!ed25519_verify((const unsigned char *) (entity->get_signature().get_buffer()), 
            //     (const unsigned char *) "temp", 4, (const unsigned char *) (ks->get_buffer()))) {
            //     cerr << "entity ed25519 signature invalid\n";
            //     return -1;
            // }
            cout << "valid entity signature\n";
            // TODO: rv.revocations
            // TODO: rv.extensions

            // TODO: get TBS keys

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
        } else if (entKeyId == ibe_bn256_params_id) {
            Params_BN256_IBE *ks = entKey.get_value().get_Params_BN256_IBE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
        } else if (entKeyId == ibe_bn256_public_id) {
            // not done
            Public_BN256_IBE *ks = entKey.get_value().get_Public_BN256_IBE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
        } else if (entKeyId == oaque_bn256_s20_params_id) {
            // not done
            Params_BN256_OAQUE *ks = entKey.get_value().get_Params_BN256_OAQUE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
        } else if (entKeyId == oaque_bn256_s20_attributeset_id) {
            // not done
            Public_OAQUE *ks = entKey.get_value().get_Public_OAQUE();
            if (ks == nullptr) {
                cerr << "entity key is null\n";
                return -1;
            }
        } else {
            cerr << "entity uses unsupported key scheme\n";
            return -1;
        }
        
        entList.push_back(entity);
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
        // TODO: figure out if attestation needs to be unmarshaled every time
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

        // TODO: skipping return value formation, subject

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
                cerr << "unsupported subject hash scheme instance\n";
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
            // TODO: no attestation key, decrypt in prover role

        } else {
            cerr << "unsupported body scheme\n";
            return -1;
        }

        LocationURL *attesterLoc = 
            decryptedBody.get_attesterLocation().get_value().get_LocationURL();
        OssEncOID attestId = decryptedBody.get_attester().get_type_id();
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
            // TODO: attestLoc never used?
            // TODO: loop through entities?
            // TODO: loop through entity secrets?
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
        // TODO: figure out marshaling of binding.TBS

        // TODO: check signature

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

        // TODO: figure out marshaling of attestation TBS
    //     const char *where = "initialization";
    //     try {
    //     objects_Control ctl;	/* ASN.1/C++ control object */

    //     try {
    //         EncodedBuffer encodedData;	/* encoded data */
    //         __seq4 pdu;		/* coding container for attestation TBS value */
    //         ossEncodingRules encRule;	/* default encoding rules */

    //         where = "initial settings";

    //         ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
    //         ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

    //         /*
    //         * Get the encoding rule, which is set currently.
    //         */
    //         encRule = ctl.getEncodingRules();

    //         /*
    //         * Set the data to the coding container.
    //         */
    //         pdu.set_data(att->get_tbs());

    //         /*
    //         * Print the input to the encoder.
    //         */
    //         printf("The input to the encoder...\n\n");
    //         where = "printing";
    //         pdu.print(ctl);

    //         /*
    //         * Encode the object.
    //         */
    //         printf("\nThe encoder's trace messages (only for SOED)...\n\n");
    //         where = "encoding";
    //         pdu.encode(ctl, encodedData);
    //         printf("\nPDU encoded successfully.\n");

    //         /*
    //         * Printing the encoded PDU.
    //         */
    //         printf("\n%s-Encoded PDU...\n\n",
    //             encRule == OSS_BER ? "BER": "PER");
    //         where = "printing";
    //         encodedData.print_hex(ctl);

    //     } catch (ASN1Exception &exc) {
    //         /*
    //         * An error occurred during decoding.
    //         */
    //         code = report_error(&ctl, where, exc);
    //     }
    //     } catch (ASN1Exception &exc) {
    //     /*
    //     * An error occurred during control object initialization.
    //     */
    //     code = report_error(NULL, where, exc);
    //     } catch (...) {
    //     /*
    //     * An unexpected exception is caught.
    //     */
    //     printf("Unexpected exception caught.\n");
    //     code = -1;
    //     }
        if (code) {
            cerr << "code #4 failed\n";
            return -1;
        }

        Ed25519OuterSignature::verifyingKey vKey = osig->get_verifyingKey();
        Ed25519OuterSignature::signature sig = osig->get_signature();
        /* verify the signature */
        //TODO: fix this
        if (ed25519_verify((const unsigned char *) (sig.get_buffer()), 
                (const unsigned char *) "temp", 4, (const unsigned char *) (vKey.get_buffer()))) {
            cout << "valid signature\n";
        } else {
            cerr << "invalid signature\n";
            return -1;
        }

    }

    cout << "Finished verifying proof\n";
    return 0;
}


