#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <stdio.h>

#include "objects.h"
#include "aes-gcm/gcm.h"
#include "ed25519/src/ed25519.h"

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

/*
 * https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp
*/
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

int main() {
    string str("Reading in PEM file");
    cout << str << "\n";

    ifstream t("proof.pem");
    string pemStr((istreambuf_iterator<char>(t)),
                             istreambuf_iterator<char>());

    pemStr.erase(0, pemStr.find("\n") + 1);
    int idx = pemStr.find("-----END WAVE");
    pemStr.erase(idx, pemStr.find("\n", idx));

    // TODO: base64_decode doesn't work right now
    // string derEncodedData(base64_decode(pemStr));
    
    ifstream v("proof_bin.der");
    string derEncodedData((istreambuf_iterator<char>(v)),
                             istreambuf_iterator<char>());
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

#ifdef RELAXED_MODE
	    /*
	     * Set relaxed mode.
	     */
	    ctl.setEncodingFlags(NOCONSTRAIN | RELAXDER);
	    ctl.setDecodingFlags(NOCONSTRAIN | RELAXDER);
#endif

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
	     * Print the encoded message.
	     */
	    // printf("Printing the DER-encoded PDU...\n\n");
	    // encodedData.print_hex(ctl);

	    /*
	     * Decode the encoded PDU whose encoding is in "encodedData".
	     * An exception will be thrown on any error.
	     */
	    printf("\nThe decoder's trace messages (only for SOED)...\n\n");
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

    // // TODO: skip parsing Entities

    // // retrieve attestations
    WaveExplicitProof::attestations atsts = exp->get_attestations();
    cout << "attestations retrieved\n";
    OssIndex attIndex = atsts.first();
    while (attIndex != OSS_NOINDEX) {
        AttestationReference *atst = atsts.at(attIndex);
        // retrieve next attestation to parse
        attIndex = atsts.next(attIndex);

        AttestationReference::keys keys = atst->get_keys();
        AVKeyAES128_GCM *vfk;
        if (keys.empty()) {
            cout << "atst has no keys\n";
        }
        OssIndex keyIndex = keys.first();
        while (keyIndex != OSS_NOINDEX) {
            printf("This should not print twice\n");
            AttestationVerifierKey * key = keys.at(keyIndex);

            AttestationVerifierKeySchemes_Type vf = key->get_value();
            vfk = vf.get_AVKeyAES128_GCM();
            if (vfk == nullptr) {
                cout << "atst key was not aes\n";
            } else {
                break;
            }
            keyIndex = keys.next(keyIndex);
        }

        // parse attestation
        // TODO: figure out if attestation needs to be unmarshaled every time
        int code = 0;		/* return code */
        AttestationReference::content *derEncodedData = atst->get_content();
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

// #ifdef RELAXED_MODE
//                 /*
//      * Set relaxed mode.
//      */
//     ctl.setEncodingFlags(NOCONSTRAIN | RELAXDER);
//     ctl.setDecodingFlags(NOCONSTRAIN | RELAXDER);
// #endif

//                 ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
//                 ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

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
                 * Print the encoded message.
                 */
                // printf("Printing the DER-encoded PDU...\n\n");
                // encodedData.print_hex(ctl);

                /*
                 * Decode the encoded PDU whose encoding is in "encodedData".
                 * An exception will be thrown on any error.
                 */
                printf("\nThe decoder's trace messages (only for SOED)...\n\n");
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
        if (exp == nullptr) {
            cerr << "DER is not a wave attestation\n";
            return -1;
        }

        // TODO: skipping return value formation, subject

        OssEncOID schemeID = att->get_tbs().get_body().get_type_id();
        if (schemeID == unencrypted_body_scheme) {
            cout << "unencrypted body scheme, currently not supported\n";
        } else if (schemeID == wr1_body_scheme_v1) {
            cout << "wr1 body scheme\n";
            // decrypt body
            WR1BodyCiphertext *wr1body = att->get_tbs().get_body()
                    .get_value().get_WR1BodyCiphertext();

            if (wr1body == nullptr) {
                cerr << "getting body ciphertext failed\n";
            }

            //TODO: skipping subject HI check
            if (vfk) {
                string verifierKey(vfk->get_buffer(), vfk->get_buffer() + vfk->length());
                string verifierBodyKey = verifierKey.substr(0, 16);
                string verifierBodyNonce = verifierKey.substr(16, verifierKey.length());

                mbedtls_gcm_context ctx;
                mbedtls_gcm_init( &ctx );
                int ret = 0;

                int keyLen = verifierBodyKey.length();
                printf("Keylen: %d\n", keyLen);
                ret = mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, (const unsigned char *) verifierBodyKey.c_str(), keyLen);
                if (ret) {
                    cerr << "aes set key failed\n";
                    return -1;
                }

        
                WR1BodyCiphertext::verifierBodyCiphertext vbodyCipher = wr1body->get_verifierBodyCiphertext();
                const unsigned char additional[] = {};
                int bodyLen = vbodyCipher.length();
                unsigned char verifierBodyDER[bodyLen];
                unsigned char tag_buf[16];
                ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_DECRYPT, bodyLen, (const unsigned char *) verifierBodyNonce.c_str(), 
                    16, additional, 0, (const unsigned char *) vbodyCipher.get_buffer(), verifierBodyDER, 16, tag_buf);
                if (ret) {
                    cerr << "aes decrypt failed\n";
                    return 01;
                }
                mbedtls_gcm_free( &ctx );

                //unmarshal into WR1VerifierBody
                code = 0;		/* return code */
                WR1VerifierBody *vbody = NULL;	/* pointer to decoded data */

                /*
                * Handle ASN.1/C++ runtime errors with C++ exceptions.
                */
                asn1_set_error_handling(throw_error, TRUE);

                try {
                objects_Control ctl;	/* ASN.1/C++ control object */

                try {
                    EncodedBuffer encodedData;	/* encoded data */
                    WR1VerifierBody_PDU pdu;	 /* coding container for a WWO value */ 
                    int encRule;	/* default encoding rules */

            #ifdef RELAXED_MODE
                    /*
                    * Set relaxed mode.
                    */
                    ctl.setEncodingFlags(NOCONSTRAIN | RELAXDER);
                    ctl.setDecodingFlags(NOCONSTRAIN | RELAXDER);
            #endif

                    ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
                    ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

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
                    encodedData.set_buffer(bodyLen, (char *) verifierBodyDER);
                    } else {
                        cout << "can't find encoding rule\n";
                    }

                    /*
                    * Print the encoded message.
                    */
                    printf("Printing the DER-encoded PDU...\n\n");
                    encodedData.print_hex(ctl);

                    /*
                    * Decode the encoded PDU whose encoding is in "encodedData".
                    * An exception will be thrown on any error.
                    */
                    printf("\nThe decoder's trace messages (only for SOED)...\n\n");
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
                WR1VerifierBody::attestationVerifierBody decryptedBody = 
                    vbody->get_attestationVerifierBody();
            }

            // TODO: no attestation key, decrypt in prover role
        } else {
            cerr << "unsupported body scheme\n";
            return -1;
        }

        // TODO: do stuff here after decrypting body

        // check signature
        Ed25519OuterSignature *osig = 
            att->get_outerSignature().get_value().get_Ed25519OuterSignature();
        if (osig == nullptr) {
            cerr << "Outer signature lied about its scheme/is not supported\n";
            return -1;
        }

        // TODO: figure out marshaling of attestation TBS
    //     const char *where = "initialization";
    //     try {
    //     objects_Control ctl;	/* ASN.1/C++ control object */

    //     try {
    //         EncodedBuffer encodedData;	/* encoded data */
    //         __seq4 pdu;		/* coding container for attestation TBS value */
    //         ossEncodingRules encRule;	/* default encoding rules */

    //         where = "initial settings";

    // #ifdef RELAXED_MODE
    //         /*
    //         * Set relaxed mode.
    //         */
    //         ctl.setEncodingFlags(NOCONSTRAIN | RELAXBER | RELAXPER);
    //         ctl.setDecodingFlags(NOCONSTRAIN | RELAXBER | RELAXPER);
    // #endif

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
