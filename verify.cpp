#include "objects.h"
#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <stdio.h>

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

/*
 * https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp
*/
static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


std::string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

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


int main() {
    std::string str("Reading in PEM file");
    cout << str << "\n";

    std::ifstream t("proof.pem");
    std::string pemStr((std::istreambuf_iterator<char>(t)),
                             std::istreambuf_iterator<char>());

    pemStr.erase(0, pemStr.find("\n") + 1);
    int idx = pemStr.find("-----END WAVE");
    pemStr.erase(idx, pemStr.find("\n", idx));

    std::string derEncodedData = base64_decode(pemStr);
    if (derEncodedData.length() == 0) {
    	cerr << "could not decode proof from DER format";
    }


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
		encodedData.set_buffer(derEncodedData.length(), (char *)derEncodedData.c_str());
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

    WaveExplicitProof *exp = wwoPtr->get_value().get_WaveExplicitProof();
    if (exp == nullptr) {
        printf("bad explicit proof\n");
    }

    // TODO: skip parsing Entities

    // retrieve attestations
    WaveExplicitProof::attestations atsts = exp->get_attestations();
    OssIndex attIndex = atsts.first();
    while (attIndex != OSS_NOINDEX) {
        AttestationReference *atst = atsts.at(attIndex);

        AttestationReference::keys keys = atst->get_keys();
        if (keys.empty()) {
            printf("atst has no keys\n");
        }
        OssIndex keyIndex = keys.first();
        while (keyIndex != OSS_NOINDEX) {
            AttestationVerifierKey *key = keys.at(keyIndex);

            AttestationVerifierKeySchemes_Type vf = key->get_value();
            AVKeyAES128_GCM *vfk = vf.get_AVKeyAES128_GCM();
            if (vfk == nullptr) {
                printf("atst key was not aes\n");
            }
        }

        attIndex = atsts.next(attIndex);

    }
    return code;
}
