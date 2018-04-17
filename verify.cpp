#include "objects.h"
#include <string>
#include <fstream>
#include <streambuf>
#include <iostream>
#include <stdio.h>

using namespace std;
int main() {
    std::ifstream t("proof.pem");
    std::string str((std::istreambuf_iterator<char>(t)),
                             std::istreambuf_iterator<char>());
    cout << str << "\n";
    WaveExplicitProof w((const WaveExplicitProof &) str); 
    printf("Hello");


//     int code = 0;		/* return code */
//     BBCard *cardPtr = NULL;	/* pointer to decoded data */

//     /*
//      * Handle ASN.1/C++ runtime errors with C++ exceptions.
//      */
//     asn1_set_error_handling(throw_error, TRUE);

//     try {
// 	bcas_Control ctl;	/* ASN.1/C++ control object */

// 	try {
// 	    EncodedBuffer encodedData;	/* encoded data */
// 	    BBCard_PDU pdu;	 coding container for a BBCard value 
// 	    int encRule;	/* default encoding rules */

// #ifdef RELAXED_MODE
// 	    /*
// 	     * Set relaxed mode.
// 	     */
// 	    ctl.setEncodingFlags(NOCONSTRAIN | RELAXBER | RELAXPER);
// 	    ctl.setDecodingFlags(NOCONSTRAIN | RELAXBER | RELAXPER);
// #endif

// 	    ctl.setEncodingFlags(ctl.getEncodingFlags() | DEBUGPDU);
// 	    ctl.setDecodingFlags(ctl.getDecodingFlags() | DEBUGPDU);

// 	    /*
// 	     * Do decoding. Note that API is the same for any encoding method.
// 	     * Get encoding rules which were specified on the ASN.1 compiler
// 	     * command line.
// 	     */
// 	    encRule = ctl.getEncodingRules();

	    /*
	     * Set the decoder's input.
	     */
	//     if (encRule == OSS_BER) {
	// 	encodedData.set_buffer(berDataLen, (char *)berEncodedData);
	//     } else if (encRule == OSS_PER_ALIGNED) {
	// 	encodedData.set_buffer(perDataLen, (char *)perEncodedData);
	//     }

	//     /*
	//      * Print the encoded message.
	//      */
	//     printf("Printing the %s-encoded PDU...\n\n",
	// 		encRule == OSS_BER ? "BER": "PER");
	//     encodedData.print_hex(ctl);

	//     /*
	//      * Decode the encoded PDU whose encoding is in "encodedData".
	//      * An exception will be thrown on any error.
	//      */
	//     printf("\nThe decoder's trace messages (only for SOED)...\n\n");
	//     pdu.decode(ctl, encodedData);

	    
	//      * Read and print the decoded data.
	     
	//     cardPtr = pdu.get_data();
	//     printCard(cardPtr);
	// } catch (ASN1Exception &exc) {
	//     /*
	//      * An error occurred during decoding.
	//      */
	//     code = report_error(&ctl, "decode", exc);
	// }
 //    } catch (ASN1Exception &exc) {
	// /*
	//  * An error occurred during control object initialization.
	//  */
	// code = report_error(NULL, "initialization", exc);
 //    } catch (...) {
	// /*
	//  * An unexpected exception is caught.
	//  */
	// printf("Unexpected exception caught.\n");
	// code = -1;
 //    }
 //    /*
 //     * Delete the decoded data (if there are any).
 //     */
 //    delete cardPtr;
 //    return code;
}
