package verify

/*
#cgo CFLAGS: -I ../../include
#cgo LDFLAGS: ${SRCDIR}/verify.a
#include "verify/verify.hpp"
*/
import "C"

import (
	"github.com/immesys/wave/eapi/pb"
)

func VerifyProof(proofDER []byte, subject []byte, requiredRTreePolicy *pb.RTreePolicy) {
	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	(*spol).NamespaceLocation = *nsloc

	wrappedPol := serdes.WaveWireObject{
		Content: asn1.NewExternal(*spol),
	}
	polBytes, err := asn1.Marshal(wrappedPol.Content)
	if err != nil {
		panic(err)
	}
	
	polDER := (*C.char)(unsafe.Pointer(&polBytes[0]))
	subject := (*C.char)(unsafe.Pointer(&subjectHash[2]))
	proofDER := (*C.char)(unsafe.Pointer(&DER[0]))
	C.verifyProof(char *proofDER, size_t proofDERSize, char *subject, size_t subj_size, 
		char *policyDER, size_t policyDER_size);

}