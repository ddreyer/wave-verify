package verify

/*
#cgo CFLAGS: -I../../include/verify -I../../include/asn1c -I../../src/
#cgo LDFLAGS: ${SRCDIR}/../../verify.a -lstdc++ -lcrypto
#include "verify.hpp"
*/
import "C"

import (
	"unsafe"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

// Verifies a proof given the proof DER, expected subject, and required policy.
// Returns the proof expiry as a long and possibly any errors that may have occurred.
func VerifyProof(DER []byte, subjectHash []byte, reqPol *pb.RTreePolicy) (int64, error) {
	var statements []serdes.RTreeStatement
	for _, statement := range reqPol.Statements {
		phash := iapi.HashSchemeInstanceFromMultihash(statement.PermissionSet)
		if !phash.Supported() {
			return -1, wve.Err(wve.InvalidParameter, "bad namespace")
		}
		pext := phash.CanonicalForm()
		s := serdes.RTreeStatement{
			PermissionSet: *pext,
			Permissions:   statement.Permissions,
			Resource:      statement.Resource,
		}
		statements = append(statements, s)
	}

	ehash := iapi.HashSchemeInstanceFromMultihash(reqPol.Namespace)
	if !ehash.Supported() {
		return -1, wve.Err(wve.InvalidParameter, "bad namespace")
	}
	ext := ehash.CanonicalForm()
	spol := serdes.RTreePolicy{
		Namespace:  *ext,
		Statements: statements,
	}
	//This is not important
	nsloc := iapi.NewLocationSchemeInstanceURL("https://foo.com", 1).CanonicalForm()
	spol.NamespaceLocation = *nsloc

	wrappedPol := serdes.WaveWireObject{
		Content: asn1.NewExternal(spol),
	}
	polBytes, err := asn1.Marshal(wrappedPol.Content)
	if err != nil {
		panic(err)
	}

	polDER := (*C.char)(unsafe.Pointer(&polBytes[0]))
	subject := (*C.char)(unsafe.Pointer(&subjectHash[2]))
	proofDER := (*C.char)(unsafe.Pointer(&DER[0]))
	CExpiry := C.verifyProof(proofDER, C.ulong(len(DER)), subject, C.ulong(len(subjectHash)-2), polDER, C.ulong(len(polBytes)))
	if int64(CExpiry) == -1 {
		return -1, wve.Err(wve.ProofInvalid, "failed to C verify proof")
	}
	return int64(CExpiry), nil
}
