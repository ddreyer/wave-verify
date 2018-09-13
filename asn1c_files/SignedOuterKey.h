/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_SignedOuterKey_H_
#define	_SignedOuterKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <OBJECT_IDENTIFIER.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SignedOuterKey */
typedef struct SignedOuterKey {
	struct SignedOuterKey__tbs {
		OBJECT_IDENTIFIER_t	 outerSignatureScheme;
		OCTET_STRING_t	 verifyingKey;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tbs;
	OCTET_STRING_t	 signature;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SignedOuterKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SignedOuterKey;

#ifdef __cplusplus
}
#endif

#endif	/* _SignedOuterKey_H_ */
#include <asn_internal.h>
