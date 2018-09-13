/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_MessageKeyCurve25519ECDH_H_
#define	_MessageKeyCurve25519ECDH_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MessageKeyCurve25519ECDH */
typedef struct MessageKeyCurve25519ECDH {
	OCTET_STRING_t	 ciphertext;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MessageKeyCurve25519ECDH_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MessageKeyCurve25519ECDH;

#ifdef __cplusplus
}
#endif

#endif	/* _MessageKeyCurve25519ECDH_H_ */
#include <asn_internal.h>
