/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_NameDeclarationKeyWR1_H_
#define	_NameDeclarationKeyWR1_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include "EntityHash.h"
#include "Location.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NameDeclarationKeyWR1 */
typedef struct NameDeclarationKeyWR1 {
	OCTET_STRING_t	 envelope;
	OCTET_STRING_t	 envelopeKey_ibe_BLS12381;
	EntityHash_t	 Namespace;
	Location_t	 namespaceLocation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NameDeclarationKeyWR1_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NameDeclarationKeyWR1;

#ifdef __cplusplus
}
#endif

#endif	/* _NameDeclarationKeyWR1_H_ */
#include <asn_internal.h>
