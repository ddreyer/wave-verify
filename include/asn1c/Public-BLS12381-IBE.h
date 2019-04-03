/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Public_BLS12381_IBE_H_
#define	_Public_BLS12381_IBE_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Params-BLS12381-IBE.h"
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Public-BLS12381-IBE */
typedef struct Public_BLS12381_IBE {
	Params_BLS12381_IBE_t	 params;
	OCTET_STRING_t	 id;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Public_BLS12381_IBE_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Public_BLS12381_IBE;

#ifdef __cplusplus
}
#endif

#endif	/* _Public_BLS12381_IBE_H_ */
#include <asn_internal.h>