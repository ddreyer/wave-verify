/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_RevocationOption_H_
#define	_RevocationOption_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include "EXTERNAL.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RevocationOption */
typedef struct RevocationOption {
	BOOLEAN_t	 critical;
	EXTERNAL_t	 scheme;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RevocationOption_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RevocationOption;
extern asn_SEQUENCE_specifics_t asn_SPC_RevocationOption_specs_1;
extern asn_TYPE_member_t asn_MBR_RevocationOption_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RevocationOption_H_ */
#include <asn_internal.h>