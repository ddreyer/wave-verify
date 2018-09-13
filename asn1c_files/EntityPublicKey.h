/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_EntityPublicKey_H_
#define	_EntityPublicKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EXTERNAL.h"
#include "Capability.h"
#include <asn_SET_OF.h>
#include <constr_SET_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EntityPublicKey */
typedef struct EntityPublicKey {
	struct EntityPublicKey__capabilityFlags {
		A_SET_OF(Capability_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} capabilityFlags;
	EXTERNAL_t	 key;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EntityPublicKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EntityPublicKey;
extern asn_SEQUENCE_specifics_t asn_SPC_EntityPublicKey_specs_1;
extern asn_TYPE_member_t asn_MBR_EntityPublicKey_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _EntityPublicKey_H_ */
#include <asn_internal.h>
