/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_TrustLevel_H_
#define	_TrustLevel_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TrustLevel */
typedef struct TrustLevel {
	long	 trust;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TrustLevel_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TrustLevel;

#ifdef __cplusplus
}
#endif

#endif	/* _TrustLevel_H_ */
#include <asn_internal.h>
