/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_WR1Envelope_H_
#define	_WR1Envelope_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* WR1Envelope */
typedef struct WR1Envelope {
	OCTET_STRING_t	 bodyKeys_oaque;
	struct WR1Envelope__partition {
		A_SEQUENCE_OF(OCTET_STRING_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} partition;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} WR1Envelope_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_WR1Envelope;

#ifdef __cplusplus
}
#endif

#endif	/* _WR1Envelope_H_ */
#include <asn_internal.h>
