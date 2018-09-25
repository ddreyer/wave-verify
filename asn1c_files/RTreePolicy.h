/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_RTreePolicy_H_
#define	_RTreePolicy_H_


#include <asn_application.h>

/* Including external dependencies */
#include "EntityHash.h"
#include "Location.h"
#include <NativeInteger.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RTreeStatement;

/* RTreePolicy */
typedef struct RTreePolicy {
	EntityHash_t	 Namespace;
	Location_t	 namespaceLocation;
	long	 indirections;
	struct RTreePolicy__statements {
		A_SEQUENCE_OF(struct RTreeStatement) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} statements;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RTreePolicy_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RTreePolicy;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RTreeStatement.h"

#endif	/* _RTreePolicy_H_ */
#include <asn_internal.h>
