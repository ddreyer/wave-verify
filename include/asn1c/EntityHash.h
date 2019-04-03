/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_EntityHash_H_
#define	_EntityHash_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EntityHash */
typedef Hash_t	 EntityHash_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EntityHash;
asn_struct_free_f EntityHash_free;
asn_struct_print_f EntityHash_print;
asn_constr_check_f EntityHash_constraint;
ber_type_decoder_f EntityHash_decode_ber;
der_type_encoder_f EntityHash_encode_der;
xer_type_decoder_f EntityHash_decode_xer;
xer_type_encoder_f EntityHash_encode_xer;
oer_type_decoder_f EntityHash_decode_oer;
oer_type_encoder_f EntityHash_encode_oer;
per_type_decoder_f EntityHash_decode_uper;
per_type_encoder_f EntityHash_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _EntityHash_H_ */
#include <asn_internal.h>