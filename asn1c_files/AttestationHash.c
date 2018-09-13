/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "AttestationHash.h"

/*
 * This type is implemented using Hash,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_AttestationHash_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (8 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_AttestationHash = {
	"AttestationHash",
	"AttestationHash",
	&asn_OP_SEQUENCE,
	asn_DEF_AttestationHash_tags_1,
	sizeof(asn_DEF_AttestationHash_tags_1)
		/sizeof(asn_DEF_AttestationHash_tags_1[0]) - 1, /* 1 */
	asn_DEF_AttestationHash_tags_1,	/* Same as above */
	sizeof(asn_DEF_AttestationHash_tags_1)
		/sizeof(asn_DEF_AttestationHash_tags_1[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_EXTERNAL_1,
	4,	/* Elements count */
	&asn_SPC_EXTERNAL_specs_1	/* Additional specs */
};

