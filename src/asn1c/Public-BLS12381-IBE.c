/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "Public-BLS12381-IBE.h"

static asn_TYPE_member_t asn_MBR_Public_BLS12381_IBE_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Public_BLS12381_IBE, params),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_Params_BLS12381_IBE,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"params"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Public_BLS12381_IBE, id),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"id"
		},
};
static const ber_tlv_tag_t asn_DEF_Public_BLS12381_IBE_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Public_BLS12381_IBE_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 1 }, /* params */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, -1, 0 } /* id */
};
static asn_SEQUENCE_specifics_t asn_SPC_Public_BLS12381_IBE_specs_1 = {
	sizeof(struct Public_BLS12381_IBE),
	offsetof(struct Public_BLS12381_IBE, _asn_ctx),
	asn_MAP_Public_BLS12381_IBE_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Public_BLS12381_IBE = {
	"Public-BLS12381-IBE",
	"Public-BLS12381-IBE",
	&asn_OP_SEQUENCE,
	asn_DEF_Public_BLS12381_IBE_tags_1,
	sizeof(asn_DEF_Public_BLS12381_IBE_tags_1)
		/sizeof(asn_DEF_Public_BLS12381_IBE_tags_1[0]), /* 1 */
	asn_DEF_Public_BLS12381_IBE_tags_1,	/* Same as above */
	sizeof(asn_DEF_Public_BLS12381_IBE_tags_1)
		/sizeof(asn_DEF_Public_BLS12381_IBE_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Public_BLS12381_IBE_1,
	2,	/* Elements count */
	&asn_SPC_Public_BLS12381_IBE_specs_1	/* Additional specs */
};
