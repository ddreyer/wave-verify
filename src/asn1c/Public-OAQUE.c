/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "Public-OAQUE.h"

static asn_TYPE_member_t asn_MBR_attributeset_3[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_attributeset_tags_3[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_attributeset_specs_3 = {
	sizeof(struct Public_OAQUE__attributeset),
	offsetof(struct Public_OAQUE__attributeset, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_attributeset_3 = {
	"attributeset",
	"attributeset",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_attributeset_tags_3,
	sizeof(asn_DEF_attributeset_tags_3)
		/sizeof(asn_DEF_attributeset_tags_3[0]), /* 1 */
	asn_DEF_attributeset_tags_3,	/* Same as above */
	sizeof(asn_DEF_attributeset_tags_3)
		/sizeof(asn_DEF_attributeset_tags_3[0]), /* 1 */
	{ 0, 0, SEQUENCE_OF_constraint },
	asn_MBR_attributeset_3,
	1,	/* Single element */
	&asn_SPC_attributeset_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_Public_OAQUE_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Public_OAQUE, params),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_Params_BLS12381_OAQUE,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"params"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Public_OAQUE, attributeset),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_attributeset_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"attributeset"
		},
};
static const ber_tlv_tag_t asn_DEF_Public_OAQUE_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Public_OAQUE_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* params */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 } /* attributeset */
};
static asn_SEQUENCE_specifics_t asn_SPC_Public_OAQUE_specs_1 = {
	sizeof(struct Public_OAQUE),
	offsetof(struct Public_OAQUE, _asn_ctx),
	asn_MAP_Public_OAQUE_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Public_OAQUE = {
	"Public-OAQUE",
	"Public-OAQUE",
	&asn_OP_SEQUENCE,
	asn_DEF_Public_OAQUE_tags_1,
	sizeof(asn_DEF_Public_OAQUE_tags_1)
		/sizeof(asn_DEF_Public_OAQUE_tags_1[0]), /* 1 */
	asn_DEF_Public_OAQUE_tags_1,	/* Same as above */
	sizeof(asn_DEF_Public_OAQUE_tags_1)
		/sizeof(asn_DEF_Public_OAQUE_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Public_OAQUE_1,
	2,	/* Elements count */
	&asn_SPC_Public_OAQUE_specs_1	/* Additional specs */
};

