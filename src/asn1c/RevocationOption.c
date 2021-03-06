/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "RevocationOption.h"

asn_TYPE_member_t asn_MBR_RevocationOption_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RevocationOption, critical),
		(ASN_TAG_CLASS_UNIVERSAL | (1 << 2)),
		0,
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"critical"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RevocationOption, scheme),
		(ASN_TAG_CLASS_UNIVERSAL | (8 << 2)),
		0,
		&asn_DEF_EXTERNAL,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"scheme"
		},
};
static const ber_tlv_tag_t asn_DEF_RevocationOption_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RevocationOption_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (1 << 2)), 0, 0, 0 }, /* critical */
    { (ASN_TAG_CLASS_UNIVERSAL | (8 << 2)), 1, 0, 0 } /* scheme */
};
asn_SEQUENCE_specifics_t asn_SPC_RevocationOption_specs_1 = {
	sizeof(struct RevocationOption),
	offsetof(struct RevocationOption, _asn_ctx),
	asn_MAP_RevocationOption_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RevocationOption = {
	"RevocationOption",
	"RevocationOption",
	&asn_OP_SEQUENCE,
	asn_DEF_RevocationOption_tags_1,
	sizeof(asn_DEF_RevocationOption_tags_1)
		/sizeof(asn_DEF_RevocationOption_tags_1[0]), /* 1 */
	asn_DEF_RevocationOption_tags_1,	/* Same as above */
	sizeof(asn_DEF_RevocationOption_tags_1)
		/sizeof(asn_DEF_RevocationOption_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_RevocationOption_1,
	2,	/* Elements count */
	&asn_SPC_RevocationOption_specs_1	/* Additional specs */
};

