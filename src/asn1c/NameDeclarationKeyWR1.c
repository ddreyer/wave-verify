/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "NameDeclarationKeyWR1.h"

static asn_TYPE_member_t asn_MBR_NameDeclarationKeyWR1_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NameDeclarationKeyWR1, envelope),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"envelope"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NameDeclarationKeyWR1, envelopeKey_ibe_BLS12381),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"envelopeKey-ibe-BLS12381"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NameDeclarationKeyWR1, Namespace),
		(ASN_TAG_CLASS_UNIVERSAL | (8 << 2)),
		0,
		&asn_DEF_EntityHash,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"namespace"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct NameDeclarationKeyWR1, namespaceLocation),
		(ASN_TAG_CLASS_UNIVERSAL | (8 << 2)),
		0,
		&asn_DEF_Location,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"namespaceLocation"
		},
};
static const ber_tlv_tag_t asn_DEF_NameDeclarationKeyWR1_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NameDeclarationKeyWR1_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 1 }, /* envelope */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, -1, 0 }, /* envelopeKey-ibe-BLS12381 */
    { (ASN_TAG_CLASS_UNIVERSAL | (8 << 2)), 2, 0, 1 }, /* namespace */
    { (ASN_TAG_CLASS_UNIVERSAL | (8 << 2)), 3, -1, 0 } /* namespaceLocation */
};
static asn_SEQUENCE_specifics_t asn_SPC_NameDeclarationKeyWR1_specs_1 = {
	sizeof(struct NameDeclarationKeyWR1),
	offsetof(struct NameDeclarationKeyWR1, _asn_ctx),
	asn_MAP_NameDeclarationKeyWR1_tag2el_1,
	4,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NameDeclarationKeyWR1 = {
	"NameDeclarationKeyWR1",
	"NameDeclarationKeyWR1",
	&asn_OP_SEQUENCE,
	asn_DEF_NameDeclarationKeyWR1_tags_1,
	sizeof(asn_DEF_NameDeclarationKeyWR1_tags_1)
		/sizeof(asn_DEF_NameDeclarationKeyWR1_tags_1[0]), /* 1 */
	asn_DEF_NameDeclarationKeyWR1_tags_1,	/* Same as above */
	sizeof(asn_DEF_NameDeclarationKeyWR1_tags_1)
		/sizeof(asn_DEF_NameDeclarationKeyWR1_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_NameDeclarationKeyWR1_1,
	4,	/* Elements count */
	&asn_SPC_NameDeclarationKeyWR1_specs_1	/* Additional specs */
};

