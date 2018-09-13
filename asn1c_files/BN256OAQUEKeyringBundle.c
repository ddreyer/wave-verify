/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "BN256OAQUEKeyringBundle.h"

static asn_TYPE_member_t asn_MBR_entries_3[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_BN256OAQUEBundleEntry,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_entries_tags_3[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_entries_specs_3 = {
	sizeof(struct BN256OAQUEKeyringBundle__entries),
	offsetof(struct BN256OAQUEKeyringBundle__entries, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_entries_3 = {
	"entries",
	"entries",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_entries_tags_3,
	sizeof(asn_DEF_entries_tags_3)
		/sizeof(asn_DEF_entries_tags_3[0]), /* 1 */
	asn_DEF_entries_tags_3,	/* Same as above */
	sizeof(asn_DEF_entries_tags_3)
		/sizeof(asn_DEF_entries_tags_3[0]), /* 1 */
	{ 0, 0, SEQUENCE_OF_constraint },
	asn_MBR_entries_3,
	1,	/* Single element */
	&asn_SPC_entries_specs_3	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_BN256OAQUEKeyringBundle_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct BN256OAQUEKeyringBundle, params),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_Params_BN256_OAQUE,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"params"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BN256OAQUEKeyringBundle, entries),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_entries_3,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"entries"
		},
};
static const ber_tlv_tag_t asn_DEF_BN256OAQUEKeyringBundle_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_BN256OAQUEKeyringBundle_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* params */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 } /* entries */
};
static asn_SEQUENCE_specifics_t asn_SPC_BN256OAQUEKeyringBundle_specs_1 = {
	sizeof(struct BN256OAQUEKeyringBundle),
	offsetof(struct BN256OAQUEKeyringBundle, _asn_ctx),
	asn_MAP_BN256OAQUEKeyringBundle_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_BN256OAQUEKeyringBundle = {
	"BN256OAQUEKeyringBundle",
	"BN256OAQUEKeyringBundle",
	&asn_OP_SEQUENCE,
	asn_DEF_BN256OAQUEKeyringBundle_tags_1,
	sizeof(asn_DEF_BN256OAQUEKeyringBundle_tags_1)
		/sizeof(asn_DEF_BN256OAQUEKeyringBundle_tags_1[0]), /* 1 */
	asn_DEF_BN256OAQUEKeyringBundle_tags_1,	/* Same as above */
	sizeof(asn_DEF_BN256OAQUEKeyringBundle_tags_1)
		/sizeof(asn_DEF_BN256OAQUEKeyringBundle_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_BN256OAQUEKeyringBundle_1,
	2,	/* Elements count */
	&asn_SPC_BN256OAQUEKeyringBundle_specs_1	/* Additional specs */
};

