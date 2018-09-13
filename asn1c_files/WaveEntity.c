/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "WaveEntity.h"

static asn_TYPE_member_t asn_MBR_keys_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_EntityPublicKey,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_keys_tags_4[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_keys_specs_4 = {
	sizeof(struct WaveEntity__tbs__keys),
	offsetof(struct WaveEntity__tbs__keys, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_keys_4 = {
	"keys",
	"keys",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_keys_tags_4,
	sizeof(asn_DEF_keys_tags_4)
		/sizeof(asn_DEF_keys_tags_4[0]), /* 1 */
	asn_DEF_keys_tags_4,	/* Same as above */
	sizeof(asn_DEF_keys_tags_4)
		/sizeof(asn_DEF_keys_tags_4[0]), /* 1 */
	{ 0, 0, SEQUENCE_OF_constraint },
	asn_MBR_keys_4,
	1,	/* Single element */
	&asn_SPC_keys_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_validity_6[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs__validity, notBefore),
		(ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),
		0,
		&asn_DEF_UTCTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notBefore"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs__validity, notAfter),
		(ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),
		0,
		&asn_DEF_UTCTime,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"notAfter"
		},
};
static const ber_tlv_tag_t asn_DEF_validity_tags_6[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_validity_tag2el_6[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 0, 0, 1 }, /* notBefore */
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 1, -1, 0 } /* notAfter */
};
static asn_SEQUENCE_specifics_t asn_SPC_validity_specs_6 = {
	sizeof(struct WaveEntity__tbs__validity),
	offsetof(struct WaveEntity__tbs__validity, _asn_ctx),
	asn_MAP_validity_tag2el_6,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_validity_6 = {
	"validity",
	"validity",
	&asn_OP_SEQUENCE,
	asn_DEF_validity_tags_6,
	sizeof(asn_DEF_validity_tags_6)
		/sizeof(asn_DEF_validity_tags_6[0]), /* 1 */
	asn_DEF_validity_tags_6,	/* Same as above */
	sizeof(asn_DEF_validity_tags_6)
		/sizeof(asn_DEF_validity_tags_6[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_validity_6,
	2,	/* Elements count */
	&asn_SPC_validity_specs_6	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_revocations_9[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_RevocationOption,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_revocations_tags_9[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_revocations_specs_9 = {
	sizeof(struct WaveEntity__tbs__revocations),
	offsetof(struct WaveEntity__tbs__revocations, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_revocations_9 = {
	"revocations",
	"revocations",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_revocations_tags_9,
	sizeof(asn_DEF_revocations_tags_9)
		/sizeof(asn_DEF_revocations_tags_9[0]), /* 1 */
	asn_DEF_revocations_tags_9,	/* Same as above */
	sizeof(asn_DEF_revocations_tags_9)
		/sizeof(asn_DEF_revocations_tags_9[0]), /* 1 */
	{ 0, 0, SEQUENCE_OF_constraint },
	asn_MBR_revocations_9,
	1,	/* Single element */
	&asn_SPC_revocations_specs_9	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_extensions_11[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Extension,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_extensions_tags_11[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_extensions_specs_11 = {
	sizeof(struct WaveEntity__tbs__extensions),
	offsetof(struct WaveEntity__tbs__extensions, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_extensions_11 = {
	"extensions",
	"extensions",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_extensions_tags_11,
	sizeof(asn_DEF_extensions_tags_11)
		/sizeof(asn_DEF_extensions_tags_11[0]), /* 1 */
	asn_DEF_extensions_tags_11,	/* Same as above */
	sizeof(asn_DEF_extensions_tags_11)
		/sizeof(asn_DEF_extensions_tags_11[0]), /* 1 */
	{ 0, 0, SEQUENCE_OF_constraint },
	asn_MBR_extensions_11,
	1,	/* Single element */
	&asn_SPC_extensions_specs_11	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_tbs_2[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs, verifyingKey),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_EntityPublicKey,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"verifyingKey"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs, keys),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_keys_4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"keys"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs, validity),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_validity_6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"validity"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs, revocations),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_revocations_9,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"revocations"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity__tbs, extensions),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_extensions_11,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"extensions"
		},
};
static const ber_tlv_tag_t asn_DEF_tbs_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_tbs_tag2el_2[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 4 }, /* verifyingKey */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 3 }, /* keys */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -2, 2 }, /* validity */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -3, 1 }, /* revocations */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 4, -4, 0 } /* extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_tbs_specs_2 = {
	sizeof(struct WaveEntity__tbs),
	offsetof(struct WaveEntity__tbs, _asn_ctx),
	asn_MAP_tbs_tag2el_2,
	5,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_tbs_2 = {
	"tbs",
	"tbs",
	&asn_OP_SEQUENCE,
	asn_DEF_tbs_tags_2,
	sizeof(asn_DEF_tbs_tags_2)
		/sizeof(asn_DEF_tbs_tags_2[0]), /* 1 */
	asn_DEF_tbs_tags_2,	/* Same as above */
	sizeof(asn_DEF_tbs_tags_2)
		/sizeof(asn_DEF_tbs_tags_2[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_tbs_2,
	5,	/* Elements count */
	&asn_SPC_tbs_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_WaveEntity_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity, tbs),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_tbs_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"tbs"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct WaveEntity, signature),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"signature"
		},
};
static const ber_tlv_tag_t asn_DEF_WaveEntity_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_WaveEntity_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* signature */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* tbs */
};
asn_SEQUENCE_specifics_t asn_SPC_WaveEntity_specs_1 = {
	sizeof(struct WaveEntity),
	offsetof(struct WaveEntity, _asn_ctx),
	asn_MAP_WaveEntity_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_WaveEntity = {
	"WaveEntity",
	"WaveEntity",
	&asn_OP_SEQUENCE,
	asn_DEF_WaveEntity_tags_1,
	sizeof(asn_DEF_WaveEntity_tags_1)
		/sizeof(asn_DEF_WaveEntity_tags_1[0]), /* 1 */
	asn_DEF_WaveEntity_tags_1,	/* Same as above */
	sizeof(asn_DEF_WaveEntity_tags_1)
		/sizeof(asn_DEF_WaveEntity_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_WaveEntity_1,
	2,	/* Elements count */
	&asn_SPC_WaveEntity_specs_1	/* Additional specs */
};

