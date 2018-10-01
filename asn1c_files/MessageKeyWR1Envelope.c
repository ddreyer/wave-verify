/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "MessageKeyWR1Envelope.h"

static asn_TYPE_member_t asn_MBR_partition_2[] = {
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
static const ber_tlv_tag_t asn_DEF_partition_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_partition_specs_2 = {
	sizeof(struct MessageKeyWR1Envelope__partition),
	offsetof(struct MessageKeyWR1Envelope__partition, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_partition_2 = {
	"partition",
	"partition",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_partition_tags_2,
	sizeof(asn_DEF_partition_tags_2)
		/sizeof(asn_DEF_partition_tags_2[0]), /* 1 */
	asn_DEF_partition_tags_2,	/* Same as above */
	sizeof(asn_DEF_partition_tags_2)
		/sizeof(asn_DEF_partition_tags_2[0]), /* 1 */
	{ 0, 0, SEQUENCE_OF_constraint },
	asn_MBR_partition_2,
	1,	/* Single element */
	&asn_SPC_partition_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_MessageKeyWR1Envelope_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MessageKeyWR1Envelope, partition),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_partition_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"partition"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct MessageKeyWR1Envelope, contentsKey),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"contentsKey"
		},
};
static const ber_tlv_tag_t asn_DEF_MessageKeyWR1Envelope_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MessageKeyWR1Envelope_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 1, 0, 0 }, /* contentsKey */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* partition */
};
static asn_SEQUENCE_specifics_t asn_SPC_MessageKeyWR1Envelope_specs_1 = {
	sizeof(struct MessageKeyWR1Envelope),
	offsetof(struct MessageKeyWR1Envelope, _asn_ctx),
	asn_MAP_MessageKeyWR1Envelope_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MessageKeyWR1Envelope = {
	"MessageKeyWR1Envelope",
	"MessageKeyWR1Envelope",
	&asn_OP_SEQUENCE,
	asn_DEF_MessageKeyWR1Envelope_tags_1,
	sizeof(asn_DEF_MessageKeyWR1Envelope_tags_1)
		/sizeof(asn_DEF_MessageKeyWR1Envelope_tags_1[0]), /* 1 */
	asn_DEF_MessageKeyWR1Envelope_tags_1,	/* Same as above */
	sizeof(asn_DEF_MessageKeyWR1Envelope_tags_1)
		/sizeof(asn_DEF_MessageKeyWR1Envelope_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MessageKeyWR1Envelope_1,
	2,	/* Elements count */
	&asn_SPC_MessageKeyWR1Envelope_specs_1	/* Additional specs */
};
