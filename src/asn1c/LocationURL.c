/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "WAVE-Schema"
 * 	found in "objects-lite.asn"
 * 	`asn1c -fcompound-names`
 */

#include "LocationURL.h"

static asn_TYPE_member_t asn_MBR_LocationURL_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LocationURL, value),
		(ASN_TAG_CLASS_UNIVERSAL | (12 << 2)),
		0,
		&asn_DEF_UTF8String,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"value"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LocationURL, apiVersion),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_NativeInteger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"apiVersion"
		},
};
static const ber_tlv_tag_t asn_DEF_LocationURL_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LocationURL_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 }, /* apiVersion */
    { (ASN_TAG_CLASS_UNIVERSAL | (12 << 2)), 0, 0, 0 } /* value */
};
static asn_SEQUENCE_specifics_t asn_SPC_LocationURL_specs_1 = {
	sizeof(struct LocationURL),
	offsetof(struct LocationURL, _asn_ctx),
	asn_MAP_LocationURL_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_LocationURL = {
	"LocationURL",
	"LocationURL",
	&asn_OP_SEQUENCE,
	asn_DEF_LocationURL_tags_1,
	sizeof(asn_DEF_LocationURL_tags_1)
		/sizeof(asn_DEF_LocationURL_tags_1[0]), /* 1 */
	asn_DEF_LocationURL_tags_1,	/* Same as above */
	sizeof(asn_DEF_LocationURL_tags_1)
		/sizeof(asn_DEF_LocationURL_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_LocationURL_1,
	2,	/* Elements count */
	&asn_SPC_LocationURL_specs_1	/* Additional specs */
};

