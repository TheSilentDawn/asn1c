#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

#include <OCTET_STRING.h>
#include <OCTET_STRING.c>
#include <OCTET_STRING_aper.c>
#include <BIT_STRING.h>
#include <per_support.c>
#include <aper_support.h>

static char buf[1024];

static int
write_buf(const void *buffer, size_t size, void *key) {
	size_t *off = key;
	assert(*off + size < sizeof(buf));
	memcpy(buf + *off, buffer, size);
	*off += size;
	return 0;
}

extern asn_enc_rval_t
OCTET_STRING_encode_aper(const asn_TYPE_descriptor_t *td,
                         const asn_per_constraints_t *constraints,
                         const void *sptr, asn_per_outp_t *po);

static void
encode_constrained_size(char *orig, char *encoded, long lbound, unsigned long ubound, int bit_range) {
	OCTET_STRING_t os;
	asn_enc_rval_t er;
	struct asn_per_constraints_s cts;
	asn_per_outp_t po;
	char *out_str;

	memset(&os, 0, sizeof(os));
	OCTET_STRING_fromString(&os, orig);

	memset(&po, 0, sizeof(po));
	memset(&cts, 0, sizeof(cts));

	cts.value.flags = APC_UNCONSTRAINED;
	cts.value.range_bits = -1;
	cts.value.effective_bits = -1;
	cts.value.lower_bound = 0;
	cts.value.upper_bound = 0;

	cts.size.flags = APC_CONSTRAINED;
	cts.size.range_bits = bit_range;
	cts.size.effective_bits = bit_range;
	cts.size.lower_bound = lbound;
	cts.size.upper_bound = ubound;

	po.buffer = po.tmpspace;
	po.nboff = 0;
	po.nbits = 8 * sizeof(po.tmpspace);
	po.output = write_buf;

	er = OCTET_STRING_encode_aper(&asn_DEF_OCTET_STRING, &cts, &os, &po);

	assert(er.encoded >= 0);
	unsigned l = (po.buffer - po.tmpspace) + (po.nboff + 7)/8;
	memcpy(&buf[er.encoded], po.tmpspace, l);
	er.encoded += l;

	buf[er.encoded] = '\0';
	/* Get rid of length at start: */
	out_str = &buf[0] + (cts.size.effective_bits + 7) / 8;
	printf("Orig: [%s], encoded: [%s], check [%s]\n",
		orig, out_str, encoded);
	assert(strcmp(out_str, encoded) == 0);
	ASN_STRUCT_RESET(asn_DEF_OCTET_STRING, &os);
}

int
main() {

	encode_constrained_size("12345678901234567890", "12345678901234567890", 1, 9600, 14);

	return 0;
}
