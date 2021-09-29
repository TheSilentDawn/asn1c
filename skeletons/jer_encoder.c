/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <stdio.h>
#include <errno.h>

/*
 * The JER encoder of any type. May be invoked by the application.
 */
asn_enc_rval_t
jer_encode(const asn_TYPE_descriptor_t *td, const void *sptr,
           asn_app_consume_bytes_f *cb,
           void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
	asn_enc_rval_t tmper;
	const char *mname;
	size_t mlen;
	int xcan = (jer_flags & JER_F_CANONICAL) ? 1 : 2;

	if(!td || !sptr) goto cb_failed;

	mname = td->xml_tag;
	mlen = strlen(mname);

	ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

	tmper = td->op->jer_encoder(td, sptr, 1, jer_flags, cb, app_key);
	if(tmper.encoded == -1) return tmper;
	er.encoded += tmper.encoded;

	ASN__CALLBACK3("</", 2, mname, mlen, ">\n", xcan);

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}

/*
 * This is a helper function for jer_fprint, which directs all incoming data
 * into the provided file descriptor.
 */
static int
jer__print2fp(const void *buffer, size_t size, void *app_key) {
	FILE *stream = (FILE *)app_key;

	if(fwrite(buffer, 1, size, stream) != size)
		return -1;

	return 0;
}

int
jer_fprint(FILE *stream, const asn_TYPE_descriptor_t *td, const void *sptr) {
	asn_enc_rval_t er = {0,0,0};

	if(!stream) stream = stdout;
	if(!td || !sptr)
		return -1;

	er = jer_encode(td, sptr, JER_F_BASIC, jer__print2fp, stream);
	if(er.encoded == -1)
		return -1;

	return fflush(stream);
}

struct jer_buffer {
    char *buffer;
    size_t buffer_size;
    size_t allocated_size;
};

static int
jer__buffer_append(const void *buffer, size_t size, void *app_key) {
    struct jer_buffer *xb = app_key;

    while(xb->buffer_size + size + 1 > xb->allocated_size) {
        size_t new_size = 2 * (xb->allocated_size ? xb->allocated_size : 64);
        char *new_buf = MALLOC(new_size);
        if(!new_buf) return -1;
        if (xb->buffer) {
            memcpy(new_buf, xb->buffer, xb->buffer_size);
        }
        FREEMEM(xb->buffer);
        xb->buffer = new_buf;
        xb->allocated_size = new_size;
    }

    memcpy(xb->buffer + xb->buffer_size, buffer, size);
    xb->buffer_size += size;
    xb->buffer[xb->buffer_size] = '\0';
    return 0;
}

enum jer_equivalence_e
jer_equivalent(const struct asn_TYPE_descriptor_s *td, const void *struct1,
               const void *struct2, FILE *opt_debug_stream) {
    struct jer_buffer xb1 = {0, 0, 0};
    struct jer_buffer xb2 = {0, 0, 0};
    asn_enc_rval_t e1, e2;
    asn_dec_rval_t rval;
    void *sptr = NULL;

    if(!td || !struct1 || !struct2) {
        if(opt_debug_stream) {
            if(!td) fprintf(opt_debug_stream, "Type descriptor missing\n");
            if(!struct1) fprintf(opt_debug_stream, "Structure 1 missing\n");
            if(!struct2) fprintf(opt_debug_stream, "Structure 2 missing\n");
        }
        return XEQ_FAILURE;
    }

    e1 = jer_encode(td, struct1, JER_F_BASIC, jer__buffer_append, &xb1);
    if(e1.encoded == -1) {
        if(opt_debug_stream) {
            fprintf(stderr, "JER Encoding of %s failed\n", td->name);
        }
        FREEMEM(xb1.buffer);
        return XEQ_ENCODE1_FAILED;
    }

    e2 = jer_encode(td, struct2, JER_F_BASIC, jer__buffer_append, &xb2);
    if(e2.encoded == -1) {
        if(opt_debug_stream) {
            fprintf(stderr, "JER Encoding of %s failed\n", td->name);
        }
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ENCODE1_FAILED;
    }

    if(xb1.buffer_size != xb2.buffer_size
       || memcmp(xb1.buffer, xb2.buffer, xb1.buffer_size) != 0) {
        if(opt_debug_stream) {
            fprintf(opt_debug_stream,
                    "Structures JER-encoded into different byte streams:\n=== "
                    "Structure 1 ===\n%s\n=== Structure 2 ===\n%s\n",
                    xb1.buffer, xb2.buffer);
        }
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_DIFFERENT;
    } else {
        if(opt_debug_stream) {
            fprintf(opt_debug_stream,
                    "Both structures encoded into the same JER byte stream "
                    "of size %" ASN_PRI_SIZE ":\n%s",
                    xb1.buffer_size, xb1.buffer);
        }
    }
    // this needs to be changed as jer_decode does not exist

    rval = jer_decode(NULL, td, (void **)&sptr, xb1.buffer,
               xb1.buffer_size);
    switch(rval.code) {
    case RC_OK:
        break;
    case RC_WMORE:
        if(opt_debug_stream) {
            fprintf(opt_debug_stream,
                    "Structure %s JER decode unexpectedly requires "
                    "more data:\n%s\n",
                    td->name, xb1.buffer);
        }
        /* Fall through */
    case RC_FAIL:
    default:
        if(opt_debug_stream) {
            fprintf(opt_debug_stream,
                    "Structure %s JER decoding resulted in failure.\n",
                    td->name);
        }
        ASN_STRUCT_FREE(*td, sptr);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_DECODE_FAILED;
    }

    if(rval.consumed != xb1.buffer_size
       && ((rval.consumed > xb1.buffer_size)
           || jer_whitespace_span(xb1.buffer + rval.consumed,
                                  xb1.buffer_size - rval.consumed)
                  != (xb1.buffer_size - rval.consumed))) {
        if(opt_debug_stream) {
            fprintf(opt_debug_stream,
                    "Round-trip decode of %s required less bytes (%" ASN_PRI_SIZE ") than "
                    "encoded (%" ASN_PRI_SIZE ")\n",
                    td->name, rval.consumed, xb1.buffer_size);
        }
        ASN_STRUCT_FREE(*td, sptr);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ROUND_TRIP_FAILED;
    }

    /*
     * Reuse xb2 to encode newly decoded structure.
     */
    FREEMEM(xb2.buffer);
    memset(&xb2, 0, sizeof(xb2));

    e2 = jer_encode(td, sptr, JER_F_BASIC, jer__buffer_append, &xb2);
    if(e2.encoded == -1) {
        if(opt_debug_stream) {
            fprintf(stderr, "JER Encoding of round-trip decode of %s failed\n",
                    td->name);
        }
        ASN_STRUCT_FREE(*td, sptr);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ROUND_TRIP_FAILED;
    }

    ASN_STRUCT_FREE(*td, sptr);
    sptr = 0;

    if(xb1.buffer_size != xb2.buffer_size
       || memcmp(xb1.buffer, xb2.buffer, xb1.buffer_size) != 0) {
        if(opt_debug_stream) {
            fprintf(opt_debug_stream,
                    "JER Encoding of round-trip decode of %s resulted in "
                    "different byte stream:\n"
                    "=== Original ===\n%s\n"
                    "=== Round-tripped ===\n%s\n",
                    xb1.buffer, xb2.buffer, td->name);
        }
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ROUND_TRIP_FAILED;
    }

	FREEMEM(xb1.buffer);
	FREEMEM(xb2.buffer);
	return XEQ_SUCCESS;
}

