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
	int xcan = 0;

	if(!td || !sptr) goto cb_failed;

	mname = td->xml_tag;
	mlen = strlen(mname);

	ASN__CALLBACK3("{\n\"", 3, mname, mlen, "\":", 2);

	tmper = td->op->jer_encoder(td, sptr, 1, 0, cb, app_key);
	if(tmper.encoded == -1) return tmper;
	er.encoded += tmper.encoded;

        ASN__CALLBACK("}", 1);
        //	ASN__CALLBACK3("</", 2, mname, mlen, ">\n", xcan);

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

	er = jer_encode(td, sptr, jer__print2fp, stream);
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


