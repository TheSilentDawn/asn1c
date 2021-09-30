/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <constr_SEQUENCE.h>
#include <OPEN_TYPE.h>

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

#undef JER_ADVANCE
#define JER_ADVANCE(num_bytes)            \
    do {                                  \
        size_t num = (num_bytes);         \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        consumed_myself += num;           \
    } while(0)

asn_enc_rval_t SEQUENCE_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int ilevel, enum jer_encoder_flags_e flags,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};
    int xcan = 0;
    asn_TYPE_descriptor_t *tmp_def_val_td = 0;
    void *tmp_def_val = 0;
    size_t edx;

    if(!sptr) ASN__ENCODE_FAILED;

    er.encoded = 0;

    for(edx = 0; edx < td->elements_count; edx++) {
        asn_enc_rval_t tmper = {0,0,0};
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;
        const char *mname = elm->name;
        unsigned int mlen = strlen(mname);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                assert(tmp_def_val == 0);
                if(elm->default_value_set) {
                    if(elm->default_value_set(&tmp_def_val)) {
                        ASN__ENCODE_FAILED;
                    } else {
                        memb_ptr = tmp_def_val;
                        tmp_def_val_td = elm->type;
                    }
                } else if(elm->optional) {
                    continue;
                } else {
                    /* Mandatory element is missing */
                    ASN__ENCODE_FAILED;
                }
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        if(!xcan) ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

        /* Print the member itself */
        tmper = elm->type->op->jer_encoder(elm->type, memb_ptr, ilevel + 1,
                                           flags, cb, app_key);
        if(tmp_def_val) {
            ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
            tmp_def_val = 0;
        }
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;

        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    if(tmp_def_val) ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
    ASN__ENCODE_FAILED;
}