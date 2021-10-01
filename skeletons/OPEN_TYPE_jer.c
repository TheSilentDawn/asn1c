/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>

asn_enc_rval_t
OPEN_TYPE_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_per_constraints_t *constraints,
                      const void *sptr, asn_per_outp_t *po) {
    const void *memb_ptr;   /* Pointer to the member */
    asn_TYPE_member_t *elm; /* CHOICE's element */
    asn_enc_rval_t er = {0,0,0};
    unsigned present;

    (void)constraints;

    present = CHOICE_variant_get_presence(td, sptr);
    if(present == 0 || present > td->elements_count) {
        ASN__ENCODE_FAILED;
    } else {
        present--;
    }

    ASN_DEBUG("Encoding %s OPEN TYPE element %d", td->name, present);

    elm = &td->elements[present];
    if(elm->flags & ATF_POINTER) {
        /* Member is a pointer to another structure */
        memb_ptr =
            *(const void *const *)((const char *)sptr + elm->memb_offset);
        if(!memb_ptr) ASN__ENCODE_FAILED;
    } else {
        memb_ptr = (const char *)sptr + elm->memb_offset;
    }

    if(jer_open_type_put(elm->type, NULL, memb_ptr, po) < 0) {
        ASN__ENCODE_FAILED;
    }

    er.encoded = 0;
    ASN__ENCODED_OK(er);
}
