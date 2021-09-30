/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <INTEGER.h>

struct e2v_key {
    const char *start;
    const char *stop;
    const asn_INTEGER_enum_map_t *vemap;
    const unsigned int *evmap;
};
static int
INTEGER__compar_enum2value(const void *kp, const void *am) {
    const struct e2v_key *key = (const struct e2v_key *)kp;
    const asn_INTEGER_enum_map_t *el = (const asn_INTEGER_enum_map_t *)am;
    const char *ptr, *end, *name;

    /* Remap the element (sort by different criterion) */
    el = key->vemap + key->evmap[el - key->vemap];

    /* Compare strings */
    for(ptr = key->start, end = key->stop, name = el->enum_name;
            ptr < end; ptr++, name++) {
        if(*ptr != *name || !*name)
            return *(const unsigned char *)ptr - *(const unsigned char *)name;
    }
    return name[0] ? -1 : 0;
}

static const asn_INTEGER_enum_map_t *
INTEGER_map_enum2value(const asn_INTEGER_specifics_t *specs, const char *lstart,
                       const char *lstop) {
    const asn_INTEGER_enum_map_t *el_found;
    int count = specs ? specs->map_count : 0;
    struct e2v_key key;
    const char *lp;

    if(!count) return NULL;

    /* Guaranteed: assert(lstart < lstop); */
    /* Figure out the tag name */
    for(lstart++, lp = lstart; lp < lstop; lp++) {
        switch(*lp) {
        case 9: case 10: case 11: case 12: case 13: case 32: /* WSP */
        case 0x2f: /* '/' */ case 0x3e: /* '>' */
            break;
        default:
            continue;
        }
        break;
    }
    if(lp == lstop) return NULL;  /* No tag found */
    lstop = lp;

    key.start = lstart;
    key.stop = lstop;
    key.vemap = specs->value2enum;
    key.evmap = specs->enum2value;
    el_found = (asn_INTEGER_enum_map_t *)bsearch(&key,
        specs->value2enum, count, sizeof(specs->value2enum[0]),
        INTEGER__compar_enum2value);
    if(el_found) {
        /* Remap enum2value into value2enum */
        el_found = key.vemap + key.evmap[el_found - key.vemap];
    }
    return el_found;
}

static int
INTEGER_st_prealloc(INTEGER_t *st, int min_size) {
    void *p = MALLOC(min_size + 1);
    if(p) {
        void *b = st->buf;
        st->size = 0;
        st->buf = p;
        FREEMEM(b);
        return 0;
    } else {
        return -1;
    }
}


asn_enc_rval_t
INTEGER_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, enum jer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;
    (void)flags;

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = INTEGER__dump(td, st, cb, app_key, 1);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
