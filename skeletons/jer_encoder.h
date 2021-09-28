/*-
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_JER_ENCODER_H_
#define	_JER_ENCODER_H_

#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/* Flags used by the jer_encode() and (*jer_type_encoder_f), defined below */
enum jer_encoder_flags_e {
	/* Mode of encoding */
	JER_F_BASIC	= 0x01,	/* BASIC-JER (pretty-printing) */
	JER_F_CANONICAL	= 0x02	/* Canonical JER (strict rules) */
};

/*
 * The JER encoder of any type. May be invoked by the application.
 * Produces CANONICAL-JER and BASIC-JER depending on the (jer_flags).
 */
asn_enc_rval_t jer_encode(const struct asn_TYPE_descriptor_s *type_descriptor,
                          const void *struct_ptr, /* Structure to be encoded */
                          enum jer_encoder_flags_e jer_flags,
                          asn_app_consume_bytes_f *consume_bytes_cb,
                          void *app_key /* Arbitrary callback argument */
);

/*
 * The variant of the above function which dumps the BASIC-JER (JER_F_BASIC)
 * output into the chosen file pointer.
 * RETURN VALUES:
 * 	 0: The structure is printed.
 * 	-1: Problem printing the structure.
 * WARNING: No sensible errno value is returned.
 */
int jer_fprint(FILE *stream, const struct asn_TYPE_descriptor_s *td,
               const void *struct_ptr);

/*
 * A helper function that uses JER encoding/decoding to verify that:
 * - Both structures encode into the same BASIC JER.
 * - Both resulting JER byte streams can be decoded back.
 * - Both decoded structures encode into the same BASIC JER (round-trip).
 * All of this verifies equivalence between structures and a round-trip.
 * ARGUMENTS:
 *  (opt_debug_stream)  - If specified, prints ongoing details.
 */
enum jer_equivalence_e {
    JEQ_SUCCESS,          /* The only completely positive return value */
    JEQ_FAILURE,          /* General failure */
    JEQ_ENCODE1_FAILED,   /* First structure JER encoding failed */
    JEQ_ENCODE2_FAILED,   /* Second structure JER encoding failed */
    JEQ_DIFFERENT,        /* Structures encoded into different JER */
    JEQ_DECODE_FAILED,    /* Decode of the JER data failed */
    JEQ_ROUND_TRIP_FAILED /* Bad round-trip */
};
enum jer_equivalence_e jer_equivalent(
    const struct asn_TYPE_descriptor_s *type_descriptor, const void *struct1,
    const void *struct2, FILE *opt_debug_stream);

/*
 * Type of the generic JER encoder.
 */
typedef asn_enc_rval_t(jer_type_encoder_f)(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const void *struct_ptr, /* Structure to be encoded */
    int ilevel,             /* Level of indentation */
    enum jer_encoder_flags_e jer_flags,
    asn_app_consume_bytes_f *consume_bytes_cb, /* Callback */
    void *app_key                              /* Arbitrary callback argument */
);

#ifdef __cplusplus
}
#endif

#endif	/* _JER_ENCODER_H_ */
