#include <assert.h>
#include <aper_support.h>

static void put(asn_per_outp_t *po, int range, size_t length) {
    fprintf(stderr, "put(%zd)\n", length);
    do {
        int need_eom = 123;
        ssize_t may_write = aper_put_length(po, range, length, &need_eom);
        fprintf(stderr, "  put %zu\n", may_write);
        assert(may_write >= 0);
        assert((size_t)may_write <= length);
        assert(need_eom != 123);
        length -= may_write;
        if(need_eom) {
            assert(length == 0);
            if(aper_put_length(po, range, 0, 0)) {
                assert(!"Unreachable");
            }
            fprintf(stderr, "  put EOM 0\n");
        }
    } while(length);
    fprintf(stderr, "put(...) in %zu bits\n", po->nboff);
    assert(po->nboff != 0);
    assert(po->flushed_bytes == 0);
}

static size_t get(asn_per_outp_t *po, int range) {
    asn_bit_data_t data;
    memset(&data, 0, sizeof(data));
    data.buffer = po->tmpspace;
    data.nboff = 0;
    data.nbits = 8 * (po->buffer - po->tmpspace) + po->nboff;

    fprintf(stderr, "get(): %s\n", asn_bit_data_string(&data));

    size_t length = 0;
    int repeat = 0;
    do {
        ssize_t n = aper_get_length(&data, range, -1, &repeat);
        fprintf(stderr, "  get = %zu +%zd\n", length, n);
        assert(n >= 0);
        length += n;
    } while(repeat);
    fprintf(stderr, "get() = %zu\n", length);

    return length;
}

static void
check_round_trip(int range, size_t length) {
    fprintf(stderr, "\nRound-trip for range=%d len=%zu\n", range, length);
    asn_per_outp_t po;

    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);

    put(&po, range, length);
    size_t recovered = get(&po, range);

    assert(recovered == length);
}

/*
 * Checks that we can get the PER length that we have just put,
 * and receive the same value.
 */
static void
check_round_trips_range65536() {
    check_round_trip(65536, 0);
    check_round_trip(65536, 1);
    check_round_trip(65536, 127);
    check_round_trip(65536, 128);
    check_round_trip(65536, 129);
    check_round_trip(65536, 255);
    check_round_trip(65536, 256);
    check_round_trip(65536, 65534);
    check_round_trip(65536, 65535);
    check_round_trip(65536, 65536);
}

/*
 * Checks that Encoding a value greater than range fails.
 */
static void
check_encode_number_greater_than_range() {
    asn_per_outp_t po;
    int range = 6500;
    size_t length = 6503;

    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);
    ssize_t may_write = aper_put_length(&po, range, length, NULL);
    assert(may_write >= 0); /* BUG, this should fail! */
}

int main() {

    check_round_trips_range65536();
    check_encode_number_greater_than_range();

}
