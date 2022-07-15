#include <assert.h>
#include <aper_support.h>

static void put(asn_per_outp_t *po, ssize_t lb, ssize_t ub, size_t n) {
    fprintf(stderr, "put(%zd)\n", n);
    do {
        int need_eom = 123;
        ssize_t may_write = aper_put_length(po, lb, ub, n, &need_eom);
        fprintf(stderr, "  put %zu\n", may_write);
        assert(may_write >= 0);
        assert((size_t)may_write <= n);
        assert(need_eom != 123);
        n -= may_write;
        if(need_eom) {
            assert(n == 0);
            if(aper_put_length(po, -1, -1, 0, NULL)) {
                assert(!"Unreachable");
            }
            fprintf(stderr, "  put EOM 0\n");
        }
    } while(n);
    fprintf(stderr, "put(...) in %zu bits\n", po->nboff);
    assert(po->nboff != 0);
    assert(po->flushed_bytes == 0);
}

static size_t get(asn_per_outp_t *po, ssize_t lb, ssize_t ub) {
    asn_bit_data_t data;
    memset(&data, 0, sizeof(data));
    data.buffer = po->tmpspace;
    data.nboff = 0;
    data.nbits = 8 * (po->buffer - po->tmpspace) + po->nboff;

    fprintf(stderr, "get(): %s\n", asn_bit_data_string(&data));

    size_t length = 0;
    int repeat = 0;
    do {
        ssize_t n = aper_get_length(&data, lb, ub, -1, &repeat);
        fprintf(stderr, "  get = %zu +%zd\n", length, n);
        assert(n >= 0);
        length += n;
    } while(repeat);
    fprintf(stderr, "get() = %zu\n", length);

    return length;
}

static void
check_round_trip(ssize_t lb, ssize_t ub, size_t n) {
    fprintf(stderr, "\nRound-trip for range=(%zd..%zd) n=%zu\n", lb, ub, n);
    asn_per_outp_t po;

    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);

    put(&po, lb, ub, n);
    size_t recovered = get(&po, lb, ub);

    assert(recovered == n);
}

/*
 * Checks that we can get the PER length that we have just put,
 * and receive the same value.
 */
static void
check_round_trips_range65536() {
    check_round_trip(0, 65535, 0);
    check_round_trip(0, 65535, 1);
    check_round_trip(0, 65535, 127);
    check_round_trip(0, 65535, 128);
    check_round_trip(0, 65535, 129);
    check_round_trip(0, 65535, 255);
    check_round_trip(0, 65535, 256);
    check_round_trip(0, 65535, 65534);
    check_round_trip(0, 65535, 65535);
}

/*
 * Checks that Encoding a value greater than range fails.
 */
static void
check_encode_number_greater_than_range() {
    asn_per_outp_t po;
    int lb = 0;
    int ub = 6499;
    size_t n = 6503;
    ssize_t may_write;

    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);
    may_write = aper_put_length(&po, lb, ub, n, NULL);
    assert(may_write < 0);

    /* Also check value = range should fail: */
    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);
    n = ub - lb + 1;
    may_write = aper_put_length(&po, lb, ub, n, NULL);
    assert(may_write < 0);

    /* Again value = range, with edge case 65536: */
    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);
    ub = 65535;
    n = ub - lb + 1;
    may_write = aper_put_length(&po, lb, ub, n, NULL);
    assert(may_write < 0);
}

/*
 * Checks that a value which can be put in 1 byte (<256) but with a range type
 * of 2 bytes (65536) is encoded as 2 octets.
 */
static void
check_range65536_encoded_as_2octet() {
    asn_per_outp_t po;
    int lb = 0;
    int ub = 65535;
    size_t n = 5;

    memset(&po, 0, sizeof(po));
    po.buffer = po.tmpspace;
    po.nbits = 8 * sizeof(po.tmpspace);
    ssize_t may_write = aper_put_length(&po, lb, ub, n, NULL);
    assert(may_write >= 0);
    unsigned int bytes_needed = (po.buffer - po.tmpspace) + po.nboff/8;
    fprintf(stderr, "\naper_put_length(range=(%d..%d), len=%zu) => bytes_needed=%u\n",
            lb, ub, n, bytes_needed);
    assert(bytes_needed == 2);
}

int main() {

    check_round_trips_range65536();
    check_encode_number_greater_than_range();
    check_range65536_encoded_as_2octet();

}
