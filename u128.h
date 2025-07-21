#include <netinet/in.h>

/* on a modern processor, this code has no loops */

typedef struct {
    uint64_t h;
    uint64_t l;
} u128_t;

static inline u128_t u128(uint64_t h, uint64_t l) {
    return (u128_t){ h, l };
}

static inline u128_t u128_add(u128_t x, u128_t y, int *carry) {
    /* this relies on the sum being greater than both terms of the
     * addition, otherwise an overflow must have occurred. */
    uint64_t h, l, c;

    l = x.l + y.l;
    c = (l < x.l || l < y.l) ? 1 : 0;
    h = x.h + y.h + c;
    if (carry) *carry = (h < x.h || h < y.h) ? 1 : 0;
    return u128(h, l);
}

static inline u128_t u128_and(u128_t x, u128_t y) {
    return u128(x.h & y.h, x.l & y.l);
}

static inline u128_t u128_or(u128_t x, u128_t y) {
    return u128(x.h | y.h, x.l | y.l);
}

static inline u128_t u128_xor(u128_t x, u128_t y) {
    return u128(x.h ^ y.h, x.l ^ y.l);
}

static inline u128_t u128_not(u128_t v) {
    return u128(~v.h, ~v.l);
}

static inline int u128_cmp(u128_t x, u128_t y) {
    /* return -1, 0, 1 on sort order */
    if(x.h < y.h) return -1;
    if(x.h > y.h) return 1;
    if(x.l < y.l) return -1;
    if(x.l > y.l) return 1;
    return 0;
}

static inline u128_t u128_of_v4(struct in_addr *s) {
    return u128(0, ((uint64_t)0xffff << 32) | ntohl(s->s_addr));
}

static inline struct in_addr v4_of_u128(u128_t v) {
    return (struct in_addr){ htonl(v.l & 0xffffffff) };
}

static inline u128_t u128_of_v6(struct in6_addr *s6) {
    const uint8_t *addr = s6->s6_addr;
    return u128(
        (((uint64_t)addr[0])  << 56) | (((uint64_t)addr[1])  << 48) |
        (((uint64_t)addr[2])  << 40) | (((uint64_t)addr[3])  << 32) |
        (((uint64_t)addr[4])  << 24) | (((uint64_t)addr[5])  << 16) |
        (((uint64_t)addr[6])  <<  8) | (((uint64_t)addr[7])  <<  0),
        (((uint64_t)addr[8])  << 56) | (((uint64_t)addr[9])  << 48) |
        (((uint64_t)addr[10]) << 40) | (((uint64_t)addr[11]) << 32) |
        (((uint64_t)addr[12]) << 24) | (((uint64_t)addr[13]) << 16) |
        (((uint64_t)addr[14]) <<  8) | (((uint64_t)addr[15]) <<  0)
    );
}

static inline struct in6_addr v6_of_u128(u128_t v) {
    return (struct in6_addr){
        .s6_addr = {
            (uint8_t)0xff & (v.h >> 56), (uint8_t)0xff & (v.h >> 48),
            (uint8_t)0xff & (v.h >> 40), (uint8_t)0xff & (v.h >> 32),
            (uint8_t)0xff & (v.h >> 24), (uint8_t)0xff & (v.h >> 16),
            (uint8_t)0xff & (v.h >>  8), (uint8_t)0xff & (v.h >>  0),
            (uint8_t)0xff & (v.l >> 56), (uint8_t)0xff & (v.l >> 48),
            (uint8_t)0xff & (v.l >> 40), (uint8_t)0xff & (v.l >> 32),
            (uint8_t)0xff & (v.l >> 24), (uint8_t)0xff & (v.l >> 16),
            (uint8_t)0xff & (v.l >>  8), (uint8_t)0xff & (v.l >>  0),
        }
    };
}

static inline u128_t u128_mask(uint8_t n) {
    if (n > 128) n = 128;
    if (n > 64) return u128(~0ULL, ~0ULL << (128 - n));
    if (n > 0) return u128(~0ULL << (64 - n), 0);
    return u128(0, 0);
}

static inline int u128_is_valid_mask(u128_t mask) {
    if (mask.l && !mask.h) return 0;
    if ((~mask.h + 1) & ~mask.h) return 0;
    if ((~mask.l + 1) & ~mask.l) return 0;
    return 1;
}

static inline uint8_t u128_bit(u128_t v, uint8_t i) {
    if(i < 64) return 1 & (v.h >> (63 - i));
    if(i < 128) return 1 & (v.l >> (127 - i));
    return 0;
}

static inline uint8_t u64_popc(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcountll((unsigned long long)v);
#else
    uint8_t i;
    for (i = 0; v; i++) v &= v - 1;
    return i;
#endif
}

static inline uint8_t u128_popc(u128_t v) {
    return u64_popc(v.h) + u64_popc(v.l);
}

static inline uint8_t u64_clz(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
    return v ? __builtin_clzll((unsigned long long)v) : 64;
#else
    uint8_t n = 0;
    if (v == 0) return 64;
    for (; (v & (1ULL << 63)) == 0; n++, v <<= 1);
    return n;
#endif
}

static inline uint8_t u128_clz(u128_t v) {
    if (v.h)
        return u64_clz(v.h);
    else
        return 64 + u64_clz(v.l);
}

/* longest common prefix */
static inline uint8_t u128_lcp(u128_t x, u128_t y) {
    return u128_clz(u128_xor(x, y));
}
