/* netmask.c - a netmask generator
 *
 * Copyright (c) 2013  Robert Stone <talby@trap.mtview.ca.us>,
 *                     Tom Lear <tom@trap.mtview.ca.us>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "errors.h"
#include "netmask.h"
#include "u128.h"

#define PRIx128 "%016" PRIx64 "%016" PRIx64
#define PRMu128(x) (x).h, (x).l

struct nm {
    u128_t neta;
    uint8_t len;
    int domain;
    NM l, r;
};

NM nm_new_u128(u128_t neta, uint8_t len, uint8_t domain) {
    if (len > 128) return NULL;
    NM self = (NM)calloc(1, sizeof(struct nm));
    self->neta = u128_and(neta, u128_mask(len));
    self->len = len;
    self->domain = domain;
    return self;
}

NM nm_new_v4(struct in_addr *s) {
    return nm_new_u128(u128_of_v4(s), 128, AF_INET);
}

NM nm_new_v6(struct in6_addr *s6) {
    return nm_new_u128(u128_of_v6(s6), 128, AF_INET6);
}

/* this is slightly complicated because an NM can outgrow it's initial
 * v4 state, but if it doesn't, we want to retain the fact that it
 * was and remained v4.  */
static inline int is_v4(NM self) {
    return self->domain == AF_INET && 0 == u128_cmp(
        u128(0, 0x0000ffff00000000ULL),
        u128_and(self->neta, u128_mask(96))
    );
}

static inline int is_leaf(NM self) {
    return !self->l && !self->r;
}

static inline int domain_merge(NM a, NM b) {
    return a->domain == AF_INET && b->domain == AF_INET ? AF_INET : AF_INET6;
}

NM nm_new_ai(struct addrinfo *ai) {
    NM self = NULL;
    struct addrinfo *cur;

    for(cur = ai; cur; cur = cur->ai_next) {
        switch(cur->ai_family) {
            case AF_INET:
                self = nm_merge(self, nm_new_v4(&(
                    (struct sockaddr_in *)cur->ai_addr
                )->sin_addr));
                break;
            case AF_INET6:
                self = nm_merge(self, nm_new_v6(&(
                    (struct sockaddr_in6 *)cur->ai_addr
                )->sin6_addr));
                break;
            default:
                panic("unknown ai_family %d in struct addrinfo",
                        cur->ai_family);
        }
    }
    return self;
}

static inline NM parse_addr(const char *str, int flags) {
    struct in6_addr s6;
    struct in_addr s;

    if(inet_pton(AF_INET6, str, &s6))
        return nm_new_v6(&s6);

    if(inet_aton(str, &s))
        return nm_new_v4(&s);

    if(NM_USE_DNS & flags) {
        struct addrinfo in, *out;

        memset(&in, 0, sizeof(struct addrinfo));
        in.ai_family = AF_UNSPEC;
        if(getaddrinfo(str, NULL, &in, &out) == 0) {
            NM self = nm_new_ai(out);
            freeaddrinfo(out);
            return self;
        }
    }
    return NULL;
}

static inline int parse_mask(NM self, const char *str, int flags) {
    char *p;
    uint32_t v;
    struct in6_addr s6;
    struct in_addr s;
    u128_t mask;

    v = strtoul(str, &p, 0);
    if(*p == '\0') {
        /* read it as a CIDR scope */
        if(is_v4(self)) v += 96;
        if(v > 128) return 0;
        mask = u128_mask(v);
        self->len = v;
    } else if(self->domain == AF_INET6 && inet_pton(AF_INET6, str, &s6)) {
        mask = u128_of_v6(&s6);
        /* flip cisco style masks */
        if (!(s6.s6_addr[0] & 0x80) && s6.s6_addr[15] & 1)
            mask = u128_not(mask);
        self->len = u128_popc(mask);
    } else if(self->domain == AF_INET && inet_aton(str, &s)) {
        v = htonl(s.s_addr);
        if(v & 1 && ~v >> 31) /* flip cisco style masks */
            v = ~v;
        mask = u128(~0ULL, 0xffffffff00000000ULL | v);
        self->len = u128_popc(mask);
    } else {
        return 0;
    }
    if(!u128_is_valid_mask(mask)) return 0;
    /* apply mask to neta */
    self->neta = u128_and(self->neta, mask);
    return 1;
}

/* turn a pair into a range (inclusive), both of these should be
 * freshly created leaf nodes */
static inline NM nm_seq(NM min, NM max) {
    if (u128_cmp(min->neta, max->neta) > 0) {
        NM tmp = max;
        max = min;
        min = tmp;
    }
    int domain = domain_merge(min, max);
    NM rv = NULL;

    u128_t cur = min->neta;
    u128_t one = u128(0, 1);
    while (u128_cmp(cur, max->neta) <= 0) {
        uint8_t len = 128;
        while (len > 0) {
            u128_t mask = u128_mask(len - 1);
            u128_t lo = u128_and(cur, mask);
            if (u128_cmp(min->neta, lo) > 0) break;
            u128_t hi = u128_or(cur, u128_not(mask));
            if (u128_cmp(hi, max->neta) > 0) break;
            len--;
        }
        rv = nm_merge(rv, nm_new_u128(cur, len, domain));
        u128_t hi = u128_or(cur, u128_not(u128_mask(len)));
        cur = u128_add(hi, one, NULL);
    }
    free(min);
    free(max);
    return rv;
}

NM nm_new_str(const char *str, int flags) {
    char *p, buf[2048];
    NM self;

    if((p = strchr(str, '/'))) { /* mask separator */
        strncpy(buf, str, p - str);
        buf[p - str] = '\0';
        self = parse_addr(buf, flags);
        if(!self)
            return NULL;
        if(!parse_mask(self, p + 1, flags)) {
            free(self);
            return NULL;
        }
        return self;
    } else if((p = strchr(str, ','))) { /* new range character */
        NM top;
        int add;

        strncpy(buf, str, p - str);
        buf[p - str] = '\0';
        self = parse_addr(buf, flags);
        if(!self)
            return NULL;
        if(p[1] == '+')
            add = 1;
        else
            add = 0;
        top = parse_addr(p + add + 1, flags);
        if(!top) {
            free(self);
            return NULL;
        }
        if(add) {
            int carry;
            if(is_v4(top))
                top->neta.l &= 0xffffffffULL;
            top->neta = u128_add(self->neta, top->neta, &carry);
            if(carry) {
                free(self);
                free(top);
                return NULL;
            }
        }
        return nm_seq(self, top);
    } else if((self = parse_addr(str, flags))) {
        return self;
    } else if((p = strchr(str, ':'))) { /* old range character (sloppy) */
        NM top;
        int add;
        strncpy(buf, str, p - str);
        buf[p - str] = '\0';
        self = parse_addr(buf, flags);
        if(!self)
            return NULL;
        if(p[1] == '+') {
            add = 1;
            if(p[2] == '-') {
                /* this is a pretty special reverse compatibility
                 * situation.  N:+-5" would actually emit the range from
                 * N-5 to N because strtoul() hilariously accepts
                 * negative numbers and the original code never detected
                 * overflow and things just happened to work out. */
                struct in_addr s;
                char *endp;
                uint32_t v = self->neta.l + strtoul(p + 2, &endp, 0);
                if(*endp == '\0') {
                    s.s_addr = htonl(v);
                    top = nm_new_v4(&s);
                    if(!top) {
                        free(self);
                        return NULL;
                    }
                    return nm_seq(self, top);
                }
            }
        } else {
            add = 0;
        }

        top = parse_addr(p + add + 1, flags);
        if(!top) {
            free(self);
            return NULL;
        }
        if(add) {
            int carry;
            if(is_v4(top))
                top->neta.l &= 0xffffffffULL;
            top->neta = u128_add(self->neta, top->neta, &carry);
            if(carry) {
                free(self);
                free(top);
                return NULL;
            }
        }
        return nm_seq(self, top);
    } else {
        return NULL;
    }
}

void nm_free(NM self) {
    if (self->l) nm_free(self->l);
    if (self->r) nm_free(self->r);
    free(self);
}

typedef struct merge_ctx {
  NM (*call)(struct merge_ctx *, NM, NM);
} *merge_ctx;

static inline NM merge_split(merge_ctx ctx, NM a, NM b, uint8_t len) {
    NM c = nm_new_u128(a->neta, len, domain_merge(a, b));
    if(u128_bit(b->neta, len)) {
        c->l = a;
        c->r = b;
    } else {
        c->l = b;
        c->r = a;
    }
    return c;
}

static inline NM merge_child(merge_ctx ctx, NM a, NM b) {
    if (is_leaf(a))
        nm_free(b);
    else if (u128_bit(b->neta, a->len))
        a->r = ctx->call(ctx, a->r, b);
    else
        a->l = ctx->call(ctx, a->l, b);
    return a;
}

static inline NM merge_pivot(merge_ctx ctx, NM a, NM b) {
    return merge_child(ctx, b, a);
}

static inline NM merge_merge(merge_ctx ctx, NM a, NM b) {
    if (is_leaf(a)) {
        nm_free(b);
        return a;
    }
    if (is_leaf(b)) {
        nm_free(a);
        return b;
    }
    a->domain = domain_merge(a, b);
    a->l = ctx->call(ctx, a->l, b->l);
    a->r = ctx->call(ctx, a->r, b->r);
    free(b);
    return a;
}

static inline NM merge_step(merge_ctx ctx, NM a, NM b) {
    if (!a) return b;
    if (!b) return a;
    NM c;
    uint8_t len = u128_lcp(a->neta, b->neta);
    if (len < a->len && len < b->len)
        c = merge_split(ctx, a, b, len);
    else if (a->len < b->len)
        c = merge_child(ctx, a, b);
    else if (b->len < a->len)
        c = merge_pivot(ctx, a, b);
    else /* if (a->len == b->len) */
        c = merge_merge(ctx, a, b);
    /* check for aggregates */
    if (c->l && is_leaf(c->l) && c->l->len == c->len + 1 &&
        c->r && is_leaf(c->r) && c->r->len == c->len + 1) {
        free(c->l);
        free(c->r);
        c->l = NULL;
        c->r = NULL;
    }
    return c;
}

NM nm_merge(NM a, NM b) {
    struct merge_ctx ctx = { .call = merge_step };
    return ctx.call(&ctx, a, b);
}

/* LCOV_EXCL_START - debug mode is not currently tested */
static inline int nm_coherent(NM self) {
    /* validate that children belong under the parent */
    u128_t mask = u128_mask(self->len);
    if (self->l) {
        if (self->len >= self->l->len) return 0;
        if (u128_cmp(u128_and(self->l->neta, mask), self->neta)) return 0;
    }
    if (self->r) {
        if (self->len >= self->r->len) return 0;
        if (u128_cmp(u128_and(self->r->neta, mask), self->neta)) return 0;
    }
    return 1;
}

static inline NM merge_check(merge_ctx ctx, NM a, NM b) {
    /* capture the input trees */
    char lineA[1024], lineB[1024];
    if (a)
        sprintf(lineA, "a=" PRIx128 "/%d", PRMu128(a->neta), a->len);
    else
        sprintf(lineA, "a=%p", a);
    if (b)
        sprintf(lineA, "b=" PRIx128 "/%d", PRMu128(b->neta), b->len);
    else
        sprintf(lineB, "b=%p", b);
    NM c = merge_step(ctx, a, b);
    /* if anything has been corrupted, spill inputs & outputs */
    if (!c || !nm_coherent(c)) {
        status("%s", lineA);
        status("%s", lineB);
        if (c) {
            status("c=" PRIx128 "/%d", PRMu128(c->neta), c->len);
            if (c->l) status("l=" PRIx128 "/%d %d", PRMu128(c->l->neta), c->l->len, u128_bit(c->l->neta, c->len));
            else status("l=%p", c->l);
            if (c->r) status("r=" PRIx128 "/%d %d", PRMu128(c->r->neta), c->r->len, u128_bit(c->r->neta, c->len));
            else status("r=%p", c->r);
        } else {
            status("c=%p", c);
        }
        abort();
    }
    return c;
}

NM nm_merge_strict(NM a, NM b) {
    struct merge_ctx ctx = { .call = merge_check };
    return ctx.call(&ctx, a, b);
}

/* This needs some explaining.  We are building a tree using box drawing
 * characters.  Each column is a level of the tree. */
static const char *nm_dump_sp = " "; /* before left and after right child */
static const char *nm_dump_br = "│"; /* between left and right child */
static const char *nm_dump_lc = "┌"; /* at left child */
static const char *nm_dump_pr = "┤"; /* at parent */
static const char *nm_dump_rc = "└"; /* at right child */
static const char *nm_dump_lf = "╴"; /* at leaf node */
/* Since this is a patricia tree, we only ever have 2 or 0 children so
 * no need to draw "┐" or "┘". */

static inline void nm_dump_print(NM nm, const char *pre[], size_t len) {
    char line[168], *p = line, ls[4];
    for(size_t i = 0; i < len; i++) p = stpcpy(p, pre[i]);
    p = stpcpy(p, is_leaf(nm) ? nm_dump_lf : nm_dump_pr);
    snprintf(ls, 4, "%-3d", nm->len);
    status(PRIx128 "/%s %s", PRMu128(nm->neta), ls, line);
}

static inline void nm_dump_node(NM nm, const char *pre[], size_t len) {
    pre[len + 1] = nm_dump_sp;
    if (nm->l) nm_dump_node(nm->l, pre, len + 1);
    pre[len] = pre[len] == nm_dump_sp ? nm_dump_lc : nm_dump_rc;
    nm_dump_print(nm, pre, len + 1);
    pre[len] = pre[len] == nm_dump_lc ? nm_dump_br : nm_dump_sp;
    if (nm->r) nm_dump_node(nm->r, pre, len + 1);
}

void nm_dump(NM nm) {
    const char *pre[129] = { nm_dump_sp };
    if (nm->l) nm_dump_node(nm->l, pre, 0);
    nm_dump_print(nm, pre, 0);
    if (nm->r) nm_dump_node(nm->r, pre, 0);
}
/* LCOV_EXCL_STOP */

void nm_walk(NM self, nm_walk_cb cb, void *user) {
    if (!self) return;
    nm_walk(self->l, cb, user);
    if (is_leaf(self)) {
        nm_cidr cidr = {
            .domain = is_v4(self) ? AF_INET : AF_INET6,
            .addr = { .s6 = v6_of_u128(self->neta) },
            .mask = { .s6 = v6_of_u128(u128_mask(self->len)) },
            .scope = self->len,
        };
        cb(&cidr, user);
    }
    nm_walk(self->r, cb, user);
}
