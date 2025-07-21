#include <netinet/in.h>
#include <netdb.h>

typedef struct nm *NM;

NM nm_new_v4(struct in_addr *);

NM nm_new_v6(struct in6_addr *);

NM nm_new_ai(struct addrinfo *);

#define NM_USE_DNS 1

NM nm_new_str(const char *, int flags);

/* nm_merge() returns the union of the two trees passed in.  it is
 * destructive recycling branches from both sides and freeing unneeded
 * fragments. */
NM nm_merge(NM, NM);

/* adds a validation step between each merge operation, but is somewhat
 * expensive so only enabled in debug mode */
NM nm_merge_strict(NM, NM);

typedef union {
    struct in6_addr s6;
    struct {
        char _pad[12];
        struct in_addr s;
    };
} nm_addr;

typedef struct {
    int domain;
    nm_addr addr, mask;
    uint8_t scope;
} nm_cidr;

/* the void* is caller data */
typedef void (*nm_walk_cb)(nm_cidr *,void *p);

void nm_walk(NM, nm_walk_cb, void *p);

void nm_free(NM);

void nm_dump(NM);
