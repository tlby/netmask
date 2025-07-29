#include <arpa/inet.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>

#include "netmask.h"
#include "u128.h"

/* test some behaviors that are difficult to capture by running the
 * command. */

int __wrap_getaddrinfo(const char *node, const char *service,
        const struct addrinfo *hints,
        struct addrinfo **res) {
    if (strcmp(node, "example.com") == 0) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        ai->ai_family = AF_INET;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = calloc(1, sizeof(struct sockaddr_in));
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(0x01020304);
        *res = ai;
        return 0;
    }
    if (strcmp(node, "ipv6.example.com") == 0) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        if (!ai) return EAI_MEMORY;
        ai->ai_family = AF_INET6;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_addrlen = sizeof(struct sockaddr_in6);

        struct sockaddr_in6 *sin6 = calloc(1, sizeof(struct sockaddr_in6));
        if (!sin6) { free(ai); return EAI_MEMORY; }
        sin6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2600:1406:2e00:4d::172e:d85e", &sin6->sin6_addr);

        ai->ai_addr = (struct sockaddr *)sin6;
        *res = ai;
        return 0;
    }
    return EAI_NONAME; // fail for anything else
}

typedef struct {
    int len;
    char *strs[0];
} svec;

static void walk_list_cb(nm_cidr *c, svec **v) {
    char buf[1024];
    *v = (svec *)realloc(*v, sizeof(char *) * ((*v)->len + 2));
    inet_ntop(c->domain, c->addr.s6.s6_addr + (c->domain == AF_INET ? 12 : 0), buf, sizeof(buf));
    (*v)->strs[(*v)->len++] = strdup(buf);
    inet_ntop(c->domain, c->mask.s6.s6_addr + (c->domain == AF_INET ? 12 : 0), buf, sizeof(buf));
    (*v)->strs[(*v)->len++] = strdup(buf);
}

/* This is very slopppy, it doesn't bother to free() anything, it uses
 * realloc() and strdup() a lot.  The only nice thing is that we get a
 * simple list of entries from the tree we can check in the caller scope
 * so asserts will report useful line numbers. */
static svec *walk_list(NM nm) {
    svec *v = (svec *)malloc(sizeof(svec));
    v->len = 0;
    nm_walk(nm, (nm_walk_cb)walk_list_cb, &v);
    return v;
}

/* because ck_assert_* will report the line number of the failure,
 * adding helpers to make these more concise makes the failure logs far
 * less useful */

START_TEST(test_v4_host)
{
    NM tree = nm_new_str("example.com", NM_USE_DNS);
    svec *v = walk_list(tree);
    ck_assert_int_eq(v->len, 2);
    ck_assert_str_eq(v->strs[0], "1.2.3.4");
    ck_assert_str_eq(v->strs[1], "255.255.255.255");
}
END_TEST

START_TEST(test_v6_host)
{
    NM tree = nm_new_str("ipv6.example.com", NM_USE_DNS);
    svec *v = walk_list(tree);
    ck_assert_int_eq(v->len, 2);
    ck_assert_str_eq(v->strs[0], "2600:1406:2e00:4d::172e:d85e");
    ck_assert_str_eq(v->strs[1], "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}
END_TEST

START_TEST(test_zero)
{
    NM tree = nm_new_str("0/0", 0);
    svec *v = walk_list(tree);
    ck_assert_int_eq(v->len, 2);
    ck_assert_str_eq(v->strs[0], "0.0.0.0");
    ck_assert_str_eq(v->strs[1], "0.0.0.0");
}
END_TEST

START_TEST(test_fail)
{
    NM tree = nm_new_str("xyz", 0);
    ck_assert_ptr_null(tree);
}
END_TEST

START_TEST(test_fail_mask)
{
    NM tree = nm_new_str("0/xyz", 0);
    ck_assert_ptr_null(tree);
}
END_TEST

Suite *netmask_suite(void) {
    Suite *s = suite_create("Netmask");
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_v4_host);
    tcase_add_test(tc_core, test_v6_host);
    tcase_add_test(tc_core, test_zero);
    tcase_add_test(tc_core, test_fail);
    tcase_add_test(tc_core, test_fail_mask);

    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    Suite *s = netmask_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? 0 : 1;
}
