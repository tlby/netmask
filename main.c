/* main.c - a netmask generator
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

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <math.h>

#include "netmask.h"
#include "errors.h"
#include "config.h"

struct option longopts[] = {
  { "version",	0, 0, 'v' },
  { "help",	0, 0, 'h' },
  { "debug",	0, 0, 'd' },
  { "standard",	0, 0, 's' },
  { "cidr",	0, 0, 'c' },
  { "cisco",	0, 0, 'i' },
  { "range",	0, 0, 'r' },
  { "hex",	0, 0, 'x' },
  { "octal",	0, 0, 'o' },
  { "binary",	0, 0, 'b' },
  { "nodns",	0, 0, 'n' },
  { "files",	0, 0, 'f' },
//  { "max",	1, 0, 'M' },
//  { "min",	1, 0, 'm' },
  { NULL,	0, 0, 0   }
};

typedef enum {
  OUT_STD, OUT_CIDR, OUT_CISCO, OUT_RANGE, OUT_HEX, OUT_OCTAL, OUT_BINARY
} output_t;

char version[] = "netmask, version "VERSION;
char usage[] = "Try `%s --help' for more information.\n";
char *progname = NULL;

static void nm_ntop(int domain, nm_addr *addr, char *dst) {
    void *src = domain == AF_INET ? (void *)&addr->s : (void *)&addr->s6;
    inet_ntop(domain, src, dst, INET6_ADDRSTRLEN);
}

void disp_std(nm_cidr *c, void *user) {
  char nb[INET6_ADDRSTRLEN + 1],
       mb[INET6_ADDRSTRLEN + 1];

  nm_ntop(c->domain, &c->addr, nb);
  nm_ntop(c->domain, &c->mask, mb);
  printf("%15s/%-15s\n", nb, mb);
}

static void disp_cidr(nm_cidr *c, void *user) {
  char nb[INET6_ADDRSTRLEN + 1];

  nm_ntop(c->domain, &c->addr, nb);
  int scope = c->scope - (c->domain == AF_INET ? 96 : 0);
  printf("%15s/%d\n", nb, scope);
}

static void disp_cisco(nm_cidr *c, void *user) {
  char nb[INET6_ADDRSTRLEN + 1],
       mb[INET6_ADDRSTRLEN + 1];
  int i;

  for(i = 0; i < 16; i++) c->mask.s6.s6_addr[i] = ~c->mask.s6.s6_addr[i];
  nm_ntop(c->domain, &c->addr, nb);
  nm_ntop(c->domain, &c->mask, mb);
  printf("%15s %-15s\n", nb, mb);
}

static void range_num(char *dst, uint8_t *src) {
    /* roughly we must convert a 17 digit base 256 number
     * to a 39 digit base 10 number. */
    char digits[41] = { 0 }; /* ceil(17 * log(256) / log(10)) == 41 */
    int i, j, z, overflow;

    for(i = 0; i < 17; i++) {
        overflow = 0;
        for(j = sizeof(digits) - 1; j >= 0; j--) {
            int tmp = digits[j] * 256 + overflow;
            digits[j] = tmp % 10;
            overflow = tmp / 10;
        }

        overflow = src[i];
        for(j = sizeof(digits) - 1; j >= 0; j--) {
            if(!overflow)
                break;
            int sum = digits[j] + overflow;
            digits[j] = sum % 10;
            overflow = sum / 10;
        }
    }
    /* convert to string */
    z = 1;
    for(i = 0; i < sizeof(digits); i++) {
        if(z && digits[i] == 0)
            continue;
        z = 0;
        *dst++ = '0' + digits[i];
    }
    /* special case for zero */
    if(z)
        *dst++ = '0';
    *dst++ = '\0';
}

static void disp_range(nm_cidr *c, void *user) {
  char nb[INET6_ADDRSTRLEN + 1],
       mb[INET6_ADDRSTRLEN + 1],
       ns[42];
  uint8_t ra[17] = { 0 };
  int i;

  /* tiny bit of infinite precision addition */
  int carry = 1;
  for(i = 16; i > 0; i--) {
    int x = 0xff & ~c->mask.s6.s6_addr[i - 1];
    carry += x;
    ra[i] = 0xff & carry;
    carry >>= 8;
    /* also convert mask to broadcast address */
    c->mask.s6.s6_addr[i - 1] = c->addr.s6.s6_addr[i - 1] | x;
  }
  ra[0] = carry;
  range_num(ns, ra);
  nm_ntop(c->domain, &c->addr, nb);
  nm_ntop(c->domain, &c->mask, mb);
  printf("%15s-%-15s (%s)\n", nb, mb, ns);
}

static void num_str(char *dst, uint8_t *src, size_t len, size_t bs) {
  /* caller must allocate ceil(len * 8 / bs + 1) bytes in dst.
   * This is kind of like rebuffering from one block size to another,
   * but with bits, only snag is it needs to be left bit aligned */
  static const char chrs[] = "0123456789abcdef";
  if(bs > 0 && bs <= 4) {
    unsigned int pend = 0, mask = (1 << bs) - 1;
    size_t have = (bs - ((8 * len) % bs)) % bs;
    for(size_t i = 0; i < len; i++) {
      pend = (pend << 8) | src[i];
      have += 8;
      while (have >= bs) {
        *dst++  = chrs[(pend >> (have - bs)) & mask];
        have -= bs;
      }
    }
  }
  *dst = '\0';
}

static void disp_hex(nm_cidr *c, void *user) {
  char ns[16 * 2 + 1],
       ms[16 * 2 + 1];
  int off = c->domain == AF_INET ? 12 : 0,
      len = c->domain == AF_INET ? 4 : 16;
  num_str(ns, c->addr.s6.s6_addr + off, len, 4);
  num_str(ms, c->mask.s6.s6_addr + off, len, 4);
  printf("0x%s/0x%s\n", ns, ms);
}

static void disp_octal(nm_cidr *c, void *user) {
  char ns[16 * 3 + 1],
       ms[16 * 3 + 1];
  int off = c->domain == AF_INET ? 12 : 0,
      len = c->domain == AF_INET ? 4 : 16;
  num_str(ns, c->addr.s6.s6_addr + off, len, 3);
  num_str(ms, c->mask.s6.s6_addr + off, len, 3);
  printf("0%s/0%s\n", ns, ms);
}

static void disp_binary(nm_cidr *c, void *user) {
  char ns[16 * 9 + 1],
       ms[16 * 9 + 1];
  int off = c->domain == AF_INET ? 12 : 0,
      len = c->domain == AF_INET ? 4 : 16;
  /* have num_str() each byte to add spaces between */
  for(int i = 0; i < len; i++) {
    num_str(ns + 9 * i, c->addr.s6.s6_addr + off + i, 1, 1);
    ns[9 * (i + 1) - 1] = ' ';
    num_str(ms + 9 * i, c->mask.s6.s6_addr + off + i, 1, 1);
    ms[9 * (i + 1)  - 1] = ' ';
  }
  ns[9 * len - 1] = '\0';
  ms[9 * len - 1] = '\0';
  printf("%s / %s\n", ns, ms);
}

void display(NM nm, output_t style) {
  nm_walk_cb disp = NULL;

  switch(style) {
    case OUT_STD:    disp = &disp_std;    break;
    case OUT_CIDR:   disp = &disp_cidr;   break;
    case OUT_CISCO:  disp = &disp_cisco;  break;
    case OUT_RANGE:  disp = &disp_range;  break;
    case OUT_HEX:    disp = &disp_hex;    break;
    case OUT_OCTAL:  disp = &disp_octal;  break;
    case OUT_BINARY: disp = &disp_binary; break;
    default: return;
  }
  nm_walk(nm, disp, NULL);
}

static inline int add_entry(NM *nm, const char *str, int dns) {
  NM new = nm_new_str(str, dns);
  if(new) {
    *nm = nm_merge(*nm, new);
    return 0;
  } else {
    warn("parse error \"%s\"", str);
    return 1;
  }
}

int main(int argc, char *argv[]) {
  int optc, h = 0, v = 0, f = 0, d = 0, dns = NM_USE_DNS, lose = 0, rv = 0;
  output_t output = OUT_CIDR;

  progname = argv[0];
  initerrors(progname, 0, 0); /* stderr, nostatus */
  while((optc = getopt_long(argc, argv, "shoxdrvbincM:m:f", longopts,
    (int *) NULL)) != EOF) switch(optc) {
   case 'h': h = 1;   break;
   case 'v': v++;     break;
   case 'n': dns = 0; break;
   case 'f': f = 1;   break;
//   case 'M': max = mspectou32(optarg); break;
//   case 'm': min = mspectou32(optarg); break;
   case 'd':
    d = 1;
    initerrors(NULL, -1, 1); /* showstatus */
    break;
   case 's': output = OUT_STD;    break;
   case 'c': output = OUT_CIDR;   break;
   case 'i': output = OUT_CISCO;  break;
   case 'r': output = OUT_RANGE;  break;
   case 'x': output = OUT_HEX;    break;
   case 'o': output = OUT_OCTAL;  break;
   case 'b': output = OUT_BINARY; break;
   default: lose = 1; break;
  }
  if(v) {
    fprintf(stderr, "%s\n", version);
    if(!h) exit(0);
  }
  if(h) {
    fprintf(stderr,
      "This is netmask, an address netmask generation utility\n"
      "Usage: %s spec [spec ...]\n"
      "  -h, --help\t\t\tPrint a summary of the options\n"
      "  -v, --version\t\t\tPrint the version number\n"
      "  -d, --debug\t\t\tPrint status/progress information\n"
      "  -s, --standard\t\tOutput address/netmask pairs\n"
      "  -c, --cidr\t\t\tOutput CIDR format address lists\n"
      "  -i, --cisco\t\t\tOutput Cisco style address lists\n"
      "  -r, --range\t\t\tOutput ip address ranges\n"
      "  -x, --hex\t\t\tOutput address/netmask pairs in hex\n"
      "  -o, --octal\t\t\tOutput address/netmask pairs in octal\n"
      "  -b, --binary\t\t\tOutput address/netmask pairs in binary\n"
      "  -n, --nodns\t\t\tDisable DNS lookups for addresses\n"
      "  -f, --files\t\t\tTreat arguments as input files\n"
//      "  -M, --max mask\t\tLimit maximum mask size\n"
//      "  -m, --min mask\t\tLimit minimum mask size (drop small ranges)\n"
      "Definitions:\n"
      "  a spec can be any of:\n"
      "    address\n"
      "    address:address\n"
      "    address:+address\n"
      "    address/mask\n"
      "  an address can be any of:\n"
      "    N\t\tdecimal number\n"
      "    0N\t\toctal number\n"
      "    0xN\t\thex number\n"
      "    N.N.N.N\tdotted quad\n"
      "    hostname\tdns domain name\n"
      "  a mask is the number of bits set to one from the left\n", progname);
    exit(0);
  }
  if(lose || optind == argc) {
    fprintf(stderr, usage, progname);
    exit(1);
  }
  NM nm = NULL;
  for(;optind < argc; optind++) {
    if(f) {
      char buf[1024];
      FILE *fp = strncmp(argv[optind], "-", 2) ?
        fopen(argv[optind], "r") : stdin;
      if(!fp) {
        fprintf(stderr, "fopen: %s: %s\n",
          argv[optind], strerror(errno));
        continue;
      }
      while(fscanf(fp, "%1023s", buf) != EOF)
        rv |= add_entry(&nm, buf, dns);
    } else
      rv |= add_entry(&nm, argv[optind], dns);
  }
  display(nm, output);
  if(d) nm_dump(nm);
  return(rv);
}
