#ifndef HEADER_CURL_DOH_H
#define HEADER_CURL_DOH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "urldata.h"
#include "curl_addrinfo.h"

#ifndef CURL_DISABLE_DOH

/*
 * Curl_doh() resolve a name using DoH (DNS-over-HTTPS). It resolves a name
 * and returns a 'Curl_addrinfo *' with the address information.
 */

Curl_addrinfo *Curl_doh(struct connectdata *conn,
                        const char *hostname,
                        int port,
                        int *waitp);

CURLcode Curl_doh_is_resolved(struct connectdata *conn,
                              struct Curl_dns_entry **dns);

int Curl_doh_getsock(struct connectdata *conn, curl_socket_t *socks);

typedef enum {
  DOH_OK,
  DOH_DNS_BAD_LABEL,    /* 1 */
  DOH_DNS_OUT_OF_RANGE, /* 2 */
  DOH_DNS_LABEL_LOOP,   /* 3 */
  DOH_TOO_SMALL_BUFFER, /* 4 */
  DOH_OUT_OF_MEM,       /* 5 */
  DOH_DNS_RDATA_LEN,    /* 6 */
  DOH_DNS_MALFORMAT,    /* 7 */
  DOH_DNS_BAD_RCODE,    /* 8 - no such name */
  DOH_DNS_UNEXPECTED_TYPE,  /* 9 */
  DOH_DNS_UNEXPECTED_CLASS, /* 10 */
  DOH_NO_CONTENT,           /* 11 */
  DOH_DNS_BAD_ID,           /* 12 */
  DOH_DNS_NAME_TOO_LONG,    /* 13 */
  DOH_PORT_OUT_OF_RANGE,    /* 14 */
  DOH_DNS_BAD_QDCOUNT,      /* 15 */
  DOH_DNS_NAME_MISMATCH,    /* 16 */
  DOH_UNRESOLVED_ALIAS,     /* 17 - no SVCB AliasMode support in resolver */
  /* Add new definitions above here */
  /* Following definition is for use in last resort */
  DOH_DNS_UNSUPPORTED
} DOHcode;

typedef enum {                  /* RFC1035 */
  DNS_RC_NOERROR,               /* 0 */
  DNS_RC_FORMERR,               /* 1 */
  DNS_RC_SERVFAIL,              /* 2 */
  DNS_RC_NXDOMAIN,              /* 3 */
  DNS_RC_NOTIMP,                /* 4 */
  DNS_RC_REFUSED,               /* 5 */
  DNS_RC_RESERVED               /* 6 (and beyond) */
} DNSrcode;

typedef enum {
  DNS_TYPE_A = 1,
  DNS_TYPE_NS = 2,
  DNS_TYPE_CNAME = 5,
  DNS_TYPE_TXT = 16,
  DNS_TYPE_AAAA = 28,
  DNS_TYPE_DNAME = 39,          /* RFC6672 */
  DNS_TYPE_SVCB = 64,           /* was provisionally 65481 */
  DNS_TYPE_HTTPS = 65           /* was provisionally 65482 */
} DNStype;

typedef enum {
  /* IANA Service Binding (SVCB) Parameter Registry */
  /* [draft-ietf-dnsop-svcb-https] */
  DNS_SVCB_PARAM_MANDATORY,
  DNS_SVCB_PARAM_ALPN,
  DNS_SVCB_PARAM_NO_DEFAULT_ALPN,
  DNS_SVCB_PARAM_PORT,
  DNS_SVCB_PARAM_IPV4HINT,
  DNS_SVCB_PARAM_ECHCONFIG,
  DNS_SVCB_PARAM_IPV6HINT,
  /* Add names above this line as new parameters are registered */
  DNS_SVCB_PARAMTABLE_SIZE      /* Avoid prefix DNS_SVCB_PARAM_ */
} DNSsvcbparam;

#define DOH_MAX_ADDR 24
#define DOH_MAX_CNAME 8
#define DOH_MAX_ESNI_TXT 4
#define DOH_MAX_SVCB_DATA 12    /* eg. 8x alias + 4x service, or what? */

struct cnamestore {
  /* TODO: establish whether this is used for anything */
  size_t len;                /* length of cname */
  unsigned char *alloc;      /* allocated pointer */
  size_t allocsize;          /* allocated size */
};

struct txtstore {
  size_t len;                /* length of text */
  unsigned char *alloc;      /* allocated pointer */
  size_t allocsize;          /* allocated size */
};

struct svcbstore {
  int type;                  /* specific type of SVCB-compatible RR */
  size_t len;                /* length of data */
  unsigned char *alloc;      /* allocated pointer */
  size_t allocsize;          /* allocated size */
  /* An index (offset) into the data, with an entry for each parameter
   * registered in IANA's Service Binding (SVCB) Parameter Registry,
   * allows avoiding a fresh traversal of the data on later reference.
   *
   * Note that the first parameter present in the data must lie at
   * an offset of 2 greater than the length of the fully-qualified
   * TargetName (in wire format); zero may thus be used to indicate
   * that the corresponding parameter is not present.
   */
  unsigned int index[DNS_SVCB_PARAMTABLE_SIZE];
};

struct dohaddr {
  int type;
  union {
    unsigned char v4[4]; /* network byte order */
    unsigned char v6[16];
  } ip;
};

struct dohentry {
  unsigned int ttl;
  int numaddr;
  char *prefix;             /* UGLY hack: end-run around doh_decode */
  struct dohaddr addr[DOH_MAX_ADDR];
  int numcname;
  struct cnamestore cname[DOH_MAX_CNAME];
  int num_esni_txt;
  struct txtstore esni_txt[DOH_MAX_ESNI_TXT];
  int num_svcb_data;
  struct svcbstore    /* Need type-aware structure, unlike txtstore */
  svcb_data[DOH_MAX_SVCB_DATA];
};


#ifdef DEBUGBUILD
DOHcode doh_encode(const char *host,
                   const char *prefix,
                   DNStype dnstype,
                   unsigned char *dnsp, /* buffer */
                   size_t len,  /* buffer size */
                   size_t *olen); /* output length */
DOHcode doh_decode(unsigned char *doh,
                   size_t dohlen,
                   DNStype dnstype,
                   struct dohentry *d);
void de_cleanup(struct dohentry *d);
#endif

#else /* if DOH is disabled */
#define Curl_doh(a,b,c,d) NULL
#define Curl_doh_is_resolved(x,y) CURLE_COULDNT_RESOLVE_HOST
#endif

#endif /* HEADER_CURL_DOH_H */
