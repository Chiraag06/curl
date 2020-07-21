/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifndef CURL_DISABLE_DOH

#include "urldata.h"
#include "curl_addrinfo.h"
#include "doh.h"

#include "sendf.h"
#include "multiif.h"
#include "url.h"
#include "share.h"
#include "curl_base64.h"
#include "connect.h"
#include "strdup.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define DNS_CLASS_IN 0x01
#define DOH_MAX_RESPONSE_SIZE 3000 /* bytes */

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static const char * const errors[]={
  "",
  "Bad label",
  "Out of range",
  "Label loop",
  "Too small",
  "Out of memory",
  "RDATA length",
  "Malformat",
  "Bad RCODE",
  "Unexpected TYPE",
  "Unexpected CLASS",
  "No content",
  "Bad ID",
  "Name too long",
  "Port out of range",
  "Bad QDCOUNT",
  "NAME mismatch"
};

static const char *doh_strerror(DOHcode code)
{
  if((code >= DOH_OK) && (code < DOH_DNS_UNSUPPORTED))
    return errors[code];
  return "bad error code";
}
#endif

#ifdef DEBUGBUILD
#define UNITTEST
#else
#define UNITTEST static
#endif

/* @unittest 1655
 */
UNITTEST DOHcode doh_encode(const char *host,
                            const char *prefix,
                            DNStype dnstype,
                            unsigned char *dnsp, /* buffer */
                            size_t len,  /* buffer size */
                            size_t *olen) /* output length */
{
  const size_t hostlen = strlen(host);
  unsigned char *orig = dnsp;
  const size_t preflen = prefix ? strlen(prefix) : 0;
  size_t expected_len;
  int i;

  /* For C89 ... */
  char *fragment[2];
  int fragments = 2;
  fragment[0] = (char *) prefix;
  fragment[1] = (char *) host;

  /* The expected output length is 16 bytes more than the length of
   * the QNAME-encoding of the host name.
   *
   * A valid DNS name may not contain a zero-length label, except at
   * the end.  For this reason, a name beginning with a dot, or
   * containing a sequence of two or more consecutive dots, is invalid
   * and cannot be encoded as a QNAME.
   *
   * If the host name ends with a trailing dot, the corresponding
   * QNAME-encoding is one byte longer than the host name. If (as is
   * also valid) the hostname is shortened by the omission of the
   * trailing dot, then its QNAME-encoding will be two bytes longer
   * than the host name.
   *
   * Each [ label, dot ] pair is encoded as [ length, label ],
   * preserving overall length.  A final [ label ] without a dot is
   * also encoded as [ length, label ], increasing overall length
   * by one. The encoding is completed by appending a zero byte,
   * representing the zero-length root label, again increasing
   * the overall length by one.
   */

  DEBUGASSERT(hostlen);
  expected_len = 12 + hostlen + preflen + 1 + 4;
  if(host[hostlen-1]!='.')
    expected_len++;

  if((preflen) && (prefix[preflen-1]!='.'))
    expected_len++;

  if(expected_len > (256 + 16)) /* RFCs 1034, 1035 */
    return DOH_DNS_NAME_TOO_LONG;

  if(len < expected_len)
    return DOH_TOO_SMALL_BUFFER;

  *dnsp++ = 0; /* 16 bit id */
  *dnsp++ = 0;
  *dnsp++ = 0x01; /* |QR|   Opcode  |AA|TC|RD| Set the RD bit */
  *dnsp++ = '\0'; /* |RA|   Z    |   RCODE   |                */
  *dnsp++ = '\0';
  *dnsp++ = 1;    /* QDCOUNT (number of entries in the question section) */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ANCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* NSCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ARCOUNT */

  /* encode each label and store it in the QNAME */
  for(i = 0; i < fragments; i++) {
    char *hostp = (char *)fragment[i];
    if(hostp)
      while(*hostp) {
        size_t labellen;
        char *dot = strchr(hostp, '.');
        if(dot)
          labellen = dot - hostp;
        else
          labellen = strlen(hostp);
        if((labellen > 63) || (!labellen)) {
          /* label is too long or too short, error out */
          *olen = 0;
          return DOH_DNS_BAD_LABEL;
        }
        /* label is non-empty, process it */
        *dnsp++ = (unsigned char)labellen;
        memcpy(dnsp, hostp, labellen);
        dnsp += labellen;
        hostp += labellen;
        /* advance past dot, but only if there is one */
        if(dot)
          hostp++;
      } /* next label */
  }     /* next fragment */

  *dnsp++ = 0; /* append zero-length label for root */

  /* There are assigned TYPE codes beyond 255: use range [1..65535]  */
  *dnsp++ = (unsigned char)(255 & (dnstype>>8)); /* upper 8 bit TYPE */
  *dnsp++ = (unsigned char)(255 & dnstype);      /* lower 8 bit TYPE */

  *dnsp++ = '\0'; /* upper 8 bit CLASS */
  *dnsp++ = DNS_CLASS_IN; /* IN - "the Internet" */

  *olen = dnsp - orig;

  /* verify that our estimation of length is valid, since
   * this has led to buffer overflows in this function */
  DEBUGASSERT(*olen == expected_len);
  return DOH_OK;
}

static size_t
doh_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct dohresponse *mem = (struct dohresponse *)userp;

  if((mem->size + realsize) > DOH_MAX_RESPONSE_SIZE)
    /* suspiciously much for us */
    return 0;

  mem->memory = Curl_saferealloc(mem->memory, mem->size + realsize);
  if(!mem->memory)
    /* out of memory! */
    return 0;

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;

  return realsize;
}

/* called from multi.c when this DOH transfer is complete */
static int Curl_doh_done(struct Curl_easy *doh, CURLcode result)
{
  struct Curl_easy *data = doh->set.dohfor;
  /* so one of the DOH request done for the 'data' transfer is now complete! */
  data->req.doh.pending--;
  infof(data, "a DOH request is completed, %u to go\n", data->req.doh.pending);
  if(result)
    infof(data, "DOH request %s\n", curl_easy_strerror(result));

  if(!data->req.doh.pending) {
    /* DOH completed */
    curl_slist_free_all(data->req.doh.headers);
    data->req.doh.headers = NULL;
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
  return 0;
}

#define ERROR_CHECK_SETOPT(x,y) \
do {                                      \
  result = curl_easy_setopt(doh, x, y);   \
  if(result)                              \
    goto error;                           \
} while(0)

static CURLcode dohprobe(struct Curl_easy *data,
                         struct dnsprobe *p, DNStype dnstype,
                         const char *prefix,
                         const char *host,
                         const char *url, CURLM *multi,
                         struct curl_slist *headers)
{
  struct Curl_easy *doh = NULL;
  char *nurl = NULL;
  CURLcode result = CURLE_OK;
  timediff_t timeout_ms;
  DOHcode d = doh_encode(host, prefix, dnstype,
                         p->dohbuffer, sizeof(p->dohbuffer),
                         &p->dohlen);
  if(d) {
    failf(data, "Failed to encode DOH packet [%d]\n", d);
    return CURLE_OUT_OF_MEMORY;
  }

  p->dnstype = dnstype;
  p->prefix = (char *) prefix;
  p->serverdoh.memory = NULL;
  /* the memory will be grown as needed by realloc in the doh_write_cb
     function */
  p->serverdoh.size = 0;

  /* Note: this is code for sending the DoH request with GET but there's still
     no logic that actually enables this. We should either add that ability or
     yank out the GET code. Discuss! */
  if(data->set.doh_get) {
    char *b64;
    size_t b64len;
    result = Curl_base64url_encode(data, (char *)p->dohbuffer, p->dohlen,
                                   &b64, &b64len);
    if(result)
      goto error;
    nurl = aprintf("%s?dns=%s", url, b64);
    free(b64);
    if(!nurl) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    url = nurl;
  }

  timeout_ms = Curl_timeleft(data, NULL, TRUE);
  if(timeout_ms <= 0) {
    result = CURLE_OPERATION_TIMEDOUT;
    goto error;
  }
  /* Curl_open() is the internal version of curl_easy_init() */
  result = Curl_open(&doh);
  if(!result) {
    /* pass in the struct pointer via a local variable to please coverity and
       the gcc typecheck helpers */
    struct dohresponse *resp = &p->serverdoh;
    ERROR_CHECK_SETOPT(CURLOPT_URL, url);
    ERROR_CHECK_SETOPT(CURLOPT_WRITEFUNCTION, doh_write_cb);
    ERROR_CHECK_SETOPT(CURLOPT_WRITEDATA, resp);
    if(!data->set.doh_get) {
      ERROR_CHECK_SETOPT(CURLOPT_POSTFIELDS, p->dohbuffer);
      ERROR_CHECK_SETOPT(CURLOPT_POSTFIELDSIZE, (long)p->dohlen);
    }
    ERROR_CHECK_SETOPT(CURLOPT_HTTPHEADER, headers);
#ifdef USE_NGHTTP2
    ERROR_CHECK_SETOPT(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
#endif
#ifndef CURLDEBUG
    /* enforce HTTPS if not debug */
    ERROR_CHECK_SETOPT(CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
#else
    /* in debug mode, also allow http */
    ERROR_CHECK_SETOPT(CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
#endif
    ERROR_CHECK_SETOPT(CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    if(data->set.verbose)
      ERROR_CHECK_SETOPT(CURLOPT_VERBOSE, 1L);
    if(data->set.no_signal)
      ERROR_CHECK_SETOPT(CURLOPT_NOSIGNAL, 1L);

    /* Inherit *some* SSL options from the user's transfer. This is a
       best-guess as to which options are needed for compatibility. #3661 */
    if(data->set.ssl.falsestart)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_FALSESTART, 1L);
    if(data->set.ssl.primary.verifyhost)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
#ifndef CURL_DISABLE_PROXY
    if(data->set.proxy_ssl.primary.verifyhost)
      ERROR_CHECK_SETOPT(CURLOPT_PROXY_SSL_VERIFYHOST, 2L);
    if(data->set.proxy_ssl.primary.verifypeer)
      ERROR_CHECK_SETOPT(CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
    if(data->set.str[STRING_SSL_CAFILE_PROXY]) {
      ERROR_CHECK_SETOPT(CURLOPT_PROXY_CAINFO,
        data->set.str[STRING_SSL_CAFILE_PROXY]);
    }
    if(data->set.str[STRING_SSL_CRLFILE_PROXY]) {
      ERROR_CHECK_SETOPT(CURLOPT_PROXY_CRLFILE,
        data->set.str[STRING_SSL_CRLFILE_PROXY]);
    }
    if(data->set.proxy_ssl.no_revoke)
      ERROR_CHECK_SETOPT(CURLOPT_PROXY_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
    if(data->set.str[STRING_SSL_CAPATH_PROXY]) {
      ERROR_CHECK_SETOPT(CURLOPT_PROXY_CAPATH,
        data->set.str[STRING_SSL_CAPATH_PROXY]);
    }
#endif
    if(data->set.ssl.primary.verifypeer)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    if(data->set.ssl.primary.verifystatus)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYSTATUS, 1L);
    if(data->set.str[STRING_SSL_CAFILE_ORIG]) {
      ERROR_CHECK_SETOPT(CURLOPT_CAINFO,
        data->set.str[STRING_SSL_CAFILE_ORIG]);
    }
    if(data->set.str[STRING_SSL_CAPATH_ORIG]) {
      ERROR_CHECK_SETOPT(CURLOPT_CAPATH,
        data->set.str[STRING_SSL_CAPATH_ORIG]);
    }
    if(data->set.str[STRING_SSL_CRLFILE_ORIG]) {
      ERROR_CHECK_SETOPT(CURLOPT_CRLFILE,
        data->set.str[STRING_SSL_CRLFILE_ORIG]);
    }
    if(data->set.ssl.certinfo)
      ERROR_CHECK_SETOPT(CURLOPT_CERTINFO, 1L);
    if(data->set.str[STRING_SSL_RANDOM_FILE]) {
      ERROR_CHECK_SETOPT(CURLOPT_RANDOM_FILE,
        data->set.str[STRING_SSL_RANDOM_FILE]);
    }
    if(data->set.str[STRING_SSL_EGDSOCKET]) {
      ERROR_CHECK_SETOPT(CURLOPT_EGDSOCKET,
        data->set.str[STRING_SSL_EGDSOCKET]);
    }
    if(data->set.ssl.no_revoke)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
    if(data->set.ssl.fsslctx)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_CTX_FUNCTION, data->set.ssl.fsslctx);
    if(data->set.ssl.fsslctxp)
      ERROR_CHECK_SETOPT(CURLOPT_SSL_CTX_DATA, data->set.ssl.fsslctxp);

    doh->set.fmultidone = Curl_doh_done;
    doh->set.dohfor = data; /* identify for which transfer this is done */
    p->easy = doh;

    /* add this transfer to the multi handle */
    if(curl_multi_add_handle(multi, doh))
      goto error;
  }
  else
    goto error;
  free(nurl);
  return CURLE_OK;

  error:
  free(nurl);
  Curl_close(&doh);
  return result;
}

/*
 * Curl_doh() resolves a name using DOH. It resolves a name and returns a
 * 'Curl_addrinfo *' with the address information.
 */

Curl_addrinfo *Curl_doh(struct connectdata *conn,
                        const char *hostname,
                        int port,
                        int *waitp)
{
  struct Curl_easy *data = conn->data;
  int slot;
  char *prefix = NULL;
  CURLcode result = CURLE_OK;

#ifdef USE_ESNI
  int qport;
  char *scheme;
  uint16_t qtype;
#endif

  *waitp = TRUE; /* this never returns synchronously */

  /* start clean, consider allocating this struct on demand */
  memset(&data->req.doh, 0, sizeof(struct dohdata));

  data->req.doh.host = hostname;
  data->req.doh.port = port;
  data->req.doh.headers =
    curl_slist_append(NULL,
                      "Content-Type: application/dns-message");
  if(!data->req.doh.headers)
    goto error;

#ifdef USE_ESNI
  qport = port;
  scheme = data->state.up.scheme;

  infof(data, "Preparing DNS probe for service binding\n");
  infof(data, "  scheme:   %s\n", scheme);
  infof(data, "  hostname: %s\n", hostname);
  infof(data, "  port:     %d\n", port);

  /* Work out which DNS probes we should send:
   * - TXT with _esni prefix: always, while we support ESNI draft 02
   * - HTTPS without prefix, or
   * - HTTPS with _PORT prefix, or
   * - SVCB with _PORT._SCHEME prefix
   */

  if(!strcmp(scheme, "http")) {
    /* Construct (components of) "https" URL according to */
    /* section 7.5 of draft-ietf-dnsop-svcb-https-01      */
    if(qport == 80)
      qport = 443;
    scheme = (char *) "https";
    }

  if(!strcmp(scheme, "https")) {
    /* Original or constructed scheme is "https" -- use QTYPE HTTPS */
    size_t pflen = 6 + 1;
    qtype = DNS_TYPE_HTTPS;
    if((port < 1) || (port > 65534)) {
      result = DOH_PORT_OUT_OF_RANGE;
      goto error;
    }
    if(port != 443) {
      /* Non-default port in use -- construct ATTRLEAF prefix _PORT */
      prefix = calloc(1, pflen + 1);
      if((!prefix) ||
         (!curl_msnprintf(prefix, 6, "_%d", port))) {
        result = DOH_OUT_OF_MEM;
        goto error;
      }
    }
  }

  else {
    /* No appropriate SVCB-compatible RR type -- use QTYPE SVCB */
    size_t pflen = 6 + 1 + strlen(scheme) + 1;
    qtype = DNS_TYPE_SVCB;
    prefix = calloc(1, pflen + 1);
    if((!prefix) ||
        (!curl_msnprintf(prefix, pflen, "_%d._%s", port, scheme))) {
        result = DOH_OUT_OF_MEM;
        goto error;
      }
  }

  infof(data, "  prefix:   %s\n", prefix);
  infof(data, "  qtype:    %d\n", qtype);
  infof(data, "  TODO: probe for service binding is not yet implemented\n");

  /* Probe for ESNI_TXT and/or SVCB/HTTPS before probing for A/AAAA */
  if((data->set.tls_enable_esni) /* ESNI was requested */
     /* TODO: skip if we have the material already in cache */
     ) {
    /* create service binding request (for ESNI draft-07) */
    result = dohprobe(data,
                   &data->req.doh.probe[DOH_PROBE_SLOT_BIND_SVC],
                      qtype, prefix, /* each as computed */
                      hostname, data->set.str[STRING_DOH],
                      data->multi, data->req.doh.headers);
    if(result)
      goto error;
    data->req.doh.pending++;

    /* create ESNI TXT request (for ESNI draft-02) */
    result = dohprobe(data, &data->req.doh.probe[DOH_PROBE_SLOT_ESNI_TXT],
                      DNS_TYPE_TXT, "_esni",
                      hostname, data->set.str[STRING_DOH],
                      data->multi, data->req.doh.headers);
    if(result)
      goto error;
    data->req.doh.pending++;
  }
#endif

  if(conn->ip_version != CURL_IPRESOLVE_V6) {
    /* create IPv4 DOH request */
    result = dohprobe(data, &data->req.doh.probe[DOH_PROBE_SLOT_IPADDR_V4],
                      DNS_TYPE_A, NULL, hostname,
                      data->set.str[STRING_DOH],
                      data->multi, data->req.doh.headers);
    if(result)
      goto error;
    data->req.doh.pending++;
  }

  if(conn->ip_version != CURL_IPRESOLVE_V4) {
    /* create IPv6 DOH request */
    result = dohprobe(data, &data->req.doh.probe[DOH_PROBE_SLOT_IPADDR_V6],
                      DNS_TYPE_AAAA, NULL, hostname,
                      data->set.str[STRING_DOH],
                      data->multi, data->req.doh.headers);
    if(result)
      goto error;
    data->req.doh.pending++;
  }

  return NULL;

  error:
  curl_slist_free_all(data->req.doh.headers);
  data->req.doh.headers = NULL;
  for(slot = 0; slot < DOH_PROBE_SLOTS; slot++) {
    Curl_close(&data->req.doh.probe[slot].easy);
  }
  return NULL;
}

static DOHcode skipqname(unsigned char *doh, size_t dohlen,
                         unsigned int *indexp)
{
  unsigned char length;
  do {
    if(dohlen < (*indexp + 1))
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[*indexp];
    if((length & 0xc0) == 0xc0) {
      /* name pointer, advance over it and be done */
      if(dohlen < (*indexp + 2))
        return DOH_DNS_OUT_OF_RANGE;
      *indexp += 2;
      break;
    }
    if(length & 0xc0)
      return DOH_DNS_BAD_LABEL;
    if(dohlen < (*indexp + 1 + length))
      return DOH_DNS_OUT_OF_RANGE;
    *indexp += 1 + length;
  } while(length);
  return DOH_OK;
}

static unsigned short get16bit(unsigned char *doh, int index)
{
  return (unsigned short)((doh[index] << 8) | doh[index + 1]);
}

static unsigned int get32bit(unsigned char *doh, int index)
{
   /* make clang and gcc optimize this to bswap by incrementing
      the pointer first. */
   doh += index;

   /* avoid undefined behaviour by casting to unsigned before shifting
      24 bits, possibly into the sign bit. codegen is same, but
      ub sanitizer won't be upset */
  return ( (unsigned)doh[0] << 24) | (doh[1] << 16) |(doh[2] << 8) | doh[3];
}

static DOHcode acceptname(unsigned char *doh, size_t dohlen,
                          unsigned int *indexp,
                          unsigned char *expect)
{
  /* Arguments:
   * - doh:    pointer to a buffer containing a DNS response
   * - dohlen: length of DNS response in this buffer
   * - indexp: pointer to offset into buffer of current position
   * - expect: pointer to an uncompressed expected DNS label sequence, or
   *           NULL to indicate that matching is not required
   *
   * Function:
   *   A DNS label sequence starting at the current position
   *   is validated for correct format and for matching the
   *   expected label sequence, if specified
   *
   *   If validation is successful, the offset is updated past
   *   the validated label sequence and DOH_OK is returned.
   *
   *   Otherwise an error code is returned.
   *
   * Implementation notes:
   *   If the expect argument points inside the DNS response data
   *   ((expect >= doh) && (expect < doh + dohlen)), then a label
   *   sequence consisting only of a name-
   *   compression pointer whose offset is equal to (expect - doh)
   */

  unsigned int mark = *indexp;  /* save starting position */
  unsigned int point = *indexp; /* current position */
  unsigned int offset = 0;      /* compression pointer value (valid >= 12) */
  unsigned int totlen = 0;      /* total length of label sequence */
  unsigned char length;         /* length of each label */
  bool scanning = TRUE;         /* no compression yet */

  if(mark < 12)
    return DOH_DNS_MALFORMAT;   /* name must be beyond header */

  do {
    if(dohlen < (point + 1))
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[point];
    if((length & 0xc0) == 0xc0) {
      /* compression pointer, check validity */
      if(dohlen < (point + 2))
        return DOH_DNS_OUT_OF_RANGE;
      if(scanning) {
        *indexp += 2;             /* advance past pointer */
        scanning = FALSE;         /* done scanning: pointer ends input */
      }

      /* check offset value in pointer */
      offset = 0x3fff & get16bit(doh, point);
      if(dohlen < offset)
        return DOH_DNS_OUT_OF_RANGE; /* or new DOH_DNS_BAD_POINTER ? */
      if(!expect)
        break;                  /* nothing to match, so done with name */

      /* check what we can for match */
      if(expect == doh + offset) {
        /* trivial: pointer refers to what is required */
        expect = NULL;          /* nothing more to expect */
        break;                  /* done with name, match complete */
      }

      if(point > mark) {
        if(memcmp(expect, doh + mark, point - mark))
          return DOH_DNS_NAME_MISMATCH;
        expect += point - mark; /* advance past what matched */
        mark = offset;          /* set new mark from pointer */
        point = mark;           /* continue matching from there */
      }
    }
    if(length & 0xc0)
      return DOH_DNS_BAD_LABEL;
    if(dohlen < (point + 1 + length))
      return DOH_DNS_OUT_OF_RANGE;
    point += 1 + length;
    totlen += 1 + length;
    if(scanning)
      *indexp += 1 + length;
    if(totlen > 255)
      return DOH_DNS_NAME_TOO_LONG;
  } while(length);

  if(expect && memcmp(expect, doh + mark, point - mark))
    return DOH_DNS_NAME_MISMATCH;

  return DOH_OK;
}

static DOHcode store_a(unsigned char *doh, int index, struct dohentry *d)
{
  /* silently ignore addresses over the limit */
  if(d->numaddr < DOH_MAX_ADDR) {
    struct dohaddr *a = &d->addr[d->numaddr];
    a->type = DNS_TYPE_A;
    memcpy(&a->ip.v4, &doh[index], 4);
    d->numaddr++;
  }
  return DOH_OK;
}

static DOHcode store_aaaa(unsigned char *doh, int index, struct dohentry *d)
{
  /* silently ignore addresses over the limit */
  if(d->numaddr < DOH_MAX_ADDR) {
    struct dohaddr *a = &d->addr[d->numaddr];
    a->type = DNS_TYPE_AAAA;
    memcpy(&a->ip.v6, &doh[index], 16);
    d->numaddr++;
  }
  return DOH_OK;
}

static DOHcode cnameappend(struct cnamestore *c,
                           unsigned char *src,
                           size_t len)
{
  if(!c->alloc) {
    c->allocsize = len;
    c->alloc = malloc(c->allocsize);
    if(!c->alloc)
      return DOH_OUT_OF_MEM;
  }
  else if(c->allocsize < (c->allocsize + len)) {
    unsigned char *ptr;
    c->allocsize += len;
    ptr = realloc(c->alloc, c->allocsize);
    if(!ptr) {
      free(c->alloc);
      return DOH_OUT_OF_MEM;
    }
    c->alloc = ptr;
  }
  memcpy(&c->alloc[c->len], src, len);
  c->len += len;
  /* c->alloc[c->len] = 0; /\* keep it zero terminated *\/ */
  return DOH_OK;
}

static DOHcode store_cname(unsigned char *doh,
                           size_t dohlen,
                           unsigned int index,
                           struct dohentry *d)
{
  struct cnamestore *c;
  unsigned int loop = 128; /* a valid DNS name can never loop this much */
  unsigned char length;

  if(d->numcname == DOH_MAX_CNAME)
    return DOH_OK; /* skip! */

  c = &d->cname[d->numcname++];
  do {
    if(index >= dohlen)
      return DOH_DNS_OUT_OF_RANGE;
    length = doh[index];
    if((length & 0xc0) == 0xc0) {
      if((index + 1) >= dohlen)
        return DOH_DNS_OUT_OF_RANGE;
      index = 0x3fff & get16bit(doh, index);
    }

    else if(length & 0xc0)
      return DOH_DNS_BAD_LABEL; /* bad input */

    else {
      DOHcode rc;
      rc = cnameappend(c, &doh[index], length + 1);
      if(rc)
        return rc;
      index += length + 1;
    }

  } while(length && --loop);

  if(!loop)
    return DOH_DNS_LABEL_LOOP;
  return DOH_OK;
}

static DOHcode store_esni_txt(unsigned char *doh,
                              size_t dohlen,
                              unsigned int index,
                              unsigned short rdlength,
                              struct dohentry *d)
{
  struct txtstore *c;
  size_t strlen;
  size_t rdlen;
  unsigned char *src;
  unsigned char *dst;

  rdlen = rdlength;
  src = doh + index;

  if(d->num_esni_txt == DOH_MAX_ESNI_TXT)
    return DOH_OK; /* skip! */

  c = &d->esni_txt[d->num_esni_txt++];

  if(index + rdlength > dohlen)
    return DOH_DNS_OUT_OF_RANGE;

  /* Required allocation will be
   * rdlen
   * -n, the count of RFC1035 <character-string>s contained in RDATA
   * +1 for the final '\0'
  */
  c->allocsize = rdlen;        /* not less than required allocation */

  c->alloc = calloc(1, c->allocsize);
  if(!c->alloc)
    return DOH_OUT_OF_MEM;

  for(dst = c->alloc; rdlen; rdlen -= strlen) {
    strlen = *src++;            /* pick up the string length */
    rdlen--;                    /* count down for the length byte */
    if(strlen > rdlen)
      return DOH_DNS_OUT_OF_RANGE;
    memcpy(dst, src, strlen);   /* copy a <character-string> */
    src += strlen;              /* advance source cursor */
    dst += strlen;              /* advance destination cursor */
  }                             /* next <character-string> */

  *dst++ = '\0';                /* closing null */
  c->len = dst - c->alloc;      /* strlen() + 1 */

  return DOH_OK;
}

static DOHcode store_svcb_rdata(unsigned char *doh,
                                size_t dohlen,
                                unsigned short type,
                                unsigned int index,
                                unsigned short rdlength,
                                struct dohentry *d)
{
  struct svcbstore *c;
  size_t rdlen;
  unsigned char *src;

  rdlen = rdlength;
  src = doh + index;

  if(rdlen > dohlen - index)
    return DOH_DNS_OUT_OF_RANGE;

  c = &d->svcb_data[d->num_svcb_data++];
  c->allocsize = rdlen;
  c->alloc = calloc(1, c->allocsize);
  c->type = type;

  if(!c->alloc)
    return DOH_OUT_OF_MEM;

  memcpy(c->alloc, src, rdlen);
  c->len = rdlen;

  return DOH_OK;
}

static DOHcode rdata(unsigned char *doh,
                     size_t dohlen,
                     unsigned short rdlength,
                     unsigned short type,
                     int index,
                     struct dohentry *d)
{
  /* RDATA
     - A (TYPE 1):  4 bytes
     - AAAA (TYPE 28): 16 bytes
     - NS (TYPE 2): N bytes */
  DOHcode rc;
  /* uint16_t sf_priority; */
  /* unsigned char *sf_domain_name; */
  /* void *sf_value; */

  switch(type) {
  case DNS_TYPE_A:
    if(rdlength != 4)
      return DOH_DNS_RDATA_LEN;
    rc = store_a(doh, index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_AAAA:
    if(rdlength != 16)
      return DOH_DNS_RDATA_LEN;
    rc = store_aaaa(doh, index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_CNAME:
    rc = store_cname(doh, dohlen, index, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_TXT:
    if((d->prefix) && (!strcmp(d->prefix, "_esni"))) {
      /* Context: type TXT, prefix "_esni" */
      rc = store_esni_txt(doh, dohlen, index, rdlength, d);
      if(rc)
        return rc;
    }
    break;
  case DNS_TYPE_SVCB:
  case DNS_TYPE_HTTPS:
    rc = store_svcb_rdata(doh, dohlen, type, index, rdlength, d);
    if(rc)
      return rc;
    break;
  case DNS_TYPE_DNAME:
    /* explicit for clarity; just skip; rely on synthesized CNAME  */
    break;
  default:
    /* unsupported type, just skip it */
    break;
  }
  return DOH_OK;
}

static void init_dohentry(struct dohentry *de)
{
  memset(de, 0, sizeof(*de));
  de->ttl = INT_MAX;
}

static DOHcode doh_decode_in_context(struct dnsprobe *p,
                                     struct dohentry *d)
{
  /* TODO: consider adding unit test for this */

  unsigned char rcode;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short type = 0;
  unsigned short rdlength;
  unsigned short nscount;
  unsigned short arcount;
  unsigned int index = 12;
  DOHcode rc;

  /* For convenience: references to certain elements of query context */
  unsigned char *qry = p->dohbuffer;        /* query */
  unsigned char *doh = p->serverdoh.memory; /* response */
  size_t dohlen = p->serverdoh.size;        /* length of response */
  DNStype dnstype = p->dnstype;             /* query TYPE */
  unsigned char *expected = qry + 12;       /* QNAME */

  /* Add others as needed */
  /* char *prefix = p->prefix; */

  if(dohlen < 12)
    return DOH_TOO_SMALL_BUFFER; /* too small */

  /* if(!doh || doh[0] || doh[1]) */
  /*   return DOH_DNS_BAD_ID; /\* bad ID *\/ */
  if(!doh || doh[0] != qry[0] || doh[1] != qry[1])
    return DOH_DNS_BAD_ID; /* bad ID */

  rcode = doh[3] & 0x0f;
  if(rcode)
    return DOH_DNS_BAD_RCODE; /* bad rcode */

  qdcount = get16bit(doh, 4);
  if(qdcount != 1)              /* We don't send compound queries */
    return DOH_DNS_BAD_QDCOUNT;

  while(qdcount) {
    /* rc = skipqname(doh, dohlen, &index); */
    rc = acceptname(doh, dohlen, &index, expected);
    if(rc)
      return rc; /* bad qname */

    /* QNAME in response matches that in query, and is within range
     * for any compression pointers later in response
     */
    expected = doh + 12;        /* instead of qry + 12 */

    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;
    index += 4; /* skip question's type and class */
    qdcount--;
  }

  ancount = get16bit(doh, 6);
  while(ancount) {
    unsigned short class;
    unsigned int ttl;

    rc = acceptname(doh, dohlen, &index, expected);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    type = get16bit(doh, index);
    if((type != DNS_TYPE_CNAME)    /* may be synthesized from DNAME */
       && (type != DNS_TYPE_DNAME) /* if present, accept and ignore */
       && (type != dnstype))
      /* Not the same type as was asked for nor CNAME nor DNAME */
      return DOH_DNS_UNEXPECTED_TYPE;
    index += 2;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;
    class = get16bit(doh, index);
    if(DNS_CLASS_IN != class)
      return DOH_DNS_UNEXPECTED_CLASS; /* unsupported */
    index += 2;

    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;

    ttl = get32bit(doh, index);
    if(ttl < d->ttl)            /* Shorter than limit so far ? */
      d->ttl = ttl;             /* Yes: keep the shorter one */
    index += 4;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;

    rc = rdata(doh, dohlen, rdlength, type, index, d);
    if(rc)
      return rc; /* bad rdata */

    /* CNAME: update expected name from rdata */
    if(type == DNS_TYPE_CNAME)
      expected = d->cname[d->numcname].alloc;

    index += rdlength;
    ancount--;
  }

  nscount = get16bit(doh, 8);
  while(nscount) {
    /* Check well-formedness and ignore */
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2 + 2 + 4; /* type, class and ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    nscount--;
  }

  arcount = get16bit(doh, 10);
  while(arcount) {
    /* Check well-formedness and ignore */
    /* TODO:
     * take advantage of additional section for SVCB-compatible type */
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2 + 2 + 4; /* type, class and ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    arcount--;
  }

  if(index != dohlen)
    return DOH_DNS_MALFORMAT; /* unexpected residual data */

  if(((type == DNS_TYPE_A) || (type == DNS_TYPE_AAAA)) &&
     !d->numcname && !d->numaddr)
    /* TODO: take account of DNS being about more than just address data */
    /* nothing stored! */
    return DOH_NO_CONTENT;

  return DOH_OK; /* ok */
}

UNITTEST DOHcode doh_decode(unsigned char *doh,
                            size_t dohlen, /* overloaded to select decoder */
                            DNStype dnstype,
                            struct dohentry *d)
{
  unsigned char rcode;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short type = 0;
  unsigned short rdlength;
  unsigned short nscount;
  unsigned short arcount;
  unsigned int index = 12;
  DOHcode rc;

  if(dohlen < 12)
    return DOH_TOO_SMALL_BUFFER; /* too small */
  if(!doh || doh[0] || doh[1])
    return DOH_DNS_BAD_ID; /* bad ID */
  rcode = doh[3] & 0x0f;
  if(rcode)
    return DOH_DNS_BAD_RCODE; /* bad rcode */

  qdcount = get16bit(doh, 4);
  while(qdcount) {
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */
    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;
    index += 4; /* skip question's type and class */
    qdcount--;
  }

  ancount = get16bit(doh, 6);
  while(ancount) {
    unsigned short class;
    unsigned int ttl;

    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    type = get16bit(doh, index);
    if((type != DNS_TYPE_CNAME)    /* may be synthesized from DNAME */
       && (type != DNS_TYPE_DNAME) /* if present, accept and ignore */
       && (type != dnstype))
      /* Not the same type as was asked for nor CNAME nor DNAME */
      return DOH_DNS_UNEXPECTED_TYPE;
    index += 2;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;
    class = get16bit(doh, index);
    if(DNS_CLASS_IN != class)
      return DOH_DNS_UNEXPECTED_CLASS; /* unsupported */
    index += 2;

    if(dohlen < (index + 4))
      return DOH_DNS_OUT_OF_RANGE;

    ttl = get32bit(doh, index);
    if(ttl < d->ttl)            /* Shorter than limit so far ? */
      d->ttl = ttl;             /* Yes: keep the shorter one */
    index += 4;

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;

    rc = rdata(doh, dohlen, rdlength, type, index, d);
    if(rc)
      return rc; /* bad rdata */
    index += rdlength;
    ancount--;
  }

  nscount = get16bit(doh, 8);
  while(nscount) {
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2 + 2 + 4; /* type, class and ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    nscount--;
  }

  arcount = get16bit(doh, 10);
  while(arcount) {
    rc = skipqname(doh, dohlen, &index);
    if(rc)
      return rc; /* bad qname */

    if(dohlen < (index + 8))
      return DOH_DNS_OUT_OF_RANGE;

    index += 2 + 2 + 4; /* type, class and ttl */

    if(dohlen < (index + 2))
      return DOH_DNS_OUT_OF_RANGE;

    rdlength = get16bit(doh, index);
    index += 2;
    if(dohlen < (index + rdlength))
      return DOH_DNS_OUT_OF_RANGE;
    index += rdlength;
    arcount--;
  }

  if(index != dohlen)
    return DOH_DNS_MALFORMAT; /* something is wrong */

  if(((type == DNS_TYPE_A) || (type == DNS_TYPE_AAAA)) &&
     !d->numcname && !d->numaddr)
    /* nothing stored! */
    return DOH_NO_CONTENT;

  return DOH_OK; /* ok */
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
#ifdef USE_ESNI
static char *bin2hex(char *dst, size_t *dstlen,
                     unsigned char *src, size_t srclen,
                     size_t truncate)
{
  const char hex[] = "0123456789ABCDEF";
  size_t req;
  char *p = dst;

  if(!truncate || truncate > srclen) {
    truncate = srclen;
  }

  req = 1 + 2 * truncate;
  if((!p) || (*dstlen < req)) {
    if(!p)
      p = malloc(req);
    else if(*dstlen < req)
      p = realloc(dst, req);
    if(p) {
      *dstlen = req;
      dst = p;
    }
  }

  if((!*dstlen) || (!dst)) {
    if(dst)
      free(dst);
    return NULL;
  }

  if(*dstlen < req)
    truncate = (*dstlen - 1) / 2;

  while(truncate--) {
    *dst++ = hex[(255 & *src)>>4];
    *dst++ = hex[(15 & *src++)];
  }
  *dst = '\0';
  return p;
}
#endif

static size_t wire2name(char *dst, size_t dstlen,
                      unsigned char *src, size_t srclen)
{
  int i;
  size_t count = 0;          /* successfully processed source bytes */
  size_t cursor = 0;         /* current offset in source buffer     */
  char *p = dst;             /* position in destination buffer      */

  if(dst) {
    while(*src) {
      /* Process each non-empty label */
      if((*src + 2U) > srclen) {
        /* ERROR: label overflows buffer */
        count = -1;              /* treat malformed source as unprocessed */
        break;
      }
      else if((*src + 1U) > dstlen) {
        /* ERROR: not enough room in destination for label */
        count = -2;
        break;
      }
      else {
        /* Copy a non-empty label */
        cursor = 1;       /* allow for count byte */
        for(i = src[0]; i > 0; i--) {
          *p++ = src[cursor++];
          dstlen--;
        }
        src += cursor;          /* advance over processed data */
        srclen -= cursor;       /* adjust residual count */
        count += cursor;        /* adjust processed count */
        if(*src) {
          *p++ = '.';   /* separator before following label */
          dstlen--;
        }
      }
    } /* Next non-empty label */

    if((srclen) && (!*src)) {
      /* Final empty label, as expected */

      if(dstlen > (count ? 0 : 1)) {
        /* There's enough space  */
        if(!count) {
          *p++ = '.';           /* display a dot if name is empty */
        }
        *p = '\0';
        count++;                /* count past the trailing empty label */
      }
      else
        count = -3;
    }
    else                        /* Something is wrong */
      count = -4;
  }
  return count;                 /* count of processed source bytes
                                   or zero or negative for error */
}

static size_t display_public_name(struct Curl_easy *data,
                                        unsigned char *buffer, size_t more)
{
  size_t progress;
  uint16_t len = get16bit(buffer, 0);
  if(len > (more - 2)) {
    progress = more;            /* mark rest of buffer done */
  }
  else {
    char *display = calloc(1, len + 1);
    buffer += 2;
    if(display) {
      memcpy(display, buffer, len);
      infof(data, "        - public_name (%d): '%s'\n", len, display);
      free(display);
    }
    progress = 2 + len;
  }
  return progress;
}

static size_t display_cipher_suites(struct Curl_easy *data,
                                          unsigned char *buffer, size_t more)
{
  size_t progress;
  uint16_t len = get16bit(buffer, 0);
  if(len > (more - 2)) {
    progress = more;            /* mark rest of buffer done */
  }
  else {
    int i;
    buffer += 2;
    progress = 2;
    for(i = 0; i < len; i += 4) {
      unsigned int kdf_id, aead_id;
      kdf_id = get16bit(buffer, 0);
      aead_id = get16bit(buffer, 2);
      buffer += 4;
      progress += 4;
      if(!i) {
        infof(data, "        - cipher_suites (%d): 0x%04X 0x%04X\n",
              len, kdf_id, aead_id);
      }
      else {
        infof(data, "                            0x%04X 0x%04X\n",
              kdf_id, aead_id);
      }
    }
  }
  return progress;
}

static size_t display_extensions(struct Curl_easy *data,
                                       unsigned char *buffer, size_t more)
{
  size_t progress;
  uint16_t len = get16bit(buffer, 0);
  if(len > (more - 2)) {
    progress = more;            /* mark rest of buffer done */
  }
  else if(!len) {
    progress = 2;
    infof(data, "        - extensions (0)\n");
  }
  else {
    size_t limit = 2 * len;
    char *display = calloc(1, limit + 1);
    buffer += 2;
    if(display) {
      int i;
      char *ptr = display;
      for(i = 0; i < len; i++) {
        msnprintf(ptr, limit, "%02X", buffer[i]);
        ptr += 2;
        limit -= 2;
      }
      infof(data, "        - extensions (%d): '%s'\n", len, display);
      free(display);
    }
    progress = 2 + len;
  }
  return progress;
}

static size_t display_public_key(struct Curl_easy *data,
                                       unsigned char *buffer, size_t more)
{
  size_t progress;
  uint16_t len = get16bit(buffer, 0);
  if(len > (more - 2)) {
    progress = more;            /* mark rest of buffer done */
  }
  else {
    size_t limit = 2 * len;
    char *display = calloc(1, limit + 1);
    buffer += 2;
    if(display) {
      int i;
      char *ptr = display;
      for(i = 0; i < len; i++) {
        msnprintf(ptr, limit, "%02X", buffer[i]);
        ptr += 2;
        limit -= 2;
      }
      infof(data, "        - public_key (%d): '%s'\n", len, display);
      free(display);
    }
    progress = 2 + len;
  }
  return progress;
}

static void display_ECHConfigContents(struct Curl_easy *data,
                                      unsigned char *buffer, size_t more)
{
  size_t progress;
  infof(data, "      - ECHConfigContents:\n");
  if(more) {
    progress = display_public_name(data, buffer, more);
    more -= progress;
    buffer += progress;
  }

  if(more) {
    progress = display_public_key(data, buffer, more);
    more -= progress;
    buffer += progress;
  }

  if(more > 1) {
    uint16_t kem_id = get16bit(buffer, 0);
    infof(data, "        - kem_id: 0x%04X\n", kem_id);
    more += 2;
    buffer += 2;
  }
  else {
    more = 0;
  }

  if(more) {
    progress = display_cipher_suites(data, buffer, more);
    more -= progress;
    buffer += progress;
  }

  if(more) {
    progress = display_extensions(data, buffer, more);
    more -= progress;
    buffer += progress;
  }
  return;
}

static void display_generic_SvcParamValue(struct Curl_easy *data,
                                          unsigned char *buffer, size_t stock)
{
  char *tail = (char *) ((stock > 32) ? "..." : "");
  char display[32 + 32 + 1];
  char *p = display;
  size_t available = 32 + 32;
  unsigned int i;
  for(i = 0; i < ((stock > 32) ? 32 : stock); i++) {
    msnprintf(p, available, "%02X", (unsigned char) buffer[i]);
    available -= 2;
    p += 2;
  }
  infof(data, "    - SvcParamValue (%d): %s%s\n", stock, display, tail);
}

static bool display_ECHConfig(struct Curl_easy *data,
                              unsigned char *buffer, size_t stock)
{
  bool error = NULL;
  unsigned short version;
  unsigned short cont_len;

  if(stock <= 4) {

  }

  while(!error && (stock > 4)) {
    version = get16bit(buffer, 0);
    infof(data, "      - ECHConfig version 0x%04X\n", version);

    switch(version) {

    case 0xFF07:
      cont_len = get16bit(buffer, 2);
      if(cont_len > (stock - 4)) {
        infof(data, "      - ECHConfigContents exceeds buffer length\n");
        error = TRUE;
      }
      else {
        display_ECHConfigContents(data, buffer + 4, cont_len);
        stock -= (4 + cont_len);
        buffer += (4 + cont_len);
      }
      break;

    default:
      /* Unrecognized version: use generic display instead */
      infof(data,
            "        - version not recognized: using generic display\n");
      display_generic_SvcParamValue(data, buffer, stock);
      stock = 0;                /* mark it done */
      break;
    }
  }

  if(stock && !error) {
    infof(data, "      - residual data (%d) after ECHConfig \n", stock);
    error = TRUE;
  }
  return error;
}

static bool display_ECHConfigs(struct Curl_easy *data,
                               unsigned char *buffer, size_t paramlen)
{
  bool error = NULL;
  unsigned short len = get16bit(buffer, 0);
  infof(data, "    - SvcParamValue (%d):\n", paramlen);
  infof(data, "      - ECHConfigs length: %d\n", len);
  if(len > (paramlen - 2)) {
    infof(data, "      - ECHConfigs exceeds buffer length\n");
    error = TRUE;
  }
  else
    error = display_ECHConfig(data, buffer + 2, len);
  return error;
}

/* TODO: consider using ares_inet_ntop() if available */
static const char *
doh_inet_ntop(int af, const void *src, char *dst, size_t size)
{
  char *result = NULL;
  unsigned char *s = (unsigned char *) src;

  if(dst) {
    if((af == AF_INET6) && (size >= INET6_ADDRSTRLEN)) {
      int j;
      char *ptr = dst;
      struct {
        int len;
        char *pos;
      } cursor[2], *busy = NULL, *kept = NULL;
      size_t len;

      for(j = 0; j < 16; j += 2) {
        size_t l;
        if(s[j])
          msnprintf(ptr, len, "%s%x%02x", j?":":"", s[j], s[j + 1]);
        else {
          msnprintf(ptr, len, "%s%x", j?":":"", s[j + 1]);
          if(!s[j + 1]) {
            /* Zero word: may need compressed presentation */
            if(busy && (busy->pos + busy->len == ptr)) {
              /* Current position belongs to busy run */
              busy->len += 2;   /* Just update length of current run */
            }
            else {
              /* Fresh run -- must do housekeeping */
              if(!busy) {
                /* Not yet tracking a run of zero words */
                busy = cursor;  /* Select first cursor as busy */
                kept = busy;    /* First run so far, so keep it */
              }
              else if(kept == busy) {
                /* Fresh run with only one previous */
                /* Keep earlier one and move on */
                busy++;         /* Select next cursor as busy */
              }
              else if(kept->len <= busy->len) {
                /* Fresh run where most recent one is to be kept   */

                /* Note: non-strict inequality is biased towards   */
                /*       keeping later of two runs of equal length */

                /* Swap kept and busy cursors */
                if(busy > kept)
                  kept = busy--;
                else
                  kept = busy++;
              }

              /* else
               *   no housekeeping needed, as busy cursor can be re-used
               */

              /* After housekeeping, set busy cursor to current position */
              busy->pos = ptr;
              busy->len = 2;
            }
          }
        }
        l = strlen(ptr);
        len -= l;
        ptr += l;
      }
      /* infof(data, "%s\n", buffer); */
      if(busy) {
        if(kept) {
          if(busy->len > kept->len)
            kept = busy;
        }
        else
          kept = busy;
      }
      if(kept) {
        strcpy(kept->pos + 1, kept->pos + kept->len);
      }
      result = dst;
    }
    else if((af == AF_INET) && (size >= INET_ADDRSTRLEN)) {
      msnprintf(dst, size, "%u.%u.%u.%u", s[0], s[1], s[2], s[3]);
      result = dst;
    }
  }
  return result;
}

static const char *paramkeyname(uint16_t key)
{
  const char *name = NULL;
  switch(key) {
  case 0:
    name = "NO NAME -- reserved";
    break;
  case 1:
    name = "alpn";
    break;
  case 2:
    name = "no-default-alpn";
    break;
  case 3:
    name = "port";
    break;
  case 4:
    name = "ipv4hint";
    break;
  case 5:
    name = "echconfig";
    break;
  case 6:
    name = "ipv6hint";
    break;
  case 65535:
    name = "key65535 -- reserved";
    break;
  }
  if(!name) {
    if((key >= 65280) && (key <= 65534))
      name = "keyNNNNN -- private use";
    else
      name = "UNRECOGNIZED";
  }
  return name;
}

static bool display_SvcParams(struct Curl_easy *data,
                                  unsigned char *buffer, size_t stock)
{
  /* TODO: consider enum type rather than bool */

  bool error = NULL;            /* So far, so good */
  uint16_t key;
  uint16_t prev_key = 0;
  uint16_t paramlen;
  uint16_t count;
  int i;

  (void) i;                     /* TODO */

  infof(data, "    SvcParams bytes to be processed: %d\n", stock);

  while(stock && !error) {
    if(stock < 4) {
      /* Unable to fit key, length */
      infof(data, "    invalid SvcParams: buffer too short\n");
      error = TRUE;
      break;
    }

    key = get16bit(buffer, 0);
    infof(data, "    - SvcParamKey: %d (%s)\n", key, paramkeyname(key));
    if(key <= prev_key) {
      infof(data, "      SvcParamKey invalid: out of order\n");
      error = TRUE;
      break;
    }

    paramlen = get16bit(buffer, 2);
    buffer += 4;                /* advance past parameter length */
    stock -= 4;                 /* and adjust stock level */
    /* infof(data, "    - SvcParamValue (%d):\n", paramlen); */

    if(paramlen > stock) {
      infof(data, "      invalid parameter length: too big\n");
      error = TRUE;
      break;
    }

    if((key != 2) &&            /* exclude special case */
       (!paramlen)) {           /* otherwise, expect parameter data */
      infof(data, "      invalid parameter length: zero");
      error = TRUE;
    }

    if(!error) {
      switch(key) {

      case 1:
        /* alpn: Additional supported protocols */
        /*       Expect:
         *       - unsigned 8-bit count
         *       - octets
         */
        count = (unsigned char) *buffer; /* first byte is count */
        if(count >= paramlen) {
          infof(data, "      alpn-id list invalid: too long\n");
          error = TRUE;
        }
        if(!error) {
          /* TODO: Display count and URL-encoded alpn-id list */
          /* for now, use generic display */
          display_generic_SvcParamValue(data, buffer, paramlen);
        }
        break;

      case 2:
        /* no-default-alpn: No supprt for default protocol */
        if(paramlen) {
          infof(data,
                "      invalid (non-empty) value"
                " for key 'no-default-alpn'\n");
          error = TRUE;
        }
        break;

      case 3:
        /* port: Port for alternative service */
        /*       Expect:
         *       - paramlen == 2
         *       - unsigned 16-bit port number
         */
        if(paramlen == 2) {
          uint16_t port;
          port = get16bit(buffer, 0);
          infof(data, "    - SvcParamValue (%d): %d\n", paramlen, port);
        }
        else {
          infof(data,
                "       port: invalid parameter length: too %s\n",
                (paramlen < 2) ? "short" : "long"
                );
          error = TRUE;
        }
        break;

      case 5:
        /* echconfig: Encrypted ClientHello info            */
        display_ECHConfigs(data, buffer, paramlen);
        break;

      case 4:
      case 6:
        {
          char pres[INET6_ADDRSTRLEN];
          unsigned char *p = buffer;
          int step = (key == 6) ? 16 : 4;
          int af = (key == 6) ? AF_INET6 : AF_INET;

          infof(data, "    - SvcParamValue (%d):\n", paramlen);
          for(i = 0; i < paramlen; i += step, p += step) {
            if(doh_inet_ntop(af, p, pres, INET6_ADDRSTRLEN))
              infof(data, "      - %s\n", pres);
            else
              infof(data, "      - error formatting address\n");
          }
        }
        break;

      default:
        /* Generic display */
        display_generic_SvcParamValue(data, buffer, paramlen);
        break;

      }
    }

    if(!error) {
      /* Advance past current parameter */
      buffer += paramlen;
      stock -= paramlen;

      /* Report count of remaining bytes */
      infof(data, "    SvcParams bytes remaining: %d\n", stock);
    }
  } /* while(stock && !error) */

  return error;
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static const char *type2name(DNStype dnstype)
{
  switch(dnstype) {
  case DNS_TYPE_A:
    return "A";
  case DNS_TYPE_AAAA:
    return "AAAA";
  case DNS_TYPE_CNAME:
    return "CNAME";
  case DNS_TYPE_DNAME:
    return "DNAME";
  case DNS_TYPE_TXT:
    return "TXT";
  case DNS_TYPE_SVCB:
    return "SVCB";
  case DNS_TYPE_HTTPS:
    return "HTTPS";
  default:
    return "(unsupported)";
  /* return (dnstype == DNS_TYPE_A)?"A":"AAAA"; */
  }
}
#endif

static void showdoh(struct Curl_easy *data,
                    struct dohentry *d)
{
  int i;
#ifdef USE_ESNI
  size_t truncate = 48;
  size_t repr;
  char *tail;
  char *display = NULL;
  size_t displen;
#endif

  infof(data, "TTL: %u seconds\n", d->ttl);
  for(i = 0; i < d->numaddr; i++) {
    char buffer[INET6_ADDRSTRLEN];
    struct dohaddr *a = &d->addr[i];
    if(a->type == DNS_TYPE_A) {
      if(doh_inet_ntop(AF_INET, a->ip.v4, buffer, INET6_ADDRSTRLEN))
        infof(data, "DOH %5s: %s\n", "A", buffer);
    }
    else if(a->type == DNS_TYPE_AAAA) {
      if(doh_inet_ntop(AF_INET6, d->addr[i].ip.v6, buffer, INET6_ADDRSTRLEN))
        infof(data, "DOH %5s: %s\n", "AAAA", buffer);
    }
  }
  for(i = 0; i < d->numcname; i++) {
    char buffer[255] = { '\0' };
    unsigned int index = 0;
    unsigned int length;
    char *dst = buffer;
    struct cnamestore *c;

    c = &d->cname[i];

    do {
      length = c->alloc[index];
      if(length && index++)
        *(dst++) = '.';
      memcpy(dst, &c->alloc[index], length);
      index += length;
      dst += length;
    } while(length);
    *dst = '\0';

    infof(data, "DOH %5s: %s\n", "CNAME", buffer);
  }
#ifdef USE_ESNI
  for(i = 0; i < d->num_svcb_data; i++) {
    unsigned char *buffer = d->svcb_data[i].alloc;
    size_t buflen = d->svcb_data[i].len;
    uint16_t priority;
    size_t count;
    bool error = NULL;

    (void) error;               /* TODO: use or lose this variable */

    /* TODO: consider using msnprintf instead */
    display = bin2hex(display, &displen,
                      buffer, buflen,
                      truncate);

    if(display) {
      repr = strlen(display) / 2;
      tail = (char *) ((repr < buflen) ? "..." : "");
      infof(data, "DOH %s (%d/%d): %s%s\n",
            (d->svcb_data[i].type) ?
            type2name(d->svcb_data[i].type) : "svcbdata",
            repr, buflen, display, tail);

      if(buflen >= 2) {
        /* Priority (SvcRecordType) */
        /* priority = (((255 & buffer[0])<<8) | (255 & buffer[1])); */
        priority = get16bit(buffer, 0);
        buffer += 2;
        buflen -= 2;
        infof(data, "    SvcPriority: %d (%s)\n",
              priority,
              (priority ? "ServiceMode" : "AliasMode"));

        /* TargetName */
        count = wire2name(display, displen, buffer, buflen);
        if(count > 0) {
          infof(data, "    SvcDomaimName: '%s'\n", display);
          buffer += count;
          buflen -= count;
        }
        else {
          infof(data, "    TargetName: invalid (error code: %d)\n", count);
          break;
        }

        if(priority) {
          /* ServiceMode -- expect:                        */
          /* - one (zero?) or more SvcParamss          */
          if(!buflen) {
            infof(data, "    no SvcParams found\n");
          }
          else {
            display_SvcParams(data, buffer, buflen);
          }
        }
        else {
          /* AliasMode -- expect buffer already exhausted */
          if(buflen) {
            infof(data,
                  "    unexpected residual data after TargetName\n");
          }
          /* TODO (but not here): follow alias, as for CNAME,
           *       compensating if necessary in case resolver is
           *       unaware of this kind of aliasing
           */
        }
      }
    }
  }
  for(i = 0; i < d->num_esni_txt; i++) {
    CURLcode rc;
    size_t declen;
    unsigned char *decbuf = NULL;
    infof(data, "DOH esni_txt (%d): %s\n",
          strlen((char *)d->esni_txt[i].alloc),
          d->esni_txt[i].alloc);
    rc = Curl_base64_decode((const char *)d->esni_txt[i].alloc,
                            &decbuf, &declen);
    if(!rc) {
      display = bin2hex(display, &displen,
                        decbuf, declen,
                        truncate);
      if(display) {
        repr = strlen(display) / 2;
        tail = (char *) ((repr < declen) ? "..." : "");
        infof(data, "     decoded (%d/%d): %s%s\n",
              repr, declen, display, tail);
      }
    }

    else
      infof(data, "DOH esni_txt not decoded (%d)\n", rc);

    Curl_safefree(decbuf);
  }
  if(display)
    free(display);
#endif
}
#else
#define showdoh(x,y)
#endif

/*
 * doh2ai()
 *
 * This function returns a pointer to the first element of a newly allocated
 * Curl_addrinfo struct linked list filled with the data from a set of DOH
 * lookups.  Curl_addrinfo is meant to work like the addrinfo struct does for
 * a IPv6 stack, but usable also for IPv4, all hosts and environments.
 *
 * The memory allocated by this function *MUST* be free'd later on calling
 * Curl_freeaddrinfo().  For each successful call to this function there
 * must be an associated call later to Curl_freeaddrinfo().
 */

static Curl_addrinfo *
doh2ai(const struct dohentry *de, const char *hostname, int port)
{
  Curl_addrinfo *ai;
  Curl_addrinfo *prevai = NULL;
  Curl_addrinfo *firstai = NULL;
  struct sockaddr_in *addr;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *addr6;
#endif
  CURLcode result = CURLE_OK;
  int i;

  if(!de)
    /* no input == no output! */
    return NULL;

  for(i = 0; i < de->numaddr; i++) {
    size_t ss_size;
    CURL_SA_FAMILY_T addrtype;
    if(de->addr[i].type == DNS_TYPE_AAAA) {
#ifndef ENABLE_IPV6
      /* we can't handle IPv6 addresses */
      continue;
#else
      ss_size = sizeof(struct sockaddr_in6);
      addrtype = AF_INET6;
#endif
    }
    else {
      ss_size = sizeof(struct sockaddr_in);
      addrtype = AF_INET;
    }

    ai = calloc(1, sizeof(Curl_addrinfo));
    if(!ai) {
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    ai->ai_canonname = strdup(hostname);
    if(!ai->ai_canonname) {
      result = CURLE_OUT_OF_MEMORY;
      free(ai);
      break;
    }
    ai->ai_addr = calloc(1, ss_size);
    if(!ai->ai_addr) {
      result = CURLE_OUT_OF_MEMORY;
      free(ai->ai_canonname);
      free(ai);
      break;
    }

    if(!firstai)
      /* store the pointer we want to return from this function */
      firstai = ai;

    if(prevai)
      /* make the previous entry point to this */
      prevai->ai_next = ai;

    ai->ai_family = addrtype;

    /* we return all names as STREAM, so when using this address for TFTP
       the type must be ignored and conn->socktype be used instead! */
    ai->ai_socktype = SOCK_STREAM;

    ai->ai_addrlen = (curl_socklen_t)ss_size;

    /* leave the rest of the struct filled with zero */

    switch(ai->ai_family) {
    case AF_INET:
      addr = (void *)ai->ai_addr; /* storage area for this info */
      DEBUGASSERT(sizeof(struct in_addr) == sizeof(de->addr[i].ip.v4));
      memcpy(&addr->sin_addr, &de->addr[i].ip.v4, sizeof(struct in_addr));
      addr->sin_family = (CURL_SA_FAMILY_T)addrtype;
      addr->sin_port = htons((unsigned short)port);
      break;

#ifdef ENABLE_IPV6
    case AF_INET6:
      addr6 = (void *)ai->ai_addr; /* storage area for this info */
      DEBUGASSERT(sizeof(struct in6_addr) == sizeof(de->addr[i].ip.v6));
      memcpy(&addr6->sin6_addr, &de->addr[i].ip.v6, sizeof(struct in6_addr));
      addr6->sin6_family = (CURL_SA_FAMILY_T)addrtype;
      addr6->sin6_port = htons((unsigned short)port);
      break;
#endif
    }

    prevai = ai;
  }

  if(result) {
    Curl_freeaddrinfo(firstai);
    firstai = NULL;
  }

  return firstai;
}

#ifdef USE_ESNI
static char *
doh2et(const struct dohentry *de, const char *hostname, int port)
{
  char *p, *aggrdata = NULL;
  size_t aggrsz = 0;
  int i;

  (void) hostname;
  (void) port;

  for(i = 0; i < de->num_esni_txt; i++)
    aggrsz += de->esni_txt[i].allocsize;

  if(!aggrsz)
    return NULL;

  aggrdata = calloc(1, aggrsz);
  if(!aggrdata)
    return NULL;

  for(i = 0, p = aggrdata; i < de->num_esni_txt; i++) {
    if(i)
      *p++ = ';';       /* separate each string from the one before */
    strcpy(p, (char *) de->esni_txt[i].alloc); /* copy string */
    p += de->esni_txt[i].len;         /* update cursor */
  }

  return (void *) aggrdata;
}
#endif

UNITTEST void de_cleanup(struct dohentry *d)
{
  int i = 0;
  for(i = 0; i < d->numcname; i++) {
    free(d->cname[i].alloc);
  }
  for(i = 0; i < d->num_esni_txt; i++) {
    free(d->esni_txt[i].alloc);
  }
}

CURLcode Curl_doh_is_resolved(struct connectdata *conn,
                              struct Curl_dns_entry **dnsp)
{
  CURLcode result;
  struct Curl_easy *data = conn->data;
  *dnsp = NULL; /* defaults to no response */

  if(!data->req.doh.probe[DOH_PROBE_SLOT_IPADDR_V4].easy &&
     !data->req.doh.probe[DOH_PROBE_SLOT_IPADDR_V6].easy) {
    failf(data, "Could not DOH-resolve: %s", conn->async.hostname);
    return conn->bits.proxy?CURLE_COULDNT_RESOLVE_PROXY:
      CURLE_COULDNT_RESOLVE_HOST;
  }
  else if(!data->req.doh.pending) {
    DOHcode rc[DOH_PROBE_SLOTS] = {
      DOH_OK, DOH_OK
    };
    struct dohentry de;
    int slot;
    char *prefix = NULL;
    int type = 0;
    /* remove DOH handles from multi handle and close them */
    for(slot = 0; slot < DOH_PROBE_SLOTS; slot++) {
      curl_multi_remove_handle(data->multi, data->req.doh.probe[slot].easy);
      Curl_close(&data->req.doh.probe[slot].easy);
    }
    /* parse the responses, create the struct and return it! */
    init_dohentry(&de);
    for(slot = 0; slot < DOH_PROBE_SLOTS; slot++) {
      struct dnsprobe *p = &data->req.doh.probe[slot];
      /* prefix = data->req.doh.probe[slot].prefix; */
      prefix = p->prefix;
      de.prefix = prefix;       /* ? UGLY hack: need context for decoding */
      type = p->dnstype;        /* zero if slot unused */

      if(type) {

        /* /\* Original decoder interface *\/ */
        /* rc[slot] = doh_decode(p->serverdoh.memory, */
        /*                       p->serverdoh.size, */
        /*                       p->dnstype, */
        /*                       &de); */

        /* New decoder interface */
        rc[slot] = doh_decode_in_context(p, &de);
      }

      Curl_safefree(p->serverdoh.memory);
      if(rc[slot] == DOH_DNS_NAME_MISMATCH) {
        rc[slot] = DOH_OK;      /* TODO: when done testing, treat as error */
      }

      else if(rc[slot]) {
        infof(data, "DOH: %s (rc: %d) type %s for %s\n",
              doh_strerror(rc[slot]),
              rc[slot],
              type2name(p->dnstype),
              data->req.doh.host);
      }
    } /* next slot */

    result = CURLE_COULDNT_RESOLVE_HOST; /* until we know better */
    if(!rc[DOH_PROBE_SLOT_IPADDR_V4] || !rc[DOH_PROBE_SLOT_IPADDR_V6]) {
      /* we have an address, of one kind or other */
      struct Curl_dns_entry *dns;
      struct Curl_addrinfo *ai;
#ifdef USE_ESNI
      char *et;
#endif

      infof(data, "DOH Host name: %s\n", data->req.doh.host);
      showdoh(data, &de);

#ifdef USE_ESNI
      et = doh2et(&de, data->req.doh.host, data->req.doh.port);
      if((et) &&(!data->set.str[STRING_ESNI_ASCIIRR]))
        data->set.str[STRING_ESNI_ASCIIRR] = et;
#endif

      ai = doh2ai(&de, data->req.doh.host, data->req.doh.port);
      if(!ai) {
        de_cleanup(&de);
        return CURLE_OUT_OF_MEMORY;
      }

      if(data->share)
        Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE);

      /* we got a response, store it in the cache */
      dns = Curl_cache_addr(data, ai, data->req.doh.host, data->req.doh.port);

      if(data->share)
        Curl_share_unlock(data, CURL_LOCK_DATA_DNS);

      if(!dns) {
        /* returned failure, bail out nicely */
        Curl_freeaddrinfo(ai);
      }
      else {
        conn->async.dns = dns;
        *dnsp = dns;
        result = CURLE_OK;      /* address resolution OK */
      }
    } /* address processing done */

    /* Now process any build-specific attributes retrieved from DNS */

    /* All done */
    de_cleanup(&de);
    return result;

  } /* !data->req.doh.pending */

  /* else wait for pending DOH transactions to complete */
  return CURLE_OK;
}

#endif /* CURL_DISABLE_DOH */
