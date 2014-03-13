#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>

#define HAVE_ICONV
#include "../../whois/data.h"

#define IP4_BUFSIZ 16
#define IP6_BUFSIZ 12

void ntoa(unsigned long i, char * buf, size_t n) {
  snprintf(buf, n, "%u.%u.%u.%u",
      i >> 24 & 0xFF, i >> 16 & 0xFF, i >> 8 & 0xFF, i & 0xFF); }

void ntop(unsigned long i, char * buf, size_t n) {
  snprintf(buf, n, "%04x:%04x::", i >> 16 & 0xFFFF, i & 0xFFFF);
}

const char * make_printable(const char * p) {
  switch (*p) {
    case 0x01:
      return "WEB";
    case 0x03:
      return "NONE";
    case 0x04:
      return "VERISIGN";
    case 0x05:
      return "UNKNOWN";
    case 0x06:
      return "UNALLOCATED";
    case 0x08:
      return "AFILIAS";
    case 0x0A:
      return "6to4";
    case 0x0B:
      return "teredo";
    case 0x0C:
      return "ARPA";
    default:
      return p;
  }
}

void main() {
  const char ** hdl;
  const struct ip_del * ip_del_ptr;
  const struct ip6_del * ip6_del_ptr;
  const struct as_del * as_del_ptr;
  const struct as32_del * as32_del_ptr;
  const struct server_charset * sc_ptr;

  printf ("ripe_servers:\n");
  for (hdl = ripe_servers; *hdl; hdl++) {
    printf ("    - %s\n", *hdl);
  }

  printf ("hide_strings:\n");
  for (hdl = hide_strings; *hdl; hdl += 2) {
    printf ("    - [\"%s\", \"%s\"]\n", *hdl, *(hdl+1));
  }

  printf ("nic_handles:\n");
  for (hdl = nic_handles; *hdl; hdl += 2) {
    printf ("    '%s': '%s'\n", *hdl, *(hdl+1));
  }

  printf ("ip_assign:\n");
  for (ip_del_ptr = ip_assign; ip_del_ptr->serv; ip_del_ptr++) {
    char net[IP4_BUFSIZ], mask[IP4_BUFSIZ];

    ntoa(ip_del_ptr->net, net, sizeof(net));
    ntoa(ip_del_ptr->mask, mask, sizeof(mask));
    printf ("    '%s/%s': \"%s\"\n",
        net, mask, make_printable(ip_del_ptr->serv));
  }

  printf ("ip6_assign:\n");
  for (ip6_del_ptr = ip6_assign; ip6_del_ptr->serv; ip6_del_ptr++) {
    char net[IP6_BUFSIZ];

    ntop(ip6_del_ptr->net, net, sizeof(net));
    make_printable(ip6_del_ptr->serv);
    printf ("    '%s/%u': \"%s\"\n",
        net, ip6_del_ptr->masklen, make_printable(ip6_del_ptr->serv));
  }

  printf ("as_del:\n");
  for (as_del_ptr = as_assign; as_del_ptr->serv; as_del_ptr++) {
    printf ("    - { 'first': %u, 'last': %u, 'serv': %s }\n",
        as_del_ptr->first, as_del_ptr->last, as_del_ptr->serv);
  }

  printf ("as32_del:\n");
  for (as32_del_ptr = as32_assign; as32_del_ptr->serv; as32_del_ptr++) {
    printf ("    - { 'first': %u, 'last': %u, 'serv': %s }\n",
        as32_del_ptr->first, as32_del_ptr->last, as32_del_ptr->serv);
  }

  printf ("tld_serv:\n");
  for (hdl = tld_serv; *hdl; hdl+= 2) {
    const char * p = make_printable(*(hdl+1));
    if (strcmp(p, "NONE")) {
      printf ("    '%s': '%s'\n", *hdl, p);
    } else {
      printf ("    '%s': null\n", *hdl);
    }
  }

  printf ("servers_charset:\n");
  for (sc_ptr = servers_charset; sc_ptr->name; sc_ptr++) {
    if (sc_ptr->options) {
      printf ("    '%s': { charset: '%s', options: '%s' }\n",
          sc_ptr->name, sc_ptr->charset, sc_ptr->options);
    } else {
      printf ("    '%s': { charset: '%s', options: null }\n",
          sc_ptr->name, sc_ptr->charset);
    }
  }
}
