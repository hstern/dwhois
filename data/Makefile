WHOIS_DIR?=../../whois
WHOIS_HEADERS=\
	${WHOIS_DIR}/ip_del.h \
	${WHOIS_DIR}/ip6_del.h \
	${WHOIS_DIR}/as_del.h \
	${WHOIS_DIR}/as32_del.h \
	${WHOIS_DIR}/tld_serv.h \
	${WHOIS_DIR}/servers_charset.h
TARGET?=../src/dwhois/whois.yml

${TARGET}: import
	./$< > $@

import: import.c ${WHOIS_DIR}/data.h ${WHOIS_HEADERS}
	gcc $< -o $@

${WHOIS_HEADERS}:
	(cd ${WHOIS_DIR}; HAVE_ICONV=1 make $(notdir $@))

clean:
	rm -f ${TARGET} import ${WHOIS_HEADERS}
