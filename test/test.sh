#!/bin/sh

set -e

[ "${EXTENSION}" = "" ] && EXTENSION=.native
[ "${BINDIR}" = "" ] && BINDIR="_build/src"
[ "${CERTDIR}" = "" ] && CERTDIR="/tmp/$$"
[ "${KEYDIR}" = "" ] && KEYDIR="/tmp/$$"
[ "${OPENSSL}" = "" ] && OPENSSL="openssl"
[ "${KEY_LENGTH}" = "" ] && KEY_LENGTH=4096

[ ! -e "${CERTDIR}" ] && mkdir -p $CERTDIR
[ ! -e "${KEYDIR}" ] && mkdir -p $KEYDIR

[ "$SILENT" = "" ] && echo "Testing ${BINDIR}/selfsign$EXTENSION ..."

# make a self-signed CA cert
${BINDIR}/selfsign${EXTENSION} --ca --certificate=${CERTDIR}/ca_out.pem -d 730 --keyout=${KEYDIR}/ca_key.pem --length=${KEY_LENGTH} ca.example.com
# make sure openssl can read the generated CA
${OPENSSL} x509 -in ${CERTDIR}/ca_out.pem -text -noout >/dev/null
# make sure the key is usable
${OPENSSL} rsa -in ${KEYDIR}/ca_key.pem -text -noout >/dev/null

# make sure the key length is what we asked for
actual_length=$(${OPENSSL} x509 -in ${CERTDIR}/ca_out.pem -text -noout | grep Public-Key|sed 's/Public-Key: (//;s/ bit)//;s/ //g')
[ "$actual_length" != "${KEY_LENGTH}" ] && {
	echo "Key length $actual_length was not the requested $KEY_LENGTH"
	exit 1
}

# make sure silly key lengths are refused
${BINDIR}/selfsign${EXTENSION} --certificate=${CERTDIR}/too_short.pem --keyout=${KEY_DIR}/too_short_key.pem --length=12 too-short.example.com 2>/dev/null && {
	echo "Bogus key length 12 passed to selfsign was not detected as expected"
	exit 1
}

[ "$SILENT" = "" ] && echo "Testing ${BINDIR}/csr$EXTENSION ..."

# generate a csr
${BINDIR}/csr${EXTENSION} --certificate=${CERTDIR}/csr.pem --key=${KEYDIR}/csr_key.pem -l ${KEY_LENGTH} notaca.example.com "Exampleton Studios"
# make sure the key is usable
${OPENSSL} rsa -in ${KEYDIR}/csr_key.pem -text -noout >/dev/null
# "verify" the csr
${OPENSSL} req -verify -in ${CERTDIR}/csr.pem -text -noout >/dev/null

[ "$SILENT" = "" ] && echo "Testing ${BINDIR}/sign$EXTENSION ..."

# sign csr with ca
${BINDIR}/sign${EXTENSION} --certificate=${CERTDIR}/signed_csr.pem --cain=${CERTDIR}/ca_out.pem --csrin=${CERTDIR}/csr.pem --keyin=${KEYDIR}/ca_key.pem
# make sure openssl can read the signed cert
${OPENSSL} x509 -in ${CERTDIR}/signed_csr.pem -text -noout >/dev/null
# make sure the signed cert is valid with respect to the trust anchor
${OPENSSL} verify -CAfile ${CERTDIR}/ca_out.pem ${CERTDIR}/signed_csr.pem

rm ${CERTDIR}/ca_out.pem ${CERTDIR}/signed_csr.pem ${CERTDIR}/csr.pem
rm ${KEYDIR}/ca_key.pem ${KEYDIR}/csr_key.pem
[ "${CERTDIR}" != "${KEYDIR}" ] && rmdir ${KEYDIR}
rmdir ${CERTDIR}
