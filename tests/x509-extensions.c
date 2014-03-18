/*
 * Copyright (C) 2006-2012 Free Software Foundation, Inc.
 * Author: Simon Josefsson, Howard Chu
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>
#include "utils.h"

static char pem[] =
  "-----BEGIN CERTIFICATE-----"
  "MIIFajCCBNOgAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBkzEVMBMGA1UEAxMMQ2lu"
  "ZHkgTGF1cGVyMRcwFQYKCZImiZPyLGQBARMHY2xhdXBlcjERMA8GA1UECxMIQ0Eg"
  "ZGVwdC4xEjAQBgNVBAoTCUtva28gaW5jLjEPMA0GA1UECBMGQXR0aWtpMQswCQYD"
  "VQQGEwJHUjEcMBoGCSqGSIb3DQEJARYNbm9uZUBub25lLm9yZzAiGA8yMDA3MDQy"
  "MTIyMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjCBkzEVMBMGA1UEAxMMQ2luZHkgTGF1"
  "cGVyMRcwFQYKCZImiZPyLGQBARMHY2xhdXBlcjERMA8GA1UECxMIQ0EgZGVwdC4x"
  "EjAQBgNVBAoTCUtva28gaW5jLjEPMA0GA1UECBMGQXR0aWtpMQswCQYDVQQGEwJH"
  "UjEcMBoGCSqGSIb3DQEJARYNbm9uZUBub25lLm9yZzCBnzANBgkqhkiG9w0BAQEF"
  "AAOBjQAwgYkCgYEApcbOdUOEv2SeAicT8QNZ93ktku18L1CkA/EtebmGiwV+OrtE"
  "qq+EzxOYHhxKOPczLXqfctRrbSawMTdwEPtC6didGGV+GUn8BZYEaIMed4a/7fXl"
  "EjsT/jMYnBp6HWmvRwJgeh+56M/byDQwUZY9jJZcALxh3ggPsTYhf6kA4wUCAwEA"
  "AaOCAsYwggLCMBIGA1UdEwEB/wQIMAYBAf8CAQQwagYDVR0RBGMwYYIMd3d3Lm5v"
  "bmUub3JnghN3d3cubW9yZXRoYW5vbmUub3Jnghd3d3cuZXZlbm1vcmV0aGFub25l"
  "Lm9yZ4cEwKgBAYENbm9uZUBub25lLm9yZ4EOd2hlcmVAbm9uZS5vcmcwgfcGA1Ud"
  "IASB7zCB7DB3BgwrBgEEAapsAQpjAQAwZzAwBggrBgEFBQcCAjAkDCJUaGlzIGlz"
  "IGEgbG9uZyBwb2xpY3kgdG8gc3VtbWFyaXplMDMGCCsGAQUFBwIBFidodHRwOi8v"
  "d3d3LmV4YW1wbGUuY29tL2EtcG9saWN5LXRvLXJlYWQwcQYMKwYBBAGqbAEKYwEB"
  "MGEwJAYIKwYBBQUHAgIwGAwWVGhpcyBpcyBhIHNob3J0IHBvbGljeTA5BggrBgEF"
  "BQcCARYtaHR0cDovL3d3dy5leGFtcGxlLmNvbS9hbm90aGVyLXBvbGljeS10by1y"
  "ZWFkMFgGA1UdHgEB/wROMEygJDANggtleGFtcGxlLmNvbTATgRFubWF2QEBleGFt"
  "cGxlLm5ldKEkMBKCEHRlc3QuZXhhbXBsZS5jb20wDoEMLmV4YW1wbGUuY29tMBMG"
  "A1UdJQQMMAoGCCsGAQUFBwMJMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAYYa"
  "aHR0cDovL215Lm9jc3Auc2VydmVyL29jc3AwDwYDVR0PAQH/BAUDAwcEADAdBgNV"
  "HQ4EFgQUXUCt8M6UQJWLfpmUHZJUIspyNl8wbwYDVR0fBGgwZjBkoGKgYIYeaHR0"
  "cDovL3d3dy5nZXRjcmwuY3JsL2dldGNybDEvhh5odHRwOi8vd3d3LmdldGNybC5j"
  "cmwvZ2V0Y3JsMi+GHmh0dHA6Ly93d3cuZ2V0Y3JsLmNybC9nZXRjcmwzLzANBgkq"
  "hkiG9w0BAQsFAAOBgQCbNFcngrQinuzUy/8N9zHRtScxN3KaqLoJqyIWeFPunL10"
  "HmhzNyicK+dXOkv542PJUG6Cs40rWULK29f8pR/BqE4jv37XKolZPXoQyTaw2H8o"
  "aKTsadqPJks3tYFi/4mKy3HRymzyaVaU7dII+++y1qzozZo6oX5v+XDCLchirg=="
  "-----END CERTIFICATE-----";

#define MAX_DATA_SIZE 1024

typedef int (*ext_parse_func) (const gnutls_datum_t * der);

struct ext_handler_st {
	const char * oid;
	ext_parse_func handler;
	unsigned critical;
};

static int basic_constraints(const gnutls_datum_t * der)
{
	int ret, pathlen;
	unsigned ca;

/*
		Basic Constraints (critical):
			Certificate Authority (CA): TRUE
			Path Length Constraint: 4
*/	
	ret = gnutls_x509_ext_get_basic_constraints(der, &ca, &pathlen);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	if (ca != 1) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (pathlen != 4) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	return 0;
}

static int cmp_name(unsigned type, gnutls_datum_t *name, unsigned expected_type, const char *expected_name)
{
	if (type != expected_type) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (name->size != strlen(expected_name)) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (strcmp((char*)name->data, expected_name) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}
	return 0;
}

static int subject_alt_name(const gnutls_datum_t * der)
{
	int ret;
	gnutls_subject_alt_names_t san;
	gnutls_datum_t name;
	unsigned type;
	unsigned i = 0;

	ret = gnutls_subject_alt_names_init(&san);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_x509_ext_get_subject_alt_names(der, san);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

/*
		Subject Alternative Name (not critical):
			DNSname: www.none.org
			DNSname: www.morethanone.org
			DNSname: www.evenmorethanone.org
			IPAddress: 192.168.1.1
			tRFC822Name: none@none.org
			tRFC822Name: where@none.org
*/
	ret = cmp_name(type, &name, GNUTLS_SAN_DNSNAME, "www.none.org");
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
	ret = cmp_name(type, &name, GNUTLS_SAN_DNSNAME, "www.morethanone.org");
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
	ret = cmp_name(type, &name, GNUTLS_SAN_DNSNAME, "www.evenmorethanone.org");
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
	if (type != GNUTLS_SAN_IPADDRESS) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
	ret = cmp_name(type, &name, GNUTLS_SAN_RFC822NAME, "none@none.org");
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
	ret = cmp_name(type, &name, GNUTLS_SAN_RFC822NAME, "where@none.org");
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_subject_alt_names_get(san, i++, &type, &name, NULL);
	if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	gnutls_subject_alt_names_deinit(san);
	
	return 0;
}

static int crt_policies(const gnutls_datum_t * der)
{
	int ret;
	gnutls_x509_policies_t policies;
	struct gnutls_x509_policy_st policy;
	unsigned i = 0;

	ret = gnutls_x509_policies_init(&policies);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_x509_ext_get_policies(der, policies);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}

	ret = gnutls_x509_policies_get(policies, i++, &policy);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
/*
		Certificate Policies (not critical):
			1.3.6.1.4.1.5484.1.10.99.1.0
				Note: This is a long policy to summarize
				URI: http://www.example.com/a-policy-to-read
			1.3.6.1.4.1.5484.1.10.99.1.1
				Note: This is a short policy
				URI: http://www.example.com/another-policy-to-read
*/
	if (strcmp(policy.oid, "1.3.6.1.4.1.5484.1.10.99.1.0") != 0 || policy.qualifiers != 2) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (policy.qualifier[0].type != GNUTLS_X509_QUALIFIER_NOTICE ||
		policy.qualifier[0].size != 34) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (policy.qualifier[1].type != GNUTLS_X509_QUALIFIER_URI ||
		policy.qualifier[1].size != strlen("http://www.example.com/a-policy-to-read") ||
		strcmp("http://www.example.com/a-policy-to-read", policy.qualifier[1].data) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	/* second policy */
	ret = gnutls_x509_policies_get(policies, i++, &policy);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return ret;
	}
	if (strcmp(policy.oid, "1.3.6.1.4.1.5484.1.10.99.1.1") != 0 || policy.qualifiers != 2) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (policy.qualifier[0].type != GNUTLS_X509_QUALIFIER_NOTICE ||
		policy.qualifier[0].size != 22) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	if (policy.qualifier[1].type != GNUTLS_X509_QUALIFIER_URI ||
		policy.qualifier[1].size != strlen("http://www.example.com/another-policy-to-read") ||
		strcmp("http://www.example.com/another-policy-to-read", policy.qualifier[1].data) != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	ret = gnutls_x509_policies_get(policies, i++, &policy);
	if (ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		fprintf(stderr, "error in %d\n", __LINE__);
		return -1;
	}

	gnutls_x509_policies_deinit(policies);
	
	return 0;
}

#if  0
		Name Constraints (critical):
			Permitted:
				DNSname: example.com
				tRFC822Name: nmav@@example.net
			Excluded:
				DNSname: test.example.com
				tRFC822Name: .example.com
		Key Purpose (not critical):
			OCSP signing.
		Authority Information Access (not critical):
			Access Method: 1.3.6.1.5.5.7.48.1 (id-ad-ocsp)
			Access Location URI: http://my.ocsp.server/ocsp
		Key Usage (critical):
			Certificate signing.
		Subject Key Identifier (not critical):
			5d40adf0ce9440958b7e99941d925422ca72365f
		CRL Distribution points (not critical):
			URI: http://www.getcrl.crl/getcrl1/
			URI: http://www.getcrl.crl/getcrl2/
			URI: http://www.getcrl.crl/getcrl3/

#endif

struct ext_handler_st handlers[] =
{
	{GNUTLS_X509EXT_OID_BASIC_CONSTRAINTS, basic_constraints, 1},
	{GNUTLS_X509EXT_OID_SAN, subject_alt_name},
	{GNUTLS_X509EXT_OID_CRT_POLICY, crt_policies},
	{GNUTLS_X509EXT_OID_EXTENDED_KEY_USAGE, ext_key_usage},
#if 0
	{GNUTLS_X509EXT_OID_NAME_CONSTRAINTS, name_constraints},
	{GNUTLS_X509EXT_OID_AUTHORITY_INFO_ACCESS, ext_aia},
	{GNUTLS_X509EXT_OID_KEY_USAGE, key_usage},
	{GNUTLS_X509EXT_OID_SUBJECT_KEY_ID, subject_key_id},
	{GNUTLS_X509EXT_OID_CRL_DIST_POINTS, crl_dist_points},
#endif
	{NULL, NULL}
};

void doit(void)
{
	int ret;
	gnutls_datum_t derCert = { (void *) pem, sizeof(pem) };
	gnutls_x509_crt_t cert;
	size_t oid_len = MAX_DATA_SIZE;
	gnutls_datum_t ext;
	char oid[MAX_DATA_SIZE];
	unsigned int critical = 0;
	unsigned i, j;

	ret = global_init();
	if (ret < 0)
		fail("init %d\n", ret);

	ret = gnutls_x509_crt_init(&cert);
	if (ret < 0)
		fail("crt_init %d\n", ret);

	ret = gnutls_x509_crt_import(cert, &derCert, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("crt_import %d\n", ret);

	for (i=0;;i++) {
		oid_len = sizeof(oid);
		ret = gnutls_x509_crt_get_extension_info(cert, i, oid, &oid_len, &critical);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			if (i != 9) {
				fail("unexpected number of extensions: %d\n", i);
			}
			break;
		}

		if (ret < 0) {
			fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));
		}

		ret = gnutls_x509_crt_get_extension_data2(cert, i, &ext);
		if (ret < 0) {
			fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));
		}

		/* find the handler for this extension and run it */
		for (j=0;;j++) {
			if (handlers[j].oid == NULL) {
//				fail("could not find handler for extension %s\n", oid);
				break;
			}

			if (strcmp(handlers[j].oid, oid) == 0) {
				if (critical != handlers[j].critical) {
					fail("error in %d (%s): %s\n", __LINE__, oid, gnutls_strerror(ret));
				}

				ret = handlers[j].handler(&ext);
				if (ret < 0) {
					fail("error in %d (%s): %s\n", __LINE__, oid, gnutls_strerror(ret));
				}
				break;
			}
		}
		gnutls_free(ext.data);
		ext.data = NULL;
	}

	if (debug)
		success("done\n");

	gnutls_x509_crt_deinit(cert);
	gnutls_global_deinit();
}

/* The template used to generate the certificate */

/*
# X.509 Certificate options
#
# DN options

# The organization of the subject.
organization = "Koko inc."

# The organizational unit of the subject.
unit = "CA dept."

# The locality of the subject.
# locality =

# The state of the certificate owner.
state = "Attiki"

# The country of the subject. Two letter code.
country = GR

# The common name of the certificate owner.
cn = "Cindy Lauper"

# A user id of the certificate owner.
uid = "clauper"

# This is deprecated and should not be used in new
# certificates.
pkcs9_email = "none@none.org"

# The serial number of the certificate
serial = 7

# In how many days, counting from today, this certificate will expire.
expiration_days = -1

# X.509 v3 extensions

# A dnsname in case of a WWW server.
dns_name = "www.none.org"
dns_name = "www.morethanone.org"

# An IP address in case of a server.
ip_address = "192.168.1.1"

dns_name = "www.evenmorethanone.org"

# An email in case of a person
email = "none@none.org"

# An URL that has CRLs (certificate revocation lists)
# available. Needed in CA certificates.
crl_dist_points = "http://www.getcrl.crl/getcrl1/"
crl_dist_points = "http://www.getcrl.crl/getcrl2/"
crl_dist_points = "http://www.getcrl.crl/getcrl3/"

email = "where@none.org"

# Whether this is a CA certificate or not
ca
path_len = 4

nc_permit_dns = example.com
nc_exclude_dns = test.example.com
nc_permit_email = nmav@@example.net
nc_exclude_email = .example.com

proxy_policy_language = 1.3.6.1.5.5.7.21.1


policy1 = 1.3.6.1.4.1.5484.1.10.99.1.0
policy1_txt = "This is a long policy to summarize"
policy1_url = http://www.example.com/a-policy-to-read
  
policy2 = 1.3.6.1.4.1.5484.1.10.99.1.1
policy2_txt = "This is a short policy"
policy2_url = http://www.example.com/another-policy-to-read

ocsp_uri = http://my.ocsp.server/ocsp


# Whether this certificate will be used for a TLS client
#tls_www_client

# Whether this certificate will be used for a TLS server
#tls_www_server
cert_signing_key
ocsp_signing_key


# Whether this certificate will be used to sign data (needed
# in TLS DHE ciphersuites).
signing_key

# Whether this certificate will be used to encrypt data (needed
# in TLS RSA ciphersuites). Note that it is preferred to use different
# keys for encryption and signing.
#encryption_key

# Whether this key will be used to sign other certificates.
cert_signing_key

# Whether this key will be used to sign CRLs.
#crl_signing_key

# Whether this key will be used to sign code.
#code_signing_key

# Whether this key will be used to sign OCSP data.
ocsp_signing_key

# Whether this key will be used for time stamping.
#time_stamping_key

# Whether this key will be used for IPsec IKE operations.
#ipsec_ike_key

#endif

*/
