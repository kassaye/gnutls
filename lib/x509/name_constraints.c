/*
 * Copyright (C) 2003-2012 Free Software Foundation, Inc.
 * Author: Nikos Mavrogiannopoulos, Simon Josefsson, Howard Chu
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Functions on X.509 Certificate parsing
 */

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509_int.h>
#include <libtasn1.h>

/* Name constraints is limited to DNS names.
 */
typedef struct gnutls_name_constraints_st {
	struct name_constraints_node_st * permitted;
	struct name_constraints_node_st * excluded;
} gnutls_name_constraints_st;

typedef struct name_constraints_node_st {
	unsigned type;
	gnutls_datum_t name;
	struct name_constraints_node_st *next;
} name_constraints_node_st;

static int extract_name_constraints(ASN1_TYPE c2, const char *vstr,
				    name_constraints_node_st ** _nc)
{
	int ret;
	char tmpstr[128];
	unsigned indx = 0;
	gnutls_datum_t tmp = { NULL, 0 };
	unsigned int type;
	struct name_constraints_node_st *nc, *prev;

	nc = prev = *_nc;

	do {
		indx++;
		snprintf(tmpstr, sizeof(tmpstr), "%s.?%u.base", vstr, indx);

		ret =
		    _gnutls_parse_general_name2(c2, tmpstr, -1, &tmp, &type, 0);

		if (ret < 0)
			break;

		if (type != GNUTLS_SAN_DNSNAME && type != GNUTLS_SAN_RFC822NAME
		    && type != GNUTLS_SAN_DN && type != GNUTLS_SAN_URI) {
			gnutls_assert();
			ret = GNUTLS_E_ILLEGAL_PARAMETER;
			goto cleanup;
		}

		nc = gnutls_malloc(sizeof(struct name_constraints_node_st));
		if (nc == NULL) {
			gnutls_assert();
			ret = GNUTLS_E_MEMORY_ERROR;
			goto cleanup;
		}

		memcpy(&nc->name, &tmp, sizeof(gnutls_datum_t));
		nc->type = type;
		nc->next = NULL;

		if (prev == NULL) {
			*_nc = prev = nc;
		} else {
			prev->next = nc;
			prev = nc;
		}

		tmp.data = NULL;
	} while (ret >= 0);

	if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
 cleanup:
 	if (ret < 0) {
 		nc = *_nc;
 		while (nc != NULL) {
			prev = nc->next;
			free(nc->name.data);
			free(nc);
			nc = prev;
		}
		*_nc = NULL;
	}
	gnutls_free(tmp.data);
	return ret;
}

/**
 * gnutls_x509_crt_get_name_constraints:
 * @crt: should contain a #gnutls_x509_crt_t structure
 * @nc: The nameconstraints intermediate structure
 * @critical: the extension status
 *
 * This function will return an intermediate structure containing
 * the name constraints of the provided CA certificate. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 **/
int gnutls_x509_crt_get_name_constraints(gnutls_x509_crt_t crt,
					 gnutls_x509_name_constraints_t * nc,
					 unsigned int *critical)
{
	int result, ret;
	gnutls_datum_t der = { NULL, 0 };
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

	if (crt == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	*nc = NULL;

	ret =
	    _gnutls_x509_crt_get_extension(crt, "2.5.29.30", 0, &der,
					   critical);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (der.size == 0 || der.data == NULL)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	result = asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.NameConstraints", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_der_decoding(&c2, der.data, der.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	*nc = gnutls_calloc(1, sizeof(struct gnutls_name_constraints_st));
	if (*nc == NULL) {
		gnutls_assert();
		goto cleanup;
	}

	ret = extract_name_constraints(c2, "permittedSubtrees", &(*nc)->permitted);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = extract_name_constraints(c2, "excludedSubtrees", &(*nc)->excluded);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

 cleanup:
	if (ret < 0 && *nc != NULL)
		gnutls_x509_name_constraints_release(*nc);
	_gnutls_free_datum(&der);
	asn1_delete_structure(&c2);

	return ret;

}

void gnutls_x509_name_constraints_release(gnutls_x509_name_constraints_t _nc)
{
	name_constraints_node_st * next, *nc;

	nc = _nc->permitted;
	while (nc != NULL) {
		next = nc->next;
		free(nc->name.data);
		free(nc);
		nc = next;
	}

	nc = _nc->excluded;
	while (nc != NULL) {
		next = nc->next;
		free(nc->name.data);
		free(nc);
		nc = next;
	}
}

#if 0
int gnutls_x509_name_constraints_check(gnutls_x509_name_constraints_t nc,
				       gnutls_x509_subject_alt_name_t type,
				       const gnutls_datum_t * name);

int gnutls_x509_crt_set_name_constraints(gnutls_x509_crt_t crt, 
					 gnutls_x509_name_constraints_t nc,
					 unsigned int critical);

int gnutls_x509_name_constraints_add_permitted(gnutls_x509_name_constraints_t
					       nc,
					       gnutls_x509_subject_alt_name_t
					       type,
					       const gnutls_datum_t * name);
int gnutls_x509_name_constraints_add_excluded(gnutls_x509_name_constraints_t nc,
					      gnutls_x509_subject_alt_name_t
					      type,
					      const gnutls_datum_t * name);
#endif

/**
 * gnutls_x509_name_constraints_get_permitted:
 * @nc: the extracted name constraints structure
 * @idx: the index of the constraint
 * @type: the type of the constraint (of type gnutls_x509_subject_alt_name_t)
 * @name: the name in the constraint (of the specific type)
 *
 * This function will return an intermediate structure containing
 * the name constraints of the provided CA certificate. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 **/
int gnutls_x509_name_constraints_get_permitted(gnutls_x509_name_constraints_t nc,
				     unsigned idx,
				     unsigned *type, gnutls_datum_t * name)
{
	unsigned int i;
	struct name_constraints_node_st * tmp = nc->permitted;

	for (i = 0; i < idx; i++) {
		if (tmp == NULL)
			return
			    gnutls_assert_val
			    (GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

		tmp = tmp->next;
	}

	if (tmp == NULL)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	*type = tmp->type;
	*name = tmp->name;

	return 0;
}

/**
 * gnutls_x509_name_constraints_get_excluded:
 * @nc: the extracted name constraints structure
 * @idx: the index of the constraint
 * @type: the type of the constraint (of type gnutls_x509_subject_alt_name_t)
 * @name: the name in the constraint (of the specific type)
 *
 * This function will return an intermediate structure containing
 * the name constraints of the provided CA certificate. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 **/
int gnutls_x509_name_constraints_get_excluded(gnutls_x509_name_constraints_t nc,
				     unsigned idx,
				     unsigned *type, gnutls_datum_t * name)
{
	unsigned int i;
	struct name_constraints_node_st * tmp = nc->excluded;

	for (i = 0; i < idx; i++) {
		if (tmp == NULL)
			return
			    gnutls_assert_val
			    (GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

		tmp = tmp->next;
	}

	if (tmp == NULL)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	*type = tmp->type;
	*name = tmp->name;

	return 0;
}
