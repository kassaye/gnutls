/*
 * Copyright (C) 2014 Free Software Foundation
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

/* This file contains functions to handle X.509 certificate extensions (the x509-ext API)
 */

#include <gnutls_int.h>

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <c-ctype.h>
#include <gnutls/x509-ext.h>

#define MAX_ENTRIES 32
struct gnutls_subject_alt_names_st {
	unsigned int type[MAX_ENTRIES];
	gnutls_datum_t san[MAX_ENTRIES];
	gnutls_datum_t othername_oid[MAX_ENTRIES];
	unsigned int size;
};

/**
 * gnutls_subject_alt_names_init:
 * @sans: The alternative names structure
 *
 * This function will initialize an alternative names structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_subject_alt_names_init(gnutls_subject_alt_names_t * sans)
{
	*sans = gnutls_calloc(1, sizeof(struct gnutls_subject_alt_names_st));
	if (*sans == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;
}

/**
 * gnutls_subject_alt_names_deinit:
 * @sans: The alternative names structure
 *
 * This function will deinitialize an alternative names structure.
 *
 * Since: 3.3.0
 **/
void gnutls_subject_alt_names_deinit(gnutls_subject_alt_names_t sans)
{
unsigned int i;

	for (i=0;i<sans->size;i++) {
		gnutls_free(sans->san[i].data);
		gnutls_free(sans->othername_oid[i].data);
	}
	gnutls_free(sans);
}

/**
 * gnutls_subject_alt_names_get:
 * @sans: The alternative names structure
 * @seq: The index of the name to get
 * @san_type: Will hold the type of the name (of %gnutls_subject_alt_names_t)
 * @san: The alternative name data
 *
 * This function will return a specific alternative name as stored in
 * the @sans structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the index is out of bounds, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_subject_alt_names_get(gnutls_subject_alt_names_t sans, unsigned int seq,
				 unsigned int *san_type, gnutls_datum_t * san)
{
	if (seq >= sans->size)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (san)
		memcpy(san, &sans[seq].san, sizeof(gnutls_datum_t));

	if (san_type)
		*san_type = sans->type[seq];

	return 0;
}

/**
 * gnutls_subject_alt_names_get_othername_oid:
 * @sans: The alternative names structure
 * @seq: The index of the name to get
 * @oid: The object identifier
 *
 * This function will return a the object identifier (as a null terminated string),
 * of the specified name. The output of that function is valid only when the
 * type of name is othername.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the index is out of bounds, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_subject_alt_names_get_othername_oid(gnutls_subject_alt_names_t sans,
					       unsigned int seq,
					       gnutls_datum_t * oid)
{
	if (seq >= sans->size)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (sans->type[seq] != GNUTLS_SAN_OTHERNAME)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	oid->data = sans->othername_oid[seq].data;
	oid->size = sans->othername_oid[seq].size;

	return 0;
}

/**
 * gnutls_subject_alt_names_set:
 * @sans: The alternative names structure
 * @san_type: The type of the name (of %gnutls_subject_alt_names_t)
 * @san: The alternative name data
 * @othername_oid: The object identifier if @san_type is %GNUTLS_SAN_OTHERNAME
 *
 * This function will store the specified alternative name in
 * the @sans structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0), otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_subject_alt_names_set(gnutls_subject_alt_names_t sans,
				 unsigned int san_type,
				 const gnutls_datum_t * san,
				 const char* othername_oid)
{
int ret;

	if (sans->size+1 > MAX_ENTRIES)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	sans->type[sans->size] = san_type;

	ret = _gnutls_set_datum(&sans->san[sans->size], san->data, san->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (othername_oid) {
		sans->othername_oid[sans->size].data = (uint8_t*)gnutls_strdup(othername_oid);
		if (sans->othername_oid[sans->size].data == NULL) {
			gnutls_free(sans->san[sans->size].data);
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		}
		sans->othername_oid[sans->size].size = strlen(othername_oid);
	}

	sans->size++;
	return 0;
}

/**
 * gnutls_x509_ext_get_subject_alt_names:
 * @ext: The DER-encoded extension data
 * @sans: The alternative names structure
 *
 * This function will export the alternative names in the provided DER-encoded
 * PKIX extension, to a %gnutls_subject_alt_names_t structure. The structure
 * must have been initialized.
 * 
 * This function will succeed even if there no subject alternative names
 * in the structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_subject_alt_names(const gnutls_datum_t * ext,
					  gnutls_subject_alt_names_t sans)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result, ret;
	unsigned int i;

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.GeneralNames", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&c2, ext->data, ext->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	i = 0;
	do {
		ret = _gnutls_parse_general_name2(c2, "", i, &sans->san[i], &sans->type[i], 0);
		if (ret < 0)
			break;

		if (sans->type[i] == GNUTLS_SAN_OTHERNAME) {
			ret = _gnutls_parse_general_name2(c2, "", i, &sans->othername_oid[i], NULL, 1);
			if (ret < 0)
				break;
		}

		i++;
	} while(ret >= 0 && i < MAX_ENTRIES);

	sans->size = i;
	if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
 cleanup:
	asn1_delete_structure(&c2);
	return ret;
}

/**
 * gnutls_x509_ext_set_subject_alt_names:
 * @sans: The alternative names structure
 * @ext: The DER-encoded extension data
 *
 * This function will convert the provided alternative names structure to a
 * DER-encoded PKIX extension. The output data in @ext will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_subject_alt_names(gnutls_subject_alt_names_t sans,
					  gnutls_datum_t * ext)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result;
	unsigned i;

	result =
	    asn1_create_element(_gnutls_get_pkix(), "PKIX1.GeneralNames",
				&c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	for (i=0;i<sans->size;i++) {
		result = _gnutls_write_new_general_name(c2, "", sans->type[i], 
				sans->san[i].data, sans->san[i].size);
		if (result < 0) {
			gnutls_assert();
			asn1_delete_structure(&c2);
			return result;
		}
	}

	result = _gnutls_x509_der_encode(c2, "", ext, 0);

	asn1_delete_structure(&c2);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}

#if 0

typedef struct gnutls_crl_dist_points_st *gnutls_crl_dist_points_t;

int gnutls_crl_dist_points_init(gnutls_crl_dist_points_t *);
void gnutls_crl_dist_points_deinit(gnutls_crl_dist_points_t);
int gnutls_crl_dist_points_get(gnutls_crl_dist_points_t, unsigned int seq,
				  unsigned int *type,
				  gnutls_datum_t *dist, unsigned int *reason_flags);
int gnutls_crl_dist_points_set(gnutls_crl_dist_points_t,
				 gnutls_x509_subject_alt_name_t type,
				 const gnutls_datum_t *dist, unsigned int reason_flags);

int gnutls_x509_ext_get_crl_dist_points(const gnutls_datum_t * ext,
					gnutls_crl_dist_points_t dp,
					unsigned int *critical);
int gnutls_x509_ext_set_crl_dist_points(gnutls_crl_dist_points_t dp,
					gnutls_datum_t * ext);

int gnutls_x509_ext_get_name_constraints(const gnutls_datum_t * ext,
					 gnutls_x509_name_constraints_t nc,
					 unsigned int flags,
					 unsigned int *critical);
int gnutls_x509_ext_set_name_constraints(gnutls_x509_name_constraints_t nc,
					 unsigned int critical,
					 gnutls_datum_t * ext);

typedef struct gnutls_aia_st *gnutls_aia_t;

int gnutls_aia_init(gnutls_aia_t *);
void gnutls_aia_deinit(gnutls_aia_t);
int gnutls_aia_get(gnutls_aia_t, unsigned int seq,
		   gnutls_info_access_what_t what,
		   gnutls_datum_t *data);
int gnutls_aia_set(gnutls_aia_t,
		   gnutls_info_access_what_t what,
		   const gnutls_datum_t *data);

int gnutls_x509_ext_get_authority_info_access(const gnutls_datum_t * ext,
				gnutls_aia_t, unsigned int *critical);
int gnutls_x509_ext_set_authority_info_access(gnutls_aia_t aia,
					      unsigned int critical,
					      gnutls_datum_t * ext);

int gnutls_x509_ext_get_subject_key_id(const gnutls_datum_t * ext,
				       gnutls_datum_t * id,
				       unsigned int *critical);
int gnutls_x509_ext_set_subject_key_id(const gnutls_datum_t * id,
				       unsigned int critical,
				       gnutls_datum_t * ext);

int gnutls_x509_ext_set_authority_key_id(const gnutls_datum_t * id,
					 unsigned int critical,
					 gnutls_datum_t * ext);
int gnutls_x509_ext_get_authority_key_id(const gnutls_datum_t * ext,
					 gnutls_datum_t * id,
					 unsigned int *critical);

int gnutls_x509_ext_get_private_key_usage_period(const gnutls_datum_t * ext,
						 time_t * activation,
						 time_t * expiration,
						 unsigned int *critical);
int gnutls_x509_ext_set_private_key_usage_period(time_t * activation,
						 time_t * expiration,
						 unsigned int critical,
						 gnutls_datum_t * ext);

int gnutls_x509_ext_get_basic_constraints(const gnutls_datum_t * ext,
					  unsigned int *ca, int *pathlen,
					  unsigned int *critical);
int gnutls_x509_ext_set_basic_constraints(unsigned int ca, int pathlen,
					  unsigned int critical,
					  gnutls_datum_t * ext);

int gnutls_x509_ext_get_key_usage(const gnutls_datum_t * ext,
				  unsigned int *key_usage,
				  unsigned int *critical);
int gnutls_x509_ext_set_key_usage(unsigned int key_usage, unsigned int critical,
				  gnutls_datum_t * ext);

int gnutls_x509_ext_get_proxy(const gnutls_datum_t * ext, int *pathlen,
			      char **policyLanguage, char **policy,
			      size_t * sizeof_policy, unsigned int *critical);
int gnutls_x509_ext_set_proxy(int pathLenConstraint, const char *policyLanguage,
			      const char *policy, size_t sizeof_policy,
			      unsigned int critical, gnutls_datum_t * ext);

int gnutls_x509_ext_get_policies(const gnutls_datum_t * ext, struct gnutls_x509_policy_st
				 **policy, unsigned int *max_policies,
				 unsigned int *critical);
int gnutls_x509_ext_set_policies(struct gnutls_x509_policy_st *policies,
				 unsigned int n_policies, unsigned int critical,
				 gnutls_datum_t * ext);
#endif
