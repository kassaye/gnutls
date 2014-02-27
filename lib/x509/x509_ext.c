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
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <c-ctype.h>
#include <gnutls/x509-ext.h>

#define MAX_ENTRIES 64
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

static void subject_alt_names_deinit(gnutls_subject_alt_names_t sans)
{
	unsigned int i;

	for (i = 0; i < sans->size; i++) {
		gnutls_free(sans->san[i].data);
		gnutls_free(sans->othername_oid[i].data);
	}
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
	subject_alt_names_deinit(sans);
	gnutls_free(sans);
}

/**
 * gnutls_subject_alt_names_get:
 * @sans: The alternative names structure
 * @seq: The index of the name to get
 * @san_type: Will hold the type of the name (of %gnutls_subject_alt_names_t)
 * @san: The alternative name data (should be treated as constant)
 * @othername_oid: The object identifier if @san_type is %GNUTLS_SAN_OTHERNAME (should be treated as constant)
 *
 * This function will return a specific alternative name as stored in
 * the @sans structure. The returned values should be treated as constant
 * and valid for the lifetime of @sans.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the index is out of bounds, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_subject_alt_names_get(gnutls_subject_alt_names_t sans,
				 unsigned int seq, unsigned int *san_type,
				 gnutls_datum_t * san,
				 gnutls_datum_t * othername_oid)
{
	if (seq >= sans->size)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (san) {
		memcpy(san, &sans->san[seq], sizeof(gnutls_datum_t));
	}

	if (san_type)
		*san_type = sans->type[seq];

	if (sans->type[seq] == GNUTLS_SAN_OTHERNAME) {
		othername_oid->data = sans->othername_oid[seq].data;
		othername_oid->size = sans->othername_oid[seq].size;
	}

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
				 const char *othername_oid)
{
	int ret;

	if (sans->size + 1 > MAX_ENTRIES)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	sans->type[sans->size] = san_type;

	ret = _gnutls_set_datum(&sans->san[sans->size], san->data, san->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (othername_oid) {
		sans->othername_oid[sans->size].data =
		    (uint8_t *) gnutls_strdup(othername_oid);
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
 * SubjectAltName PKIX extension, to a %gnutls_subject_alt_names_t structure. The structure
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

	result =
	    asn1_create_element(_gnutls_get_pkix(), "PKIX1.GeneralNames", &c2);
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
		ret =
		    _gnutls_parse_general_name2(c2, "", i, &sans->san[i],
						&sans->type[i], 0);
		if (ret < 0)
			break;

		if (sans->type[i] == GNUTLS_SAN_OTHERNAME) {
			ret =
			    _gnutls_parse_general_name2(c2, "", i,
							&sans->othername_oid[i],
							NULL, 1);
			if (ret < 0)
				break;
		}

		i++;
	} while (ret >= 0 && i < MAX_ENTRIES);

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
 * DER-encoded SubjectAltName PKIX extension. The output data in @ext will be allocated using
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
	    asn1_create_element(_gnutls_get_pkix(), "PKIX1.GeneralNames", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	for (i = 0; i < sans->size; i++) {
		result = _gnutls_write_new_general_name(c2, "", sans->type[i],
							sans->san[i].data,
							sans->san[i].size);
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

/**
 * gnutls_x509_crt_get_name_constraints:
 * @ext: a DER encoded extension
 * @nc: The nameconstraints intermediate structure
 * @flags: zero or %GNUTLS_NAME_CONSTRAINTS_FLAG_APPEND
 *
 * This function will return an intermediate structure containing
 * the name constraints of the provided NameConstraints extension. That
 * structure can be used in combination with gnutls_x509_name_constraints_check()
 * to verify whether a server's name is in accordance with the constraints.
 *
 * When the @flags is set to %GNUTLS_NAME_CONSTRAINTS_FLAG_APPEND, then if 
 * the @nc structure is empty
 * this function will behave identically as if the flag was not set.
 * Otherwise if there are elements in the @nc structure then only the
 * excluded constraints will be appended to the constraints.
 *
 * Note that @nc must be initialized prior to calling this function.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_name_constraints(const gnutls_datum_t * ext,
					 gnutls_x509_name_constraints_t nc,
					 unsigned int flags)
{
	int result, ret;
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

	result = asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.NameConstraints", &c2);
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

	if (!(flags & GNUTLS_NAME_CONSTRAINTS_FLAG_APPEND)
	    || (nc->permitted == NULL && nc->excluded == NULL)) {
		ret =
		    _gnutls_extract_name_constraints(c2, "permittedSubtrees",
						     &nc->permitted);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	ret =
	    _gnutls_extract_name_constraints(c2, "excludedSubtrees",
					     &nc->excluded);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

 cleanup:
	asn1_delete_structure(&c2);

	return ret;
}

/**
 * gnutls_x509_ext_set_name_constraints:
 * @nc: The nameconstraints structure
 * @ext: Will hold the DER encoded extension
 *
 * This function will convert the provided name constraints structure to a
 * DER-encoded PKIX NameConstraints extension. The output data in @ext will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_name_constraints(gnutls_x509_name_constraints_t nc,
					 gnutls_datum_t * ext)
{
	int ret, result;
	uint8_t null = 0;
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	struct name_constraints_node_st *tmp;

	if (nc->permitted == NULL && nc->excluded == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	result = asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.NameConstraints", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (nc->permitted == NULL) {
		asn1_write_value(c2, "permittedSubtrees", NULL, 0);
	} else {
		tmp = nc->permitted;
		do {
			result =
			    asn1_write_value(c2, "permittedSubtrees", "NEW", 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				ret = _gnutls_asn2err(result);
				goto cleanup;
			}

			result =
			    asn1_write_value(c2,
					     "permittedSubtrees.?LAST.maximum",
					     NULL, 0);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				ret = _gnutls_asn2err(result);
				goto cleanup;
			}

			result =
			    asn1_write_value(c2,
					     "permittedSubtrees.?LAST.minimum",
					     &null, 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				ret = _gnutls_asn2err(result);
				goto cleanup;
			}

			ret =
			    _gnutls_write_general_name(c2,
						       "permittedSubtrees.?LAST.base",
						       tmp->type,
						       tmp->name.data,
						       tmp->name.size);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
			tmp = tmp->next;
		} while (tmp != NULL);
	}

	if (nc->excluded == NULL) {
		asn1_write_value(c2, "excludedSubtrees", NULL, 0);
	} else {
		tmp = nc->excluded;
		do {
			result =
			    asn1_write_value(c2, "excludedSubtrees", "NEW", 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				ret = _gnutls_asn2err(result);
				goto cleanup;
			}

			result =
			    asn1_write_value(c2,
					     "excludedSubtrees.?LAST.maximum",
					     NULL, 0);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				ret = _gnutls_asn2err(result);
				goto cleanup;
			}

			result =
			    asn1_write_value(c2,
					     "excludedSubtrees.?LAST.minimum",
					     &null, 1);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				ret = _gnutls_asn2err(result);
				goto cleanup;
			}

			ret =
			    _gnutls_write_general_name(c2,
						       "excludedSubtrees.?LAST.base",
						       tmp->type,
						       tmp->name.data,
						       tmp->name.size);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
			tmp = tmp->next;
		} while (tmp != NULL);

	}

	ret = _gnutls_x509_der_encode(c2, "", ext, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

 cleanup:
	asn1_delete_structure(&c2);
	return ret;
}

/**
 * gnutls_x509_ext_get_subject_key_id:
 * @ext: a DER encoded extension
 * @id: will contain the subject key ID
 *
 * This function will return the subject key ID stored in the provided
 * SubjectKeyIdentifier extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_subject_key_id(const gnutls_datum_t * ext,
				       gnutls_datum_t * id)
{
	int result, ret;
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

	if (ext->size == 0 || ext->data == NULL) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	result = asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.SubjectKeyIdentifier", &c2);
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

	ret = _gnutls_x509_read_value(c2, "", id);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
 cleanup:
	asn1_delete_structure(&c2);

	return ret;

}

/**
 * gnutls_x509_ext_set_subject_key_id:
 * @id: The key identifier
 * @ext: Will hold the DER encoded extension
 *
 * This function will convert the provided key identifier to a
 * DER-encoded PKIX SubjectKeyIdentifier extension. 
 * The output data in @ext will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_subject_key_id(const gnutls_datum_t * id,
				       gnutls_datum_t * ext)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int ret, result;

	result =
	    asn1_create_element(_gnutls_get_pkix(),
				"PKIX1.SubjectKeyIdentifier", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_write_value(c2, "", id->data, id->size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	ret = _gnutls_x509_der_encode(c2, "", ext, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
 cleanup:
	asn1_delete_structure(&c2);
	return ret;
}

struct gnutls_aki_st {
	gnutls_datum_t id;
	struct gnutls_subject_alt_names_st cert_issuer;
	gnutls_datum_t serial;
};

/**
 * gnutls_aki_init:
 * @aki: The authority key ID structure
 *
 * This function will initialize an authority key ID structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_aki_init(gnutls_aki_t * aki)
{
	*aki = gnutls_calloc(1, sizeof(struct gnutls_aki_st));
	if (*aki == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	return 0;
}

/**
 * gnutls_aki_get_id:
 * @aki: The authority key ID structure
 * @id: Will hold the identifier
 *
 * This function will return the key identifier as stored in
 * the @aki structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the index is out of bounds, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_aki_get_id(gnutls_aki_t aki, gnutls_datum_t * id)
{
	if (aki->id.size == 0)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	memcpy(id, &aki->id, sizeof(gnutls_datum_t));
	return 0;
}

/**
 * gnutls_aki_set_id:
 * @aki: The authority key ID structure
 * @id: the key identifier
 *
 * This function will set the keyIdentifier to be stored in the @aki
 * structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_aki_set_id(gnutls_aki_t aki, const gnutls_datum_t * id)
{
	return _gnutls_set_datum(&aki->id, id->data, id->size);
}

/**
 * gnutls_aki_set_cert_issuer:
 * @aki: The authority key ID structure
 * @san_type: the type of the name (of %gnutls_subject_alt_names_t), may be null
 * @san: The alternative name data
 * @othername_oid: The object identifier if @san_type is %GNUTLS_SAN_OTHERNAME
 * @serial: The authorityCertSerialNumber number (may be null)
 *
 * This function will set the authorityCertIssuer name and the authorityCertSerialNumber 
 * to be stored in the @aki structure. When storing multiple names, the serial
 * should be set on the first call, and subsequent calls should use a %NULL serial.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_aki_set_cert_issuer(gnutls_aki_t aki,
			       unsigned int san_type,
			       const gnutls_datum_t * san,
			       const char *othername_oid,
			       const gnutls_datum_t * serial)
{
	int ret;

	if (aki->cert_issuer.size + 1 > MAX_ENTRIES)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	ret = _gnutls_set_datum(&aki->serial, serial->data, serial->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	aki->cert_issuer.type[aki->cert_issuer.size] = san_type;

	ret =
	    _gnutls_set_datum(&aki->cert_issuer.san[aki->cert_issuer.size],
			      san->data, san->size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (othername_oid) {
		aki->cert_issuer.othername_oid[aki->cert_issuer.size].data =
		    (uint8_t *) gnutls_strdup(othername_oid);
		if (aki->cert_issuer.othername_oid[aki->cert_issuer.size].
		    data == NULL) {
			gnutls_free(aki->cert_issuer.san[aki->cert_issuer.size].
				    data);
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		}
		aki->cert_issuer.othername_oid[aki->cert_issuer.size].size =
		    strlen(othername_oid);
	}

	aki->cert_issuer.size++;

	return 0;
}

/**
 * gnutls_aki_get_cert_issuer:
 * @aki: The authority key ID structure
 * @seq: The index of the name to get
 * @san_type: Will hold the type of the name (of %gnutls_subject_alt_names_t), may be null
 * @san: The alternative name data (may be null)
 * @othername_oid: The object identifier if @san_type is %GNUTLS_SAN_OTHERNAME (should be treated as constant)
 * @serial: The authorityCertSerialNumber number (may be null)
 *
 * This function will return a specific authorityCertIssuer name as stored in
 * the @aki structure, as well as the authorityCertSerialNumber.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the index is out of bounds, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_aki_get_cert_issuer(gnutls_aki_t aki, unsigned int seq,
			       unsigned int *san_type, gnutls_datum_t * san,
			       gnutls_datum_t * othername_oid,
			       gnutls_datum_t * serial)
{
	if (seq >= aki->cert_issuer.size)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (aki->serial.size == 0)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (serial)
		memcpy(serial, &aki->serial, sizeof(gnutls_datum_t));

	if (san) {
		memcpy(san, &aki->cert_issuer.san[seq], sizeof(gnutls_datum_t));
	}

	if (othername_oid != NULL
	    && aki->cert_issuer.type[seq] == GNUTLS_SAN_OTHERNAME) {
		othername_oid->data = aki->cert_issuer.othername_oid[seq].data;
		othername_oid->size = aki->cert_issuer.othername_oid[seq].size;
	}

	if (san_type)
		*san_type = aki->cert_issuer.type[seq];

	return 0;

}

/**
 * gnutls_aki_deinit:
 * @aki: The authority key identifier structure
 *
 * This function will deinitialize an authority key identifier structure.
 *
 * Since: 3.3.0
 **/
void gnutls_aki_deinit(gnutls_aki_t aki)
{
	gnutls_free(aki->serial.data);
	gnutls_free(aki->id.data);
	subject_alt_names_deinit(&aki->cert_issuer);
	gnutls_free(aki);
}

/**
 * gnutls_x509_ext_get_authority_key_id:
 * @ext: a DER encoded extension
 * @aki: An initialized authority key identifier structure
 *
 * This function will return the subject key ID stored in the provided
 * AuthorityKeyIdentifier extension.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
 * if the extension is not present, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_authority_key_id(const gnutls_datum_t * ext,
					 gnutls_aki_t aki)
{
	int ret;
	unsigned i;
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

	ret = asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.AuthorityKeyIdentifier", &c2);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(ret);
	}

	ret = asn1_der_decoding(&c2, ext->data, ext->size, NULL);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto cleanup;
	}

	/* Read authorityCertIssuer */
	i = 0;
	do {
		ret = _gnutls_parse_general_name2(c2, "authorityCertIssuer", i,
						  &aki->cert_issuer.san[i],
						  &aki->cert_issuer.type[i], 0);
		if (ret < 0)
			break;

		if (aki->cert_issuer.type[i] == GNUTLS_SAN_OTHERNAME) {
			ret =
			    _gnutls_parse_general_name2(c2,
							"authorityCertIssuer",
							i,
							&aki->cert_issuer.
							othername_oid[i], NULL,
							1);
			if (ret < 0)
				break;
		}

		i++;
	} while (ret >= 0 && i < MAX_ENTRIES);

	aki->cert_issuer.size = i;
	if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
	    && ret != GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
		gnutls_assert();
		goto cleanup;
	}

	/* Read the serial number */
	ret =
	    _gnutls_x509_read_value(c2, "authorityCertSerialNumber",
				    &aki->serial);
	if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
	    && ret != GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
		gnutls_assert();
		goto cleanup;
	}

	/* Read the key identifier */
	ret = _gnutls_x509_read_value(c2, "keyIdentifier", &aki->id);
	if (ret < 0 && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
	    && ret != GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

 cleanup:
	asn1_delete_structure(&c2);

	return ret;
}

/**
 * gnutls_x509_ext_set_authority_key_id:
 * @aki: An initialized authority key identifier structure
 * @ext: Will hold the DER encoded extension
 *
 * This function will convert the provided key identifier to a
 * DER-encoded PKIX AuthorityKeyIdentifier extension. 
 * The output data in @ext will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_authority_key_id(gnutls_aki_t aki, gnutls_datum_t * ext)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	unsigned i;
	int result, ret;

	result =
	    asn1_create_element(_gnutls_get_pkix(),
				"PKIX1.AuthorityKeyIdentifier", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (aki->id.data != NULL) {
		result =
		    asn1_write_value(c2, "keyIdentifier", aki->id.data,
				     aki->id.size);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			goto cleanup;
		}
	} else {
		asn1_write_value(c2, "keyIdentifier", NULL, 0);
	}

	if (aki->serial.data != NULL) {
		result =
		    asn1_write_value(c2, "authorityCertSerialNumber",
				     aki->serial.data, aki->serial.size);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			goto cleanup;
		}
	} else {
		asn1_write_value(c2, "authorityCertSerialNumber", NULL, 0);
	}

	if (aki->cert_issuer.size == 0) {
		asn1_write_value(c2, "authorityCertIssuer", NULL, 0);
	} else {
		for (i = 0; i < aki->cert_issuer.size; i++) {
			ret =
			    _gnutls_write_new_general_name(c2,
							   "authorityCertIssuer",
							   aki->cert_issuer.
							   type[i],
							   aki->cert_issuer.
							   san[i].data,
							   aki->cert_issuer.
							   san[i].size);
			if (result < 0) {
				gnutls_assert();
				goto cleanup;
			}
		}
	}

	ret = _gnutls_x509_der_encode(c2, "", ext, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
 cleanup:
	asn1_delete_structure(&c2);
	return ret;

}

/**
 * gnutls_x509_ext_get_key_usage:
 * @ext: the DER encoded extension data
 * @key_usage: where the key usage bits will be stored
 *
 * This function will return certificate's key usage, by reading the DER
 * data of the keyUsage X.509 extension (2.5.29.15). The key usage value will ORed
 * values of the: %GNUTLS_KEY_DIGITAL_SIGNATURE,
 * %GNUTLS_KEY_NON_REPUDIATION, %GNUTLS_KEY_KEY_ENCIPHERMENT,
 * %GNUTLS_KEY_DATA_ENCIPHERMENT, %GNUTLS_KEY_KEY_AGREEMENT,
 * %GNUTLS_KEY_KEY_CERT_SIGN, %GNUTLS_KEY_CRL_SIGN,
 * %GNUTLS_KEY_ENCIPHER_ONLY, %GNUTLS_KEY_DECIPHER_ONLY.
 *
 * Returns: the certificate key usage, or a negative error code in case of
 *   parsing error.  If the certificate does not contain the keyUsage
 *   extension %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be
 *   returned.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_key_usage(const gnutls_datum_t * ext,
				  unsigned int *key_usage)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int len, result;
	uint8_t str[2];

	str[0] = str[1] = 0;
	*key_usage = 0;

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.KeyUsage", &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&c2, ext->data, ext->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	len = sizeof(str);
	result = asn1_read_value(c2, "", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c2);
		return 0;
	}

	*key_usage = str[0] | (str[1] << 8);

	asn1_delete_structure(&c2);

	return 0;
}

/**
 * gnutls_x509_ext_set_key_usage:
 * @usage: an ORed sequence of the GNUTLS_KEY_* elements.
 * @ext: will hold the DER encoded extension data
 *
 * This function will convert the keyUsage bit string to a DER
 * encoded PKIX extension. The @ext data will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_key_usage(unsigned int usage, gnutls_datum_t * ext)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result;
	uint8_t str[2];

	result = asn1_create_element(_gnutls_get_pkix(), "PKIX1.KeyUsage", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	str[0] = usage & 0xff;
	str[1] = usage >> 8;

	result = asn1_write_value(c2, "", str, 9);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_der_encode(c2, "", ext, 0);

	asn1_delete_structure(&c2);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}

/**
 * gnutls_x509_ext_get_private_key_usage_period:
 * @ext: the DER encoded extension data
 * @activation: Will hold the activation time
 * @expiration: Will hold the expiration time
 *
 * This function will return the expiration and activation
 * times of the private key as written in the
 * PKIX extension 2.5.29.16.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_private_key_usage_period(const gnutls_datum_t * ext,
						 time_t * activation,
						 time_t * expiration)
{
	int result, ret;
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

	result = asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.PrivateKeyUsagePeriod", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_der_decoding(&c2, ext->data, ext->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (activation)
		*activation = _gnutls_x509_get_time(c2, "notBefore", 1);

	if (expiration)
		*expiration = _gnutls_x509_get_time(c2, "notAfter", 1);

	ret = 0;

 cleanup:
	asn1_delete_structure(&c2);

	return ret;
}

/**
 * gnutls_x509_ext_set_private_key_usage_period:
 * @activation: The activation time
 * @expiration: The expiration time
 * @ext: will hold the DER encoded extension data
 *
 * This function will convert the periods provided to a private key
 * usage DER encoded extension (2.5.29.16).
 (
 * The @ext data will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_private_key_usage_period(time_t activation,
						 time_t expiration,
						 gnutls_datum_t * ext)
{
	int result;
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;

	result =
	    asn1_create_element(_gnutls_get_pkix(),
				"PKIX1.PrivateKeyUsagePeriod", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = _gnutls_x509_set_time(c2, "notBefore", activation, 1);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = _gnutls_x509_set_time(c2, "notAfter", expiration, 1);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = _gnutls_x509_der_encode(c2, "", ext, 0);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

 cleanup:
	asn1_delete_structure(&c2);

	return result;

}

/**
 * gnutls_x509_ext_get_basic_constraints:
 * @ext: the DER encoded extension data
 * @ca: will be non zero if the CA status is true
 * @pathlen: the path length constraint; will be set to -1 for no limit
 *
 * This function will return the CA status and path length constraint
 * as written in the PKIX extension 2.5.29.19.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_get_basic_constraints(const gnutls_datum_t * ext,
					  unsigned int *ca, int *pathlen)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	char str[128];
	int len, result;

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.BasicConstraints",
	      &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&c2, ext->data, ext->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (pathlen) {
		result = _gnutls_x509_read_uint(c2, "pathLenConstraint",
						(unsigned int *)
						pathlen);
		if (result == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
			*pathlen = -1;
		else if (result != GNUTLS_E_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}
	}

	/* the default value of cA is false.
	 */
	len = sizeof(str) - 1;
	result = asn1_read_value(c2, "cA", str, &len);
	if (result == ASN1_SUCCESS && strcmp(str, "TRUE") == 0)
		*ca = 1;
	else
		*ca = 0;

	result = 0;
 cleanup:
	asn1_delete_structure(&c2);

	return result;

}

/**
 * gnutls_x509_ext_set_basic_constraints:
 * @ca: non-zero for a CA
 * @pathlen: The path length constraint (set to -1 for no constraint)
 * @ext: will hold the DER encoded extension data
 *
 * This function will convert the parameters provided to a basic constraints
 * DER encoded extension (2.5.29.19).
 (
 * The @ext data will be allocated using
 * gnutls_malloc().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.3.0
 **/
int gnutls_x509_ext_set_basic_constraints(unsigned int ca, int pathlen,
					  gnutls_datum_t * ext)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	const char *str;
	int result;

	if (ca == 0)
		str = "FALSE";
	else
		str = "TRUE";

	result =
	    asn1_create_element(_gnutls_get_pkix(),
				"PKIX1.BasicConstraints", &c2);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_write_value(c2, "cA", str, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (pathlen < 0) {
		result = asn1_write_value(c2, "pathLenConstraint", NULL, 0);
		if (result < 0)
			result = _gnutls_asn2err(result);
	} else
		result =
		    _gnutls_x509_write_uint32(c2, "pathLenConstraint", pathlen);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = _gnutls_x509_der_encode(c2, "", ext, 0);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = 0;

 cleanup:
	asn1_delete_structure(&c2);
	return result;

}

#if 0

typedef struct gnutls_crl_dist_points_st *gnutls_crl_dist_points_t;

int gnutls_crl_dist_points_init(gnutls_crl_dist_points_t *);
void gnutls_crl_dist_points_deinit(gnutls_crl_dist_points_t);
int gnutls_crl_dist_points_get(gnutls_crl_dist_points_t, unsigned int seq,
			       unsigned int *type,
			       gnutls_datum_t * dist,
			       unsigned int *reason_flags);
int gnutls_crl_dist_points_set(gnutls_crl_dist_points_t,
			       gnutls_x509_subject_alt_name_t type,
			       const gnutls_datum_t * dist,
			       unsigned int reason_flags);

int gnutls_x509_ext_get_crl_dist_points(const gnutls_datum_t * ext,
					gnutls_crl_dist_points_t dp);
int gnutls_x509_ext_set_crl_dist_points(gnutls_crl_dist_points_t dp,
					gnutls_datum_t * ext);

typedef struct gnutls_aia_st *gnutls_aia_t;

int gnutls_aia_init(gnutls_aia_t *);
void gnutls_aia_deinit(gnutls_aia_t);
int gnutls_aia_get(gnutls_aia_t, unsigned int seq,
		   gnutls_info_access_what_t what, gnutls_datum_t * data);
int gnutls_aia_set(gnutls_aia_t,
		   gnutls_info_access_what_t what, const gnutls_datum_t * data);

int gnutls_x509_ext_get_authority_info_access(const gnutls_datum_t * ext,
					      gnutls_aia_t);
int gnutls_x509_ext_set_authority_info_access(gnutls_aia_t aia,
					      gnutls_datum_t * ext);

int gnutls_x509_ext_get_proxy(const gnutls_datum_t * ext, int *pathlen,
			      char **policyLanguage, char **policy,
			      size_t * sizeof_policy);
int gnutls_x509_ext_set_proxy(int pathLenConstraint, const char *policyLanguage,
			      const char *policy, size_t sizeof_policy,
			      gnutls_datum_t * ext);

int gnutls_x509_ext_get_policies(const gnutls_datum_t * ext, struct gnutls_x509_policy_st
				 **policy, unsigned int *max_policies);
int gnutls_x509_ext_set_policies(struct gnutls_x509_policy_st *policies,
				 unsigned int n_policies, gnutls_datum_t * ext);
#endif
