/*
 * Copyright (C) 2014 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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

/* Prototypes for direct handling of extension data */

#ifndef GNUTLS_X509_EXT_H
#define GNUTLS_X509_EXT_H

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

typedef struct gnutls_subject_alt_names_st *gnutls_subject_alt_names_t;

int gnutls_subject_alt_names_init(gnutls_subject_alt_names_t *);
void gnutls_subject_alt_names_deinit(gnutls_subject_alt_names_t);
int gnutls_subject_alt_names_get(gnutls_subject_alt_names_t, unsigned int seq,
				 unsigned int *san_type, gnutls_datum_t * san);
int gnutls_subject_alt_names_get_othername_oid(gnutls_subject_alt_names_t,
					       unsigned int seq,
					       gnutls_datum_t * oid);
int gnutls_subject_alt_names_set(gnutls_subject_alt_names_t sans,
				 unsigned int san_type,
				 const gnutls_datum_t * san,
				 const char* othername_oid);


int gnutls_x509_ext_get_subject_alt_name(const gnutls_datum_t * ext,
					 gnutls_subject_alt_names_t,
					 unsigned int *critical);
int gnutls_x509_ext_set_subject_alt_name(gnutls_subject_alt_names_t,
					 unsigned int critical,
					 gnutls_datum_t * ext);

/* They are exactly the same */
#define gnutls_x509_ext_get_issuer_alt_name gnutls_x509_ext_get_subject_alt_name
#define gnutls_x509_ext_set_issuer_alt_name gnutls_x509_ext_set_subject_alt_name

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


/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */
#endif				/* GNUTLS_X509_H */
