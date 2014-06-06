/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson
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

#ifndef EXT_STATUS_REQUEST_H
#define EXT_STATUS_REQUEST_H

#include <gnutls_extensions.h>

#define MAX_OCSP_RESPONSES 16

typedef struct {
	gnutls_datum_t *responder_id;
	size_t responder_id_size;
	gnutls_datum_t request_extensions;
	gnutls_datum_t raw_resp;

	/* read only */
	gnutls_datum_t responses[MAX_OCSP_RESPONSES];
	unsigned int responses_size;

	unsigned int expect_cstatus;
	unsigned int status_type;
} status_request_ext_st;

extern extension_entry_st ext_mod_status_request;

int
_gnutls_send_server_certificate_status(gnutls_session_t session,
				       int again);
int _gnutls_recv_server_certificate_status(gnutls_session_t session);

void _gnutls_deinit_responder_id(status_request_ext_st *priv);

int
_gnutls_status_request_server_recv(gnutls_session_t session,
	    status_request_ext_st * priv,
	    const uint8_t * data, size_t size, unsigned v2);

int
_gnutls_status_request_client_recv(gnutls_session_t session,
	    status_request_ext_st * priv,
	    const uint8_t * data, size_t size, unsigned v2);

void _gnutls_status_request_deinit_data(extension_priv_data_t epriv);

int
_gnutls_status_request_pack(extension_priv_data_t epriv,
			    gnutls_buffer_st * ps);

int
_gnutls_status_request_unpack(gnutls_buffer_st * ps,
			      extension_priv_data_t * epriv);

#endif
