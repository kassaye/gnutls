/*
 * Copyright (C) 2014 Red Hat, Inc.
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

/*
  Status Request (OCSP) TLS extension.  See RFC 6961
  https://tools.ietf.org/html/rfc6961
*/

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include <gnutls_extensions.h>
#include <ext/status_request_multi.h>
#include <ext/status_request.h>
#include <gnutls_mbuffers.h>
#include <gnutls_auth.h>
#include <auth/cert.h>
#include <gnutls_handshake.h>

#ifdef ENABLE_OCSP

/*
  From RFC 6961.  Client sends:

      struct {
          CertificateStatusType status_type;
          uint16 request_length; -- Length of request field in bytes
          select (status_type) {
              case ocsp: OCSPStatusRequest;
              case ocsp_multi: OCSPStatusRequest;
          } request;
       } CertificateStatusRequestItemV2;

      enum { ocsp(1), ocsp_multi(2), (255) } CertificateStatusType;

      struct {
          ResponderID responder_id_list<0..2^16-1>;
          Extensions  request_extensions;
      } OCSPStatusRequest;

      opaque ResponderID<1..2^16-1>;
      opaque Extensions<0..2^16-1>;
      
      struct {
          CertificateStatusRequestItemV2 certificate_status_req_list<1..2^16-1>;
      } CertificateStatusRequestListV2;
*/

static int
client_send(gnutls_session_t session,
	    gnutls_buffer_st *extdata, status_request_ext_st *priv)
{
	int ret, ret_len;
	unsigned spos;
	size_t i;

	spos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_buffer_append_prefix(extdata, 8, 2);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret =
	    _gnutls_buffer_append_prefix(extdata, 16,
					 priv->responder_id_size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	for (i = 0; i < priv->responder_id_size; i++) {
		if (priv->responder_id[i].size <= 0)
			return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

		ret = _gnutls_buffer_append_data_prefix(extdata, 16,
							priv->
							responder_id[i].
							data,
							priv->
							responder_id[i].
							size);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	ret = _gnutls_buffer_append_data_prefix(extdata, 16,
						priv->request_extensions.
						data,
						priv->request_extensions.
						size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret_len = extdata->length - spos;
	_gnutls_write_uint16(ret_len-2, &extdata->data[spos]);

	return ret_len;
}

/*
  Servers return a certificate response along with their certificate
  by sending a "CertificateStatus" message immediately after the
  "Certificate" message (and before any "ServerKeyExchange" or
  "CertificateRequest" messages).  If a server returns a
  "CertificateStatus" message, then the server MUST have included an
  extension of type "status_request" with empty "extension_data" in
  the extended server hello.
*/

static int
server_send(gnutls_session_t session,
	    gnutls_buffer_st * extdata, status_request_ext_st * priv)
{
	int ret;
	gnutls_certificate_credentials_t cred;

	cred = (gnutls_certificate_credentials_t)
	    _gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE);
	if (cred == NULL)	/* no certificate authentication */
		return gnutls_assert_val(0);

	if (cred->ocsp_func == NULL)
		return gnutls_assert_val(GNUTLS_E_SUCCESS);

	ret =
	    cred->ocsp_func(session, cred->ocsp_func_ptr, &priv->raw_resp);
	if (ret == GNUTLS_E_NO_CERTIFICATE_STATUS)
		return 0;
	else if (ret < 0)
		return gnutls_assert_val(ret);

	return GNUTLS_E_INT_RET_0;
}

static int
_gnutls_status_request_v2_send_params(gnutls_session_t session,
				   gnutls_buffer_st * extdata)
{
	extension_priv_data_t epriv;
	status_request_ext_st *priv;
	int ret;

	ret = _gnutls_ext_get_session_data(session,
					   GNUTLS_EXTENSION_STATUS_REQUEST_V2,
					   &epriv);

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (ret < 0 || epriv.ptr == NULL)	/* it is ok not to have it */
			return 0;
		priv = epriv.ptr;

		return client_send(session, extdata, priv);
	} else {
		epriv.ptr = priv = gnutls_calloc(1, sizeof(*priv));
		if (priv == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

		_gnutls_ext_set_session_data(session,
					     GNUTLS_EXTENSION_STATUS_REQUEST_V2,
					     epriv);

		return server_send(session, extdata, priv);
	}
}

static int
_gnutls_status_request_v2_recv_params(gnutls_session_t session,
				   const uint8_t * data, size_t size)
{
	extension_priv_data_t epriv;
	status_request_ext_st *priv;
	int ret;

	ret = _gnutls_ext_get_session_data(session,
					   GNUTLS_EXTENSION_STATUS_REQUEST_V2,
					   &epriv);
	if (ret < 0 || epriv.ptr == NULL)	/* it is ok not to have it */
		return 0;

	priv = epriv.ptr;

	if (session->security_parameters.entity == GNUTLS_CLIENT)
		return _gnutls_status_request_client_recv(session, priv, data, size, 1);
	else
		return _gnutls_status_request_server_recv(session, priv, data, size, 1);
}

/**
 * gnutls_ocsp_status_request_get_multi:
 * @session: is a #gnutls_session_t structure.
 * @response: a #gnutls_datum_t with DER encoded OCSP response
 * @idx: the index of the response to retrieve (starting from zero)
 *
 * This function returns the indexed OCSP status response received
 * from the TLS server. The @response should be treated as
 * constant. If no OCSP response is available then
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 *
 * Since: 3.3.5
 **/
int
gnutls_ocsp_status_request_get_multi(gnutls_session_t session,
			       gnutls_datum_t *response, unsigned idx)
{
	status_request_ext_st *priv;
	extension_priv_data_t epriv;
	int ret;

	if (session->security_parameters.entity == GNUTLS_SERVER)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	ret = _gnutls_ext_get_session_data(session,
					   GNUTLS_EXTENSION_STATUS_REQUEST_V2,
					   &epriv);
	if (ret < 0) {
		ret = _gnutls_ext_get_session_data(session,
					   GNUTLS_EXTENSION_STATUS_REQUEST,
					   &epriv);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	priv = epriv.ptr;

	if (priv == NULL || idx >= priv->responses_size)
		return
		    gnutls_assert_val
		    (GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
	
	if (priv->responses[idx].data == NULL)
		return
		    gnutls_assert_val
		    (GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	response->data = priv->responses[idx].data;
	response->size = priv->responses[idx].size;

	return 0;
}

extension_entry_st ext_mod_status_request_v2 = {
	.name = "STATUS REQUEST V2",
	.type = GNUTLS_EXTENSION_STATUS_REQUEST_V2,
	.parse_type = GNUTLS_EXT_TLS,
	.recv_func = _gnutls_status_request_v2_recv_params,
	.send_func = _gnutls_status_request_v2_send_params,
	.pack_func = _gnutls_status_request_pack,
	.unpack_func = _gnutls_status_request_unpack,
	.deinit_func = _gnutls_status_request_deinit_data
};

#endif
