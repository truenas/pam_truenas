// SPDX-License-Identifier: LGPL-3.0-or-later

#include "json.h"
#include "kr_session.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <pwd.h>
#include <openssl/rand.h>

// auth data
#define FIELD_DBID "dbid"
#define FIELD_UNAME "username"
#define FIELD_SALT "salt"
#define FIELD_ITERS "iterations"
#define FIELD_EXPIRY "expiry"
#define FIELD_STORED "stored_key"
#define FIELD_SERVER "server_key"

// session data
#define FIELD_ADDR_F "origin_family"  /* json string "AF_UNIX", "AF_INET", "AF_INET6" */
#define FIELD_ADDR "origin"  // json object -- basically union based on origin_family
#define FIELD_ADDR_UNIX_PID "pid" // json int
#define FIELD_ADDR_UNIX_UID "uid" // json int
#define FIELD_ADDR_UNIX_GID "gid" // json int
#define FIELD_ADDR_UNIX_LUID "loginuid" // json int
#define FIELD_ADDR_UNIX_SEC "sec" // json string
#define FIELD_ADDR_TCP_LADDR "loc_addr"  // json string (to be converted to bytes)
#define FIELD_ADDR_TCP_LPORT "loc_port"  // json int
#define FIELD_ADDR_TCP_RADDR "rem_addr"  // json string (to be converted to bytes)
#define FIELD_ADDR_TCP_RPORT "rem_port"  // json int
#define FIELD_ADDR_TCP_SSL "ssl"  // json bool

/* JSON parsing functions for API key data */
/* --------------------------------------- */

/* Convert JSON value into the database ID for an API key and populate
 * relevant part of auth data struct. */
static
json_resp_t parse_dbid_json(ptn_auth_data_t *auth_data,
			    json_t *value,
			    json_error_info_t *error_info)
{
	json_int_t dbid;

	if (!json_is_integer(value)) {
		ptn_set_error(error_info, "Incorrect data type for \"dbid\" key");
		return JSON_E_PARSE;
	}

	dbid = json_integer_value(value);
	if ((dbid < 0) || (dbid > INT32_MAX)) {
		ptn_set_error(error_info, "%ll: invalid API key dbid", dbid);
		return JSON_E_PARSE;
	}

	auth_data->principal.api_key_id = dbid;
	return JSON_E_SUCCESS;
}

/* Copy JSON value into the username in the auth data struct */
static
json_resp_t parse_username_json(ptn_auth_data_t *auth_data,
				json_t *value,
				json_error_info_t *error_info)
{
	const char *username = NULL;

	if (!json_is_string(value)) {
		ptn_set_error(error_info, "Incorrect data type for \"username\" key");
		return JSON_E_PARSE;
	}

	username = json_string_value(value);
	strlcpy(auth_data->principal.username,
		username, sizeof(auth_data->principal.username));

	return JSON_E_SUCCESS;
}

/* Parse the iteration count for PBKDF2_HMAC_SHA512 from JSON info */
static
json_resp_t parse_iters_json(ptn_auth_data_t *auth_data,
			     json_t *value,
			     json_error_info_t *error_info)
{
	json_int_t iters;

	if (!json_is_integer(value)) {
		ptn_set_error(error_info, "Incorrect data type for \"iterations\" key");
		return JSON_E_PARSE;
	}

	iters = json_integer_value(value);
	if ((iters < SCRAM_MIN_ITERS) || (iters > SCRAM_MAX_ITERS)) {
		ptn_set_error(error_info, "%ll: invalid iteration count", iters);
		return JSON_E_PARSE;
	}

	auth_data->scram_data.iterations = iters;

	return JSON_E_SUCCESS;
}

/* Parse the expiration time for an API key from the provided JSON and insert
 * into auth data */
static
json_resp_t parse_expiry_json(ptn_auth_data_t *auth_data,
			      json_t *value,
			      json_error_info_t *error_info)
{
	json_int_t expiry;

	if (!json_is_integer(value)) {
		ptn_set_error(error_info, "Incorrect data type for \"expiry\" key");
		return JSON_E_PARSE;
	}

	expiry = json_integer_value(value);
	if (expiry < TRUENAS_KEY_REVOKED) {
		ptn_set_error(error_info, "%ll: invalid expiry timestamp", expiry);
		return JSON_E_PARSE;
	}

	auth_data->expiry = expiry;

	return JSON_E_SUCCESS;
}

/* General-purpose function to convert a base64-encoded blob into a
 * crypto_dataum_t type. This is for fields holding crypto information
 * (server_key, stored_key, salt, etc).
 */
static
json_resp_t parse_datum_json(const char *field,
			     json_t *value,
			     crypto_datum_t *datum,
			     json_error_info_t *error_info)
{
	const char *data = NULL;
	crypto_datum_t to_decode = {0};
	scram_resp_t scram_ret;
	scram_error_t scram_error;

	if (!json_is_string(value)) {
		ptn_set_error(error_info, "Incorrect data type for \"%s\" key", field);
		return JSON_E_PARSE;
	}

	data = json_string_value(value);
	to_decode = (crypto_datum_t) {
		.data = (unsigned char *)data,
		.size = strlen(data)
	};

	scram_ret = scram_base64_decode(&to_decode, datum, &scram_error);
	if (scram_ret != SCRAM_E_SUCCESS) {
		ptn_set_error(error_info, "Failed to decode %s: %s",
			      field, scram_error.message);
		return JSON_E_CRYPTO;
	}

	return JSON_E_SUCCESS;
}

/**
 * Parse JSON authentication data from a single API key entry
 * Populates the auth_data struct directly. This happens after
 * the JSON string has been decrypted using the generic TrueNAS
 * encryption / decryption library (truenas_pwenc).
 */
json_resp_t parse_json_auth_data(ptn_auth_data_t *auth_data,
				 pwenc_datum_t *json_data,
				 json_error_info_t *err)
{
	json_t *root = NULL;
	json_error_t error;
	json_resp_t resp;

	/* Initialize the auth_data struct */
	memset(auth_data, 0, sizeof(*auth_data));

	/* Parse JSON */
	root = json_loadb(json_data->data, json_data->size, 0, &error);
	if (!root) {
		ptn_set_error(err, "JSON parse error: %s", error.text);
		return JSON_E_PARSE;
	}

	if (!json_is_object(root)) {
		ptn_set_error(err, "JSON data is not an object");
		json_decref(root);
		return JSON_E_PARSE;
	}

	/* Parse dbid (API key ID) */
	resp = parse_dbid_json(auth_data, json_object_get(root, FIELD_DBID), err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	/* Parse username if present */
	resp = parse_username_json(auth_data, json_object_get(root, FIELD_UNAME), err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	/* Parse iterations */
	resp = parse_iters_json(auth_data, json_object_get(root, FIELD_ITERS), err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	/* Parse expiry */
	resp = parse_expiry_json(auth_data, json_object_get(root, FIELD_EXPIRY), err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	/* Parse and decode salt */
	resp = parse_datum_json(FIELD_SALT, json_object_get(root, FIELD_SALT),
			       &auth_data->scram_data.salt, err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	/* Parse and decode stored_key */
	resp = parse_datum_json(FIELD_STORED, json_object_get(root, FIELD_STORED),
			       &auth_data->scram_data.stored_key, err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	/* Parse and decode server_key */
	resp = parse_datum_json(FIELD_SERVER, json_object_get(root, FIELD_SERVER),
			       &auth_data->scram_data.server_key, err);
	if (resp != JSON_E_SUCCESS) {
		json_decref(root);
		return resp;
	}

	json_decref(root);
	return JSON_E_SUCCESS;
}

/* JSON parsing functions for session information */
/* ---------------------------------------------- */

/* Insert what information we can from PAM get_item items (strings)
 * This includes:
 * - PAM_USER -> cred.uname (canonicalized through getpwnam_r)
 *            -> cred.uid (based on getpwnam_r result)
 *            -> cred.gid (based on getpwnam_r result)
 * - PAM_RUSER -> pam_item.ruser
 * - PAM_RHOST -> pam_item.rhost
 * - PAM_TTY -> pam_item.tty
 * - PAM_SERVICE -> pam_item.service
 *
 * See man(3) pam_set_item for more information about the above item
 * types.
 */
static
json_resp_t populate_pam_items(pam_tn_ctx_t *ctx, kr_sess_t *sess, json_error_info_t *err)
{
	const char *pam_val;
	char *username = NULL;
	int ret;
	uid_t uid;
	gid_t gid;

	ret = pam_get_item(ctx->pamh, PAM_USER, (const void**)&pam_val);
	if ((ret != PAM_SUCCESS) || (pam_val == NULL)) {
		ptn_set_error(err, "Failed to retrieve PAM_USER");
		return JSON_E_NOT_FOUND;
	}

	username = canonicalize_username(pam_val, &uid, &gid);
	if (username == NULL) {
		ptn_set_error(err, "%s: failed to canonicalize username: %s",
			      pam_val, strerror(errno));
		return JSON_E_NOT_FOUND;
	}

	strlcpy(sess->cred.name, username, sizeof(sess->cred.name));
	free(username);
	sess->cred.uid = uid;
	sess->cred.gid = gid;

	/* Get other PAM items */
	if (pam_get_item(ctx->pamh, PAM_SERVICE, (const void **)&pam_val) == PAM_SUCCESS && pam_val) {
		strlcpy(sess->pam_item.service, pam_val, sizeof(sess->pam_item.service));
	}

	if (pam_get_item(ctx->pamh, PAM_RUSER, (const void **)&pam_val) == PAM_SUCCESS && pam_val) {
		strlcpy(sess->pam_item.ruser, pam_val, sizeof(sess->pam_item.ruser));
	}

	if (pam_get_item(ctx->pamh, PAM_RHOST, (const void **)&pam_val) == PAM_SUCCESS && pam_val) {
		strlcpy(sess->pam_item.rhost, pam_val, sizeof(sess->pam_item.rhost));
	}

	if (pam_get_item(ctx->pamh, PAM_TTY, (const void **)&pam_val) == PAM_SUCCESS && pam_val) {
		strlcpy(sess->pam_item.tty, pam_val, sizeof(sess->pam_item.tty));
	}

	return JSON_E_SUCCESS;
}

/*
 * The JSON object about session contains information about an AF_UNIX origin
 * This function parses the object's fields into a properly formatted unix_origin struct
 */
static
json_resp_t parse_origin_unix(kr_sess_t *sess, json_t *origin_obj, json_error_info_t *err)
{
	json_t *val;
	json_int_t intval;
	const char *strval;

	val = json_object_get(origin_obj, FIELD_ADDR_UNIX_PID);
	if (val && json_is_integer(val)) {
		intval = json_integer_value(val);
		/* Validate pid_t range */
		if (intval < 0 || intval > INT32_MAX) {
			ptn_set_error(err, "PID value out of range: %lld", (long long)intval);
			return JSON_E_PARSE;
		}
		sess->origin.unix_origin.pid = (pid_t)intval;
	}

	val = json_object_get(origin_obj, FIELD_ADDR_UNIX_UID);
	if (val && json_is_integer(val)) {
		intval = json_integer_value(val);
		/* Validate uid_t range */
		if (intval < 0 || intval > UINT32_MAX) {
			ptn_set_error(err, "UID value out of range: %lld", (long long)intval);
			return JSON_E_PARSE;
		}
		sess->origin.unix_origin.uid = (uid_t)intval;
	}

	val = json_object_get(origin_obj, FIELD_ADDR_UNIX_GID);
	if (val && json_is_integer(val)) {
		intval = json_integer_value(val);
		/* Validate gid_t range */
		if (intval < 0 || intval > UINT32_MAX) {
			ptn_set_error(err, "GID value out of range: %lld", (long long)intval);
			return JSON_E_PARSE;
		}
		sess->origin.unix_origin.gid = (gid_t)intval;
	}

	val = json_object_get(origin_obj, FIELD_ADDR_UNIX_LUID);
	if (val && json_is_integer(val)) {
		intval = json_integer_value(val);
		/* Validate uid_t range for loginuid (-1 is special value) */
		if (intval < -1 || intval > UINT32_MAX) {
			ptn_set_error(err, "LoginUID value out of range: %lld", (long long)intval);
			return JSON_E_PARSE;
		}
		sess->origin.unix_origin.loginuid = (uid_t)intval;
	}

	val = json_object_get(origin_obj, FIELD_ADDR_UNIX_SEC);
	if (val && json_is_string(val)) {
		strval = json_string_value(val);
		strlcpy(sess->origin.unix_origin.sec, strval, sizeof(sess->origin.unix_origin.sec));
	}

	return JSON_E_SUCCESS;
}

/*
 * The JSON object about session contains information about an AF_INET or AF_INET6 origin
 * This function parses the object's fields into a properly formatted tcp_origin struct
 */
static
json_resp_t parse_origin_tcp(kr_sess_t *sess, int family, json_t *origin_obj, json_error_info_t *err)
{
	json_t *val;
	json_int_t intval;
	const char *strval;
	int ret;

	val = json_object_get(origin_obj, FIELD_ADDR_TCP_LADDR);
	if (val && json_is_string(val)) {
		strval = json_string_value(val);
		ret = inet_pton(family, strval, &sess->origin.tcp_origin.loc_addr);
		if (ret != 1) {
			ptn_set_error(err, "Invalid local address: %s", strval);
			return JSON_E_PARSE;
		}
	}

	val = json_object_get(origin_obj, FIELD_ADDR_TCP_LPORT);
	if (val && json_is_integer(val)) {
		intval = json_integer_value(val);
		/* Validate port range */
		if (intval < 0 || intval > UINT16_MAX) {
			ptn_set_error(err, "Local port out of range: %lld", (long long)intval);
			return JSON_E_PARSE;
		}
		sess->origin.tcp_origin.loc_port = (uint16_t)intval;
	}

	val = json_object_get(origin_obj, FIELD_ADDR_TCP_RADDR);
	if (val && json_is_string(val)) {
		strval = json_string_value(val);
		ret = inet_pton(family, strval, &sess->origin.tcp_origin.rem_addr);
		if (ret != 1) {
			ptn_set_error(err, "Invalid remote address: %s", strval);
			return JSON_E_PARSE;
		}
	}

	val = json_object_get(origin_obj, FIELD_ADDR_TCP_RPORT);
	if (val && json_is_integer(val)) {
		intval = json_integer_value(val);
		/* Validate port range */
		if (intval < 0 || intval > UINT16_MAX) {
			ptn_set_error(err, "Remote port out of range: %lld", (long long)intval);
			return JSON_E_PARSE;
		}
		sess->origin.tcp_origin.rem_port = (uint16_t)intval;
	}

	val = json_object_get(origin_obj, FIELD_ADDR_TCP_SSL);
	if (val && json_is_boolean(val)) {
		sess->origin.tcp_origin.ssl = json_boolean_value(val);
	}

	return JSON_E_SUCCESS;
}

/*
 * This function populates kr_sess_t based on the PAM handle items set by the
 * PAM application as well as additional JSON-formatted session information
 * inserted into a PAM environmental variable (see `PAM_TN_ENV_SES_DATA`
 * definition in header). The JSON session information should contain
 * the required fields to properly define the session's origin as well as
 * any additional required data. Extra fields not related to the origin
 * are written to `sess->json_data` so that they can be inserted into
 * the SESSIONS keyring for the user.
 */
json_resp_t parse_json_sess_entry(pam_tn_ctx_t *ctx, json_error_info_t *err)
{
	const char *session_json;
	json_t *root = NULL;
	json_t *val;
	json_error_t json_err;
	json_resp_t resp;
	kr_sess_t *sess = &ctx->session_info;
	const char *strval;
	int ret;

	/* Initialize session structure */
	memset(sess, 0, sizeof(*sess));

	/*
	 * Generate new UUID for this session using OpenSSL RAND_bytes
	 *
	 * We are using SSL RAND_bytes here to ensure that FIPS-validated
	 * cryptographic module is being used to generate UUIDs.
	 */
	ret = RAND_bytes(sess->session_id, sizeof(sess->session_id));
	if (ret != 1) {
		ptn_set_error(err, "Failed to generate session UUID");
		return JSON_E_CRYPTO;
	}
	/* Set UUID version (4) and variant bits per RFC 4122 */
	sess->session_id[6] = (sess->session_id[6] & 0x0f) | 0x40; /* Version 4 */
	sess->session_id[8] = (sess->session_id[8] & 0x3f) | 0x80; /* Variant 10 */

	/* Get current time */
	if (clock_gettime(CLOCK_REALTIME, &sess->creation) != 0) {
		ptn_set_error(err, "Failed to get current time: %s", strerror(errno));
		return JSON_E_PARSE;
	}

	/* Get process info */
	sess->pid = getpid();
	sess->sid = getsid(sess->pid);

	/* Populate PAM items and user credentials */
	resp = populate_pam_items(ctx, sess, err);
	if (resp != JSON_E_SUCCESS) {
		return resp;
	}

	/* Parse JSON session data from PAM environment */
	session_json = pam_getenv(ctx->pamh, PAM_TN_ENV_SES_DATA);
	if (session_json == NULL) {
		/* No JSON data is not an error - just means no extra session info */
		return JSON_E_SUCCESS;
	}

	root = json_loads(session_json, 0, &json_err);
	if (root == NULL) {
		ptn_set_error(err, "JSON parse error: %s", json_err.text);
		return JSON_E_PARSE;
	}

	if (!json_is_object(root)) {
		ptn_set_error(err, "JSON data is not an object");
		json_decref(root);
		return JSON_E_PARSE;
	}

	/* Parse origin_family */
	val = json_object_get(root, FIELD_ADDR_F);
	if (val && json_is_string(val)) {
		strval = json_string_value(val);
		if (strcmp(strval, "AF_UNIX") == 0) {
			sess->origin_family = AF_UNIX;
		} else if (strcmp(strval, "AF_INET") == 0) {
			sess->origin_family = AF_INET;
		} else if (strcmp(strval, "AF_INET6") == 0) {
			sess->origin_family = AF_INET6;
		}
	}

	/* Parse origin data based on family */
	val = json_object_get(root, FIELD_ADDR);
	if (val && json_is_object(val)) {
		if (sess->origin_family == AF_UNIX) {
			resp = parse_origin_unix(sess, val, err);
			if (resp != JSON_E_SUCCESS) {
				json_decref(root);
				return resp;
			}
		} else if (sess->origin_family == AF_INET || sess->origin_family == AF_INET6) {
			resp = parse_origin_tcp(sess, sess->origin_family, val, err);
			if (resp != JSON_E_SUCCESS) {
				json_decref(root);
				return resp;
			}
		}

		/*
		 * Remove origin fields from JSON before storing
		 *
		 * We've already stored this information in data structure
		 * and so this helps reduce overall size of JSON object inserted
		 * as extra JSON data.
		 */
		json_object_del(root, FIELD_ADDR_F);
		json_object_del(root, FIELD_ADDR);
	}

	/* Store remaining JSON data as opaque string */
	if (json_object_size(root) > 0) {
		char *json_str = json_dumps(root, JSON_COMPACT);
		if (!json_str) {
			ptn_set_error(err, "Failed to serialize JSON data");
			json_decref(root);
			return JSON_E_PARSE;
		}

		/* Copy to static buffer, ensuring null termination */
		strlcpy(sess->json_data, json_str, sizeof(sess->json_data));

		/* Check if data was truncated */
		if (strlen(json_str) >= sizeof(sess->json_data)) {
			PAM_CTX_DEBUG(ctx, LOG_WARNING,
				      "JSON session data truncated (%zu bytes to %zu)",
				      strlen(json_str), sizeof(sess->json_data) - 1);
		}

		free(json_str);
	} else {
		sess->json_data[0] = '\0';
	}

	json_decref(root);
	return JSON_E_SUCCESS;
}
