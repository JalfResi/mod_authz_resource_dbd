#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_lib.h" /* apr_isspace */
#include "apr_dbd.h"
#include "mod_dbd.h"

#include <mod_authz_resource_permissions.h>

static APR_OPTIONAL_FN_TYPE(ap_dbd_acquire) *dbd_acquire_fn = NULL;

typedef struct {
    char *permissionsfile;
    char *permissionsLookupSQL;
    int authoritative;
} authz_resource_permissions_config_rec;

static void *create_authz_resource_permissions_dir_config(apr_pool_t *p, char *d)
{
    authz_resource_permissions_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->permissionsfile = NULL;
    conf->permissionsLookupSQL = NULL;
    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const char *permissions_SQL_conf(cmd_parms *cmd, void *config,
                                      	const char *arg)
{
	((authz_resource_permissions_config_rec*)config)->permissionsLookupSQL = arg;

	return NULL;
}

static const command_rec provider_dbd_cmds[] =
{
    AP_INIT_TAKE1("AuthzResourcePermissionsSQL", permissions_SQL_conf, 
    				NULL, OR_ALL,
                    "specify the SQL query to call when looking up permissions"),
    {NULL}
};

static resource_permissions_t *create_resource_permission(apr_pool_t *p)
{
	resource_permissions_t *resPerms;
	resPerms = (resource_permissions_t *) apr_palloc(p, sizeof(resource_permissions_t));

	resPerms->owner = (char *) apr_palloc(p, sizeof(15));
	resPerms->group = (char *) apr_palloc(p, sizeof(15));

	resPerms->ownerPerms = apr_table_make(p, 15);
	resPerms->groupPerms = apr_table_make(p, 15);
	resPerms->worldPerms = apr_table_make(p, 15);
	return resPerms;
}

module AP_MODULE_DECLARE_DATA authz_resource_permissions_dbd_module;

static apr_status_t *get_permissions_by_uri(request_rec *r, resource_permissions_t ** out)
{
    authz_resource_permissions_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_resource_permissions_dbd_module);
    ap_configfile_t *f;
    apr_pool_t *sp;
    
    char l[MAX_STRING_LEN];
    const char *setting_name, *ll, *w;
    apr_status_t status;
    apr_size_t setting_len;

	ap_dbd_t *dbd;
	const char *prepsql = NULL;
	const char *prepsqlupdate = NULL;
	int rows = 0;
    int cols = 0;
    int n = 0;
    int re = 0;
	apr_dbd_results_t *res = NULL;
	apr_dbd_row_t *row = NULL;
	apr_dbd_prepared_t *prepstmt = NULL;
	apr_dbd_prepared_t *prepstmtupdate = NULL;

	resource_permissions_t *resPerms = create_resource_permission(r->pool);
	char *ownerPerms = NULL;
	char *groupPerms = NULL;
	char *worldPerms = NULL;

	/* if theres no request filename, error! */
	if (!r->uri) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Missing request uri");
        return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Uri: %s", r->uri);
	
	
	// Acquire dtabase connection
    if ((dbd = dbd_acquire_fn(r)) == NULL) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Could not aquire connection");
		return OK;
    }

	// Prepare Query
	// The following query must be specified via the directive:
	// AuthzResourcePermissionsSQL <string>
	//prepsql = "SELECT owner, `group`, ownerPermissions, groupPermissions, worldPermissions FROM resources WHERE uri = %s;";
	prepsql = conf->permissionsLookupSQL;
	
	re = apr_dbd_prepare(dbd->driver, r->pool, dbd->handle, 
			prepsql, NULL, &prepstmt);
	if (re) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Could not prepare query");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// Execute query
	if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle,
			&res, prepstmt, 0, 
			r->uri, NULL)!= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Unable to execute query");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
    rows = apr_dbd_num_tuples(dbd->driver, res);
	if (!rows) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Query resulted in zero results");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// Get one (and only one) row
	apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
	if (!row) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "No rows to pull");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Owner: %s", apr_dbd_get_entry(dbd->driver, row, 0));
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Group: %s", apr_dbd_get_entry(dbd->driver, row, 1));
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "ownerPerms: %s", apr_dbd_get_entry(dbd->driver, row, 2));
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "groupPerms: %s", apr_dbd_get_entry(dbd->driver, row, 3));
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "worldPerms: %s", apr_dbd_get_entry(dbd->driver, row, 4));
    
	resPerms->owner = apr_dbd_get_entry(dbd->driver, row, 0);
	if (resPerms->owner == NULL) resPerms->owner = "";
	resPerms->group = apr_dbd_get_entry(dbd->driver, row, 1);
	if (resPerms->group == NULL) resPerms->group = "";
	
	// Must process string by splitting into tokens 

	ownerPerms = apr_pstrdup(r->pool, apr_dbd_get_entry(dbd->driver, row, 2));
	if (ownerPerms != NULL) {

		apr_pool_t *sp;
		const char *w;
		apr_pool_create(&sp, r->pool);
		while(*(w = ap_getword_conf(sp, &ownerPerms)) != '\0') {
			apr_table_setn(resPerms->ownerPerms, apr_pstrdup(r->pool, w), "in");
		}
		apr_pool_destroy(sp);

	} else {
		apr_table_setn(resPerms->ownerPerms, "", "in");
	}
	
	groupPerms = apr_pstrdup(r->pool, apr_dbd_get_entry(dbd->driver, row, 3));
	if (groupPerms != NULL) {

		apr_pool_t *sp;
		const char *w;
		apr_pool_create(&sp, r->pool);
		while(*(w = ap_getword_conf(sp, &groupPerms)) != '\0') {
			apr_table_setn(resPerms->groupPerms, apr_pstrdup(r->pool, w), "in");
		}
		apr_pool_destroy(sp);

	} else {
		apr_table_setn(resPerms->groupPerms, "", "in");
	}
	
	worldPerms = apr_pstrdup(r->pool, apr_dbd_get_entry(dbd->driver, row, 4));
	if (worldPerms != NULL) {

		apr_pool_t *sp;
		const char *w;
		apr_pool_create(&sp, r->pool);
		while(*(w = ap_getword_conf(sp, &worldPerms)) != '\0') {
			apr_table_setn(resPerms->worldPerms, apr_pstrdup(r->pool, w), "in");
		}
		apr_pool_destroy(sp);

	} else {
		apr_table_setn(resPerms->worldPerms, "", "in");
	}

    *out = resPerms;
    return APR_SUCCESS;
}

static const authz_resource_permissions_provider authz_resource_permissions_bob_provider =
{
    &get_permissions_by_uri,
};

static void provider_test_bob_register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHZ_RESOURCE_PERMISSIONS_PROVIDER_GROUP, "dbd-test", "0",
                         &authz_resource_permissions_bob_provider);
}

static void *config_server(apr_pool_t *p, server_rec *s)
{   
    if (!dbd_acquire_fn) {
       // dbd_prepare_fn = 
       //             APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        dbd_acquire_fn = 
                    APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA authz_resource_permissions_dbd_module = {
    STANDARD20_MODULE_STUFF, 
    create_authz_resource_permissions_dir_config,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    config_server,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    provider_dbd_cmds,             /* table of config file commands       */
    provider_test_bob_register_hooks  /* register hooks                      */
};
