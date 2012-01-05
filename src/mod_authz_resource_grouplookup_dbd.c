#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_dbd.h"
#include "mod_dbd.h"

#include <mod_authz_resource_grouplookup.h>

static APR_OPTIONAL_FN_TYPE(ap_dbd_acquire) *dbd_acquire_fn = NULL;

typedef struct {
    char *groupfile;
    char *groupLookupSQL;
    int authoritative;
} authz_resource_groupdbd_config_rec;

static void *create_authz_resource_groupdbd_dir_config(apr_pool_t *p, char *d)
{
    authz_resource_groupdbd_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->groupfile = NULL;
    conf->groupLookupSQL = NULL;
    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const char *permissions_SQL_conf(cmd_parms *cmd, void *config,
                                      	const char *arg)
{
	((authz_resource_groupdbd_config_rec*)config)->groupLookupSQL = arg;

	return NULL;
}

static const command_rec authz_groupdbd_cmds[] =
{
    AP_INIT_TAKE1("AuthzResourceGroupSQL", permissions_SQL_conf, 
    				NULL, OR_ALL,
                    "specify the SQL query to call when looking up a users groups"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_resource_grouplookup_dbd_module;

static apr_status_t *get_groups_by_username(request_rec *r, apr_table_t ** out)
{
    authz_resource_groupdbd_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_resource_grouplookup_dbd_module);
    apr_table_t *grps = apr_table_make(r->pool, 15); // This needs to be set in a constant in the header file
    apr_status_t status;

	char *group_name = NULL;
    apr_size_t group_len;

	ap_dbd_t *dbd;
	const char *prepsql = NULL;
	int rows = 0;
    int cols = 0;
    int n = 0;
    int re = 0;
	apr_dbd_results_t *res = NULL;
	apr_dbd_row_t *row = NULL;
	apr_dbd_prepared_t *prepstmt = NULL;
    apr_status_t rv;

    /* If there is no group file - then we are not
     * configured. So decline.
     */
    if (!(conf->groupLookupSQL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					  "AuthzResourceGroupSQL directive not configured");    
        return DECLINED;
    }

    /* If there's no user, it's a misconfiguration */
    if (!r->user) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "NO USER; GAH!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

	// Acquire dtabase connection
    if ((dbd = dbd_acquire_fn(r)) == NULL) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Could not aquire connection");
		return OK;
    }
        
	// Prepare Query
	// The following query must be specified via the directive:
	// AuthzResourceGroupSQL <string>
	prepsql = conf->groupLookupSQL;
	
	re = apr_dbd_prepare(dbd->driver, r->pool, dbd->handle, 
			prepsql, NULL, &prepstmt);
	if (re) {
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Could not prepare query");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// Execute query
	if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle,
			&res, prepstmt, 0, 
			r->user, NULL)!= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Unable to execute query");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

    rows = apr_dbd_num_tuples(dbd->driver, res);
	if (!rows) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Query resulted in zero results");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
    
	// Now we need to construct a table and populate it with out group names    
	for(rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
		rv != -1;
		rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {

		if (rv != 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "No rows to pull");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		group_name = apr_pstrdup(r->pool, apr_dbd_get_entry(dbd->driver, row, 0));
		group_len = strlen(group_name);
        apr_table_setn(grps, apr_pstrmemdup(r->pool, group_name, group_len), "in");
    	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r, "Group Name: %s", group_name);
    }
    
    *out = grps;
    return APR_SUCCESS;
}

static const authz_resource_grouplookup_provider authz_resource_grouplookup_bob_provider =
{
    &get_groups_by_username,
};

static void provider_test_bob_register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHZ_RESOURCE_GROUPLOOKUP_PROVIDER_GROUP, "dbd", "0",
                         &authz_resource_grouplookup_bob_provider);
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
module AP_MODULE_DECLARE_DATA authz_resource_grouplookup_dbd_module = {
    STANDARD20_MODULE_STUFF, 
    create_authz_resource_groupdbd_dir_config,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    config_server,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    authz_groupdbd_cmds,             /* table of config file commands       */
    provider_test_bob_register_hooks  /* register hooks                      */
};
