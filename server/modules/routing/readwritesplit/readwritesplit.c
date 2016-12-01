/*
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl.
 *
 * Change Date: 2019-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
#include <my_config.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <router.h>
#include <readwritesplit.h>

#include <mysql.h>
#include <skygw_utils.h>
#include <log_manager.h>
#include <query_classifier.h>
#include <dcb.h>
#include <spinlock.h>
#include <modinfo.h>
#include <modutil.h>
#include <mysql_client_server_protocol.h>
#include <mysqld_error.h>

MODULE_INFO info =
{
    MODULE_API_ROUTER, MODULE_GA, ROUTER_VERSION,
    "A Read/Write splitting router for enhancement read scalability"
};

#if defined(SS_DEBUG)
#include <mysql_client_server_protocol.h>
#endif

#define RWSPLIT_TRACE_MSG_LEN 1000

/**
 * @file readwritesplit.c   The entry points for the read/write query splitting
 * router module.
 *
 * This file contains the entry points that comprise the API to the read write
 * query splitting router.
 * @verbatim
 * Revision History
 *
 * Date          Who                 Description
 * 01/07/2013    Vilho Raatikka      Initial implementation
 * 15/07/2013    Massimiliano Pinto  Added clientReply from master only in case
 *                                   of session change
 * 17/07/2013    Massimiliano Pinto  clientReply is now used by mysql_backend
 *                                   for all reply situations
 * 18/07/2013    Massimiliano Pinto  routeQuery now handles COM_QUIT
 *                                   as QUERY_TYPE_SESSION_WRITE
 * 17/07/2014    Massimiliano Pinto  Server connection counter is updated in
 * closeSession
 * 09/09/2015    Martin Brampton     Modify error handler
 * 25/09/2015    Martin Brampton     Block callback processing when no router
 * session in the DCB
 *
 * @endverbatim
 */

#define RW_CHK_DCB(bref, dcb) \
do{ \
    if(dcb->state == DCB_STATE_DISCONNECTED){ \
        MXS_NOTICE("DCB was closed on line %d and another attempt to close it is  made on line %d." , \
            (bref) ? (bref)->closed_at : -1, __LINE__); \
        } \
}while (false)

#define RW_CLOSE_BREF(b) do{ if (bref){ bref->closed_at = __LINE__; } } while (false)

static char *version_str = "V1.1.0";

static ROUTER *createInstance(SERVICE *service, char **options);
static void *newSession(ROUTER *instance, SESSION *session);
static void closeSession(ROUTER *instance, void *session);
static void freeSession(ROUTER *instance, void *session);
static int routeQuery(ROUTER *instance, void *session, GWBUF *queue);
static void diagnostic(ROUTER *instance, DCB *dcb);

static void clientReply(ROUTER *instance, void *router_session, GWBUF *queue,
                        DCB *backend_dcb);

static void handleError(ROUTER *instance, void *router_session,
                        GWBUF *errmsgbuf, DCB *backend_dcb,
                        error_action_t action, bool *succp);

static void print_error_packet(ROUTER_CLIENT_SES *rses, GWBUF *buf, DCB *dcb);
static int router_get_servercount(ROUTER_INSTANCE *router);
static int rses_get_max_slavecount(ROUTER_CLIENT_SES *rses,
                                   int router_nservers);
static int rses_get_max_replication_lag(ROUTER_CLIENT_SES *rses);
static backend_ref_t *get_bref_from_dcb(ROUTER_CLIENT_SES *rses, DCB *dcb);
static DCB *rses_get_client_dcb(ROUTER_CLIENT_SES *rses);

static backend_ref_t *check_candidate_bref(backend_ref_t *candidate_bref,
                                           backend_ref_t *new_bref,
                                           select_criteria_t sc);

static bool is_read_tmp_table(ROUTER_CLIENT_SES *router_cli_ses,
                                         GWBUF *querybuf, qc_query_type_t type);

static void check_create_tmp_table(ROUTER_CLIENT_SES *router_cli_ses,
                                   GWBUF *querybuf, qc_query_type_t type);

static bool route_single_stmt(ROUTER_INSTANCE *inst, ROUTER_CLIENT_SES *rses,
                              GWBUF *querybuf);

static int getCapabilities();

#if defined(NOT_USED)
static bool router_option_configured(ROUTER_INSTANCE *router,
                                     const char *optionstr, void *data);
#endif

#if defined(PREP_STMT_CACHING)
static prep_stmt_t *prep_stmt_init(prep_stmt_type_t type, void *id);
static void prep_stmt_done(prep_stmt_t *pstmt);
#endif /*< PREP_STMT_CACHING */

int bref_cmp_global_conn(const void *bref1, const void *bref2);

int bref_cmp_router_conn(const void *bref1, const void *bref2);

int bref_cmp_behind_master(const void *bref1, const void *bref2);

int bref_cmp_current_load(const void *bref1, const void *bref2);

/**
 * The order of functions _must_ match with the order the select criteria are
 * listed in select_criteria_t definition in readwritesplit.h
 */
int (*criteria_cmpfun[LAST_CRITERIA])(const void *, const void *) =
{
    NULL,
    bref_cmp_global_conn,
    bref_cmp_router_conn,
    bref_cmp_behind_master,
    bref_cmp_current_load
};

static bool select_connect_backend_servers(backend_ref_t **p_master_ref,
                                           backend_ref_t *backend_ref,
                                           int router_nservers, int max_nslaves,
                                           int max_rlag,
                                           select_criteria_t select_criteria,
                                           SESSION *session,
                                           ROUTER_INSTANCE *router,
                                           bool new_session);

static bool get_dcb(DCB **dcb, ROUTER_CLIENT_SES *rses, backend_type_t btype,
                    char *name, int max_rlag);

static bool rwsplit_process_router_options(ROUTER_INSTANCE *router,
                                           char **options);



static ROUTER_OBJECT MyObject =
{
    createInstance,
    newSession,
    closeSession,
    freeSession,
    routeQuery,
    diagnostic,
    clientReply,
    handleError,
    getCapabilities
};

static bool rses_begin_locked_router_action(ROUTER_CLIENT_SES *rses);

static void rses_end_locked_router_action(ROUTER_CLIENT_SES *rses);

static void mysql_sescmd_done(mysql_sescmd_t *sescmd);

static mysql_sescmd_t *mysql_sescmd_init(rses_property_t *rses_prop,
                                         GWBUF *sescmd_buf,
                                         unsigned char packet_type,
                                         ROUTER_CLIENT_SES *rses);

static rses_property_t *mysql_sescmd_get_property(mysql_sescmd_t *scmd);

static rses_property_t *rses_property_init(rses_property_type_t prop_type);

static int rses_property_add(ROUTER_CLIENT_SES *rses, rses_property_t *prop);

static void rses_property_done(rses_property_t *prop);

static mysql_sescmd_t *rses_property_get_sescmd(rses_property_t *prop);

static bool execute_sescmd_history(backend_ref_t *bref);

static bool execute_sescmd_in_backend(backend_ref_t *backend_ref);

static void sescmd_cursor_reset(sescmd_cursor_t *scur);

static bool sescmd_cursor_history_empty(sescmd_cursor_t *scur);

static void sescmd_cursor_set_active(sescmd_cursor_t *sescmd_cursor,
                                     bool value);

static bool sescmd_cursor_is_active(sescmd_cursor_t *sescmd_cursor);

static GWBUF *sescmd_cursor_clone_querybuf(sescmd_cursor_t *scur);

static mysql_sescmd_t *sescmd_cursor_get_command(sescmd_cursor_t *scur);

static bool sescmd_cursor_next(sescmd_cursor_t *scur);

static GWBUF *sescmd_cursor_process_replies(GWBUF *replybuf,
                                            backend_ref_t *bref, bool *);

static void tracelog_routed_query(ROUTER_CLIENT_SES *rses, char *funcname,
                                  backend_ref_t *bref, GWBUF *buf);

static bool route_session_write(ROUTER_CLIENT_SES *router_client_ses,
                                GWBUF *querybuf, ROUTER_INSTANCE *inst,
                                unsigned char packet_type,
                                qc_query_type_t qtype);

static void refreshInstance(ROUTER_INSTANCE *router, CONFIG_PARAMETER *param);

static void bref_clear_state(backend_ref_t *bref, bref_state_t state);
static void bref_set_state(backend_ref_t *bref, bref_state_t state);
static sescmd_cursor_t *backend_ref_get_sescmd_cursor(backend_ref_t *bref);

static int router_handle_state_switch(DCB *dcb, DCB_REASON reason, void *data);
static bool handle_error_new_connection(ROUTER_INSTANCE *inst,
                                        ROUTER_CLIENT_SES **rses,
                                        DCB *backend_dcb, GWBUF *errmsg);
static void handle_error_reply_client(SESSION *ses, ROUTER_CLIENT_SES *rses,
                                      DCB *backend_dcb, GWBUF *errmsg);

static backend_ref_t *get_root_master_bref(ROUTER_CLIENT_SES *rses);

static BACKEND *get_root_master(backend_ref_t *servers, int router_nservers);

static bool have_enough_servers(ROUTER_CLIENT_SES **rses, const int nsrv,
                                int router_nsrv, ROUTER_INSTANCE *router);

static SPINLOCK instlock;
static ROUTER_INSTANCE *instances;

static int hashkeyfun(void *key);
static int hashcmpfun(void *, void *);
static bool check_for_multi_stmt(ROUTER_CLIENT_SES *rses, GWBUF *buf,
                                 mysql_server_cmd_t packet_type);
static bool send_readonly_error(DCB *dcb);

static int hashkeyfun(void *key)
{
    if (key == NULL)
    {
        return 0;
    }

    unsigned int hash = 0, c = 0;
    char *ptr = (char *)key;

    while ((c = *ptr++))
    {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

static int hashcmpfun(void *v1, void *v2)
{
    char *i1 = (char *)v1;
    char *i2 = (char *)v2;

    return strcmp(i1, i2);
}

static void *hstrdup(void *fval)
{
    char *str = (char *)fval;
    return strdup(str);
}

static void *hfree(void *fval)
{
    free(fval);
    return NULL;
}

/**
 * Implementation of the mandatory version entry point
 *
 * @return version string of the module
 */
char *version()
{
    return version_str;
}

/**
 * The module initialisation routine, called when the module
 * is first loaded.
 */
void ModuleInit()
{
    MXS_NOTICE("Initializing statemend-based read/write split router module.");
    spinlock_init(&instlock);
    instances = NULL;
}

/**
 * The module entry point routine. It is this routine that
 * must populate the structure that is referred to as the
 * "module object", this is a structure with the set of
 * external entry points for this module.
 *
 * @return The module object
 */
ROUTER_OBJECT *GetModuleObject()
{
    return &MyObject;
}

/**
 * Refresh the instance by the given parameter value.
 *
 * @param router    Router instance
 * @param singleparam   Parameter fo be reloaded
 *
 * Note: this part is not done. Needs refactoring.
 */
static void refreshInstance(ROUTER_INSTANCE *router,
                            CONFIG_PARAMETER *singleparam)
{
    CONFIG_PARAMETER *param;
    bool refresh_single;
    config_param_type_t paramtype;

    if (singleparam != NULL)
    {
        param = singleparam;
        refresh_single = true;
    }
    else
    {
        param = router->service->svc_config_param;
        refresh_single = false;
    }
    paramtype = config_get_paramtype(param);

    while (param != NULL)
    {
        /** Catch unused parameter types */
        ss_dassert(paramtype == COUNT_TYPE || paramtype == PERCENT_TYPE ||
                   paramtype == SQLVAR_TARGET_TYPE);

        if (paramtype == COUNT_TYPE)
        {
            if (strncmp(param->name, "max_slave_connections", MAX_PARAM_LEN) == 0)
            {
                int val;
                bool succp;

                router->rwsplit_config.rw_max_slave_conn_percent = 0;

                succp = config_get_valint(&val, param, NULL, paramtype);

                if (succp)
                {
                    router->rwsplit_config.rw_max_slave_conn_count = val;
                }
            }
            else if (strncmp(param->name, "max_slave_replication_lag",
                             MAX_PARAM_LEN) == 0)
            {
                int val;
                bool succp;

                succp = config_get_valint(&val, param, NULL, paramtype);

                if (succp)
                {
                    router->rwsplit_config.rw_max_slave_replication_lag = val;
                }
            }
        }
        else if (paramtype == PERCENT_TYPE)
        {
            if (strncmp(param->name, "max_slave_connections", MAX_PARAM_LEN) == 0)
            {
                int val;
                bool succp;

                router->rwsplit_config.rw_max_slave_conn_count = 0;

                succp = config_get_valint(&val, param, NULL, paramtype);

                if (succp)
                {
                    router->rwsplit_config.rw_max_slave_conn_percent = val;
                }
            }
        }
        else if (paramtype == SQLVAR_TARGET_TYPE)
        {
            if (strncmp(param->name, "use_sql_variables_in", MAX_PARAM_LEN) == 0)
            {
                target_t valtarget;
                bool succp;

                succp = config_get_valtarget(&valtarget, param, NULL, paramtype);

                if (succp)
                {
                    router->rwsplit_config.rw_use_sql_variables_in = valtarget;
                }
            }
        }

        if (refresh_single)
        {
            break;
        }
        param = param->next;
    }

#if defined(NOT_USED) /*< can't read monitor config parameters */
    if ((*router->servers)->backend_server->rlag == -2)
    {
        rlag_enabled = false;
    }
    else
    {
        rlag_enabled = true;
    }
    /**
     * If replication lag detection is not enabled the measure can't be
     * used in slave selection.
     */
    if (!rlag_enabled)
    {
        if (rlag_limited)
        {
            MXS_WARNING("Configuration Failed, max_slave_replication_lag "
                        "is set to %d,\n\t\t      but detect_replication_lag "
                        "is not enabled. Replication lag will not be checked.",
                        router->rwsplit_config.rw_max_slave_replication_lag);
        }

        if (router->rwsplit_config.rw_slave_select_criteria ==
            LEAST_BEHIND_MASTER)
        {
            MXS_WARNING("Configuration Failed, router option "
                        "\n\t\t      slave_selection_criteria=LEAST_BEHIND_MASTER "
                        "is specified, but detect_replication_lag "
                        "is not enabled.\n\t\t      "
                        "slave_selection_criteria=%s will be used instead.",
                        STRCRITERIA(DEFAULT_CRITERIA));

            router->rwsplit_config.rw_slave_select_criteria = DEFAULT_CRITERIA;
        }
    }
#endif /*< NOT_USED */
}

static inline void free_rwsplit_instance(ROUTER_INSTANCE *router)
{
    if (router)
    {
        if (router->servers)
        {
            for (int i = 0; router->servers[i]; i++)
            {
                free(router->servers[i]);
            }
        }
        free(router->servers);
        free(router);
    }
}

/**
 * Create an instance of read/write statement router within the MaxScale.
 *
 * @param service   The service this router is being create for
 * @param options   The options for this query router
 * @return NULL in failure, pointer to router in success.
 */
static ROUTER *createInstance(SERVICE *service, char **options)
{
    ROUTER_INSTANCE *router;
    SERVER *server;
    SERVER_REF *sref;
    int nservers;
    int i;
    CONFIG_PARAMETER *param;
    char *weightby;

    if ((router = calloc(1, sizeof(ROUTER_INSTANCE))) == NULL)
    {
        return NULL;
    }
    router->service = service;
    spinlock_init(&router->lock);

    /** Calculate number of servers */
    sref = service->dbref;
    nservers = 0;

    while (sref != NULL)
    {
        nservers++;
        sref = sref->next;
    }
    router->servers = (BACKEND **)calloc(nservers + 1, sizeof(BACKEND *));

    if (router->servers == NULL)
    {
        free_rwsplit_instance(router);
        return NULL;
    }
    /**
     * Create an array of the backend servers in the router structure to
     * maintain a count of the number of connections to each
     * backend server.
     */

    sref = service->dbref;
    nservers = 0;

    while (sref != NULL)
    {
        if ((router->servers[nservers] = malloc(sizeof(BACKEND))) == NULL)
        {
            free_rwsplit_instance(router);
            return NULL;
        }
        router->servers[nservers]->backend_server = sref->server;
        router->servers[nservers]->backend_conn_count = 0;
        router->servers[nservers]->be_valid = false;
        router->servers[nservers]->weight = 1000;
#if defined(SS_DEBUG)
        router->servers[nservers]->be_chk_top = CHK_NUM_BACKEND;
        router->servers[nservers]->be_chk_tail = CHK_NUM_BACKEND;
#endif
        nservers += 1;
        sref = sref->next;
    }
    router->servers[nservers] = NULL;

    /*
     * Until we know otherwise assume we have some available slaves.
     */
    router->available_slaves = true;

    /*
     * If server weighting has been defined calculate the percentage
     * of load that will be sent to each server. This is only used for
     * calculating the least connections, either globally or within a
     * service, or the number of current operations on a server.
     */
    if ((weightby = serviceGetWeightingParameter(service)) != NULL)
    {
        int total = 0;

        for (int n = 0; router->servers[n]; n++)
        {
            BACKEND *backend = router->servers[n];
            char *param = serverGetParameter(backend->backend_server, weightby);
            if (param)
            {
                total += atoi(param);
            }
        }
        if (total == 0)
        {
            MXS_WARNING("Weighting Parameter for service '%s' "
                        "will be ignored as no servers have values "
                        "for the parameter '%s'.",
                        service->name, weightby);
        }
        else if (total < 0)
        {
            MXS_ERROR("Sum of weighting parameter '%s' for service '%s' exceeds "
                      "maximum value of %d. Weighting will be ignored.",
                      weightby, service->name, INT_MAX);
        }
        else
        {
            for (int n = 0; router->servers[n]; n++)
            {
                BACKEND *backend = router->servers[n];
                char *param = serverGetParameter(backend->backend_server, weightby);
                if (param)
                {
                    int wght = atoi(param);
                    int perc = (wght * 1000) / total;

                    if (perc == 0)
                    {
                        MXS_ERROR("Weighting parameter '%s' with a value of %d for"
                                  " server '%s' rounds down to zero with total weight"
                                  " of %d for service '%s'. No queries will be "
                                  "routed to this server as long as a server with"
                                  " positive weight is available.",
                                  weightby, wght, backend->backend_server->unique_name,
                                  total, service->name);
                    }
                    else if (perc < 0)
                    {
                        MXS_ERROR("Weighting parameter '%s' for server '%s' is too large, "
                                  "maximum value is %d. No weighting will be used for this "
                                  "server.",
                                  weightby, backend->backend_server->unique_name,
                                  INT_MAX / 1000);
                        perc = 1000;
                    }
                    backend->weight = perc;
                }
                else
                {
                    MXS_WARNING("Server '%s' has no parameter '%s' used for weighting"
                                " for service '%s'.",
                                backend->backend_server->unique_name, weightby,
                                service->name);
                }
            }
        }
    }

    /** Enable strict multistatement handling by default */
    router->rwsplit_config.rw_strict_multi_stmt = true;

    /** By default, the client connection is closed immediately when a master
     * failure is detected */
    router->rwsplit_config.rw_master_failure_mode = RW_FAIL_INSTANTLY;

    /** Call this before refreshInstance */
    if (options && !rwsplit_process_router_options(router, options))
    {
        free_rwsplit_instance(router);
        return NULL;
    }

    /** These options cancel each other out */
    if (router->rwsplit_config.rw_disable_sescmd_hist &&
        router->rwsplit_config.rw_max_sescmd_history_size > 0)
    {
        router->rwsplit_config.rw_max_sescmd_history_size = 0;
    }

    /**
     * Set default value for max_slave_connections as 100%. This way
     * LEAST_CURRENT_OPERATIONS allows us to balance evenly across all the
     * configured slaves.
     */
    router->rwsplit_config.rw_max_slave_conn_count = nservers;

    if (router->rwsplit_config.rw_slave_select_criteria == UNDEFINED_CRITERIA)
    {
        router->rwsplit_config.rw_slave_select_criteria = DEFAULT_CRITERIA;
    }
    /**
     * Copy all config parameters from service to router instance.
     * Finally, copy version number to indicate that configs match.
     */
    param = config_get_param(service->svc_config_param, "max_slave_connections");

    if (param != NULL)
    {
        refreshInstance(router, param);
    }
    /**
     * Read default value for slave replication lag upper limit and then
     * configured value if it exists.
     */
    router->rwsplit_config.rw_max_slave_replication_lag = CONFIG_MAX_SLAVE_RLAG;
    param = config_get_param(service->svc_config_param, "max_slave_replication_lag");

    if (param != NULL)
    {
        refreshInstance(router, param);
    }
    router->rwsplit_version = service->svc_config_version;
    /** Set default values */
    router->rwsplit_config.rw_use_sql_variables_in = CONFIG_SQL_VARIABLES_IN;
    param = config_get_param(service->svc_config_param, "use_sql_variables_in");

    if (param != NULL)
    {
        refreshInstance(router, param);
    }
    /**
     * We have completed the creation of the router data, so now
     * insert this router into the linked list of routers
     * that have been created with this module.
     */
    spinlock_acquire(&instlock);
    router->next = instances;
    instances = router;
    spinlock_release(&instlock);

    return (ROUTER *)router;
}

/**
 * Associate a new session with this instance of the router.
 *
 * The session is used to store all the data required for a particular
 * client connection.
 *
 * @param instance  The router instance data
 * @param session   The session itself
 * @return Session specific data for this session
 */
static void *newSession(ROUTER *router_inst, SESSION *session)
{
    backend_ref_t
    *backend_ref; /*< array of backend references (DCB,BACKEND,cursor) */
    backend_ref_t *master_ref = NULL; /*< pointer to selected master */
    ROUTER_CLIENT_SES *client_rses = NULL;
    ROUTER_INSTANCE *router = (ROUTER_INSTANCE *)router_inst;
    bool succp;
    int router_nservers = 0; /*< # of servers in total */
    int max_nslaves;         /*< max # of slaves used in this session */
    int max_slave_rlag;      /*< max allowed replication lag for any slave */
    int i;
    const int min_nservers = 1; /*< hard-coded for now */

    client_rses = (ROUTER_CLIENT_SES *)calloc(1, sizeof(ROUTER_CLIENT_SES));

    if (client_rses == NULL)
    {
        ss_dassert(false);
        goto return_rses;
    }
#if defined(SS_DEBUG)
    client_rses->rses_chk_top = CHK_NUM_ROUTER_SES;
    client_rses->rses_chk_tail = CHK_NUM_ROUTER_SES;
#endif

    client_rses->router = router;
    client_rses->client_dcb = session->client_dcb;
    /**
     * If service config has been changed, reload config from service to
     * router instance first.
     */
    spinlock_acquire(&router->lock);

    if (router->service->svc_config_version > router->rwsplit_version)
    {
        /** re-read all parameters to rwsplit config structure */
        refreshInstance(router, NULL); /*< scan through all parameters */
        /** increment rwsplit router's config version number */
        router->rwsplit_version = router->service->svc_config_version;
        /** Read options */
        rwsplit_process_router_options(router, router->service->routerOptions);
    }
    /** Copy config struct from router instance */
    memcpy(&client_rses->rses_config, &router->rwsplit_config, sizeof(rwsplit_config_t));

    spinlock_release(&router->lock);
    /**
     * Set defaults to session variables.
     */
    client_rses->rses_autocommit_enabled = true;
    client_rses->rses_transaction_active = false;
    client_rses->have_tmp_tables = false;
    client_rses->forced_node = NULL;

    router_nservers = router_get_servercount(router);

    if (!have_enough_servers(&client_rses, min_nservers, router_nservers, router))
    {
        goto return_rses;
    }
    /**
     * Create backend reference objects for this session.
     */
    backend_ref = (backend_ref_t *)calloc(1, router_nservers * sizeof(backend_ref_t));

    if (backend_ref == NULL)
    {
        /** log this */
        free(client_rses);
        free(backend_ref);
        client_rses = NULL;
        goto return_rses;
    }
    /**
     * Initialize backend references with BACKEND ptr.
     * Initialize session command cursors for each backend reference.
     */
    for (i = 0; i < router_nservers; i++)
    {
#if defined(SS_DEBUG)
        backend_ref[i].bref_chk_top = CHK_NUM_BACKEND_REF;
        backend_ref[i].bref_chk_tail = CHK_NUM_BACKEND_REF;
        backend_ref[i].bref_sescmd_cur.scmd_cur_chk_top = CHK_NUM_SESCMD_CUR;
        backend_ref[i].bref_sescmd_cur.scmd_cur_chk_tail = CHK_NUM_SESCMD_CUR;
#endif
        backend_ref[i].bref_state = 0;
        backend_ref[i].bref_backend = router->servers[i];
        /** store pointers to sescmd list to both cursors */
        backend_ref[i].bref_sescmd_cur.scmd_cur_rses = client_rses;
        backend_ref[i].bref_sescmd_cur.scmd_cur_active = false;
        backend_ref[i].bref_sescmd_cur.scmd_cur_ptr_property =
            &client_rses->rses_properties[RSES_PROP_TYPE_SESCMD];
        backend_ref[i].bref_sescmd_cur.scmd_cur_cmd = NULL;
    }
    max_nslaves = rses_get_max_slavecount(client_rses, router_nservers);
    max_slave_rlag = rses_get_max_replication_lag(client_rses);

    spinlock_init(&client_rses->rses_lock);
    client_rses->rses_backend_ref = backend_ref;

    /**
     * Find a backend servers to connect to.
     * This command requires that rsession's lock is held.
     */

    succp = rses_begin_locked_router_action(client_rses);

    if (!succp)
    {
        free(client_rses->rses_backend_ref);
        free(client_rses);
        client_rses = NULL;
        goto return_rses;
    }
    succp = select_connect_backend_servers(&master_ref, backend_ref, router_nservers,
                                           max_nslaves, max_slave_rlag,
                                           client_rses->rses_config.rw_slave_select_criteria,
                                           session, router, false);

    rses_end_locked_router_action(client_rses);

    /**
     * Master and at least <min_nslaves> slaves must be found if the router is
     * in the strict mode. If sessions without master are allowed, only
     * <min_nslaves> slaves must be found.
     */
    if (!succp)
    {
        free(client_rses->rses_backend_ref);
        free(client_rses);
        client_rses = NULL;
        goto return_rses;
    }

    /** Copy backend pointers to router session. */
    client_rses->rses_master_ref = master_ref;
    client_rses->rses_backend_ref = backend_ref;
    client_rses->rses_nbackends = router_nservers; /*< # of backend servers */

    if (client_rses->rses_config.rw_max_slave_conn_percent)
    {
        int n_conn = 0;
        double pct = (double)client_rses->rses_config.rw_max_slave_conn_percent / 100.0;
        n_conn = MAX(floor((double)client_rses->rses_nbackends * pct), 1);
        client_rses->rses_config.rw_max_slave_conn_count = n_conn;
    }

    router->stats.n_sessions += 1;

    /**
     * Version is bigger than zero once initialized.
     */
    atomic_add(&client_rses->rses_versno, 2);
    ss_dassert(client_rses->rses_versno == 2);
    /**
     * Add this session to end of the list of active sessions in router.
     */
    spinlock_acquire(&router->lock);
    client_rses->next = router->connections;
    router->connections = client_rses;
    spinlock_release(&router->lock);

return_rses:
#if defined(SS_DEBUG)
    if (client_rses != NULL)
    {
        CHK_CLIENT_RSES(client_rses);
    }
#endif
    return (void *)client_rses;
}

/**
 * Close a session with the router, this is the mechanism
 * by which a router may cleanup data structure etc.
 *
 * @param instance  The router instance data
 * @param session   The session being closed
 */
static void closeSession(ROUTER *instance, void *router_session)
{
    ROUTER_CLIENT_SES *router_cli_ses;
    backend_ref_t *backend_ref;

    MXS_DEBUG("%lu [RWSplit:closeSession]", pthread_self());

    /**
     * router session can be NULL if newSession failed and it is discarding
     * its connections and DCB's.
     */
    if (router_session == NULL)
    {
        return;
    }
    router_cli_ses = (ROUTER_CLIENT_SES *)router_session;
    CHK_CLIENT_RSES(router_cli_ses);

    backend_ref = router_cli_ses->rses_backend_ref;
    /**
     * Lock router client session for secure read and update.
     */
    if (!router_cli_ses->rses_closed &&
        rses_begin_locked_router_action(router_cli_ses))
    {
        int i;
        /**
         * This sets router closed. Nobody is allowed to use router
         * without checking this first.
         */
        router_cli_ses->rses_closed = true;

        for (i = 0; i < router_cli_ses->rses_nbackends; i++)
        {
            backend_ref_t *bref = &backend_ref[i];
            DCB *dcb = bref->bref_dcb;
            /** Close those which had been connected */
            if (BREF_IS_IN_USE(bref))
            {
                CHK_DCB(dcb);
#if defined(SS_DEBUG)
                /**
                 * session must be moved to SESSION_STATE_STOPPING state before
                 * router session is closed.
                 */
                if (dcb->session != NULL)
                {
                    ss_dassert(dcb->session->state == SESSION_STATE_STOPPING);
                }
#endif
                /** Clean operation counter in bref and in SERVER */
                if (BREF_IS_WAITING_RESULT(bref))
                {
                    bref_clear_state(bref, BREF_WAITING_RESULT);
                }
                bref_clear_state(bref, BREF_IN_USE);
                bref_set_state(bref, BREF_CLOSED);

                RW_CHK_DCB(bref, dcb);

                /** MXS-956: This will prevent closed DCBs from being closed twice.
                 * It should not happen but for currently unknown reasons, a DCB
                 * gets closed twice; first in handleError and a second time here. */
                if (dcb && dcb->state == DCB_STATE_POLLING)
                {
                    dcb_close(dcb);
                }

                RW_CLOSE_BREF(bref);

                /** decrease server current connection counters */
                atomic_add(&bref->bref_backend->backend_conn_count, -1);
            }
            else
            {
                ss_dassert(!BREF_IS_WAITING_RESULT(bref));

                /** This should never be true unless a backend reference is taken
                 * out of use before clearing the BREF_WAITING_RESULT state */
                if (BREF_IS_WAITING_RESULT(bref))
                {
                    MXS_WARNING("A closed backend was expecting a result, this should not be possible. "
                                "Decrementing active operation counter for this backend.");
                    bref_clear_state(bref, BREF_WAITING_RESULT);
                }
            }
        }
        /** Unlock */
        rses_end_locked_router_action(router_cli_ses);
    }
}

/**
 * When router session is closed, freeSession can be called to free allocated
 * resources.
 *
 * @param router_instance   The router instance the session belongs to
 * @param router_client_session Client session
 *
 */
static void freeSession(ROUTER *router_instance, void *router_client_session)
{
    ROUTER_CLIENT_SES *router_cli_ses;
    ROUTER_INSTANCE *router;
    int i;

    router_cli_ses = (ROUTER_CLIENT_SES *)router_client_session;
    router = (ROUTER_INSTANCE *)router_instance;

    spinlock_acquire(&router->lock);

    if (router->connections == router_cli_ses)
    {
        router->connections = router_cli_ses->next;
    }
    else
    {
        ROUTER_CLIENT_SES *ptr = router->connections;

        while (ptr && ptr->next != router_cli_ses)
        {
            ptr = ptr->next;
        }

        if (ptr)
        {
            ptr->next = router_cli_ses->next;
        }
    }
    spinlock_release(&router->lock);

    /**
     * For each property type, walk through the list, finalize properties
     * and free the allocated memory.
     */
    for (i = RSES_PROP_TYPE_FIRST; i < RSES_PROP_TYPE_COUNT; i++)
    {
        rses_property_t *p = router_cli_ses->rses_properties[i];
        rses_property_t *q = p;

        while (p != NULL)
        {
            q = p->rses_prop_next;
            rses_property_done(p);
            p = q;
        }
    }
    /*
     * We are no longer in the linked list, free
     * all the memory and other resources associated
     * to the client session.
     */
    free(router_cli_ses->rses_backend_ref);
    free(router_cli_ses);
    return;
}

/**
 * @brief Mark a backend reference as failed
 *
 * @param bref Backend reference to close
 * @param fatal Whether the failure was fatal
 */
static void close_failed_bref(backend_ref_t *bref, bool fatal)
{
    if (BREF_IS_WAITING_RESULT(bref))
    {
        bref_clear_state(bref, BREF_WAITING_RESULT);
    }

    bref_clear_state(bref, BREF_QUERY_ACTIVE);
    bref_clear_state(bref, BREF_IN_USE);
    bref_set_state(bref, BREF_CLOSED);

    if (fatal)
    {
        bref_set_state(bref, BREF_FATAL_FAILURE);
    }

    if (sescmd_cursor_is_active(&bref->bref_sescmd_cur))
    {
        sescmd_cursor_set_active(&bref->bref_sescmd_cur, false);
    }

    if (bref->bref_pending_cmd)
    {
        gwbuf_free(bref->bref_pending_cmd);
        bref->bref_pending_cmd = NULL;
    }
}

/**
 * Provide the router with a pointer to a suitable backend dcb.
 *
 * Detect failures in server statuses and reselect backends if necessary.
 * If name is specified, server name becomes primary selection criteria.
 * Similarly, if max replication lag is specified, skip backends which lag too
 * much.
 *
 * @param p_dcb Address of the pointer to the resulting DCB
 * @param rses  Pointer to router client session
 * @param btype Backend type
 * @param name  Name of the backend which is primarily searched. May be NULL.
 *
 * @return True if proper DCB was found, false otherwise.
 */
static bool get_dcb(DCB **p_dcb, ROUTER_CLIENT_SES *rses, backend_type_t btype,
                    char *name, int max_rlag)
{
    backend_ref_t *backend_ref;
    backend_ref_t *master_bref;
    int i;
    bool succp = false;

    CHK_CLIENT_RSES(rses);
    ss_dassert(p_dcb != NULL && *(p_dcb) == NULL);

    if (p_dcb == NULL)
    {
        goto return_succp;
    }
    backend_ref = rses->rses_backend_ref;

    /** get root master from available servers */
    master_bref = get_root_master_bref(rses);

    if (name != NULL) /*< Choose backend by name from a hint */
    {
        ss_dassert(btype != BE_MASTER); /*< Master dominates and no name should be passed with it */

        for (i = 0; i < rses->rses_nbackends; i++)
        {
            BACKEND *b = backend_ref[i].bref_backend;
            SERVER server;
            server.status = backend_ref[i].bref_backend->backend_server->status;
            /**
             * To become chosen:
             * backend must be in use, name must match,
             * backend's role must be either slave, relay
             * server, or master.
             */
            if (BREF_IS_IN_USE((&backend_ref[i])) &&
                (strncasecmp(name, b->backend_server->unique_name, PATH_MAX) == 0) &&
                (SERVER_IS_SLAVE(&server) || SERVER_IS_RELAY_SERVER(&server) ||
                 SERVER_IS_MASTER(&server)))
            {
                *p_dcb = backend_ref[i].bref_dcb;
                succp = true;
                ss_dassert(backend_ref[i].bref_dcb->state != DCB_STATE_ZOMBIE ||
                           backend_ref[i].bref_dcb->state != DCB_STATE_DISCONNECTED);
                break;
            }
        }
        if (succp)
        {
            goto return_succp;
        }
        else
        {
            btype = BE_SLAVE;
        }
    }

    if (btype == BE_SLAVE)
    {
        backend_ref_t *candidate_bref = NULL;

        for (i = 0; i < rses->rses_nbackends; i++)
        {
            BACKEND *b = (&backend_ref[i])->bref_backend;
            SERVER server;
            SERVER candidate;
            server.status = backend_ref[i].bref_backend->backend_server->status;
            /**
             * Unused backend or backend which is not master nor
             * slave can't be used
             */
            if (!BREF_IS_IN_USE(&backend_ref[i]) ||
                (!SERVER_IS_MASTER(&server) && !SERVER_IS_SLAVE(&server)))
            {
                continue;
            }
            /**
             * If there are no candidates yet accept both master or
             * slave.
             */
            else if (candidate_bref == NULL)
            {
                /**
                 * Ensure that master has not changed dunring
                 * session and abort if it has.
                 */
                if (SERVER_IS_MASTER(&server) && &backend_ref[i] == master_bref)
                {
                    /** found master */
                    candidate_bref = &backend_ref[i];
                    candidate.status = candidate_bref->bref_backend->backend_server->status;
                    succp = true;
                }
                /**
                 * Ensure that max replication lag is not set
                 * or that candidate's lag doesn't exceed the
                 * maximum allowed replication lag.
                 */
                else if (max_rlag == MAX_RLAG_UNDEFINED ||
                         (b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
                          b->backend_server->rlag <= max_rlag))
                {
                    /** found slave */
                    candidate_bref = &backend_ref[i];
                    candidate.status = candidate_bref->bref_backend->backend_server->status;
                    succp = true;
                }
            }
            /**
             * If candidate is master, any slave which doesn't break
             * replication lag limits replaces it.
             */
            else if (SERVER_IS_MASTER(&candidate) && SERVER_IS_SLAVE(&server) &&
                     (max_rlag == MAX_RLAG_UNDEFINED ||
                      (b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
                       b->backend_server->rlag <= max_rlag)) &&
                     !rses->rses_config.rw_master_reads)
            {
                /** found slave */
                candidate_bref = &backend_ref[i];
                candidate.status = candidate_bref->bref_backend->backend_server->status;
                succp = true;
            }
            /**
             * When candidate exists, compare it against the current
             * backend and update assign it to new candidate if
             * necessary.
             */
            else if (SERVER_IS_SLAVE(&server))
            {
                if (max_rlag == MAX_RLAG_UNDEFINED ||
                    (b->backend_server->rlag != MAX_RLAG_NOT_AVAILABLE &&
                     b->backend_server->rlag <= max_rlag))
                {
                    candidate_bref =
                        check_candidate_bref(candidate_bref, &backend_ref[i],
                                             rses->rses_config.rw_slave_select_criteria);
                    candidate.status =
                        candidate_bref->bref_backend->backend_server->status;
                }
                else
                {
                    MXS_INFO("Server %s:%d is too much behind the "
                             "master, %d s. and can't be chosen.",
                             b->backend_server->name, b->backend_server->port,
                             b->backend_server->rlag);
                }
            }
        } /*<  for */
        /** Assign selected DCB's pointer value */
        if (candidate_bref != NULL)
        {
            *p_dcb = candidate_bref->bref_dcb;
        }

        goto return_succp;
    } /*< if (btype == BE_SLAVE) */
    /**
     * If target was originally master only then the execution jumps
     * directly here.
     */
    if (btype == BE_MASTER)
    {
        if (master_bref)
        {
            /** It is possible for the server status to change at any point in time
             * so copying it locally will make possible error messages
             * easier to understand */
            SERVER server;
            server.status = master_bref->bref_backend->backend_server->status;
            if (BREF_IS_IN_USE(master_bref) && SERVER_IS_MASTER(&server))
            {
                *p_dcb = master_bref->bref_dcb;
                succp = true;
                /** if bref is in use DCB should not be closed */
                ss_dassert(master_bref->bref_dcb->state != DCB_STATE_ZOMBIE ||
                           master_bref->bref_dcb->state != DCB_STATE_DISCONNECTED);
            }
            else
            {
                MXS_ERROR("Server at %s:%d should be master but "
                          "is %s instead and can't be chosen to master.",
                          master_bref->bref_backend->backend_server->name,
                          master_bref->bref_backend->backend_server->port,
                          STRSRVSTATUS(&server));
                succp = false;
            }
        }
    }

return_succp:
    return succp;
}

/**
 * Find out which of the two backend servers has smaller value for select
 * criteria property.
 *
 * @param cand  previously selected candidate
 * @param new   challenger
 * @param sc    select criteria
 *
 * @return pointer to backend reference of that backend server which has smaller
 * value in selection criteria. If either reference pointer is NULL then the
 * other reference pointer value is returned.
 */
static backend_ref_t *check_candidate_bref(backend_ref_t *cand,
                                           backend_ref_t *new,
                                           select_criteria_t sc)
{
    int (*p)(const void *, const void *);
    /** get compare function */
    p = criteria_cmpfun[sc];

    if (new == NULL)
    {
        return cand;
    }
    else if (cand == NULL || (p((void *)cand, (void *)new) > 0))
    {
        return new;
    }
    else
    {
        return cand;
    }
}

/**
 * Examine the query type, transaction state and routing hints. Find out the
 * target for query routing.
 *
 *  @param qtype      Type of query
 *  @param trx_active Is transacation active or not
 *  @param hint       Pointer to list of hints attached to the query buffer
 *
 *  @return bitfield including the routing target, or the target server name
 *          if the query would otherwise be routed to slave.
 */
static route_target_t get_route_target(ROUTER_CLIENT_SES *rses,
                                       qc_query_type_t qtype, HINT *hint)
{
    bool trx_active = rses->rses_transaction_active;
    bool load_active = rses->rses_load_active;
    target_t use_sql_variables_in = rses->rses_config.rw_use_sql_variables_in;
    route_target_t target = TARGET_UNDEFINED;

    if (rses->rses_config.rw_strict_multi_stmt && rses->forced_node &&
        rses->forced_node == rses->rses_master_ref)
    {
        target = TARGET_MASTER;
    }
    /**
     * These queries are not affected by hints
     */
    else if (!load_active &&
             (QUERY_IS_TYPE(qtype, QUERY_TYPE_SESSION_WRITE) ||
              /** Configured to allow writing user variables to all nodes */
              (use_sql_variables_in == TYPE_ALL &&
               QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_WRITE)) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_WRITE) ||
              /** enable or disable autocommit are always routed to all */
              QUERY_IS_TYPE(qtype, QUERY_TYPE_ENABLE_AUTOCOMMIT) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_DISABLE_AUTOCOMMIT)))
    {
        /**
         * This is problematic query because it would be routed to all
         * backends but since this is SELECT that is not possible:
         * 1. response set is not handled correctly in clientReply and
         * 2. multiple results can degrade performance.
         *
         * Prepared statements are an exception to this since they do not
         * actually do anything but only prepare the statement to be used.
         * They can be safely routed to all backends since the execution
         * is done later.
         *
         * With prepared statement caching the task of routing
         * the execution of the prepared statements to the right server would be
         * an easy one. Currently this is not supported.
         */
        if (QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) &&
            !(QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_STMT) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_NAMED_STMT)))
        {
            MXS_WARNING("The query can't be routed to all "
                        "backend servers because it includes SELECT and "
                        "SQL variable modifications which is not supported. "
                        "Set use_sql_variables_in=master or split the "
                        "query to two, where SQL variable modifications "
                        "are done in the first and the SELECT in the "
                        "second one.");

            target = TARGET_MASTER;
        }
        target |= TARGET_ALL;
    }
    /**
     * Hints may affect on routing of the following queries
     */
    else if (!trx_active && !load_active &&
             !QUERY_IS_TYPE(qtype, QUERY_TYPE_MASTER_READ) &&
             !QUERY_IS_TYPE(qtype, QUERY_TYPE_WRITE) &&
             !QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_STMT) &&
             !QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_NAMED_STMT) &&
             (QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_SHOW_TABLES) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) ||
              QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ)))
    {
        if (QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ))
        {
            if (use_sql_variables_in == TYPE_ALL)
            {
                target = TARGET_SLAVE;
            }
        }
        else if (QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) || // Normal read
            QUERY_IS_TYPE(qtype, QUERY_TYPE_SHOW_TABLES) || // SHOW TABLES
            QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) || // System variable
            QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ)) // Global system variable
        {
            target = TARGET_SLAVE;
        }

        /** If nothing matches then choose the master */
        if ((target & (TARGET_ALL | TARGET_SLAVE | TARGET_MASTER)) == 0)
        {
            target = TARGET_MASTER;
        }
    }
    else
    {
        ss_dassert(trx_active || load_active ||
                   (QUERY_IS_TYPE(qtype, QUERY_TYPE_WRITE) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_MASTER_READ) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_SESSION_WRITE) ||
                    (QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ) &&
                     use_sql_variables_in == TYPE_MASTER) ||
                    (QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) &&
                     use_sql_variables_in == TYPE_MASTER) ||
                    (QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ) &&
                     use_sql_variables_in == TYPE_MASTER) ||
                    (QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_WRITE) &&
                     use_sql_variables_in == TYPE_MASTER) ||
                    (QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_WRITE) &&
                     use_sql_variables_in == TYPE_MASTER) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_BEGIN_TRX) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_ENABLE_AUTOCOMMIT) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_DISABLE_AUTOCOMMIT) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_ROLLBACK) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_COMMIT) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_EXEC_STMT) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_CREATE_TMP_TABLE) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_READ_TMP_TABLE) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_UNKNOWN)) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_EXEC_STMT) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_STMT) ||
                    QUERY_IS_TYPE(qtype, QUERY_TYPE_PREPARE_NAMED_STMT));
        target = TARGET_MASTER;
    }

    /** process routing hints */
    while (hint != NULL)
    {
        if (hint->type == HINT_ROUTE_TO_MASTER)
        {
            target = TARGET_MASTER; /*< override */
            MXS_DEBUG("%lu [get_route_target] Hint: route to master.",
                      pthread_self());
            break;
        }
        else if (hint->type == HINT_ROUTE_TO_NAMED_SERVER)
        {
            /**
             * Searching for a named server. If it can't be
             * found, the oroginal target is chosen.
             */
            target |= TARGET_NAMED_SERVER;
            MXS_DEBUG("%lu [get_route_target] Hint: route to "
                      "named server : ",
                      pthread_self());
        }
        else if (hint->type == HINT_ROUTE_TO_UPTODATE_SERVER)
        {
            /** not implemented */
        }
        else if (hint->type == HINT_ROUTE_TO_ALL)
        {
            /** not implemented */
        }
        else if (hint->type == HINT_PARAMETER)
        {
            if (strncasecmp((char *)hint->data, "max_slave_replication_lag",
                            strlen("max_slave_replication_lag")) == 0)
            {
                target |= TARGET_RLAG_MAX;
            }
            else
            {
                MXS_ERROR("Unknown hint parameter "
                          "'%s' when 'max_slave_replication_lag' "
                          "was expected.",
                          (char *)hint->data);
            }
        }
        else if (hint->type == HINT_ROUTE_TO_SLAVE)
        {
            target = TARGET_SLAVE;
            MXS_DEBUG("%lu [get_route_target] Hint: route to "
                      "slave.",
                      pthread_self());
        }
        hint = hint->next;
    } /*< while (hint != NULL) */

#if defined(SS_EXTRA_DEBUG)
    MXS_INFO("Selected target \"%s\"", STRTARGET(target));
#endif
    return target;
}

/**
 * Check if the query is a DROP TABLE... query and
 * if it targets a temporary table, remove it from the hashtable.
 * @param router_cli_ses Router client session
 * @param querybuf GWBUF containing the query
 * @param type The type of the query resolved so far
 */
void check_drop_tmp_table(ROUTER_CLIENT_SES *router_cli_ses, GWBUF *querybuf,
                          qc_query_type_t type)
{

    int tsize = 0, klen = 0, i;
    char **tbl = NULL;
    char *hkey, *dbname;
    MYSQL_session *data;
    rses_property_t *rses_prop_tmp;

    if (router_cli_ses == NULL || querybuf == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameters passed: %p %p", __FUNCTION__,
                  router_cli_ses, querybuf);
        return;
    }

    if (router_cli_ses->client_dcb == NULL)
    {
        MXS_ERROR("[%s] Error: Client DCB is NULL.", __FUNCTION__);
        return;
    }

    rses_prop_tmp = router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES];
    data = (MYSQL_session *)router_cli_ses->client_dcb->data;

    if (data == NULL)
    {
        MXS_ERROR("[%s] Error: User data in master server DBC is NULL.",
                  __FUNCTION__);
        return;
    }

    dbname = (char *)data->db;

    if (qc_is_drop_table_query(querybuf))
    {
        tbl = qc_get_table_names(querybuf, &tsize, false);
        if (tbl != NULL)
        {
            for (i = 0; i < tsize; i++)
            {
                klen = strlen(dbname) + strlen(tbl[i]) + 2;
                hkey = calloc(klen, sizeof(char));
                strcpy(hkey, dbname);
                strcat(hkey, ".");
                strcat(hkey, tbl[i]);

                if (rses_prop_tmp && rses_prop_tmp->rses_prop_data.temp_tables)
                {
                    if (hashtable_delete(rses_prop_tmp->rses_prop_data.temp_tables,
                                         (void *)hkey))
                    {
                        MXS_INFO("Temporary table dropped: %s", hkey);
                    }
                }
                free(tbl[i]);
                free(hkey);
            }

            free(tbl);
        }
    }
}

/**
 * Check if the query targets a temporary table.
 * @param router_cli_ses Router client session
 * @param querybuf GWBUF containing the query
 * @param type The type of the query resolved so far
 * @return The type of the query
 */
static bool is_read_tmp_table(ROUTER_CLIENT_SES *router_cli_ses,
                                         GWBUF *querybuf,
                                         qc_query_type_t qtype)
{

    bool target_tmp_table = false;
    int tsize = 0, klen = 0, i;
    char **tbl = NULL;
    char *dbname;
    char hkey[MYSQL_DATABASE_MAXLEN + MYSQL_TABLE_MAXLEN + 2];
    MYSQL_session *data;
    bool rval = false;
    rses_property_t *rses_prop_tmp;

    if (router_cli_ses == NULL || querybuf == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameters passed: %p %p", __FUNCTION__,
                  router_cli_ses, querybuf);
        return false;
    }

    if (router_cli_ses->client_dcb == NULL)
    {
        MXS_ERROR("[%s] Error: Client DCB is NULL.", __FUNCTION__);
        return false;
    }

    rses_prop_tmp = router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES];
    data = (MYSQL_session *)router_cli_ses->client_dcb->data;

    if (data == NULL)
    {
        MXS_ERROR("[%s] Error: User data in client DBC is NULL.", __FUNCTION__);
        return false;
    }

    dbname = (char *)data->db;

    if (QUERY_IS_TYPE(qtype, QUERY_TYPE_READ) ||
        QUERY_IS_TYPE(qtype, QUERY_TYPE_LOCAL_READ) ||
        QUERY_IS_TYPE(qtype, QUERY_TYPE_USERVAR_READ) ||
        QUERY_IS_TYPE(qtype, QUERY_TYPE_SYSVAR_READ) ||
        QUERY_IS_TYPE(qtype, QUERY_TYPE_GSYSVAR_READ))
    {
        tbl = qc_get_table_names(querybuf, &tsize, false);

        if (tbl != NULL && tsize > 0)
        {
            /** Query targets at least one table */
            for (i = 0; i < tsize && !target_tmp_table && tbl[i]; i++)
            {
                sprintf(hkey, "%s.%s", dbname, tbl[i]);
                if (rses_prop_tmp && rses_prop_tmp->rses_prop_data.temp_tables)
                {
                    if (hashtable_fetch(rses_prop_tmp->rses_prop_data.temp_tables, hkey))
                    {
                        /**Query target is a temporary table*/
                        rval = true;
                        MXS_INFO("Query targets a temporary table: %s", hkey);
                        break;
                    }
                }
            }
        }
    }

    if (tbl != NULL)
    {
        for (i = 0; i < tsize; i++)
        {
            free(tbl[i]);
        }
        free(tbl);
    }

    return rval;
}

/**
 * If query is of type QUERY_TYPE_CREATE_TMP_TABLE then find out
 * the database and table name, create a hashvalue and
 * add it to the router client session's property. If property
 * doesn't exist then create it first.
 * @param router_cli_ses Router client session
 * @param querybuf GWBUF containing the query
 * @param type The type of the query resolved so far
 */
static void check_create_tmp_table(ROUTER_CLIENT_SES *router_cli_ses,
                                   GWBUF *querybuf, qc_query_type_t type)
{
    if (!QUERY_IS_TYPE(type, QUERY_TYPE_CREATE_TMP_TABLE))
    {
        return;
    }

    int klen = 0;
    char *hkey, *dbname;
    MYSQL_session *data;
    rses_property_t *rses_prop_tmp;
    HASHTABLE *h;

    if (router_cli_ses == NULL || querybuf == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameters passed: %p %p", __FUNCTION__,
                  router_cli_ses, querybuf);
        return;
    }

    if (router_cli_ses->client_dcb == NULL)
    {
        MXS_ERROR("[%s] Error: Client DCB is NULL.", __FUNCTION__);
        return;
    }

    router_cli_ses->have_tmp_tables = true;
    rses_prop_tmp = router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES];
    data = (MYSQL_session *)router_cli_ses->client_dcb->data;

    if (data == NULL)
    {
        MXS_ERROR("[%s] Error: User data in master server DBC is NULL.",
                  __FUNCTION__);
        return;
    }

    dbname = (char *)data->db;

    bool is_temp = true;
    char *tblname = NULL;

    tblname = qc_get_created_table_name(querybuf);

    if (tblname && strlen(tblname) > 0)
    {
        klen = strlen(dbname) + strlen(tblname) + 2;
        hkey = calloc(klen, sizeof(char));
        strcpy(hkey, dbname);
        strcat(hkey, ".");
        strcat(hkey, tblname);
    }
    else
    {
        hkey = NULL;
    }

    if (rses_prop_tmp == NULL)
    {
        if ((rses_prop_tmp = (rses_property_t *)calloc(1, sizeof(rses_property_t))))
        {
#if defined(SS_DEBUG)
            rses_prop_tmp->rses_prop_chk_top = CHK_NUM_ROUTER_PROPERTY;
            rses_prop_tmp->rses_prop_chk_tail = CHK_NUM_ROUTER_PROPERTY;
#endif
            rses_prop_tmp->rses_prop_rsession = router_cli_ses;
            rses_prop_tmp->rses_prop_refcount = 1;
            rses_prop_tmp->rses_prop_next = NULL;
            rses_prop_tmp->rses_prop_type = RSES_PROP_TYPE_TMPTABLES;
            router_cli_ses->rses_properties[RSES_PROP_TYPE_TMPTABLES] = rses_prop_tmp;
        }
        else
        {
            MXS_ERROR("Call to malloc() failed.");
        }
    }
    if (rses_prop_tmp)
    {
        if (rses_prop_tmp->rses_prop_data.temp_tables == NULL)
        {
            h = hashtable_alloc(7, hashkeyfun, hashcmpfun);
            hashtable_memory_fns(h, hstrdup, NULL, hfree, NULL);
            if (h != NULL)
            {
                rses_prop_tmp->rses_prop_data.temp_tables = h;
            }
            else
            {
                MXS_ERROR("Failed to allocate a new hashtable.");
            }
        }

        if (hkey && rses_prop_tmp->rses_prop_data.temp_tables &&
            hashtable_add(rses_prop_tmp->rses_prop_data.temp_tables, (void *)hkey,
                          (void *)is_temp) == 0) /*< Conflict in hash table */
        {
            MXS_INFO("Temporary table conflict in hashtable: %s", hkey);
        }
#if defined(SS_DEBUG)
        {
            bool retkey = hashtable_fetch(rses_prop_tmp->rses_prop_data.temp_tables, hkey);
            if (retkey)
            {
                MXS_INFO("Temporary table added: %s", hkey);
            }
        }
#endif
    }

    free(hkey);
    free(tblname);
}

/**
 * Get client DCB pointer of the router client session.
 * This routine must be protected by Router client session lock.
 *
 * @param rses  Router client session pointer
 *
 * @return Pointer to client DCB
 */
static DCB *rses_get_client_dcb(ROUTER_CLIENT_SES *rses)
{
    DCB *dcb = NULL;
    int i;

    for (i = 0; i < rses->rses_nbackends; i++)
    {
        if ((dcb = rses->rses_backend_ref[i].bref_dcb) != NULL &&
            BREF_IS_IN_USE(&rses->rses_backend_ref[i]) && dcb->session != NULL &&
            dcb->session->client_dcb != NULL)
        {
            return dcb->session->client_dcb;
        }
    }
    return NULL;
}

/**
 * @brief The main routing entry point
 *
 * The routeQuery will make the routing decision based on the contents
 * of the instance, session and the query itself. The query always represents
 * a complete MariaDB/MySQL packet because we define the RCAP_TYPE_STMT_INPUT in
 * getCapabilities().
 *
 * @param instance       Router instance
 * @param router_session Router session associated with the client
 * @param querybuf       Buffer containing the query
 * @return 1 on success, 0 on error
 */
static int routeQuery(ROUTER *instance, void *router_session, GWBUF *querybuf)
{
    ROUTER_INSTANCE *inst = (ROUTER_INSTANCE *) instance;
    ROUTER_CLIENT_SES *rses = (ROUTER_CLIENT_SES *) router_session;
    int rval = 0;

    CHK_CLIENT_RSES(rses);

    if (rses->rses_closed)
    {
        uint8_t* data = GWBUF_DATA(querybuf);

        if (GWBUF_LENGTH(querybuf) >= 5 && !MYSQL_IS_COM_QUIT(data))
        {
            char *query_str = modutil_get_query(querybuf);
            MXS_ERROR("Can't route %s:\"%s\" to backend server. Router is closed.",
                      STRPACKETTYPE(data[4]), query_str ? query_str : "(empty)");
            free(query_str);
        }
    }
    else
    {
        if (GWBUF_IS_TYPE_UNDEFINED(querybuf))
        {
            GWBUF *tmpbuf = querybuf;

            querybuf = modutil_get_complete_packets(&tmpbuf);
            if (tmpbuf)
            {
                rses->client_dcb->dcb_readqueue = gwbuf_append(rses->client_dcb->dcb_readqueue, tmpbuf);
            }
            querybuf = gwbuf_make_contiguous(querybuf);

            /** Mark buffer to as MySQL type */
            gwbuf_set_type(querybuf, GWBUF_TYPE_MYSQL);
            gwbuf_set_type(querybuf, GWBUF_TYPE_SINGLE_STMT);
        }

        if (route_single_stmt(inst, rses, querybuf))
        {
            rval = 1;
        }
    }

    if (querybuf != NULL)
    {
        gwbuf_free(querybuf);
    }

    return rval;
}

/**
 * @brief Log master write failure
 *
 * @param rses Router session
 */
static void log_master_routing_failure(ROUTER_CLIENT_SES *rses, bool found,
                                       DCB *master_dcb, DCB *curr_master_dcb)
{
    char errmsg[MAX_SERVER_NAME_LEN * 2 + 100]; // Extra space for error message

    if (!found)
    {
            sprintf(errmsg, "Could not find a valid master connection");
    }
    else if (master_dcb && curr_master_dcb)
    {
        /** We found a master but it's not the same connection */
        ss_dassert(master_dcb != curr_master_dcb);
        if (master_dcb->server != curr_master_dcb->server)
        {
            sprintf(errmsg, "Master server changed from '%s' to '%s'",
                    master_dcb->server->unique_name,
                    curr_master_dcb->server->unique_name);
        }
        else
        {
            ss_dassert(false); // Currently we don't reconnect to the master
            sprintf(errmsg, "Connection to master '%s' was recreated",
                    curr_master_dcb->server->unique_name);
        }
    }
    else if (master_dcb)
    {
        /** We have an original master connection but we couldn't find it */
        sprintf(errmsg, "The connection to master server '%s' is not available",
                master_dcb->server->unique_name);
    }
    else
    {
        /** We never had a master connection, the session must be in read-only mode */
        if (rses->rses_config.rw_master_failure_mode != RW_FAIL_INSTANTLY)
        {
            sprintf(errmsg, "Session is in read-only mode because it was created "
                    "when no master was available");
        }
        else
        {
            ss_dassert(false); // A session should always have a master reference
            sprintf(errmsg, "Was supposed to route to master but couldn't "
                    "find master in a suitable state");
        }
    }

    MXS_WARNING("[%s] Write query received from %s@%s. %s. Closing client connection.",
                rses->router->service->name, rses->client_dcb->user,
                rses->client_dcb->remote, errmsg);
}

/**
 * Routing function. Find out query type, backend type, and target DCB(s).
 * Then route query to found target(s).
 * @param inst      router instance
 * @param rses      router session
 * @param querybuf  GWBUF including the query
 *
 * @return true if routing succeed or if it failed due to unsupported query.
 * false if backend failure was encountered.
 */
static bool route_single_stmt(ROUTER_INSTANCE *inst, ROUTER_CLIENT_SES *rses,
                              GWBUF *querybuf)
{
    qc_query_type_t qtype = QUERY_TYPE_UNKNOWN;
    mysql_server_cmd_t packet_type = MYSQL_COM_UNDEFINED;
    uint8_t *packet;
    size_t packet_len;
    int ret = 0;
    DCB *target_dcb = NULL;
    route_target_t route_target;
    bool succp = false;
    int rlag_max = MAX_RLAG_UNDEFINED;
    backend_type_t btype; /*< target backend type */

    ss_dassert(querybuf->next == NULL); // The buffer must be contiguous.
    ss_dassert(!GWBUF_IS_TYPE_UNDEFINED(querybuf));

    packet = GWBUF_DATA(querybuf);
    packet_len = gw_mysql_get_byte3(packet);

    if (packet_len == 0)
    {
        /** Empty packet signals end of LOAD DATA LOCAL INFILE, send it to master*/
        route_target = TARGET_MASTER;
        packet_type = MYSQL_COM_UNDEFINED;
        rses->rses_load_active = false;
        route_target = TARGET_MASTER;
        MXS_INFO("> LOAD DATA LOCAL INFILE finished: %lu bytes sent.",
                 rses->rses_load_data_sent + gwbuf_length(querybuf));
    }
    else
    {
        packet_type = packet[4];

        switch (packet_type)
        {
            case MYSQL_COM_QUIT:        /*< 1 QUIT will close all sessions */
            case MYSQL_COM_INIT_DB:     /*< 2 DDL must go to the master */
            case MYSQL_COM_REFRESH:     /*< 7 - I guess this is session but not sure */
            case MYSQL_COM_DEBUG:       /*< 0d all servers dump debug info to stdout */
            case MYSQL_COM_PING:        /*< 0e all servers are pinged */
            case MYSQL_COM_CHANGE_USER: /*< 11 all servers change it accordingly */
                qtype = QUERY_TYPE_SESSION_WRITE;
                break;

            case MYSQL_COM_CREATE_DB:           /**< 5 DDL must go to the master */
            case MYSQL_COM_DROP_DB:             /**< 6 DDL must go to the master */
            case MYSQL_COM_STMT_CLOSE:          /*< free prepared statement */
            case MYSQL_COM_STMT_SEND_LONG_DATA: /*< send data to column */
            case MYSQL_COM_STMT_RESET: /*< resets the data of a prepared statement */
                qtype = QUERY_TYPE_WRITE;
                break;

            case MYSQL_COM_QUERY:
                qtype = qc_get_type(querybuf);
                break;

            case MYSQL_COM_STMT_PREPARE:
                qtype = qc_get_type(querybuf);
                qtype |= QUERY_TYPE_PREPARE_STMT;
                break;

            case MYSQL_COM_STMT_EXECUTE:
                /** Parsing is not needed for this type of packet */
                qtype = QUERY_TYPE_EXEC_STMT;
                break;

            case MYSQL_COM_SHUTDOWN:       /**< 8 where should shutdown be routed ? */
            case MYSQL_COM_STATISTICS:     /**< 9 ? */
            case MYSQL_COM_PROCESS_INFO:   /**< 0a ? */
            case MYSQL_COM_CONNECT:        /**< 0b ? */
            case MYSQL_COM_PROCESS_KILL:   /**< 0c ? */
            case MYSQL_COM_TIME:           /**< 0f should this be run in gateway ? */
            case MYSQL_COM_DELAYED_INSERT: /**< 10 ? */
            case MYSQL_COM_DAEMON:         /**< 1d ? */
            default:
                break;
        } /**< switch by packet type */

        /** This might not be absolutely necessary as some parts of the code
         * can only be executed by one thread at a time. */
        if (!rses_begin_locked_router_action(rses))
        {
            succp = false;
            goto retblock;
        }

        /** Check for multi-statement queries. If no master server is available
         * and a multi-statement is issued, an error is returned to the client
         * when the query is routed.
         *
         * If we do not have a master node, assigning the forced node is not
         * effective since we don't have a node to force queries to. In this
         * situation, assigning QUERY_TYPE_WRITE for the query will trigger
         * the error processing. */
        if (check_for_multi_stmt(rses, querybuf, packet_type) &&
            rses->rses_master_ref == NULL)
        {
            qtype |= QUERY_TYPE_WRITE;
        }

        /**
         * Check if the query has anything to do with temporary tables.
         */
        if (rses->have_tmp_tables &&
            (packet_type == MYSQL_COM_QUERY || packet_type == MYSQL_COM_DROP_DB))
        {
            check_drop_tmp_table(rses, querybuf, qtype);
            if (packet_type == MYSQL_COM_QUERY && is_read_tmp_table(rses, querybuf, qtype))
            {
                qtype |= QUERY_TYPE_MASTER_READ;
            }
        }
        check_create_tmp_table(rses, querybuf, qtype);

        /**
         * Check if this is a LOAD DATA LOCAL INFILE query. If so, send all queries
         * to the master until the last, empty packet arrives.
         */
        if (rses->rses_load_active)
        {
            rses->rses_load_data_sent += gwbuf_length(querybuf);
        }
        else if (packet_type == MYSQL_COM_QUERY)
        {
            qc_query_op_t queryop = qc_get_operation(querybuf);
            if (queryop == QUERY_OP_LOAD)
            {
                rses->rses_load_active = true;
                rses->rses_load_data_sent = 0;
            }
        }

        rses_end_locked_router_action(rses);
        /**
         * If autocommit is disabled or transaction is explicitly started
         * transaction becomes active and master gets all statements until
         * transaction is committed and autocommit is enabled again.
         */
        if (rses->rses_autocommit_enabled &&
            QUERY_IS_TYPE(qtype, QUERY_TYPE_DISABLE_AUTOCOMMIT))
        {
            rses->rses_autocommit_enabled = false;

            if (!rses->rses_transaction_active)
            {
                rses->rses_transaction_active = true;
            }
        }
        else if (!rses->rses_transaction_active &&
                 QUERY_IS_TYPE(qtype, QUERY_TYPE_BEGIN_TRX))
        {
            rses->rses_transaction_active = true;
        }
        /**
         * Explicit COMMIT and ROLLBACK, implicit COMMIT.
         */
        if (rses->rses_autocommit_enabled && rses->rses_transaction_active &&
            (QUERY_IS_TYPE(qtype, QUERY_TYPE_COMMIT) ||
             QUERY_IS_TYPE(qtype, QUERY_TYPE_ROLLBACK)))
        {
            rses->rses_transaction_active = false;
        }
        else if (!rses->rses_autocommit_enabled &&
                 QUERY_IS_TYPE(qtype, QUERY_TYPE_ENABLE_AUTOCOMMIT))
        {
            rses->rses_autocommit_enabled = true;
            rses->rses_transaction_active = false;
        }

        if (MXS_LOG_PRIORITY_IS_ENABLED(LOG_INFO))
        {
            if (!rses->rses_load_active)
            {
                uint8_t *packet = GWBUF_DATA(querybuf);
                unsigned char ptype = packet[4];
                size_t len = MIN(GWBUF_LENGTH(querybuf),
                                 MYSQL_GET_PACKET_LEN((unsigned char *)querybuf->start) - 1);
                char *data = (char *)&packet[5];
                char *contentstr = strndup(data, MIN(len, RWSPLIT_TRACE_MSG_LEN));
                char *qtypestr = qc_get_qtype_str(qtype);
                MXS_INFO("> Autocommit: %s, trx is %s, cmd: %s, type: %s, stmt: %s%s %s",
                         (rses->rses_autocommit_enabled ? "[enabled]" : "[disabled]"),
                         (rses->rses_transaction_active ? "[open]" : "[not open]"),
                         STRPACKETTYPE(ptype), (qtypestr == NULL ? "N/A" : qtypestr),
                         contentstr, (querybuf->hint == NULL ? "" : ", Hint:"),
                         (querybuf->hint == NULL ? "" : STRHINTTYPE(querybuf->hint->type)));
                free(contentstr);
                free(qtypestr);
            }
            else
            {
                MXS_INFO("> Processing LOAD DATA LOCAL INFILE: %lu bytes sent.",
                         rses->rses_load_data_sent);
            }
        }
        /**
         * Find out where to route the query. Result may not be clear; it is
         * possible to have a hint for routing to a named server which can
         * be either slave or master.
         * If query would otherwise be routed to slave then the hint determines
         * actual target server if it exists.
         *
         * route_target is a bitfield and may include :
         * TARGET_ALL
         * - route to all connected backend servers
         * TARGET_SLAVE[|TARGET_NAMED_SERVER|TARGET_RLAG_MAX]
         * - route primarily according to hints, then to slave and if those
         *   failed, eventually to master
         * TARGET_MASTER[|TARGET_NAMED_SERVER|TARGET_RLAG_MAX]
         * - route primarily according to the hints and if they failed,
         *   eventually to master
         */
        route_target = get_route_target(rses, qtype, querybuf->hint);

        if (TARGET_IS_ALL(route_target))
        {
            /** Multiple, conflicting routing target. Return error */
            if (TARGET_IS_MASTER(route_target) || TARGET_IS_SLAVE(route_target))
            {
                backend_ref_t *bref = rses->rses_backend_ref;

                char *query_str = modutil_get_query(querybuf);
                char *qtype_str = qc_get_qtype_str(qtype);

                MXS_ERROR("Can't route %s:%s:\"%s\". SELECT with session data "
                          "modification is not supported if configuration parameter "
                          "use_sql_variables_in=all .", STRPACKETTYPE(packet_type),
                          qtype_str, (query_str == NULL ? "(empty)" : query_str));

                MXS_INFO("Unable to route the query without losing session data "
                         "modification from other servers. <");

                while (bref != NULL && !BREF_IS_IN_USE(bref))
                {
                    bref++;
                }

                if (bref != NULL && BREF_IS_IN_USE(bref))
                {
                    /** Create and add MySQL error to eventqueue */
                    modutil_reply_parse_error(bref->bref_dcb,
                                              strdup("Routing query to backend failed. "
                                                     "See the error log for further "
                                                     "details."), 0);
                    succp = true;
                }
                else
                {
                    /**
                     * If there were no available backend references
                     * available return false - session will be closed
                     */
                    MXS_ERROR("Sending error message to client "
                              "failed. Router doesn't have any "
                              "available backends. Session will be "
                              "closed.");
                    succp = false;
                }
                if (query_str)
                {
                    free(query_str);
                }
                if (qtype_str)
                {
                    free(qtype_str);
                }
                goto retblock;
            }
            /**
             * It is not sure if the session command in question requires
             * response. Statement is examined in route_session_write.
             * Router locking is done inside the function.
             */
            succp = route_session_write(rses, gwbuf_clone(querybuf), inst,
                                        packet_type, qtype);

            if (succp)
            {
                atomic_add(&inst->stats.n_all, 1);
            }
            goto retblock;
        }
    }
    /** Lock router session */
    if (!rses_begin_locked_router_action(rses))
    {
        if (packet_type != MYSQL_COM_QUIT)
        {
            char *query_str = modutil_get_query(querybuf);

            MXS_ERROR("Can't route %s:%s:\"%s\" to "
                      "backend server. Router is closed.",
                      STRPACKETTYPE(packet_type), STRQTYPE(qtype),
                      (query_str == NULL ? "(empty)" : query_str));
            free(query_str);
        }
        succp = false;
        goto retblock;
    }

    DCB *master_dcb = rses->rses_master_ref ? rses->rses_master_ref->bref_dcb : NULL;

    /**
     * There is a hint which either names the target backend or
     * hint which sets maximum allowed replication lag for the
     * backend.
     */
    if (TARGET_IS_NAMED_SERVER(route_target) ||
        TARGET_IS_RLAG_MAX(route_target))
    {
        HINT *hint;
        char *named_server = NULL;

        hint = querybuf->hint;

        while (hint != NULL)
        {
            if (hint->type == HINT_ROUTE_TO_NAMED_SERVER)
            {
                /**
                 * Set the name of searched
                 * backend server.
                 */
                named_server = hint->data;
                MXS_INFO("Hint: route to server "
                         "'%s'",
                         named_server);
            }
            else if (hint->type == HINT_PARAMETER &&
                     (strncasecmp((char *)hint->data, "max_slave_replication_lag",
                                  strlen("max_slave_replication_lag")) == 0))
            {
                int val = (int)strtol((char *)hint->value, (char **)NULL, 10);

                if (val != 0 || errno == 0)
                {
                    /** Set max. acceptable replication lag value for backend srv */
                    rlag_max = val;
                    MXS_INFO("Hint: max_slave_replication_lag=%d", rlag_max);
                }
            }
            hint = hint->next;
        } /*< while */

        if (rlag_max == MAX_RLAG_UNDEFINED) /*< no rlag max hint, use config */
        {
            rlag_max = rses_get_max_replication_lag(rses);
        }

        /** target may be master or slave */
        btype = route_target & TARGET_SLAVE ? BE_SLAVE : BE_MASTER;

        /**
         * Search backend server by name or replication lag.
         * If it fails, then try to find valid slave or master.
         */
        succp = get_dcb(&target_dcb, rses, btype, named_server, rlag_max);

        if (!succp)
        {
            if (TARGET_IS_NAMED_SERVER(route_target))
            {
                MXS_INFO("Was supposed to route to named server "
                         "%s but couldn't find the server in a "
                         "suitable state.", named_server);
            }
            else if (TARGET_IS_RLAG_MAX(route_target))
            {
                MXS_INFO("Was supposed to route to server with "
                         "replication lag at most %d but couldn't "
                         "find such a slave.", rlag_max);
            }
        }
    }
    else if (TARGET_IS_SLAVE(route_target))
    {
        btype = BE_SLAVE;

        if (rlag_max == MAX_RLAG_UNDEFINED) /*< no rlag max hint, use config */
        {
            rlag_max = rses_get_max_replication_lag(rses);
        }
        /**
         * Search suitable backend server, get DCB in target_dcb
         */
        succp = get_dcb(&target_dcb, rses, BE_SLAVE, NULL, rlag_max);

        if (succp)
        {
#if defined(SS_EXTRA_DEBUG)
            MXS_INFO("Found DCB for slave.");
#endif
            atomic_add(&inst->stats.n_slave, 1);
        }
        else
        {
            MXS_INFO("Was supposed to route to slave but finding suitable one failed.");
        }
    }
    else if (TARGET_IS_MASTER(route_target))
    {
        DCB *curr_master_dcb = NULL;

        succp = get_dcb(&curr_master_dcb, rses, BE_MASTER, NULL, MAX_RLAG_UNDEFINED);

        if (succp && master_dcb == curr_master_dcb)
        {
            atomic_add(&inst->stats.n_master, 1);
            target_dcb = master_dcb;
        }
        else
        {
            /** The original master is not available, we can't route the write */
            if (rses->rses_config.rw_master_failure_mode == RW_ERROR_ON_WRITE)
            {
                succp = send_readonly_error(rses->client_dcb);
            }
            else
            {
                log_master_routing_failure(rses, succp, master_dcb, curr_master_dcb);
                succp = false;
            }

            rses_end_locked_router_action(rses);
            goto retblock;
        }
    }

    if (succp) /*< Have DCB of the target backend */
    {
        backend_ref_t *bref;
        sescmd_cursor_t *scur;

        bref = get_bref_from_dcb(rses, target_dcb);
        scur = &bref->bref_sescmd_cur;

        ss_dassert(target_dcb != NULL);

        MXS_INFO("Route query to %s \t%s:%d <",
                 (SERVER_IS_MASTER(bref->bref_backend->backend_server) ? "master"
                  : "slave"), bref->bref_backend->backend_server->name,
                 bref->bref_backend->backend_server->port);
        /**
         * Store current stmt if execution of previous session command
         * haven't completed yet.
         *
         * !!! Note that according to MySQL protocol
         * there can only be one such non-sescmd stmt at the time.
         * It is possible that bref->bref_pending_cmd includes a pending
         * command if rwsplit is parent or child for another router,
         * which runs all the same commands.
         *
         * If the assertion below traps, pending queries are treated
         * somehow wrong, or client is sending more queries before
         * previous is received.
         */
        if (sescmd_cursor_is_active(scur))
        {
            ss_dassert(bref->bref_pending_cmd == NULL);
            bref->bref_pending_cmd = gwbuf_clone(querybuf);

            rses_end_locked_router_action(rses);
            goto retblock;
        }

        if ((ret = target_dcb->func.write(target_dcb, gwbuf_clone(querybuf))) == 1)
        {
            backend_ref_t *bref;

            atomic_add(&inst->stats.n_queries, 1);
            /**
             * Add one query response waiter to backend reference
             */
            bref = get_bref_from_dcb(rses, target_dcb);
            bref_set_state(bref, BREF_QUERY_ACTIVE);
            bref_set_state(bref, BREF_WAITING_RESULT);
        }
        else
        {
            MXS_ERROR("Routing query failed.");
            succp = false;
        }
    }
    rses_end_locked_router_action(rses);

retblock :
#if defined(SS_DEBUG2)
    {
        char *canonical_query_str;

        canonical_query_str = skygw_get_canonical(querybuf);

        if (canonical_query_str != NULL)
        {
            MXS_INFO("Canonical version: %s", canonical_query_str);
            free(canonical_query_str);
        }
    }
#endif
    return succp;
}

/**
 * @node Acquires lock to router client session if it is not closed.
 *
 * Parameters:
 * @param rses - in, use
 *
 *
 * @return true if router session was not closed. If return value is true
 * it means that router is locked, and must be unlocked later. False, if
 * router was closed before lock was acquired.
 *
 *
 * @details (write detailed description here)
 *
 */
static bool rses_begin_locked_router_action(ROUTER_CLIENT_SES *rses)
{
    bool succp = false;

    if (rses == NULL)
    {
        return false;
    }

    CHK_CLIENT_RSES(rses);

    if (rses->rses_closed)
    {

        goto return_succp;
    }
    spinlock_acquire(&rses->rses_lock);
    if (rses->rses_closed)
    {
        spinlock_release(&rses->rses_lock);
        goto return_succp;
    }
    succp = true;

return_succp:
    return succp;
}

/** to be inline'd */

/**
 * @node Releases router client session lock.
 *
 * Parameters:
 * @param rses - <usage>
 *          <description>
 *
 * @return void
 *
 *
 * @details (write detailed description here)
 *
 */
static void rses_end_locked_router_action(ROUTER_CLIENT_SES *rses)
{
    CHK_CLIENT_RSES(rses);
    spinlock_release(&rses->rses_lock);
}

/**
 * Diagnostics routine
 *
 * Print query router statistics to the DCB passed in
 *
 * @param   instance    The router instance
 * @param   dcb     The DCB for diagnostic output
 */
static void diagnostic(ROUTER *instance, DCB *dcb)
{
    ROUTER_CLIENT_SES *router_cli_ses;
    ROUTER_INSTANCE *router = (ROUTER_INSTANCE *)instance;
    int i = 0;
    BACKEND *backend;
    char *weightby;

    spinlock_acquire(&router->lock);
    router_cli_ses = router->connections;
    while (router_cli_ses)
    {
        i++;
        router_cli_ses = router_cli_ses->next;
    }
    spinlock_release(&router->lock);

    double master_pct = 0.0, slave_pct = 0.0, all_pct = 0.0;

    if (router->stats.n_queries > 0)
    {
        master_pct = ((double)router->stats.n_master / (double)router->stats.n_queries) * 100.0;
        slave_pct = ((double)router->stats.n_slave / (double)router->stats.n_queries) * 100.0;
        all_pct = ((double)router->stats.n_all / (double)router->stats.n_queries) * 100.0;
    }

    dcb_printf(dcb, "\tNumber of router sessions:           	%d\n",
               router->stats.n_sessions);
    dcb_printf(dcb, "\tCurrent no. of router sessions:      	%d\n", i);
    dcb_printf(dcb, "\tNumber of queries forwarded:          	%d\n",
               router->stats.n_queries);
    dcb_printf(dcb, "\tNumber of queries forwarded to master:	%d (%.2f%%)\n",
               router->stats.n_master, master_pct);
    dcb_printf(dcb, "\tNumber of queries forwarded to slave: 	%d (%.2f%%)\n",
               router->stats.n_slave, slave_pct);
    dcb_printf(dcb, "\tNumber of queries forwarded to all:   	%d (%.2f%%)\n",
               router->stats.n_all, all_pct);

    if ((weightby = serviceGetWeightingParameter(router->service)) != NULL)
    {
        dcb_printf(dcb, "\tConnection distribution based on %s "
                   "server parameter.\n",
                   weightby);
        dcb_printf(dcb, "\t\tServer               Target %%    Connections  "
                   "Operations\n");
        dcb_printf(dcb, "\t\t                               Global  Router\n");
        for (i = 0; router->servers[i]; i++)
        {
            backend = router->servers[i];
            dcb_printf(dcb, "\t\t%-20s %3.1f%%     %-6d  %-6d  %d\n",
                       backend->backend_server->unique_name, (float)backend->weight / 10,
                       backend->backend_server->stats.n_current, backend->backend_conn_count,
                       backend->backend_server->stats.n_current_ops);
        }
    }
}

/**
 * Client Reply routine
 *
 * The routine will reply to client for session change with master server data
 *
 * @param   instance    The router instance
 * @param   router_session  The router session
 * @param   backend_dcb The backend DCB
 * @param   queue       The GWBUF with reply data
 */
static void clientReply(ROUTER *instance, void *router_session, GWBUF *writebuf,
                        DCB *backend_dcb)
{
    DCB *client_dcb;
    ROUTER_INSTANCE *router_inst;
    ROUTER_CLIENT_SES *router_cli_ses;
    sescmd_cursor_t *scur = NULL;
    backend_ref_t *bref;

    router_cli_ses = (ROUTER_CLIENT_SES *)router_session;
    router_inst = (ROUTER_INSTANCE *)instance;
    CHK_CLIENT_RSES(router_cli_ses);

    /**
     * Lock router client session for secure read of router session members.
     * Note that this could be done without lock by using version #
     */
    if (!rses_begin_locked_router_action(router_cli_ses))
    {
        print_error_packet(router_cli_ses, writebuf, backend_dcb);
        goto lock_failed;
    }
    /** Holding lock ensures that router session remains open */
    ss_dassert(backend_dcb->session != NULL);
    client_dcb = backend_dcb->session->client_dcb;

    /** Unlock */
    rses_end_locked_router_action(router_cli_ses);
    /**
     * 1. Check if backend received reply to sescmd.
     * 2. Check sescmd's state whether OK_PACKET has been
     *    sent to client already and if not, lock property cursor,
     *    reply to client, and move property cursor forward. Finally
     *    release the lock.
     * 3. If reply for this sescmd is sent, lock property cursor
     *    and
     */
    if (client_dcb == NULL)
    {
        gwbuf_free(writebuf);
        /** Log that client was closed before reply */
        goto lock_failed;
    }
    /** Lock router session */
    if (!rses_begin_locked_router_action(router_cli_ses))
    {
        /** Log to debug that router was closed */
        goto lock_failed;
    }
    bref = get_bref_from_dcb(router_cli_ses, backend_dcb);

#if !defined(FOR_BUG548_FIX_ONLY)
    /** This makes the issue becoming visible in poll.c */
    if (bref == NULL)
    {
        /** Unlock router session */
        rses_end_locked_router_action(router_cli_ses);
        goto lock_failed;
    }
#endif

    CHK_BACKEND_REF(bref);
    scur = &bref->bref_sescmd_cur;
    /**
     * Active cursor means that reply is from session command
     * execution.
     */
    if (sescmd_cursor_is_active(scur))
    {
        if (MXS_LOG_PRIORITY_IS_ENABLED(LOG_ERR) &&
            MYSQL_IS_ERROR_PACKET(((uint8_t *)GWBUF_DATA(writebuf))))
        {
            uint8_t *buf = (uint8_t *)GWBUF_DATA((scur->scmd_cur_cmd->my_sescmd_buf));
            uint8_t *replybuf = (uint8_t *)GWBUF_DATA(writebuf);
            size_t len = MYSQL_GET_PACKET_LEN(buf);
            size_t replylen = MYSQL_GET_PACKET_LEN(replybuf);
            char *err = strndup(&((char *)replybuf)[8], 5);
            char *replystr = strndup(&((char *)replybuf)[13], replylen - 4 - 5);

            ss_dassert(len + 4 == GWBUF_LENGTH(scur->scmd_cur_cmd->my_sescmd_buf));

            MXS_ERROR("Failed to execute session command in %s:%d. Error was: %s %s",
                      bref->bref_backend->backend_server->name,
                      bref->bref_backend->backend_server->port, err, replystr);
            free(err);
            free(replystr);
        }

        if (GWBUF_IS_TYPE_SESCMD_RESPONSE(writebuf))
        {
            /**
             * Discard all those responses that have already been sent to
             * the client. Return with buffer including response that
             * needs to be sent to client or NULL.
             */
            bool rconn = false;
            writebuf = sescmd_cursor_process_replies(writebuf, bref, &rconn);

            if (rconn && !router_inst->rwsplit_config.rw_disable_sescmd_hist)
            {
                select_connect_backend_servers(
                    &router_cli_ses->rses_master_ref, router_cli_ses->rses_backend_ref,
                    router_cli_ses->rses_nbackends,
                    router_cli_ses->rses_config.rw_max_slave_conn_count,
                    router_cli_ses->rses_config.rw_max_slave_replication_lag,
                    router_cli_ses->rses_config.rw_slave_select_criteria,
                    router_cli_ses->rses_master_ref->bref_dcb->session,
                    router_cli_ses->router,
                    true);
            }
        }
        /**
         * If response will be sent to client, decrease waiter count.
         * This applies to session commands only. Counter decrement
         * for other type of queries is done outside this block.
         */

        /** Set response status as replied */
        bref_clear_state(bref, BREF_WAITING_RESULT);
    }
    /**
     * Clear BREF_QUERY_ACTIVE flag and decrease waiter counter.
     * This applies for queries  other than session commands.
     */
    else if (BREF_IS_QUERY_ACTIVE(bref))
    {
        bref_clear_state(bref, BREF_QUERY_ACTIVE);
        /** Set response status as replied */
        bref_clear_state(bref, BREF_WAITING_RESULT);
    }

    if (writebuf != NULL && client_dcb != NULL)
    {
        /** Write reply to client DCB */
        SESSION_ROUTE_REPLY(backend_dcb->session, writebuf);
    }
    /** Unlock router session */
    rses_end_locked_router_action(router_cli_ses);

    /** Lock router session */
    if (!rses_begin_locked_router_action(router_cli_ses))
    {
        /** Log to debug that router was closed */
        goto lock_failed;
    }
    /** There is one pending session command to be executed. */
    if (sescmd_cursor_is_active(scur))
    {
        bool succp;

        MXS_INFO("Backend %s:%d processed reply and starts to execute "
                 "active cursor.", bref->bref_backend->backend_server->name,
                 bref->bref_backend->backend_server->port);

        succp = execute_sescmd_in_backend(bref);

        if (!succp)
        {
            MXS_INFO("Backend %s:%d failed to execute session command.",
                     bref->bref_backend->backend_server->name,
                     bref->bref_backend->backend_server->port);
        }
    }
    else if (bref->bref_pending_cmd != NULL) /*< non-sescmd is waiting to be routed */
    {
        int ret;

        CHK_GWBUF(bref->bref_pending_cmd);

        if ((ret = bref->bref_dcb->func.write(bref->bref_dcb,
                       gwbuf_clone(bref->bref_pending_cmd))) == 1)
        {
            ROUTER_INSTANCE* inst = (ROUTER_INSTANCE *)instance;
            atomic_add(&inst->stats.n_queries, 1);
            /**
             * Add one query response waiter to backend reference
             */
            bref_set_state(bref, BREF_QUERY_ACTIVE);
            bref_set_state(bref, BREF_WAITING_RESULT);
        }
        else
        {
            char* sql = modutil_get_SQL(bref->bref_pending_cmd);

            if (sql)
            {
                MXS_ERROR("Routing query \"%s\" failed.", sql);
                free(sql);
            }
            else
            {
                MXS_ERROR("Failed to route query.");
            }
        }
        gwbuf_free(bref->bref_pending_cmd);
        bref->bref_pending_cmd = NULL;
    }
    /** Unlock router session */
    rses_end_locked_router_action(router_cli_ses);

lock_failed:
    return;
}

/** Compare nunmber of connections from this router in backend servers */
int bref_cmp_router_conn(const void *bref1, const void *bref2)
{
    BACKEND *b1 = ((backend_ref_t *)bref1)->bref_backend;
    BACKEND *b2 = ((backend_ref_t *)bref2)->bref_backend;

    if (b1->weight == 0 && b2->weight == 0)
    {
        return b1->backend_server->stats.n_current -
               b2->backend_server->stats.n_current;
    }
    else if (b1->weight == 0)
    {
        return 1;
    }
    else if (b2->weight == 0)
    {
        return -1;
    }

    return ((1000 + 1000 * b1->backend_conn_count) / b1->weight) -
           ((1000 + 1000 * b2->backend_conn_count) / b2->weight);
}

/** Compare nunmber of global connections in backend servers */
int bref_cmp_global_conn(const void *bref1, const void *bref2)
{
    BACKEND *b1 = ((backend_ref_t *)bref1)->bref_backend;
    BACKEND *b2 = ((backend_ref_t *)bref2)->bref_backend;

    if (b1->weight == 0 && b2->weight == 0)
    {
        return b1->backend_server->stats.n_current -
               b2->backend_server->stats.n_current;
    }
    else if (b1->weight == 0)
    {
        return 1;
    }
    else if (b2->weight == 0)
    {
        return -1;
    }

    return ((1000 + 1000 * b1->backend_server->stats.n_current) / b1->weight) -
           ((1000 + 1000 * b2->backend_server->stats.n_current) / b2->weight);
}

/** Compare relication lag between backend servers */
int bref_cmp_behind_master(const void *bref1, const void *bref2)
{
    BACKEND *b1 = ((backend_ref_t *)bref1)->bref_backend;
    BACKEND *b2 = ((backend_ref_t *)bref2)->bref_backend;

    return ((b1->backend_server->rlag < b2->backend_server->rlag) ? -1
            : ((b1->backend_server->rlag > b2->backend_server->rlag) ? 1 : 0));
}

/** Compare nunmber of current operations in backend servers */
int bref_cmp_current_load(const void *bref1, const void *bref2)
{
    SERVER *s1 = ((backend_ref_t *)bref1)->bref_backend->backend_server;
    SERVER *s2 = ((backend_ref_t *)bref2)->bref_backend->backend_server;
    BACKEND *b1 = ((backend_ref_t *)bref1)->bref_backend;
    BACKEND *b2 = ((backend_ref_t *)bref2)->bref_backend;

    if (b1->weight == 0 && b2->weight == 0)
    {
        return b1->backend_server->stats.n_current -
               b2->backend_server->stats.n_current;
    }
    else if (b1->weight == 0)
    {
        return 1;
    }
    else if (b2->weight == 0)
    {
        return -1;
    }

    return ((1000 * s1->stats.n_current_ops) - b1->weight) -
           ((1000 * s2->stats.n_current_ops) - b2->weight);
}

static void bref_clear_state(backend_ref_t *bref, bref_state_t state)
{
    if (bref == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return;
    }

    if ((state & BREF_WAITING_RESULT) && (bref->bref_state & BREF_WAITING_RESULT))
    {
        int prev1;
        int prev2;

        /** Decrease waiter count */
        prev1 = atomic_add(&bref->bref_num_result_wait, -1);

        if (prev1 <= 0)
        {
            atomic_add(&bref->bref_num_result_wait, 1);
        }
        else
        {
            /** Decrease global operation count */
            prev2 = atomic_add(&bref->bref_backend->backend_server->stats.n_current_ops, -1);
            ss_dassert(prev2 > 0);
            if (prev2 <= 0)
            {
                MXS_ERROR("[%s] Error: negative current operation count in backend %s:%u",
                          __FUNCTION__, bref->bref_backend->backend_server->name,
                          bref->bref_backend->backend_server->port);
            }
        }
    }

    bref->bref_state &= ~state;
}

static void bref_set_state(backend_ref_t *bref, bref_state_t state)
{
    if (bref == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return;
    }

    if ((state & BREF_WAITING_RESULT) && (bref->bref_state & BREF_WAITING_RESULT) == 0)
    {
        int prev1;
        int prev2;

        /** Increase waiter count */
        prev1 = atomic_add(&bref->bref_num_result_wait, 1);
        ss_dassert(prev1 >= 0);
        if (prev1 < 0)
        {
            MXS_ERROR("[%s] Error: negative number of connections waiting for "
                      "results in backend %s:%u",
                      __FUNCTION__, bref->bref_backend->backend_server->name,
                      bref->bref_backend->backend_server->port);
        }
        /** Increase global operation count */
        prev2 =
            atomic_add(&bref->bref_backend->backend_server->stats.n_current_ops, 1);
        ss_dassert(prev2 >= 0);
        if (prev2 < 0)
        {
            MXS_ERROR("[%s] Error: negative current operation count in backend %s:%u",
                      __FUNCTION__, bref->bref_backend->backend_server->name,
                      bref->bref_backend->backend_server->port);
        }
    }

    bref->bref_state |= state;
}

/**
 * @brief Connect a server
 *
 * Connects to a server, adds callbacks to the created DCB and updates
 * router statistics. If @p execute_history is true, the session command
 * history will be executed on this server.
 *
 * @param b Router's backend structure for the server
 * @param session Client's session object
 * @param execute_history Execute session command history
 * @return True if successful, false if an error occurred
 */
bool connect_server(backend_ref_t *bref, SESSION *session, bool execute_history)
{
    SERVER *serv = bref->bref_backend->backend_server;
    bool rval = false;

    bref->bref_dcb = dcb_connect(serv, session, serv->protocol);

    if (bref->bref_dcb != NULL)
    {
        bref_clear_state(bref, BREF_CLOSED);
        bref->closed_at = 0;

        if (!execute_history || execute_sescmd_history(bref))
        {
            /** Add a callback for unresponsive server */
            dcb_add_callback(bref->bref_dcb, DCB_REASON_NOT_RESPONDING,
                             &router_handle_state_switch, (void *) bref);
            bref->bref_state = 0;
            bref_set_state(bref, BREF_IN_USE);
            atomic_add(&bref->bref_backend->backend_conn_count, 1);
            rval = true;
        }
        else
        {
            MXS_ERROR("Failed to execute session command in %s (%s:%d). See earlier "
                      "errors for more details.",
                      bref->bref_backend->backend_server->unique_name,
                      bref->bref_backend->backend_server->name,
                      bref->bref_backend->backend_server->port);
            RW_CHK_DCB(bref, bref->bref_dcb);
            dcb_close(bref->bref_dcb);
            RW_CLOSE_BREF(bref);
            bref->bref_dcb = NULL;
        }
    }
    else
    {
        MXS_ERROR("Unable to establish connection with server %s:%d",
                  serv->name, serv->port);
    }

    return rval;
}

/**
 * @brief Log server connections
 *
 * @param select_criteria Slave selection criteria
 * @param backend_ref Backend reference array
 * @param router_nservers Number of backends in @p backend_ref
 */
void log_server_connections(select_criteria_t select_criteria,
                            backend_ref_t *backend_ref, int router_nservers)
{
    if (select_criteria == LEAST_GLOBAL_CONNECTIONS ||
        select_criteria == LEAST_ROUTER_CONNECTIONS ||
        select_criteria == LEAST_BEHIND_MASTER ||
        select_criteria == LEAST_CURRENT_OPERATIONS)
    {
        MXS_INFO("Servers and %s connection counts:",
                 select_criteria == LEAST_GLOBAL_CONNECTIONS ? "all MaxScale"
                 : "router");

        for (int i = 0; i < router_nservers; i++)
        {
            BACKEND *b = backend_ref[i].bref_backend;

            switch (select_criteria)
            {
                case LEAST_GLOBAL_CONNECTIONS:
                    MXS_INFO("MaxScale connections : %d in \t%s:%d %s",
                             b->backend_server->stats.n_current, b->backend_server->name,
                             b->backend_server->port, STRSRVSTATUS(b->backend_server));
                    break;

                case LEAST_ROUTER_CONNECTIONS:
                    MXS_INFO("RWSplit connections : %d in \t%s:%d %s",
                             b->backend_conn_count, b->backend_server->name,
                             b->backend_server->port, STRSRVSTATUS(b->backend_server));
                    break;

                case LEAST_CURRENT_OPERATIONS:
                    MXS_INFO("current operations : %d in \t%s:%d %s",
                             b->backend_server->stats.n_current_ops,
                             b->backend_server->name, b->backend_server->port,
                             STRSRVSTATUS(b->backend_server));
                    break;

                case LEAST_BEHIND_MASTER:
                    MXS_INFO("replication lag : %d in \t%s:%d %s",
                             b->backend_server->rlag, b->backend_server->name,
                             b->backend_server->port, STRSRVSTATUS(b->backend_server));
                default:
                    break;
            }
        }
    }
}

/**
 * @brief Check whether it's possible to connect to this server
 *
 * @param bref Backend reference
 * @return True if a connection to this server can be attempted
 */
static bool bref_valid_for_connect(const backend_ref_t *bref)
{
    return !BREF_HAS_FAILED(bref) &&
        SERVER_IS_RUNNING(bref->bref_backend->backend_server);
}

/**
 * Check whether it's possible to use this server as a slave
 *
 * @param bref Backend reference
 * @param master_host The master server
 * @return True if this server is a valid slave candidate
 */
static bool bref_valid_for_slave(const backend_ref_t *bref, const SERVER *master_host)
{
    SERVER *server = bref->bref_backend->backend_server;

    return (SERVER_IS_SLAVE(server) || SERVER_IS_RELAY_SERVER(server)) &&
        (master_host == NULL || (server != master_host));
}

/**
 * @brief Find the best slave candidate
 *
 * This function iterates through @c bref and tries to find the best backend
 * reference that is not in use. @c cmpfun will be called to compare the backends.
 *
 * @param bref Backend reference
 * @param n Size of @c bref
 * @param master The master server
 * @param cmpfun qsort() compatible comparison function
 * @return The best slave backend reference or NULL if no candidates could be found
 */
backend_ref_t* get_slave_candidate(backend_ref_t *bref, int n, const SERVER *master,
                                   int (*cmpfun)(const void *, const void *))
{
    backend_ref_t *candidate = NULL;

    for (int i = 0; i < n; i++)
    {
        if (!BREF_IS_IN_USE(&bref[i]) &&
            bref_valid_for_connect(&bref[i]) &&
            bref_valid_for_slave(&bref[i], master))
        {
            if (candidate)
            {
                if (cmpfun(candidate, &bref[i]) > 0)
                {
                    candidate = &bref[i];
                }
            }
            else
            {
                candidate = &bref[i];
            }
        }
    }

    return candidate;
}

/**
 * @brief Search suitable backend servers from those of router instance
 *
 * It is assumed that there is only one master among servers of a router instance.
 * As a result, the first master found is chosen. There will possibly be more
 * backend references than connected backends because only those in correct state
 * are connected to.
 *
 * @param p_master_ref Pointer to location where master's backend reference is to  be stored
 * @param backend_ref Pointer to backend server reference object array
 * @param router_nservers Number of backend server pointers pointed to by @p backend_ref
 * @param max_nslaves Upper limit for the number of slaves
 * @param max_slave_rlag Maximum allowed replication lag for any slave
 * @param select_criteria Slave selection criteria
 * @param session Client session
 * @param router Router instance
 * @return true, if at least one master and one slave was found.
 */
static bool select_connect_backend_servers(backend_ref_t **p_master_ref,
                                           backend_ref_t *backend_ref,
                                           int router_nservers, int max_nslaves,
                                           int max_slave_rlag,
                                           select_criteria_t select_criteria,
                                           SESSION *session,
                                           ROUTER_INSTANCE *router,
                                           bool active_session)
{
    if (p_master_ref == NULL || backend_ref == NULL)
    {
        MXS_ERROR("Master reference (%p) or backend reference (%p) is NULL.",
                  p_master_ref, backend_ref);
        ss_dassert(false);
        return false;
    }

    /* get the root Master */
    BACKEND *master_backend = get_root_master(backend_ref, router_nservers);
    SERVER  *master_host = master_backend ? master_backend->backend_server : NULL;

    if (router->rwsplit_config.rw_master_failure_mode == RW_FAIL_INSTANTLY &&
        (master_host == NULL || SERVER_IS_DOWN(master_host)))
    {
        MXS_ERROR("Couldn't find suitable Master from %d candidates.", router_nservers);
        return false;
    }

    /**
     * New session:
     *
     * Connect to both master and slaves
     *
     * Existing session:
     *
     * Master is already connected or we don't have a master. The function was
     * called because new slaves must be selected to replace failed ones.
     */
    bool master_connected = active_session || *p_master_ref != NULL;

    /** Check slave selection criteria and set compare function */
    int (*p)(const void *, const void *) = criteria_cmpfun[select_criteria];
    ss_dassert(p);

    SERVER *old_master = *p_master_ref ? (*p_master_ref)->bref_backend->backend_server : NULL;

    if (MXS_LOG_PRIORITY_IS_ENABLED(LOG_INFO))
    {
        log_server_connections(select_criteria, backend_ref, router_nservers);
    }

    int slaves_found = 0;
    int slaves_connected = 0;
    const int min_nslaves = 0; /*< not configurable at the time */
    bool succp = false;

    if (!master_connected)
    {
        /** Find a master server */
        for (int i = 0; i < router_nservers; i++)
        {
            SERVER *serv = backend_ref[i].bref_backend->backend_server;

            if (bref_valid_for_connect(&backend_ref[i]) &&
                master_host && serv == master_host)
            {
                if (connect_server(&backend_ref[i], session, false))
                {
                    *p_master_ref = &backend_ref[i];
                    break;
                }
            }
        }
    }

    /** Calculate how many connections we already have */
    for (int i = 0; i < router_nservers; i++)
    {
        if (bref_valid_for_connect(&backend_ref[i]) &&
            bref_valid_for_slave(&backend_ref[i], master_host))
        {
            slaves_found += 1;

            if (BREF_IS_IN_USE(&backend_ref[i]))
            {
                slaves_connected += 1;
            }
        }
    }

    ss_dassert(slaves_connected < max_nslaves || max_nslaves == 0);

    if (max_nslaves > 0 && slaves_connected == max_nslaves)
    {
        MXS_ERROR("Unexpected reconnection of slave servers. Found %d slaves with "
                  "a maximum of %d connected slaves.", slaves_found, max_nslaves);
    }

    backend_ref_t *bref = get_slave_candidate(backend_ref, router_nservers, master_host, p);

    /** Connect to all possible slaves */
    while (bref && slaves_connected < max_nslaves)
    {
        if (connect_server(bref, session, true))
        {
            slaves_connected += 1;
        }
        else
        {
            /** Failed to connect, mark server as failed */
            bref_set_state(bref, BREF_FATAL_FAILURE);
        }

        bref = get_slave_candidate(backend_ref, router_nservers, master_host, p);
    }

    /**
     * Successful cases
     */
    if (slaves_connected >= min_nslaves && slaves_connected <= max_nslaves)
    {
        succp = true;

        if (MXS_LOG_PRIORITY_IS_ENABLED(LOG_INFO))
        {
            if (slaves_connected < max_nslaves)
            {
                MXS_INFO("Couldn't connect to maximum number of "
                         "slaves. Connected successfully to %d slaves "
                         "of %d of them.", slaves_connected, slaves_found);
            }

            for (int i = 0; i < router_nservers; i++)
            {
                if (BREF_IS_IN_USE((&backend_ref[i])))
                {
                    MXS_INFO("Selected %s in \t%s:%d",
                             STRSRVSTATUS(backend_ref[i].bref_backend->backend_server),
                             backend_ref[i].bref_backend->backend_server->name,
                             backend_ref[i].bref_backend->backend_server->port);
                }
            } /* for */
        }
    }
        /** Failure cases */
    else
    {
        MXS_ERROR("Couldn't establish required amount of slave connections for "
                  "router session. Would need between %d and %d slaves but only have %d.",
                  min_nslaves, max_nslaves, slaves_connected);

        /** Clean up connections */
        for (int i = 0; i < router_nservers; i++)
        {
            if (BREF_IS_IN_USE((&backend_ref[i])))
            {
                ss_dassert(backend_ref[i].bref_backend->backend_conn_count > 0);

                close_failed_bref(&backend_ref[i], true);

                /** Decrease backend's connection counter. */
                atomic_add(&backend_ref[i].bref_backend->backend_conn_count, -1);
                RW_CHK_DCB(&backend_ref[i], backend_ref[i].bref_dcb);
                dcb_close(backend_ref[i].bref_dcb);
                RW_CLOSE_BREF(&backend_ref[i]);
            }
        }
    }

    return succp;
}

/**
 * Create a generic router session property strcture.
 */
static rses_property_t *rses_property_init(rses_property_type_t prop_type)
{
    rses_property_t *prop;

    prop = (rses_property_t *)calloc(1, sizeof(rses_property_t));
    if (prop == NULL)
    {
        MXS_ERROR("Error: Malloc returned NULL. (%s:%d)", __FILE__, __LINE__);
        return NULL;
    }
    prop->rses_prop_type = prop_type;
#if defined(SS_DEBUG)
    prop->rses_prop_chk_top = CHK_NUM_ROUTER_PROPERTY;
    prop->rses_prop_chk_tail = CHK_NUM_ROUTER_PROPERTY;
#endif

    CHK_RSES_PROP(prop);
    return prop;
}

/**
 * Property is freed at the end of router client session.
 */
static void rses_property_done(rses_property_t *prop)
{
    if (prop == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return;
    }
    CHK_RSES_PROP(prop);

    switch (prop->rses_prop_type)
    {
        case RSES_PROP_TYPE_SESCMD:
            mysql_sescmd_done(&prop->rses_prop_data.sescmd);
            break;

        case RSES_PROP_TYPE_TMPTABLES:
            hashtable_free(prop->rses_prop_data.temp_tables);
            break;

        default:
            MXS_DEBUG("%lu [rses_property_done] Unknown property type %d "
                      "in property %p", pthread_self(), prop->rses_prop_type, prop);

            ss_dassert(false);
            break;
    }
    free(prop);
}

/**
 * Add property to the router_client_ses structure's rses_properties
 * array. The slot is determined by the type of property.
 * In each slot there is a list of properties of similar type.
 *
 * Router client session must be locked.
 */
static int rses_property_add(ROUTER_CLIENT_SES *rses, rses_property_t *prop)
{
    if (rses == NULL)
    {
        MXS_ERROR("Router client session is NULL. (%s:%d)", __FILE__, __LINE__);
        return -1;
    }
    if (prop == NULL)
    {
        MXS_ERROR("Router client session property is NULL. (%s:%d)", __FILE__, __LINE__);
        return -1;
    }
    rses_property_t *p;

    CHK_CLIENT_RSES(rses);
    CHK_RSES_PROP(prop);
    ss_dassert(SPINLOCK_IS_LOCKED(&rses->rses_lock));

    prop->rses_prop_rsession = rses;
    p = rses->rses_properties[prop->rses_prop_type];

    if (p == NULL)
    {
        rses->rses_properties[prop->rses_prop_type] = prop;
    }
    else
    {
        while (p->rses_prop_next != NULL)
        {
            p = p->rses_prop_next;
        }
        p->rses_prop_next = prop;
    }
    return 0;
}

/**
 * Router session must be locked.
 * Return session command pointer if succeed, NULL if failed.
 */
static mysql_sescmd_t *rses_property_get_sescmd(rses_property_t *prop)
{
    mysql_sescmd_t *sescmd;

    if (prop == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return NULL;
    }

    CHK_RSES_PROP(prop);
    ss_dassert(prop->rses_prop_rsession == NULL ||
               SPINLOCK_IS_LOCKED(&prop->rses_prop_rsession->rses_lock));

    sescmd = &prop->rses_prop_data.sescmd;

    if (sescmd != NULL)
    {
        CHK_MYSQL_SESCMD(sescmd);
    }
    return sescmd;
}

/**
 * Create session command property.
 */
static mysql_sescmd_t *mysql_sescmd_init(rses_property_t *rses_prop,
                                         GWBUF *sescmd_buf,
                                         unsigned char packet_type,
                                         ROUTER_CLIENT_SES *rses)
{
    mysql_sescmd_t *sescmd;

    CHK_RSES_PROP(rses_prop);
    /** Can't call rses_property_get_sescmd with uninitialized sescmd */
    sescmd = &rses_prop->rses_prop_data.sescmd;
    sescmd->my_sescmd_prop = rses_prop; /*< reference to owning property */
#if defined(SS_DEBUG)
    sescmd->my_sescmd_chk_top = CHK_NUM_MY_SESCMD;
    sescmd->my_sescmd_chk_tail = CHK_NUM_MY_SESCMD;
#endif
    /** Set session command buffer */
    sescmd->my_sescmd_buf = sescmd_buf;
    sescmd->my_sescmd_packet_type = packet_type;
    sescmd->position = atomic_add(&rses->pos_generator, 1);

    return sescmd;
}

static void mysql_sescmd_done(mysql_sescmd_t *sescmd)
{
    if (sescmd == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return;
    }
    CHK_RSES_PROP(sescmd->my_sescmd_prop);
    gwbuf_free(sescmd->my_sescmd_buf);
    memset(sescmd, 0, sizeof(mysql_sescmd_t));
}

/**
 * All cases where backend message starts at least with one response to session
 * command are handled here.
 * Read session commands from property list. If command is already replied,
 * discard packet. Else send reply to client. In both cases move cursor forward
 * until all session command replies are handled.
 *
 * Cases that are expected to happen and which are handled:
 * s = response not yet replied to client, S = already replied response,
 * q = query
 * 1. q+        for example : select * from mysql.user
 * 2. s+        for example : set autocommit=1
 * 3. S+
 * 4. sq+
 * 5. Sq+
 * 6. Ss+
 * 7. Ss+q+
 * 8. S+q+
 * 9. s+q+
 */
static GWBUF *sescmd_cursor_process_replies(GWBUF *replybuf,
                                            backend_ref_t *bref,
                                            bool *reconnect)
{
    mysql_sescmd_t *scmd;
    sescmd_cursor_t *scur;
    ROUTER_CLIENT_SES *ses;

    scur = &bref->bref_sescmd_cur;
    ss_dassert(SPINLOCK_IS_LOCKED(&(scur->scmd_cur_rses->rses_lock)));
    scmd = sescmd_cursor_get_command(scur);
    ses = (*scur->scmd_cur_ptr_property)->rses_prop_rsession;
    CHK_GWBUF(replybuf);

    /**
     * Walk through packets in the message and the list of session
     * commands.
     */
    while (scmd != NULL && replybuf != NULL)
    {
        bref->reply_cmd = *((unsigned char *)replybuf->start + 4);
        scur->position = scmd->position;
        /** Faster backend has already responded to client : discard */
        if (scmd->my_sescmd_is_replied)
        {
            bool last_packet = false;

            CHK_GWBUF(replybuf);

            while (!last_packet)
            {
                int buflen;

                buflen = GWBUF_LENGTH(replybuf);
                last_packet = GWBUF_IS_TYPE_RESPONSE_END(replybuf);
                /** discard packet */
                replybuf = gwbuf_consume(replybuf, buflen);
            }
            /** Set response status received */
            bref_clear_state(bref, BREF_WAITING_RESULT);

            if (bref->reply_cmd != scmd->reply_cmd && BREF_IS_IN_USE(bref))
            {
                MXS_ERROR("Slave server '%s': response differs from master's response. "
                          "Closing connection due to inconsistent session state.",
                          bref->bref_backend->backend_server->unique_name);

                close_failed_bref(bref, true);

                if (bref->bref_dcb)
                {
                    RW_CHK_DCB(bref, bref->bref_dcb);
                    dcb_close(bref->bref_dcb);
                    RW_CLOSE_BREF(bref);
                }
                *reconnect = true;
                gwbuf_free(replybuf);
                replybuf = NULL;
            }
        }
        /** This is a response from the master and it is the "right" one.
         * A slave server's response will be compared to this and if
         * their response differs from the master server's response, they
         * are dropped from the valid list of backend servers.
         * Response is in the buffer and it will be sent to client.
         *
         * If we have no master server, the first slave's response is considered
         * the "right" one. */
        else if (ses->rses_master_ref == NULL ||
                 !BREF_IS_IN_USE(ses->rses_master_ref) ||
                 ses->rses_master_ref->bref_dcb == bref->bref_dcb)
        {
            /** Mark the rest session commands as replied */
            scmd->my_sescmd_is_replied = true;
            scmd->reply_cmd = *((unsigned char *)replybuf->start + 4);

            MXS_INFO("Server '%s' responded to a session command, sending the response "
                     "to the client.", bref->bref_backend->backend_server->unique_name);

            for (int i = 0; i < ses->rses_nbackends; i++)
            {
                if (!BREF_IS_WAITING_RESULT(&ses->rses_backend_ref[i]))
                {
                    /** This backend has already received a response */
                    if (ses->rses_backend_ref[i].reply_cmd != scmd->reply_cmd &&
                        !BREF_IS_CLOSED(&ses->rses_backend_ref[i]) &&
                        BREF_IS_IN_USE(&ses->rses_backend_ref[i]))
                    {

                        close_failed_bref(&ses->rses_backend_ref[i], true);

                        if (ses->rses_backend_ref[i].bref_dcb)
                        {
                            RW_CHK_DCB(&ses->rses_backend_ref[i], ses->rses_backend_ref[i].bref_dcb);
                            dcb_close(ses->rses_backend_ref[i].bref_dcb);
                            RW_CLOSE_BREF(&ses->rses_backend_ref[i]);
                        }
                        *reconnect = true;
                        MXS_WARNING("Disabling slave %s:%d, result differs from "
                                    "master's result. Master: %0x Slave: %0x",
                                    ses->rses_backend_ref[i].bref_backend->backend_server->name,
                                    ses->rses_backend_ref[i].bref_backend->backend_server->port,
                                    bref->reply_cmd, ses->rses_backend_ref[i].reply_cmd);
                    }
                }
            }

        }
        else
        {
            MXS_INFO("Slave '%s' responded before master to a session command. Result: %d",
                     bref->bref_backend->backend_server->unique_name,
                     (int)bref->reply_cmd);
            if (bref->reply_cmd == 0xff)
            {
                SERVER *serv = bref->bref_backend->backend_server;
                MXS_ERROR("Slave '%s' (%s:%u) failed to execute session command.",
                          serv->unique_name, serv->name, serv->port);
            }

            gwbuf_free(replybuf);
            replybuf = NULL;
        }

        if (sescmd_cursor_next(scur))
        {
            scmd = sescmd_cursor_get_command(scur);
        }
        else
        {
            scmd = NULL;
            /** All session commands are replied */
            scur->scmd_cur_active = false;
        }
    }
    ss_dassert(replybuf == NULL || *scur->scmd_cur_ptr_property == NULL);

    return replybuf;
}

/**
 * Get the address of current session command.
 *
 * Router session must be locked */
static mysql_sescmd_t *sescmd_cursor_get_command(sescmd_cursor_t *scur)
{
    mysql_sescmd_t *scmd;

    ss_dassert(SPINLOCK_IS_LOCKED(&(scur->scmd_cur_rses->rses_lock)));
    scur->scmd_cur_cmd = rses_property_get_sescmd(*scur->scmd_cur_ptr_property);

    CHK_MYSQL_SESCMD(scur->scmd_cur_cmd);

    scmd = scur->scmd_cur_cmd;

    return scmd;
}

/** router must be locked */
static bool sescmd_cursor_is_active(sescmd_cursor_t *sescmd_cursor)
{
    bool succp;

    if (sescmd_cursor == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return false;
    }
    ss_dassert(SPINLOCK_IS_LOCKED(&sescmd_cursor->scmd_cur_rses->rses_lock));

    succp = sescmd_cursor->scmd_cur_active;
    return succp;
}

/** router must be locked */
static void sescmd_cursor_set_active(sescmd_cursor_t *sescmd_cursor,
                                     bool value)
{
    ss_dassert(SPINLOCK_IS_LOCKED(&sescmd_cursor->scmd_cur_rses->rses_lock));
    /** avoid calling unnecessarily */
    ss_dassert(sescmd_cursor->scmd_cur_active != value);
    sescmd_cursor->scmd_cur_active = value;
}

/**
 * Clone session command's command buffer.
 * Router session must be locked
 */
static GWBUF *sescmd_cursor_clone_querybuf(sescmd_cursor_t *scur)
{
    GWBUF *buf;
    if (scur == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return NULL;
    }
    ss_dassert(scur->scmd_cur_cmd != NULL);

    buf = gwbuf_clone_all(scur->scmd_cur_cmd->my_sescmd_buf);

    CHK_GWBUF(buf);
    return buf;
}

static bool sescmd_cursor_history_empty(sescmd_cursor_t *scur)
{
    bool succp;

    if (scur == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return true;
    }
    CHK_SESCMD_CUR(scur);

    if (scur->scmd_cur_rses->rses_properties[RSES_PROP_TYPE_SESCMD] == NULL)
    {
        succp = true;
    }
    else
    {
        succp = false;
    }

    return succp;
}

static void sescmd_cursor_reset(sescmd_cursor_t *scur)
{
    ROUTER_CLIENT_SES *rses;
    if (scur == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return;
    }
    CHK_SESCMD_CUR(scur);
    CHK_CLIENT_RSES(scur->scmd_cur_rses);
    rses = scur->scmd_cur_rses;

    scur->scmd_cur_ptr_property = &rses->rses_properties[RSES_PROP_TYPE_SESCMD];

    CHK_RSES_PROP((*scur->scmd_cur_ptr_property));
    scur->scmd_cur_active = false;
    scur->scmd_cur_cmd = &(*scur->scmd_cur_ptr_property)->rses_prop_data.sescmd;
}

static bool execute_sescmd_history(backend_ref_t *bref)
{
    bool succp = true;
    sescmd_cursor_t *scur;
    if (bref == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return false;
    }
    CHK_BACKEND_REF(bref);

    scur = &bref->bref_sescmd_cur;
    CHK_SESCMD_CUR(scur);

    if (!sescmd_cursor_history_empty(scur))
    {
        sescmd_cursor_reset(scur);
        succp = execute_sescmd_in_backend(bref);
    }

    return succp;
}

/**
 * If session command cursor is passive, sends the command to backend for
 * execution.
 *
 * Returns true if command was sent or added successfully to the queue.
 * Returns false if command sending failed or if there are no pending session
 *  commands.
 *
 * Router session must be locked.
 */
static bool execute_sescmd_in_backend(backend_ref_t *backend_ref)
{
    DCB *dcb;
    bool succp;
    int rc = 0;
    sescmd_cursor_t *scur;
    GWBUF *buf;
    if (backend_ref == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return false;
    }
    if (BREF_IS_CLOSED(backend_ref))
    {
        succp = false;
        goto return_succp;
    }
    dcb = backend_ref->bref_dcb;

    CHK_DCB(dcb);
    CHK_BACKEND_REF(backend_ref);

    /**
     * Get cursor pointer and copy of command buffer to cursor.
     */
    scur = &backend_ref->bref_sescmd_cur;

    /** Return if there are no pending ses commands */
    if (sescmd_cursor_get_command(scur) == NULL)
    {
        succp = true;
        MXS_INFO("Cursor had no pending session commands.");

        goto return_succp;
    }

    if (!sescmd_cursor_is_active(scur))
    {
        /** Cursor is left active when function returns. */
        sescmd_cursor_set_active(scur, true);
    }

    switch (scur->scmd_cur_cmd->my_sescmd_packet_type)
    {
        case MYSQL_COM_CHANGE_USER:
            /** This makes it possible to handle replies correctly */
            gwbuf_set_type(scur->scmd_cur_cmd->my_sescmd_buf, GWBUF_TYPE_SESCMD);
            buf = sescmd_cursor_clone_querybuf(scur);
            rc = dcb->func.auth(dcb, NULL, dcb->session, buf);
            break;

        case MYSQL_COM_INIT_DB:
        {
            /**
             * Record database name and store to session.
             */
            GWBUF *tmpbuf;
            MYSQL_session *data;
            unsigned int qlen;

            data = dcb->session->client_dcb->data;
            tmpbuf = scur->scmd_cur_cmd->my_sescmd_buf;
            qlen = MYSQL_GET_PACKET_LEN((unsigned char *)tmpbuf->start);
            memset(data->db, 0, MYSQL_DATABASE_MAXLEN + 1);
            if (qlen > 0 && qlen < MYSQL_DATABASE_MAXLEN + 1)
            {
                strncpy(data->db, tmpbuf->start + 5, qlen - 1);
            }
        }
        /** Fallthrough */
        case MYSQL_COM_QUERY:
        default:
            /**
             * Mark session command buffer, it triggers writing
             * MySQL command to protocol
             */

            gwbuf_set_type(scur->scmd_cur_cmd->my_sescmd_buf, GWBUF_TYPE_SESCMD);
            buf = sescmd_cursor_clone_querybuf(scur);
            rc = dcb->func.write(dcb, buf);
            break;
    }

    if (rc == 1)
    {
        succp = true;
    }
    else
    {
        succp = false;
    }
return_succp:
    return succp;
}

/**
 * Moves cursor to next property and copied address of its sescmd to cursor.
 * Current propery must be non-null.
 * If current property is the last on the list, *scur->scmd_ptr_property == NULL
 *
 * Router session must be locked
 */
static bool sescmd_cursor_next(sescmd_cursor_t *scur)
{
    bool succp = false;
    rses_property_t *prop_curr;
    rses_property_t *prop_next;

    if (scur == NULL)
    {
        MXS_ERROR("[%s] Error: NULL parameter.", __FUNCTION__);
        return false;
    }

    ss_dassert(scur != NULL);
    ss_dassert(*(scur->scmd_cur_ptr_property) != NULL);
    ss_dassert(SPINLOCK_IS_LOCKED(
                   &(*(scur->scmd_cur_ptr_property))->rses_prop_rsession->rses_lock));

    /** Illegal situation */
    if (scur == NULL || *scur->scmd_cur_ptr_property == NULL ||
        scur->scmd_cur_cmd == NULL)
    {
        /** Log error */
        goto return_succp;
    }
    prop_curr = *(scur->scmd_cur_ptr_property);

    CHK_MYSQL_SESCMD(scur->scmd_cur_cmd);
    ss_dassert(prop_curr == mysql_sescmd_get_property(scur->scmd_cur_cmd));
    CHK_RSES_PROP(prop_curr);

    /** Copy address of pointer to next property */
    scur->scmd_cur_ptr_property = &(prop_curr->rses_prop_next);
    prop_next = *scur->scmd_cur_ptr_property;
    ss_dassert(prop_next == *(scur->scmd_cur_ptr_property));

    /** If there is a next property move forward */
    if (prop_next != NULL)
    {
        CHK_RSES_PROP(prop_next);
        CHK_RSES_PROP((*(scur->scmd_cur_ptr_property)));

        /** Get pointer to next property's sescmd */
        scur->scmd_cur_cmd = rses_property_get_sescmd(prop_next);

        ss_dassert(prop_next == scur->scmd_cur_cmd->my_sescmd_prop);
        CHK_MYSQL_SESCMD(scur->scmd_cur_cmd);
        CHK_RSES_PROP(scur->scmd_cur_cmd->my_sescmd_prop);
    }
    else
    {
        /** No more properties, can't proceed. */
        goto return_succp;
    }

    if (scur->scmd_cur_cmd != NULL)
    {
        succp = true;
    }
    else
    {
        ss_dassert(false); /*< Log error, sescmd shouldn't be NULL */
    }
return_succp:
    return succp;
}

static rses_property_t *mysql_sescmd_get_property(mysql_sescmd_t *scmd)
{
    CHK_MYSQL_SESCMD(scmd);
    return scmd->my_sescmd_prop;
}

static void tracelog_routed_query(ROUTER_CLIENT_SES *rses, char *funcname,
                                  backend_ref_t *bref, GWBUF *buf)
{
    uint8_t *packet = GWBUF_DATA(buf);
    unsigned char packet_type = packet[4];
    size_t len;
    size_t buflen = GWBUF_LENGTH(buf);
    char *querystr;
    char *startpos = (char *)&packet[5];
    BACKEND *b;
    backend_type_t be_type;
    DCB *dcb;

    CHK_BACKEND_REF(bref);
    b = bref->bref_backend;
    CHK_BACKEND(b);
    dcb = bref->bref_dcb;
    CHK_DCB(dcb);

    be_type = BACKEND_TYPE(b);

    if (GWBUF_IS_TYPE_MYSQL(buf))
    {
        len = packet[0];
        len += 256 * packet[1];
        len += 256 * 256 * packet[2];

        if (packet_type == '\x03')
        {
            querystr = (char *)malloc(len);
            memcpy(querystr, startpos, len - 1);
            querystr[len - 1] = '\0';
            MXS_DEBUG("%lu [%s] %d bytes long buf, \"%s\" -> %s:%d %s dcb %p",
                      pthread_self(), funcname, (int)buflen, querystr,
                      b->backend_server->name, b->backend_server->port,
                      STRBETYPE(be_type), dcb);
            free(querystr);
        }
        else if (packet_type == '\x22' || packet_type == 0x22 ||
                 packet_type == '\x26' || packet_type == 0x26 || true)
        {
            querystr = (char *)malloc(len);
            memcpy(querystr, startpos, len - 1);
            querystr[len - 1] = '\0';
            MXS_DEBUG("%lu [%s] %d bytes long buf, \"%s\" -> %s:%d %s dcb %p",
                      pthread_self(), funcname, (int)buflen, querystr,
                      b->backend_server->name, b->backend_server->port,
                      STRBETYPE(be_type), dcb);
            free(querystr);
        }
    }
    gwbuf_free(buf);
}

/**
 * Return RCAP_TYPE_STMT_INPUT.
 */
static int getCapabilities()
{
    return RCAP_TYPE_STMT_INPUT;
}

/**
 * Execute in backends used by current router session.
 * Save session variable commands to router session property
 * struct. Thus, they can be replayed in backends which are
 * started and joined later.
 *
 * Suppress redundant OK packets sent by backends.
 *
 * The first OK packet is replied to the client.
 *
 * @param router_cli_ses    Client's router session pointer
 * @param querybuf      GWBUF including the query to be routed
 * @param inst          Router instance
 * @param packet_type       Type of MySQL packet
 * @param qtype         Query type from query_classifier
 *
 * @return True if at least one backend is used and routing succeed to all
 * backends being used, otherwise false.
 *
 */
static bool route_session_write(ROUTER_CLIENT_SES *router_cli_ses,
                                GWBUF *querybuf, ROUTER_INSTANCE *inst,
                                unsigned char packet_type,
                                qc_query_type_t qtype)
{
    bool succp;
    rses_property_t *prop;
    backend_ref_t *backend_ref;
    int i;
    int max_nslaves;
    int nbackends;
    int nsucc;

    MXS_INFO("Session write, routing to all servers.");
    /** Maximum number of slaves in this router client session */
    max_nslaves =
        rses_get_max_slavecount(router_cli_ses, router_cli_ses->rses_nbackends);
    nsucc = 0;
    nbackends = 0;
    backend_ref = router_cli_ses->rses_backend_ref;

    /**
     * These are one-way messages and server doesn't respond to them.
     * Therefore reply processing is unnecessary and session
     * command property is not needed. It is just routed to all available
     * backends.
     */
    if (packet_type == MYSQL_COM_STMT_SEND_LONG_DATA ||
        packet_type == MYSQL_COM_QUIT || packet_type == MYSQL_COM_STMT_CLOSE)
    {
        int rc;

        /** Lock router session */
        if (!rses_begin_locked_router_action(router_cli_ses))
        {
            goto return_succp;
        }

        for (i = 0; i < router_cli_ses->rses_nbackends; i++)
        {
            DCB *dcb = backend_ref[i].bref_dcb;

            if (MXS_LOG_PRIORITY_IS_ENABLED(LOG_INFO) &&
                BREF_IS_IN_USE((&backend_ref[i])))
            {
                MXS_INFO("Route query to %s \t%s:%d%s",
                         (SERVER_IS_MASTER(backend_ref[i].bref_backend->backend_server)
                          ? "master" : "slave"),
                         backend_ref[i].bref_backend->backend_server->name,
                         backend_ref[i].bref_backend->backend_server->port,
                         (i + 1 == router_cli_ses->rses_nbackends ? " <" : " "));
            }

            if (BREF_IS_IN_USE((&backend_ref[i])))
            {
                nbackends += 1;
                if ((rc = dcb->func.write(dcb, gwbuf_clone(querybuf))) == 1)
                {
                    nsucc += 1;
                }
            }
        }
        rses_end_locked_router_action(router_cli_ses);
        gwbuf_free(querybuf);
        goto return_succp;
    }
    /** Lock router session */
    if (!rses_begin_locked_router_action(router_cli_ses))
    {
        goto return_succp;
    }

    if (router_cli_ses->rses_nbackends <= 0)
    {
        MXS_INFO("Router session doesn't have any backends in use. Routing failed. <");
        goto return_succp;
    }

    if (router_cli_ses->rses_config.rw_max_sescmd_history_size > 0 &&
        router_cli_ses->rses_nsescmd >=
        router_cli_ses->rses_config.rw_max_sescmd_history_size)
    {
        MXS_WARNING("Router session exceeded session command history limit. "
                    "Slave recovery is disabled and only slave servers with "
                    "consistent session state are used "
                    "for the duration of the session.");
        router_cli_ses->rses_config.rw_disable_sescmd_hist = true;
        router_cli_ses->rses_config.rw_max_sescmd_history_size = 0;
    }

    if (router_cli_ses->rses_config.rw_disable_sescmd_hist)
    {
        rses_property_t *prop, *tmp;
        backend_ref_t *bref;
        bool conflict;

        prop = router_cli_ses->rses_properties[RSES_PROP_TYPE_SESCMD];
        while (prop)
        {
            conflict = false;

            for (i = 0; i < router_cli_ses->rses_nbackends; i++)
            {
                bref = &backend_ref[i];
                if (BREF_IS_IN_USE(bref))
                {

                    if (bref->bref_sescmd_cur.position <=
                        prop->rses_prop_data.sescmd.position + 1)
                    {
                        conflict = true;
                        break;
                    }
                }
            }

            if (conflict)
            {
                break;
            }

            tmp = prop;
            router_cli_ses->rses_properties[RSES_PROP_TYPE_SESCMD] = prop->rses_prop_next;
            rses_property_done(tmp);
            prop = router_cli_ses->rses_properties[RSES_PROP_TYPE_SESCMD];
        }
    }

    /**
     * Additional reference is created to querybuf to
     * prevent it from being released before properties
     * are cleaned up as a part of router sessionclean-up.
     */
    if ((prop = rses_property_init(RSES_PROP_TYPE_SESCMD)) == NULL)
    {
        MXS_ERROR("Router session property initialization failed");
        rses_end_locked_router_action(router_cli_ses);
        return false;
    }

    mysql_sescmd_init(prop, querybuf, packet_type, router_cli_ses);

    /** Add sescmd property to router client session */
    if (rses_property_add(router_cli_ses, prop) != 0)
    {
        MXS_ERROR("Session property addition failed.");
        rses_end_locked_router_action(router_cli_ses);
        return false;
    }

    for (i = 0; i < router_cli_ses->rses_nbackends; i++)
    {
        if (BREF_IS_IN_USE((&backend_ref[i])))
        {
            sescmd_cursor_t *scur;

            nbackends += 1;

            if (MXS_LOG_PRIORITY_IS_ENABLED(LOG_INFO))
            {
                MXS_INFO("Route query to %s \t%s:%d%s",
                         (SERVER_IS_MASTER(backend_ref[i].bref_backend->backend_server)
                          ? "master" : "slave"),
                         backend_ref[i].bref_backend->backend_server->name,
                         backend_ref[i].bref_backend->backend_server->port,
                         (i + 1 == router_cli_ses->rses_nbackends ? " <" : " "));
            }

            scur = backend_ref_get_sescmd_cursor(&backend_ref[i]);

            /**
             * Add one waiter to backend reference.
             */
            bref_set_state(get_bref_from_dcb(router_cli_ses, backend_ref[i].bref_dcb),
                           BREF_WAITING_RESULT);
            /**
             * Start execution if cursor is not already executing.
             * Otherwise, cursor will execute pending commands
             * when it completes with previous commands.
             */
            if (sescmd_cursor_is_active(scur))
            {
                nsucc += 1;
                MXS_INFO("Backend %s:%d already executing sescmd.",
                         backend_ref[i].bref_backend->backend_server->name,
                         backend_ref[i].bref_backend->backend_server->port);
            }
            else
            {
                if (execute_sescmd_in_backend(&backend_ref[i]))
                {
                    nsucc += 1;
                }
                else
                {
                    MXS_ERROR("Failed to execute session command in %s:%d",
                              backend_ref[i].bref_backend->backend_server->name,
                              backend_ref[i].bref_backend->backend_server->port);
                }
            }
        }
    }

    atomic_add(&router_cli_ses->rses_nsescmd, 1);

    /** Unlock router session */
    rses_end_locked_router_action(router_cli_ses);

return_succp:
    /**
     * Routing must succeed to all backends that are used.
     * There must be at leas one and at most max_nslaves+1 backends.
     */
    succp = (nbackends > 0 && nsucc == nbackends && nbackends <= max_nslaves + 1);
    return succp;
}

#if defined(NOT_USED)

static bool router_option_configured(ROUTER_INSTANCE *router,
                                     const char *optionstr, void *data)
{
    bool succp = false;
    char **option;

    option = router->service->routerOptions;

    while (option != NULL)
    {
        char *value;

        if ((value = strchr(options[i], '=')) == NULL)
        {
            break;
        }
        else
        {
            *value = 0;
            value++;
            if (strcmp(options[i], "slave_selection_criteria") == 0)
            {
                if (GET_SELECT_CRITERIA(value) == (select_criteria_t *)*data)
                {
                    succp = true;
                    break;
                }
            }
        }
    }
    return succp;
}
#endif /*< NOT_USED */

/**
 * @brief Process router options
 *
 * @param router Router instance
 * @param options Router options
 * @return True on success, false if a configuration error was found
 */
static bool rwsplit_process_router_options(ROUTER_INSTANCE *router,
                                           char **options)
{
    int i;
    char *value;
    select_criteria_t c;

    if (options == NULL)
    {
        return true;
    }

    bool success = true;

    for (i = 0; options[i]; i++)
    {
        if ((value = strchr(options[i], '=')) == NULL)
        {
            MXS_ERROR("Unsupported router option \"%s\" for readwritesplit router.", options[i]);
            success = false;
        }
        else
        {
            *value = 0;
            value++;
            if (strcmp(options[i], "slave_selection_criteria") == 0)
            {
                c = GET_SELECT_CRITERIA(value);
                ss_dassert(c == LEAST_GLOBAL_CONNECTIONS ||
                           c == LEAST_ROUTER_CONNECTIONS || c == LEAST_BEHIND_MASTER ||
                           c == LEAST_CURRENT_OPERATIONS || c == UNDEFINED_CRITERIA);

                if (c == UNDEFINED_CRITERIA)
                {
                    MXS_ERROR("Unknown slave selection criteria \"%s\". "
                                "Allowed values are LEAST_GLOBAL_CONNECTIONS, "
                                "LEAST_ROUTER_CONNECTIONS, LEAST_BEHIND_MASTER,"
                                "and LEAST_CURRENT_OPERATIONS.",
                                STRCRITERIA(router->rwsplit_config.rw_slave_select_criteria));
                    success = false;
                }
                else
                {
                    router->rwsplit_config.rw_slave_select_criteria = c;
                }
            }
            else if (strcmp(options[i], "max_sescmd_history") == 0)
            {
                router->rwsplit_config.rw_max_sescmd_history_size = atoi(value);
            }
            else if (strcmp(options[i], "disable_sescmd_history") == 0)
            {
                router->rwsplit_config.rw_disable_sescmd_hist = config_truth_value(value);
            }
            else if (strcmp(options[i], "master_accept_reads") == 0)
            {
                router->rwsplit_config.rw_master_reads = config_truth_value(value);
            }
            else if (strcmp(options[i], "strict_multi_stmt") == 0)
            {
                router->rwsplit_config.rw_strict_multi_stmt = config_truth_value(value);
            }
            else if (strcmp(options[i], "master_failure_mode") == 0)
            {
                if (strcasecmp(value, "fail_instantly") == 0)
                {
                    router->rwsplit_config.rw_master_failure_mode = RW_FAIL_INSTANTLY;
                }
                else if (strcasecmp(value, "fail_on_write") == 0)
                {
                    router->rwsplit_config.rw_master_failure_mode = RW_FAIL_ON_WRITE;
                }
                else if (strcasecmp(value, "error_on_write") == 0)
                {
                    router->rwsplit_config.rw_master_failure_mode = RW_ERROR_ON_WRITE;
                }
                else
                {
                    MXS_ERROR("Unknown value for 'master_failure_mode': %s", value);
                    success = false;
                }
            }
            else
            {
                MXS_ERROR("Unknown router option \"%s=%s\" for readwritesplit router.",
                          options[i], value);
                success = false;
            }
        }
    } /*< for */

    return success;
}

/**
 * Error Handler routine to resolve _backend_ failures. If it succeeds then
 * there
 * are enough operative backends available and connected. Otherwise it fails,
 * and session is terminated.
 *
 * @param       instance        The router instance
 * @param       router_session  The router session
 * @param       errmsgbuf       The error message to reply
 * @param       backend_dcb     The backend DCB
 * @param       action      The action: ERRACT_NEW_CONNECTION or
 * ERRACT_REPLY_CLIENT
 * @param   succp       Result of action: true iff router can continue
 *
 * Even if succp == true connecting to new slave may have failed. succp is to
 * tell whether router has enough master/slave connections to continue work.
 */
static void handleError(ROUTER *instance, void *router_session,
                        GWBUF *errmsgbuf, DCB *problem_dcb,
                        error_action_t action, bool *succp)
{
    SESSION *session;
    ROUTER_INSTANCE *inst = (ROUTER_INSTANCE *)instance;
    ROUTER_CLIENT_SES *rses = (ROUTER_CLIENT_SES *)router_session;

    CHK_DCB(problem_dcb);

    if (!rses_begin_locked_router_action(rses))
    {
        /** Session is already closed */
        *succp = false;
        return;
    }

    /** Don't handle same error twice on same DCB */
    if (problem_dcb->dcb_errhandle_called)
    {
        /** we optimistically assume that previous call succeed */
        /*
         * The return of true is potentially misleading, but appears to
         * be safe with the code as it stands on 9 Sept 2015 - MNB
         */
        *succp = true;
        rses_end_locked_router_action(rses);
        return;
    }
    else
    {
        problem_dcb->dcb_errhandle_called = true;
    }
    session = problem_dcb->session;

    bool close_dcb = true;
    backend_ref_t *bref = get_bref_from_dcb(rses, problem_dcb);

    if (session == NULL || rses == NULL)
    {
        *succp = false;
    }
    else if (DCB_ROLE_CLIENT_HANDLER == problem_dcb->dcb_role)
    {
        *succp = false;
    }
    else
    {
        CHK_SESSION(session);
        CHK_CLIENT_RSES(rses);

        switch (action)
        {
            case ERRACT_NEW_CONNECTION:
            {
                /**
                 * If master has lost its Master status error can't be
                 * handled so that session could continue.
                 */
                if (rses->rses_master_ref && rses->rses_master_ref->bref_dcb == problem_dcb)
                {
                    SERVER *srv = rses->rses_master_ref->bref_backend->backend_server;
                    bool can_continue = false;

                    if (rses->rses_config.rw_master_failure_mode != RW_FAIL_INSTANTLY &&
                        (bref == NULL || !BREF_IS_WAITING_RESULT(bref)))
                    {
                        /** The failure of a master is not considered a critical
                         * failure as partial functionality still remains. Reads
                         * are allowed as long as slave servers are available
                         * and writes will cause an error to be returned.
                         *
                         * If we were waiting for a response from the master, we
                         * can't be sure whether it was executed or not. In this
                         * case the safest thing to do is to close the client
                         * connection. */
                        can_continue = true;
                    }
                    else if (!SERVER_IS_MASTER(srv) && !srv->master_err_is_logged)
                    {
                        MXS_ERROR("Server %s:%d lost the master status. Readwritesplit "
                                  "service can't locate the master. Client sessions "
                                  "will be closed.", srv->name, srv->port);
                        srv->master_err_is_logged = true;
                    }

                    *succp = can_continue;

                    if (bref != NULL)
                    {
                        CHK_BACKEND_REF(bref);
                        close_failed_bref(bref, true);
                    }
                    else
                    {
                        MXS_ERROR("Server %s:%d lost the master status but could not locate the "
                                  "corresponding backend ref.", srv->name, srv->port);
                    }
                }
                else if (bref)
                {
                    /** We should reconnect only if we find a backend for this
                     * DCB. If this DCB is an older DCB that has been closed,
                     * we can ignore it. */
                    *succp = handle_error_new_connection(inst, &rses, problem_dcb, errmsgbuf);
                }

                RW_CHK_DCB(bref, problem_dcb);

                if (bref)
                {
                    /** This is a valid DCB for a backend ref */

                    if (!BREF_IS_IN_USE(bref) || bref->bref_dcb != problem_dcb)
                    {
                        /** The backend is closed or the reference was replaced */
                        dcb_close(problem_dcb);
                        RW_CLOSE_BREF(bref);
                    }
                    else
                    {
                        MXS_ERROR("Backend '%s' is still in use and points to the problem DCB. Not closing.",
                                  bref->bref_backend->backend_server->unique_name);
                    }
                }
                else
                {
                    const char *remote = problem_dcb->state == DCB_STATE_POLLING &&
                        problem_dcb->server ? problem_dcb->server->unique_name : "CLOSED";

                    MXS_ERROR("DCB connected to '%s' is not in use by the router "
                              "session, not closing it. DCB is in state '%s'",
                              remote, STRDCBSTATE(problem_dcb->state));
                    MXS_ERROR("Backends currently in use:");

                    for (int i = 0; i < rses->rses_nbackends; i++)
                    {
                        dcb_state_t state = DCB_STATE_UNDEFINED;
                        if (BREF_IS_IN_USE(&rses->rses_backend_ref[i]))
                        {
                            state = rses->rses_backend_ref[i].bref_dcb->state;
                        }

                        MXS_ERROR("%p: %s - %p", &rses->rses_backend_ref[i], STRDCBSTATE(state),
                                  rses->rses_backend_ref[i].bref_dcb);
                    }
                }

                close_dcb = false;
                break;
            }

            case ERRACT_REPLY_CLIENT:
            {
                handle_error_reply_client(session, rses, problem_dcb, errmsgbuf);
                close_dcb = false;
                *succp = false; /*< no new backend servers were made available */
                break;
            }

            default:
                ss_dassert(!true);
                *succp = false;
                break;
        }
    }

    if (close_dcb)
    {
        RW_CHK_DCB(bref, problem_dcb);
        dcb_close(problem_dcb);
        RW_CLOSE_BREF(bref);
    }
    rses_end_locked_router_action(rses);
}

static void handle_error_reply_client(SESSION *ses, ROUTER_CLIENT_SES *rses,
                                      DCB *backend_dcb, GWBUF *errmsg)
{
    session_state_t sesstate;
    DCB *client_dcb;
    backend_ref_t *bref;

    spinlock_acquire(&ses->ses_lock);
    sesstate = ses->state;
    client_dcb = ses->client_dcb;
    spinlock_release(&ses->ses_lock);

    if ((bref = get_bref_from_dcb(rses, backend_dcb)) != NULL)
    {
        CHK_BACKEND_REF(bref);

        if (BREF_IS_IN_USE(bref))
        {
            close_failed_bref(bref, false);
            RW_CHK_DCB(bref, backend_dcb);
            dcb_close(backend_dcb);
            RW_CLOSE_BREF(bref);
        }
    }
    else
    {
        // All dcbs should be associated with a backend reference.
        ss_dassert(!true);
    }

    if (sesstate == SESSION_STATE_ROUTER_READY)
    {
        CHK_DCB(client_dcb);
        client_dcb->func.write(client_dcb, gwbuf_clone(errmsg));
    }
}

/**
 * Check if there is backend reference pointing at failed DCB, and reset its
 * flags. Then clear DCB's callback and finally : try to find replacement(s)
 * for failed slave(s).
 *
 * This must be called with router lock.
 *
 * @param inst      router instance
 * @param rses      router client session
 * @param dcb       failed DCB
 * @param errmsg    error message which is sent to client if it is waiting
 *
 * @return true if there are enough backend connections to continue, false if
 * not
 */
static bool handle_error_new_connection(ROUTER_INSTANCE *inst,
                                        ROUTER_CLIENT_SES **rses,
                                        DCB *backend_dcb, GWBUF *errmsg)
{
    ROUTER_CLIENT_SES *myrses;
    SESSION *ses;
    int router_nservers;
    int max_nslaves;
    int max_slave_rlag;
    backend_ref_t *bref;
    bool succp;

    myrses = *rses;
    ss_dassert(SPINLOCK_IS_LOCKED(&myrses->rses_lock));

    ses = backend_dcb->session;
    CHK_SESSION(ses);

    /**
     * If bref == NULL it has been replaced already with another one.
     */
    if ((bref = get_bref_from_dcb(myrses, backend_dcb)) == NULL)
    {
        succp = true;
        goto return_succp;
    }
    CHK_BACKEND_REF(bref);

    /**
     * If query was sent through the bref and it is waiting for reply from
     * the backend server it is necessary to send an error to the client
     * because it is waiting for reply.
     */
    if (BREF_IS_WAITING_RESULT(bref))
    {
        DCB *client_dcb = ses->client_dcb;
        client_dcb->func.write(client_dcb, gwbuf_clone(errmsg));
    }

    close_failed_bref(bref, false);

    /**
     * Error handler is already called for this DCB because
     * it's not polling anymore. It can be assumed that
     * it succeed because rses isn't closed.
     */
    if (backend_dcb->state != DCB_STATE_POLLING)
    {
        succp = true;
        goto return_succp;
    }
    /**
     * Remove callback because this DCB won't be used
     * unless it is reconnected later, and then the callback
     * is set again.
     */
    dcb_remove_callback(backend_dcb, DCB_REASON_NOT_RESPONDING,
                        &router_handle_state_switch, (void *)bref);
    router_nservers = router_get_servercount(inst);
    max_nslaves = rses_get_max_slavecount(myrses, router_nservers);
    max_slave_rlag = rses_get_max_replication_lag(myrses);
    /**
     * Try to get replacement slave or at least the minimum
     * number of slave connections for router session.
     */
    if (inst->rwsplit_config.rw_disable_sescmd_hist)
    {
        succp = have_enough_servers(&myrses, 1, router_nservers, inst) ? true : false;
    }
    else
    {
        succp = select_connect_backend_servers(&myrses->rses_master_ref,
                                               myrses->rses_backend_ref,
                                               router_nservers,
                                               max_nslaves, max_slave_rlag,
                                               myrses->rses_config.rw_slave_select_criteria,
                                               ses, inst, true);
    }

return_succp:
    return succp;
}

static void print_error_packet(ROUTER_CLIENT_SES *rses, GWBUF *buf, DCB *dcb)
{
#if defined(SS_DEBUG)
    if (GWBUF_IS_TYPE_MYSQL(buf))
    {
        while (gwbuf_length(buf) > 0)
        {
            /**
             * This works with MySQL protocol only !
             * Protocol specific packet print functions would be nice.
             */
            uint8_t *ptr = GWBUF_DATA(buf);
            size_t len = MYSQL_GET_PACKET_LEN(ptr);

            if (MYSQL_GET_COMMAND(ptr) == 0xff)
            {
                SERVER *srv = NULL;
                backend_ref_t *bref = rses->rses_backend_ref;
                int i;
                char *bufstr;

                for (i = 0; i < rses->rses_nbackends; i++)
                {
                    if (bref[i].bref_dcb == dcb)
                    {
                        srv = bref[i].bref_backend->backend_server;
                    }
                }
                ss_dassert(srv != NULL);
                char *str = (char *)&ptr[7];
                bufstr = strndup(str, len - 3);

                MXS_ERROR("Backend server %s:%d responded with "
                          "error : %s",
                          srv->name, srv->port, bufstr);
                free(bufstr);
            }
            buf = gwbuf_consume(buf, len + 4);
        }
    }
    else
    {
        gwbuf_free(buf);
    }
#endif /*< SS_DEBUG */
}

static int router_get_servercount(ROUTER_INSTANCE *inst)
{
    int router_nservers = 0;
    BACKEND **b = inst->servers;
    /** count servers */
    while (*(b++) != NULL)
    {
        router_nservers++;
    }

    return router_nservers;
}

static bool have_enough_servers(ROUTER_CLIENT_SES **p_rses, const int min_nsrv,
                                int router_nsrv, ROUTER_INSTANCE *router)
{
    bool succp;

    /** With too few servers session is not created */
    if (router_nsrv < min_nsrv ||
        MAX((*p_rses)->rses_config.rw_max_slave_conn_count,
            (router_nsrv * (*p_rses)->rses_config.rw_max_slave_conn_percent) /
            100) < min_nsrv)
    {
        if (router_nsrv < min_nsrv)
        {
            MXS_ERROR("Unable to start %s service. There are "
                      "too few backend servers available. Found %d "
                      "when %d is required.",
                      router->service->name, router_nsrv, min_nsrv);
        }
        else
        {
            int pct = (*p_rses)->rses_config.rw_max_slave_conn_percent / 100;
            int nservers = router_nsrv * pct;

            if ((*p_rses)->rses_config.rw_max_slave_conn_count < min_nsrv)
            {
                MXS_ERROR("Unable to start %s service. There are "
                          "too few backend servers configured in "
                          "MaxScale.cnf. Found %d when %d is required.",
                          router->service->name,
                          (*p_rses)->rses_config.rw_max_slave_conn_count, min_nsrv);
            }
            if (nservers < min_nsrv)
            {
                double dbgpct = ((double)min_nsrv / (double)router_nsrv) * 100.0;
                MXS_ERROR("Unable to start %s service. There are "
                          "too few backend servers configured in "
                          "MaxScale.cnf. Found %d%% when at least %.0f%% "
                          "would be required.",
                          router->service->name,
                          (*p_rses)->rses_config.rw_max_slave_conn_percent, dbgpct);
            }
        }
        free(*p_rses);
        *p_rses = NULL;
        succp = false;
    }
    else
    {
        succp = true;
    }
    return succp;
}

/**
 * Find out the number of read backend servers.
 * Depending on the configuration value type, either copy direct count
 * of slave connections or calculate the count from percentage value.
 */
static int rses_get_max_slavecount(ROUTER_CLIENT_SES *rses,
                                   int router_nservers)
{
    int conf_max_nslaves;
    int max_nslaves;

    CHK_CLIENT_RSES(rses);

    if (rses->rses_config.rw_max_slave_conn_count > 0)
    {
        conf_max_nslaves = rses->rses_config.rw_max_slave_conn_count;
    }
    else
    {
        conf_max_nslaves = (router_nservers * rses->rses_config.rw_max_slave_conn_percent) / 100;
    }
    max_nslaves = MIN(router_nservers - 1, MAX(1, conf_max_nslaves));

    return max_nslaves;
}

static int rses_get_max_replication_lag(ROUTER_CLIENT_SES *rses)
{
    int conf_max_rlag;

    CHK_CLIENT_RSES(rses);

    /** if there is no configured value, then longest possible int is used */
    if (rses->rses_config.rw_max_slave_replication_lag > 0)
    {
        conf_max_rlag = rses->rses_config.rw_max_slave_replication_lag;
    }
    else
    {
        conf_max_rlag = ~(1 << 31);
    }

    return conf_max_rlag;
}

/**
 * Finds out if there is a backend reference pointing at the DCB given as
 * parameter.
 * @param rses  router client session
 * @param dcb   DCB
 *
 * @return backend reference pointer if succeed or NULL
 */
static backend_ref_t *get_bref_from_dcb(ROUTER_CLIENT_SES *rses, DCB *dcb)
{
    backend_ref_t *bref;
    int i = 0;
    CHK_DCB(dcb);
    CHK_CLIENT_RSES(rses);

    bref = rses->rses_backend_ref;

    while (i < rses->rses_nbackends)
    {
        if (bref->bref_dcb == dcb)
        {
            break;
        }
        bref++;
        i += 1;
    }

    if (i == rses->rses_nbackends)
    {
        bref = NULL;
    }
    return bref;
}

/**
 * Calls hang-up function for DCB if it is not both running and in
 * master/slave/joined/ndb role. Called by DCB's callback routine.
 */
static int router_handle_state_switch(DCB *dcb, DCB_REASON reason, void *data)
{
    backend_ref_t *bref;
    int rc = 1;
    SERVER *srv;
    CHK_DCB(dcb);

    if (NULL == dcb->session->router_session)
    {
        /*
         * The following processing will fail if there is no router session,
         * because the "data" parameter will not contain meaningful data,
         * so we have no choice but to stop here.
         */
        return 0;
    }
    bref = (backend_ref_t *)data;
    CHK_BACKEND_REF(bref);

    srv = bref->bref_backend->backend_server;

    if (SERVER_IS_RUNNING(srv) && SERVER_IS_IN_CLUSTER(srv))
    {
        goto return_rc;
    }

    MXS_DEBUG("%lu [router_handle_state_switch] %s %s:%d in state %s",
              pthread_self(), STRDCBREASON(reason), srv->name, srv->port,
              STRSRVSTATUS(srv));
    CHK_SESSION(((SESSION *)dcb->session));
    if (dcb->session->router_session)
    {
        CHK_CLIENT_RSES(((ROUTER_CLIENT_SES *)dcb->session->router_session));
    }

    switch (reason)
    {
        case DCB_REASON_NOT_RESPONDING:
            dcb->func.hangup(dcb);
            break;

        default:
            break;
    }

return_rc:
    return rc;
}

static sescmd_cursor_t *backend_ref_get_sescmd_cursor(backend_ref_t *bref)
{
    sescmd_cursor_t *scur;
    CHK_BACKEND_REF(bref);

    scur = &bref->bref_sescmd_cur;
    CHK_SESCMD_CUR(scur);

    return scur;
}

#if defined(PREP_STMT_CACHING)
#define MAX_STMT_LEN 1024

static prep_stmt_t *prep_stmt_init(prep_stmt_type_t type, void *id)
{
    prep_stmt_t *pstmt;

    pstmt = (prep_stmt_t *)calloc(1, sizeof(prep_stmt_t));

    if (pstmt != NULL)
    {
#if defined(SS_DEBUG)
        pstmt->pstmt_chk_top = CHK_NUM_PREP_STMT;
        pstmt->pstmt_chk_tail = CHK_NUM_PREP_STMT;
#endif
        pstmt->pstmt_state = PREP_STMT_ALLOC;
        pstmt->pstmt_type = type;

        if (type == PREP_STMT_NAME)
        {
            pstmt->pstmt_id.name = strndup((char *)id, MAX_STMT_LEN);
        }
        else
        {
            pstmt->pstmt_id.seq = 0;
        }
    }
    CHK_PREP_STMT(pstmt);
    return pstmt;
}

static void prep_stmt_done(prep_stmt_t *pstmt)
{
    CHK_PREP_STMT(pstmt);

    if (pstmt->pstmt_type == PREP_STMT_NAME)
    {
        free(pstmt->pstmt_id.name);
    }
    free(pstmt);
}

static bool prep_stmt_drop(prep_stmt_t *pstmt)
{
    CHK_PREP_STMT(pstmt);

    pstmt->pstmt_state = PREP_STMT_DROPPED;
    return true;
}
#endif /*< PREP_STMT_CACHING */

/********************************
 * This routine returns the root master server from MySQL replication tree
 * Get the root Master rule:
 *
 * find server with the lowest replication depth level
 * and the SERVER_MASTER bitval
 * Servers are checked even if they are in 'maintenance'
 *
 * @param   servers     The list of servers
 * @param   router_nservers The number of servers
 * @return          The Master found
 *
 */
static BACKEND *get_root_master(backend_ref_t *servers, int router_nservers)
{
    int i = 0;
    BACKEND *master_host = NULL;

    for (i = 0; i < router_nservers; i++)
    {
        BACKEND *b;

        if (servers[i].bref_backend == NULL)
        {
            continue;
        }

        b = servers[i].bref_backend;

        if (SERVER_IS_MASTER(b->backend_server))
        {
            if (master_host == NULL ||
                (b->backend_server->depth < master_host->backend_server->depth))
            {
                master_host = b;
            }
        }
    }
    return master_host;
}

/********************************
 * This routine returns the root master server from MySQL replication tree
 * Get the root Master rule:
 *
 * find server with the lowest replication depth level
 * and the SERVER_MASTER bitval
 * Servers are checked even if they are in 'maintenance'
 *
 * @param   rses pointer to router session
 * @return  pointer to backend reference of the root master or NULL
 *
 */
static backend_ref_t *get_root_master_bref(ROUTER_CLIENT_SES *rses)
{
    backend_ref_t *bref;
    backend_ref_t *candidate_bref = NULL;
    SERVER master = {};

    for (int i = 0; i < rses->rses_nbackends; i++)
    {
        bref = &rses->rses_backend_ref[i];
        if (bref && BREF_IS_IN_USE(bref))
        {
            ss_dassert(!BREF_IS_CLOSED(bref) && !BREF_HAS_FAILED(bref));
            if (bref == rses->rses_master_ref)
            {
                /** Store master state for better error reporting */
                master.status = bref->bref_backend->backend_server->status;
            }

            if (SERVER_IS_MASTER(bref->bref_backend->backend_server))
            {
                if (candidate_bref == NULL ||
                    (bref->bref_backend->backend_server->depth <
                     candidate_bref->bref_backend->backend_server->depth))
                {
                    candidate_bref = bref;
                }
            }
        }
    }

    if (candidate_bref == NULL && rses->rses_config.rw_master_failure_mode == RW_FAIL_INSTANTLY &&
        rses->rses_master_ref && BREF_IS_IN_USE(rses->rses_master_ref))
    {
        MXS_ERROR("Could not find master among the backend servers. "
                  "Previous master's state : %s", STRSRVSTATUS(&master));
    }

    return candidate_bref;
}

/**
 * @brief Detect multi-statement queries
 *
 * It is possible that the session state is modified inside a multi-statement
 * query which would leave any slave sessions in an inconsistent state. Due to
 * this, for the duration of this session, all queries will be sent to the
 * master
 * if the current query contains a multi-statement query.
 * @param rses Router client session
 * @param buf Buffer containing the full query
 * @return True if the query contains multiple statements
 */
static bool check_for_multi_stmt(ROUTER_CLIENT_SES *rses, GWBUF *buf,
                                 mysql_server_cmd_t packet_type)
{
    MySQLProtocol *proto = (MySQLProtocol *)rses->client_dcb->protocol;
    bool rval = false;

    if (proto->client_capabilities & GW_MYSQL_CAPABILITIES_MULTI_STATEMENTS &&
        packet_type == MYSQL_COM_QUERY &&
        (rses->forced_node == NULL || rses->forced_node != rses->rses_master_ref))
    {
        char *ptr, *data = GWBUF_DATA(buf) + 5;
        /** Payload size without command byte */
        int buflen = gw_mysql_get_byte3((uint8_t *)GWBUF_DATA(buf)) - 1;

        if ((ptr = strnchr_esc_mysql(data, ';', buflen)))
        {
            /** Skip stored procedures etc. */
            while (ptr && is_mysql_sp_end(ptr, buflen - (ptr - data)))
            {
                ptr = strnchr_esc_mysql(ptr + 1, ';', buflen - (ptr - data) - 1);
            }

            if (ptr)
            {
                if (ptr < data + buflen &&
                    !is_mysql_statement_end(ptr, buflen - (ptr - data)))
                {
                    rses->forced_node = rses->rses_master_ref;
                    rval = true;
                    MXS_INFO("Multi-statement query, routing all future queries to master.");
                }
            }
        }
    }

    return rval;
}

/**
 * Send an error message to the client telling that the server is in read only mode
 * @param dcb Client DCB
 * @return True if sending the message was successful, false if an error occurred
 */
static bool send_readonly_error(DCB *dcb)
{
    bool succp = false;
    const char* errmsg = "The MariaDB server is running with the --read-only"
        " option so it cannot execute this statement";
    GWBUF* err = modutil_create_mysql_err_msg(1, 0, ER_OPTION_PREVENTS_STATEMENT,
                                              "HY000", errmsg);

    if (err)
    {
        succp = dcb->func.write(dcb, err);
    }
    else
    {
        MXS_ERROR("Memory allocation failed when creating client error message.");
    }

    return succp;
}
