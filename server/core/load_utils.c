/*
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl.
 *
 * Change Date: 2019-07-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

/**
 * @file load_utils.c           Utility functions to aid the loading of dynamic
 *                             modules into the gateway
 *
 * @verbatim
 * Revision History
 *
 * Date         Who                     Description
 * 13/06/13     Mark Riddoch            Initial implementation
 * 14/06/13     Mark Riddoch            Updated to add call to ModuleInit if one is
 *                                      defined in the loaded module.
 *                                      Also updated to call fixed GetModuleObject
 * 02/06/14     Mark Riddoch            Addition of module info
 * 26/02/15     Massimiliano Pinto      Addition of module_feedback_send
 *
 * @endverbatim
 */
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <maxscale/modules.h>
#include <maxscale/modinfo.h>
#include <maxscale/log_manager.h>
#include <maxscale/version.h>
#include <maxscale/notification.h>
#include <curl/curl.h>
#include <sys/utsname.h>
#include <openssl/sha.h>
#include <maxscale/gwdirs.h>
#include <maxscale/alloc.h>

#include "maxscale/config.h"
#include "maxscale/utils.h"
#include <maxscale/service.h>
#include <maxscale/server.h>

static MODULES *registered = NULL;

static MODULES *find_module(const char *module);
static void register_module(const char *module,
                            const char  *type,
                            void        *dlhandle,
                            char        *version,
                            void        *modobj,
                            MODULE_INFO *info);
static void unregister_module(const char *module);
int do_http_post(GWBUF *buffer, void *cfg);

struct MemoryStruct
{
    char *data;
    size_t size;
};

/**
 * Callback write routine for curl library, getting remote server reply
 *
 * @param       contents        New data to add
 * @param       size            Data size
 * @param       nmemb           Elements in the buffer
 * @param       userp           Pointer to the buffer
 * @return      0 on failure, memory size on success
 *
 */
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    void *data = MXS_REALLOC(mem->data, mem->size + realsize + 1);

    if (data == NULL)
    {
        return 0;
    }

    mem->data = data;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

/**
 * Load the dynamic library related to a gateway module. The routine
 * will look for library files in the current directory,
 * the configured folder and /usr/lib64/maxscale.
 *
 * Note that a number of entry points are standard for any module, as is
 * the data structure named "info".  They are only accessed by explicit
 * reference to the module, and so the fact that they are duplicated in
 * every module is not a problem.  The declarations are protected from
 * lint by suppressing error 14, since the duplication is a feature and
 * not an error.
 *
 * @param module        Name of the module to load
 * @param type          Type of module, used purely for registration
 * @return              The module specific entry point structure or NULL
 */
void *
load_module(const char *module, const char *type)
{
    char *home, *version;
    char fname[MAXPATHLEN + 1];
    void *dlhandle, *sym;
    char *(*ver)();
    void *(*ep)(), *modobj;
    MODULES *mod;
    MODULE_INFO *mod_info = NULL;

    if (NULL == module || NULL == type)
    {
        return NULL;
    }

    if ((mod = find_module(module)) == NULL)
    {
        /*<
         * The module is not already loaded
         *
         * Search of the shared object.
         */

        snprintf(fname, MAXPATHLEN + 1, "%s/lib%s.so", get_libdir(), module);

        if (access(fname, F_OK) == -1)
        {
            MXS_ERROR("Unable to find library for "
                      "module: %s. Module dir: %s",
                      module, get_libdir());
            return NULL;
        }

        if ((dlhandle = dlopen(fname, RTLD_NOW | RTLD_LOCAL)) == NULL)
        {
            MXS_ERROR("Unable to load library for module: "
                      "%s\n\n\t\t      %s."
                      "\n\n",
                      module,
                      dlerror());
            return NULL;
        }

        if ((sym = dlsym(dlhandle, "version")) == NULL)
        {
            MXS_ERROR("Version interface not supported by "
                      "module: %s\n\t\t\t      %s.",
                      module,
                      dlerror());
            dlclose(dlhandle);
            return NULL;
        }
        ver = sym;
        version = ver();

        /*
         * If the module has a ModuleInit function cal it now.
         */
        if ((sym = dlsym(dlhandle, "ModuleInit")) != NULL)
        {
            void (*ModuleInit)() = sym;
            ModuleInit();
        }

        if ((sym = dlsym(dlhandle, "info")) != NULL)
        {
            int fatal = 0;
            mod_info = sym;
            if (strcmp(type, MODULE_PROTOCOL) == 0
                && mod_info->modapi != MODULE_API_PROTOCOL)
            {
                MXS_ERROR("Module '%s' does not implement the protocol API.", module);
                fatal = 1;
            }
            if (strcmp(type, MODULE_AUTHENTICATOR) == 0
                && mod_info->modapi != MODULE_API_AUTHENTICATOR)
            {
                MXS_ERROR("Module '%s' does not implement the authenticator API.", module);
                fatal = 1;
            }
            if (strcmp(type, MODULE_ROUTER) == 0
                && mod_info->modapi != MODULE_API_ROUTER)
            {
                MXS_ERROR("Module '%s' does not implement the router API.", module);
                fatal = 1;
            }
            if (strcmp(type, MODULE_MONITOR) == 0
                && mod_info->modapi != MODULE_API_MONITOR)
            {
                MXS_ERROR("Module '%s' does not implement the monitor API.", module);
                fatal = 1;
            }
            if (strcmp(type, MODULE_FILTER) == 0
                && mod_info->modapi != MODULE_API_FILTER)
            {
                MXS_ERROR("Module '%s' does not implement the filter API.", module);
                fatal = 1;
            }
            if (strcmp(type, MODULE_QUERY_CLASSIFIER) == 0
                && mod_info->modapi != MODULE_API_QUERY_CLASSIFIER)
            {
                MXS_ERROR("Module '%s' does not implement the query classifier API.", module);
                fatal = 1;
            }
            if (fatal)
            {
                dlclose(dlhandle);
                return NULL;
            }
        }

        if ((sym = dlsym(dlhandle, "GetModuleObject")) == NULL)
        {
            MXS_ERROR("Expected entry point interface missing "
                      "from module: %s\n\t\t\t      %s.",
                      module,
                      dlerror());
            dlclose(dlhandle);
            return NULL;
        }
        ep = sym;
        modobj = ep();

        MXS_NOTICE("Loaded module %s: %s from %s",
                   module,
                   version,
                   fname);
        register_module(module, type, dlhandle, version, modobj, mod_info);
    }
    else
    {
        /*
         * The module is already loaded, get the entry points again and
         * return a reference to the already loaded module.
         */
        modobj = mod->modobj;
    }

    return modobj;
}

/**
 * Unload a module.
 *
 * No errors are returned since it is not clear that much can be done
 * to fix issues relating to unloading modules.
 *
 * @param module        The name of the module
 */
void
unload_module(const char *module)
{
    MODULES *mod = find_module(module);
    void *handle;

    if (!mod)
    {
        return;
    }
    handle = mod->handle;
    unregister_module(module);
    dlclose(handle);
}

/**
 * Find a module that has been previously loaded and return the handle for that
 * library
 *
 * @param module        The name of the module
 * @return              The module handle or NULL if it was not found
 */
static MODULES *
find_module(const char *module)
{
    MODULES *mod = registered;

    if (module)
    {
        while (mod)
        {
            if (strcmp(mod->module, module) == 0)
            {
                return mod;
            }
            else
            {
                mod = mod->next;
            }
        }
    }
    return NULL;
}

/**
 * Register a newly loaded module. The registration allows for single copies
 * to be loaded and cached entry point information to be return.
 *
 * @param module        The name of the module loaded
 * @param type          The type of the module loaded
 * @param dlhandle      The handle returned by dlopen
 * @param version       The version string returned by the module
 * @param modobj        The module object
 * @param mod_info      The module information
 */
static void
register_module(const char *module,
                const char *type,
                void *dlhandle,
                char *version,
                void *modobj,
                MODULE_INFO *mod_info)
{
    module = MXS_STRDUP(module);
    type = MXS_STRDUP(type);
    version = MXS_STRDUP(version);

    MODULES *mod = (MODULES *)MXS_MALLOC(sizeof(MODULES));

    if (!module || !type || !version || !mod)
    {
        MXS_FREE((void*)module);
        MXS_FREE((void*)type);
        MXS_FREE(version);
        MXS_FREE(mod);
        return;
    }

    mod->module = (char*)module;
    mod->type = (char*)type;
    mod->handle = dlhandle;
    mod->version = version;
    mod->modobj = modobj;
    mod->next = registered;
    mod->info = mod_info;
    registered = mod;
}

/**
 * Unregister a module
 *
 * @param module        The name of the module to remove
 */
static void
unregister_module(const char *module)
{
    MODULES *mod = find_module(module);
    MODULES *ptr;

    if (!mod)
    {
        return;         // Module not found
    }
    if (registered == mod)
    {
        registered = mod->next;
    }
    else
    {
        ptr = registered;
        while (ptr && ptr->next != mod)
        {
            ptr = ptr->next;
        }

        /*<
         * Remove the module to be be freed from the list.
         */
        if (ptr && (ptr->next == mod))
        {
            ptr->next = ptr->next->next;
        }
    }

    /*<
     * The module is now not in the linked list and all
     * memory related to it can be freed
     */
    dlclose(mod->handle);
    MXS_FREE(mod->module);
    MXS_FREE(mod->type);
    MXS_FREE(mod->version);
    MXS_FREE(mod);
}

/**
 * Unload all modules
 *
 * Remove all the modules from the system, called during shutdown
 * to allow termination hooks to be called.
 */
void
unload_all_modules()
{
    while (registered)
    {
        unregister_module(registered->module);
    }
}

/**
 * Print Modules
 *
 * Diagnostic routine to display all the loaded modules
 */
void
printModules()
{
    MODULES *ptr = registered;

    printf("%-15s | %-11s | Version\n", "Module Name", "Module Type");
    printf("-----------------------------------------------------\n");
    while (ptr)
    {
        printf("%-15s | %-11s | %s\n", ptr->module, ptr->type, ptr->version);
        ptr = ptr->next;
    }
}

/**
 * Print Modules to a DCB
 *
 * Diagnostic routine to display all the loaded modules
 */
void
dprintAllModules(DCB *dcb)
{
    MODULES *ptr = registered;

    dcb_printf(dcb, "Modules.\n");
    dcb_printf(dcb, "----------------+-----------------+---------+-------+-------------------------\n");
    dcb_printf(dcb, "%-15s | %-15s | Version | API   | Status\n", "Module Name", "Module Type");
    dcb_printf(dcb, "----------------+-----------------+---------+-------+-------------------------\n");
    while (ptr)
    {
        dcb_printf(dcb, "%-15s | %-15s | %-7s ", ptr->module, ptr->type, ptr->version);
        if (ptr->info)
            dcb_printf(dcb, "| %d.%d.%d | %s",
                       ptr->info->api_version.major,
                       ptr->info->api_version.minor,
                       ptr->info->api_version.patch,
                       ptr->info->status == MODULE_IN_DEVELOPMENT
                       ? "In Development"
                       : (ptr->info->status == MODULE_ALPHA_RELEASE
                          ? "Alpha"
                          : (ptr->info->status == MODULE_BETA_RELEASE
                             ? "Beta"
                             : (ptr->info->status == MODULE_GA
                                ? "GA"
                                : (ptr->info->status == MODULE_EXPERIMENTAL
                                   ? "Experimental" : "Unknown")))));
        dcb_printf(dcb, "\n");
        ptr = ptr->next;
    }
    dcb_printf(dcb, "----------------+-----------------+---------+-------+-------------------------\n\n");
}

/**
 * Provide a row to the result set that defines the set of modules
 *
 * @param set   The result set
 * @param data  The index of the row to send
 * @return The next row or NULL
 */
static RESULT_ROW *
moduleRowCallback(RESULTSET *set, void *data)
{
    int *rowno = (int *)data;
    int i = 0;;
    char *stat, buf[20];
    RESULT_ROW *row;
    MODULES *ptr;

    ptr = registered;
    while (i < *rowno && ptr)
    {
        i++;
        ptr = ptr->next;
    }
    if (ptr == NULL)
    {
        MXS_FREE(data);
        return NULL;
    }
    (*rowno)++;
    row = resultset_make_row(set);
    resultset_row_set(row, 0, ptr->module);
    resultset_row_set(row, 1, ptr->type);
    resultset_row_set(row, 2, ptr->version);
    snprintf(buf, 19, "%d.%d.%d", ptr->info->api_version.major,
             ptr->info->api_version.minor,
             ptr->info->api_version.patch);
    buf[19] = '\0';
    resultset_row_set(row, 3, buf);
    resultset_row_set(row, 4, ptr->info->status == MODULE_IN_DEVELOPMENT
                      ? "In Development"
                      : (ptr->info->status == MODULE_ALPHA_RELEASE
                         ? "Alpha"
                         : (ptr->info->status == MODULE_BETA_RELEASE
                            ? "Beta"
                            : (ptr->info->status == MODULE_GA
                               ? "GA"
                               : (ptr->info->status == MODULE_EXPERIMENTAL
                                  ? "Experimental" : "Unknown")))));
    return row;
}

/**
 * Return a resultset that has the current set of modules in it
 *
 * @return A Result set
 */
RESULTSET *
moduleGetList()
{
    RESULTSET       *set;
    int             *data;

    if ((data = (int *)MXS_MALLOC(sizeof(int))) == NULL)
    {
        return NULL;
    }
    *data = 0;
    if ((set = resultset_create(moduleRowCallback, data)) == NULL)
    {
        MXS_FREE(data);
        return NULL;
    }
    resultset_add_column(set, "Module Name", 18, COL_TYPE_VARCHAR);
    resultset_add_column(set, "Module Type", 12, COL_TYPE_VARCHAR);
    resultset_add_column(set, "Version", 10, COL_TYPE_VARCHAR);
    resultset_add_column(set, "API Version", 8, COL_TYPE_VARCHAR);
    resultset_add_column(set, "Status", 15, COL_TYPE_VARCHAR);

    return set;
}


/**
 * Log a link to the feedback report.
 */
void module_log_feedback_report()
{
    MODULES *ptr = registered;
    int n_mod = 0;

    /* count loaded modules */
    while (ptr)
    {
        ptr = ptr->next;
        n_mod++;
    }

    /** Create a list of modules */
    char modlist[n_mod * 255];
    modlist[0] = '\0';

    /* module lists pointer is set back to the head */
    ptr = registered;

    if (ptr)
    {
        strcpy(modlist, ptr->module);
        ptr = ptr->next;

        while (ptr)
        {
            strcat(modlist, ",");
            strcat(modlist, ptr->module);
            ptr = ptr->next;
        }
    }

    GATEWAY_CONF *cnf = config_get_global_options();
    FEEDBACK_CONF *fb = config_get_feedback_data();

    /* encode MAC-sha1 to HEX */
    char hex_setup_info[2 * SHA_DIGEST_LENGTH + 1] = "";
    gw_bin2hex(hex_setup_info, cnf->mac_sha1, SHA_DIGEST_LENGTH);

    const char *dest_url_format = "Please consider submitting an anonymous feedback report of MariaDB MaxScale:\n\n"
        "www.mariadb.com/feedback?uid=%s&version=%s&system=%s&modules=%s&processors=%d"
        "&memory=%d&servers=%d&services=%d&filters=%d\n\n"
        "The unique identified is calculated from the SHA1 hash of the "
        "MAC address of the first network inteface. We do not collect any "
        "information that might be used to identify a user.";

    MXS_NOTICE(dest_url_format, hex_setup_info,
             MAXSCALE_VERSION, fb->release_info, modlist, get_processor_count(),
             get_available_memory(), server_count_servers(), service_count_services(),
             filter_count_filters());
}

bool feedback_not_submitted()
{
    char feedback_file[PATH_MAX];
    sprintf(feedback_file, "%s/.feedback_submitted", get_datadir());

    return access(feedback_file, F_OK);
}

/**
 * Send data to notification service via http/https
 *
 * @param buffer        The GWBUF with data to send
 * @param cfg           The configuration details of notification service
 * @return              0 on success, != 0 on failure
 */
int
do_http_post(GWBUF *buffer, void *cfg)
{
    CURL *curl = NULL;
    CURLcode res;
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    long http_code = 0;
    struct MemoryStruct chunk;
    int ret_code = 1;

    FEEDBACK_CONF *feedback_config = (FEEDBACK_CONF *) cfg;

    /* allocate first memory chunck for httpd servr reply */
    chunk.data = MXS_MALLOC(1);  /* will be grown as needed by the realloc above */
    MXS_ABORT_IF_NULL(chunk.data);
    chunk.size = 0;    /* no data at this point */

    /* Initializing curl library for data send via HTTP */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if (curl)
    {
        char error_message[CURL_ERROR_SIZE] = "";

        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_message);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, feedback_config->feedback_connect_timeout);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, feedback_config->feedback_timeout);

        /* curl API call for data send via HTTP POST using a "file" type input */
        curl_formadd(&formpost,
                     &lastptr,
                     CURLFORM_COPYNAME, "data",
                     CURLFORM_BUFFER, "report.txt",
                     CURLFORM_BUFFERPTR, (char *)GWBUF_DATA(buffer),
                     CURLFORM_BUFFERLENGTH, strlen((char *)GWBUF_DATA(buffer)),
                     CURLFORM_CONTENTTYPE, "text/plain",
                     CURLFORM_END);

        curl_easy_setopt(curl, CURLOPT_HEADER, 1);

        /* some servers don't like requests that are made without a user-agent field, so we provide one */
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "MaxScale-agent/http-1.0");
        /* Force HTTP/1.0 */
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);

        curl_easy_setopt(curl, CURLOPT_URL, feedback_config->feedback_url);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

        /* send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

        /* we pass our 'chunk' struct to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);

        /* Check for errors */
        if (res != CURLE_OK)
        {
            ret_code = 2;
            MXS_ERROR("do_http_post(), curl call for [%s] failed due: %s, %s",
                      feedback_config->feedback_url,
                      curl_easy_strerror(res),
                      error_message);
            goto cleanup;
        }
        else
        {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        }

        if (http_code == 302)
        {
            char *from = strstr(chunk.data, "<h1>ok</h1>");
            if (from)
            {
                ret_code = 0;
            }
            else
            {
                ret_code = 3;
                goto cleanup;
            }
        }
        else
        {
            MXS_ERROR("do_http_post(), Bad HTTP Code from remote server: %lu", http_code);
            ret_code = 4;
            goto cleanup;
        }
    }
    else
    {
        MXS_ERROR("do_http_post(), curl object not initialized");
        ret_code = 1;
        goto cleanup;
    }

    MXS_INFO("do_http_post() ret_code [%d], HTTP code [%ld]",
             ret_code, http_code);
cleanup:

    if (chunk.data)
    {
        MXS_FREE(chunk.data);
    }

    if (curl)
    {
        curl_easy_cleanup(curl);
        curl_formfree(formpost);
    }

    curl_global_cleanup();

    return ret_code;
}

