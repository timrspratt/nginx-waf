#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>

#define HTML_TEMPLATE \
        "<!DOCTYPE html>" \
        "<html>" \
        "<head>" \
        "<meta charset='UTF-8'>" \
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>" \
        "<title>%s</title>" \
        "</head>" \
        "<body>" \
        "%s" \
        "</body>" \
        "</html>"

// Structure to hold configuration
typedef struct {
    ngx_str_t expression;  // Store the blocking expression
    ngx_int_t status;      // Store the status code to return
} ngx_http_waf_config_t;

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);

// Define the module directives
static ngx_command_t ngx_http_waf_commands[] = {
    {
        ngx_string("waf_rule"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_http_waf_expression,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_waf_config_t, expression),
        NULL
    },
    ngx_null_command
};

// Define the module context
static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL,                               // preconfiguration
    ngx_http_waf_init,                  // postconfiguration
    NULL,                               // create main configuration
    NULL,                               // init main configuration
    NULL,                               // create server configuration
    NULL,                               // merge server configuration
    ngx_http_waf_create_loc_conf,       // create location configuration
    NULL                                // merge location configuration
};

// Define the module itself
ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,           // Module context
    ngx_http_waf_commands,              // Module directives
    NGX_HTTP_MODULE,                    // Module type
    NULL,                               // Init master
    NULL,                               // Init module
    NULL,                               // Init process
    NULL,                               // Init thread
    NULL,                               // Exit thread
    NULL,                               // Exit process
    NULL,                               // Exit master
    NGX_MODULE_V1_PADDING
};

// Create location configuration
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_waf_config_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_config_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    // Default status code is 403
    conf->status = NGX_HTTP_FORBIDDEN;

    return conf;
}

// Parse the expression directive from the config
static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_waf_config_t *block_conf = conf;
    ngx_str_t *value = cf->args->elts;

    // Set the expression in the configuration structure
    block_conf->expression = value[1];

    // Parse the status code and set it (default is 403 if not provided correctly)
    ngx_int_t status = ngx_atoi(value[2].data, value[2].len);
    if (status == NGX_ERROR || status < 100 || status > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid status code in expression");
        return NGX_CONF_ERROR;
    }
    block_conf->status = status;

    return NGX_CONF_OK;
}

int serve_response(ngx_http_request_t *r, ngx_http_waf_config_t *conf) {
    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;

    unsigned char buf[32768];
    static const ngx_str_t content_type = ngx_string("text/html;charset=utf-8");

    size_t size = snprintf((char *) buf, sizeof(buf), HTML_TEMPLATE, "WAF", "<h2>WAF</h2>");

    out.buf = b;
    out.next = NULL;

    b->pos = buf;
    b->last = buf + size;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = conf->status;
    r->headers_out.content_length_n = size;
    r->headers_out.content_type = content_type;
    ngx_http_send_header(r);

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);

    return NGX_DONE;
}

// Main handler to process requests and evaluate the block expression
static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r) {
    ngx_http_waf_config_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[ waf ] here");
    
    return serve_response(r, conf);

    // If no expression is configured, allow the request
    if (conf->expression.len == 0) {
        return NGX_DECLINED;
    }

    // Get relevant request details
    ngx_table_elt_t *user_agent_header = r->headers_in.user_agent;
    ngx_str_t *user_agent = user_agent_header ? &user_agent_header->value : NULL;
    ngx_str_t remote_addr = r->connection->addr_text;

    // This is a simple parser for AND/OR conditions, split by ' or ' or ' and '
    // You may expand this for full expression parsing (e.g., precedence)
    if (user_agent) {
        return conf->status;
    }

    // Example condition based on IP address (can be configured similarly)
    if (ngx_strcmp(remote_addr.data, "127.0.0.1") == 0) {
        return conf->status;  // Return the configured status code
    }

    // If no conditions match, allow the request
    return NGX_DECLINED;
}

// Register the handler to run in the access phase
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&main_conf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "null");
        return NGX_ERROR;
    }

    *h = ngx_http_waf_handler;

    return NGX_OK;
}
