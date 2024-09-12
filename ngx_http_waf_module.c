#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#define HTML_TEMPLATE \
        "<!DOCTYPE html>" \
        "<html>" \
        "<head>" \
        "<meta charset=\"UTF-8\">" \
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" \
        "<title>%s</title>" \
        "</head>" \
        "<body>" \
        "%s" \
        "</body>" \
        "</html>"

typedef struct {
    ngx_str_t expression;
    ngx_int_t status;
} ngx_http_waf_config_t;

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);

static bool eval_condition(ngx_http_request_t *r, const char *condition);
static bool parse_and_evaluate_expression(ngx_http_request_t *r, const char *expression);
static bool check_user_agent(ngx_http_request_t *r, const char *value);
static bool check_ip(ngx_http_request_t *r, const char *value);

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

ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,           // module context
    ngx_http_waf_commands,              // module directives
    NGX_HTTP_MODULE,                    // module type
    NULL,                               // init master
    NULL,                               // init module
    NULL,                               // init process
    NULL,                               // init thread
    NULL,                               // exit thread
    NULL,                               // exit process
    NULL,                               // exit master
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_waf_config_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_config_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->expression = (ngx_str_t) {0, NULL};
    conf->status = NGX_HTTP_FORBIDDEN;

    return conf;
}

static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_waf_config_t *block_conf = conf;
    ngx_str_t *value = cf->args->elts;

    block_conf->expression = value[1];

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

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r) {
    ngx_http_waf_config_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf->expression.len == 0) {
        return NGX_DECLINED;
    }

    char expression[conf->expression.len + 1];
    ngx_memcpy(expression, conf->expression.data, conf->expression.len);
    expression[conf->expression.len] = '\0';

    if (parse_and_evaluate_expression(r, expression)) {
        return serve_response(r, conf);
    }

    return NGX_DECLINED;
}

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

static bool parse_and_evaluate_expression(ngx_http_request_t *r, const char *expression) {
    bool result = false;
    bool current_value = false;
    char *operator = NULL;

    char *expr = ngx_pnalloc(r->pool, strlen(expression) + 1);
    if (expr == NULL) {
        return false;
    }

    ngx_memcpy(expr, expression, strlen(expression) + 1);

    char *token = strtok(expr, "()");

    while (token != NULL) {
        while (isspace(*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) *end-- = '\0';

        if (strncmp(token, "or", 2) == 0 || strncmp(token, "and", 3) == 0) {
            operator = token;
        } else {
            current_value = eval_condition(r, token);
            if (operator == NULL) {
                result = current_value;
            } else if (strcmp(operator, "or") == 0) {
                result = result || current_value;
            } else if (strcmp(operator, "and") == 0) {
                result = result && current_value;
            }
        }
        token = strtok(NULL, "()");
    }

    return result;
}

static bool eval_condition(ngx_http_request_t *r, const char *condition) {
    if (strstr(condition, "http.user_agent contains") != NULL) {
        char *value = strstr(condition, "\"") + 1;
        value[strlen(value) - 1] = '\0';
        return check_user_agent(r, value);
    } else if (strstr(condition, "ip.src eq") != NULL) {
        char *value = strstr(condition, "eq") + 3;
        return check_ip(r, value);
    }

    return false;
}

static bool check_user_agent(ngx_http_request_t *r, const char *value) {
    ngx_table_elt_t *user_agent_header = r->headers_in.user_agent;
    ngx_str_t *user_agent = user_agent_header ? &user_agent_header->value : NULL;

    if (user_agent && ngx_strcasestrn(user_agent->data, (char *)value, ngx_strlen(value) - 1) != NULL) {
        return true;
    }
    return false;
}

static bool check_ip(ngx_http_request_t *r, const char *value) {
    ngx_str_t remote_addr = r->connection->addr_text;

    if (ngx_strcmp(remote_addr.data, value) == 0) {
        return true;
    }

    return false;
}
