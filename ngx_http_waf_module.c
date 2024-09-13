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
    ngx_array_t *rules;
} ngx_http_waf_conf_t;

typedef struct {
    ngx_str_t expression;
    ngx_int_t status;
} ngx_http_waf_rule_t;

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
static char *ngx_http_waf_expressions(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);

int serve_response(ngx_http_request_t *r, ngx_http_waf_rule_t *conf);

static bool eval_condition(ngx_http_request_t *r, const char *condition);
static bool parse_and_evaluate_expression(ngx_http_request_t *r, const char *expression);
bool extract_quoted_value(const char *condition, char *value, size_t value_size);

static bool check_user_agent_contains(ngx_http_request_t *r, const char *value);
static bool check_user_agent_equals(ngx_http_request_t *r, const char *value);

static ngx_command_t ngx_http_waf_commands[] = {
    {
        ngx_string("waf_rules"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_BLOCK,
        ngx_http_waf_expressions,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
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
    ngx_http_waf_merge_loc_conf         // merge location configuration
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
    ngx_http_waf_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_waf_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_waf_conf_t *prev = parent;
    ngx_http_waf_conf_t *conf = child;

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }

    return NGX_CONF_OK;
}

static char *ngx_http_waf_expressions(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_conf_t save = *cf;

    cf->handler = ngx_http_waf_expression;
    cf->handler_conf = conf;

    char *rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}

static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_waf_conf_t *mlcf = conf;
    ngx_str_t *value = cf->args->elts;

    if (cf->args->nelts != 2) {
        return NGX_CONF_ERROR;
    }

    if (mlcf->rules == NULL) {
        mlcf->rules = ngx_array_create(cf->pool, 4, sizeof(ngx_http_waf_rule_t));
        if (mlcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ngx_http_waf_rule_t *rule = ngx_array_push(mlcf->rules);

    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    rule->expression = value[0];
    rule->status = ngx_atoi(value[1].data, value[1].len);

    if (rule->status == NGX_ERROR) {
        return "waf_rules directive invalid status code";
    }

    if (rule->status < 100 || rule->status > 599) {
        return "waf_rules directive invalid HTTP status code, must be between 100 and 599";
    }

    return NGX_CONF_OK;
}

int serve_response(ngx_http_request_t *r, ngx_http_waf_rule_t *conf) {
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
    ngx_http_waf_conf_t *conf;
    ngx_http_waf_rule_t *rules;
    ngx_uint_t i;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf->rules == NULL) {
        return NGX_DECLINED;
    }

    rules = conf->rules->elts;

    for (i = 0; i < conf->rules->nelts; i++) {
        ngx_http_waf_rule_t rule = rules[i];

        if (parse_and_evaluate_expression(r, (char *) rule.expression.data)) {
            return serve_response(r, &rule);
        }
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

bool extract_quoted_value(const char *condition, char *value, size_t value_size) {
    const char *start = strchr(condition, '\'');
    if (start == NULL) {
        return false;
    }
    start++;

    const char *end = start;
    size_t len = 0;

    while (*end != '\0' && len < value_size - 1) {
        if (*end == '\'' && (end == start || *(end - 1) != '\\')) {
            break;
        }
        value[len++] = *end;
        end++;
    }

    if (*end != '\'') {
        return false;
    }

    value[len] = '\0';
    return true;
}

static bool eval_condition(ngx_http_request_t *r, const char *condition) {
    bool invert = false;

    if (strncmp(condition, "not ", 4) == 0) {
        invert = true;
        condition += 4;
    }

    char action[256];
    char operator[16];
    char value[256];
    //char key[256];

    if (sscanf(condition, "%s %s", action, operator) != 2) {
        return false;
    }

    if (!extract_quoted_value(condition, value, sizeof(value))) {
        return false;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ debug ] %s", value);

    if (strcmp(action, "http.user_agent") == 0) {
        bool result;
        if (strcmp(operator, "contains") == 0) {
            result = check_user_agent_contains(r, value);
        } else if (strcmp(operator, "eq") == 0) {
            result = check_user_agent_equals(r, value);
        } else {
            return false;
        }
        return invert ? !result : result;
    }
    /*else if (strcmp(action, "http.cookie") == 0) {

    } else if (sscanf(condition, "http.request.headers[%255] %s \"%255[^\"]\"", key, operator, value) == 3) {

    } else if (sscanf(condition, "http.request.cookies[%255] %s \"%255[^\"]\"", key, operator, value) == 3) {

    }*/

    return false;
}

static bool check_user_agent_contains(ngx_http_request_t *r, const char *value) {
    ngx_table_elt_t *user_agent_header = r->headers_in.user_agent;

    if (user_agent_header == NULL) {
        return false;
    }

    u_char *user_agent = user_agent_header->value.data;

    if (ngx_strcasestrn(user_agent, (char *) value, ngx_strlen(value) - 1) != NULL) {
        return true;
    }

    return false;
}

static bool check_user_agent_equals(ngx_http_request_t *r, const char *value) {
    ngx_table_elt_t *user_agent_header = r->headers_in.user_agent;

    if (user_agent_header == NULL) {
        return false;
    }

    ngx_str_t *user_agent = &user_agent_header->value;

    if (ngx_strcasecmp(user_agent->data, (u_char *) value) == 0) {
        return true;
    }

    return false;
}
