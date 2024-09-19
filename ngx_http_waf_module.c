#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HTML_TEMPLATE \
        "<!DOCTYPE html>" \
        "<html>" \
        "<head>" \
        "<meta charset=\"UTF-8\">" \
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">" \
        "<meta name=\"robots\" content=\"noindex,nofollow\">" \
        "<title>%s</title>" \
        "</head>" \
        "<body>" \
        "%s" \
        "</body>" \
        "</html>"

#define CHALLENGE_HTML_TEMPLATE \
        "<!DOCTYPE html>" \
        "<html>" \
        "<head>" \
        "<meta charset=\"UTF-8\">" \
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">" \
        "<meta name=\"robots\" content=\"noindex,nofollow\">" \
        "<title>%s</title>" \
        "</head>" \
        "<body>" \
        "%s" \
        "<script>" \
        "window.onload=function(){!function(){function t(t){t?(f[0]=f[16]=f[1]=f[2]=f[3]=f[4]=f[5]=f[6]=f[7]=f[8]=f[9]=f[10]=f[11]=f[12]=f[13]=f[14]=f[15]=0,this.blocks=f):this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],this.h0=1732584193,this.h1=4023233417,this.h2=2562383102,this.h3=271733878,this.h4=3285377520,this.block=this.start=this.bytes=this.hBytes=0,this.finalized=this.hashed=!1,this.first=!0}var h=\"object\"==typeof window?window:{},s=!h.JS_SHA1_NO_NODE_JS&&\"object\"==typeof process&&process.versions&&process.versions.node;s&&(h=global);var i=!h.JS_SHA1_NO_COMMON_JS&&\"object\"==typeof module&&module.exports,e=\"function\"==typeof define&&define.amd,r=\"0123456789abcdef\".split(\"\"),o=[-2147483648,8388608,32768,128],n=[24,16,8,0],a=[\"hex\",\"array\",\"digest\",\"arrayBuffer\"],f=[],u=function(h){return function(s){return new t(!0).update(s)[h]()}},c=function(){var h=u(\"hex\");s&&(h=p(h)),h.create=function(){return new t},h.update=function(t){return h.create().update(t)};for(var i=0;i<a.length;++i){var e=a[i];h[e]=u(e)}return h},p=function(t){var h=eval(\"require('crypto')\"),s=eval(\"require('buffer').Buffer\"),i=function(i){if(\"string\"==typeof i)return h.createHash(\"s1\").update(i,\"utf8\").digest(\"hex\");if(i.constructor===ArrayBuffer)i=new Uint8Array(i);else if(void 0===i.length)return t(i);return h.createHash(\"s1\").update(new s(i)).digest(\"hex\")};return i};t.prototype.update=function(t){if(!this.finalized){var s=\"string\"!=typeof t;s&&t.constructor===h.ArrayBuffer&&(t=new Uint8Array(t));for(var i,e,r=0,o=t.length||0,a=this.blocks;r<o;){if(this.hashed&&(this.hashed=!1,a[0]=this.block,a[16]=a[1]=a[2]=a[3]=a[4]=a[5]=a[6]=a[7]=a[8]=a[9]=a[10]=a[11]=a[12]=a[13]=a[14]=a[15]=0),s)for(e=this.start;r<o&&e<64;++r)a[e>>2]|=t[r]<<n[3&e++];else for(e=this.start;r<o&&e<64;++r)(i=t.charCodeAt(r))<128?a[e>>2]|=i<<n[3&e++]:i<2048?(a[e>>2]|=(192|i>>6)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]):i<55296||i>=57344?(a[e>>2]|=(224|i>>12)<<n[3&e++],a[e>>2]|=(128|i>>6&63)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]):(i=65536+((1023&i)<<10|1023&t.charCodeAt(++r)),a[e>>2]|=(240|i>>18)<<n[3&e++],a[e>>2]|=(128|i>>12&63)<<n[3&e++],a[e>>2]|=(128|i>>6&63)<<n[3&e++],a[e>>2]|=(128|63&i)<<n[3&e++]);this.lastByteIndex=e,this.bytes+=e-this.start,e>=64?(this.block=a[16],this.start=e-64,this.hash(),this.hashed=!0):this.start=e}return this.bytes>4294967295&&(this.hBytes+=this.bytes/4294967296<<0,this.bytes=this.bytes%%4294967296),this}},t.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,h=this.lastByteIndex;t[16]=this.block,t[h>>2]|=o[3&h],this.block=t[16],h>=56&&(this.hashed||this.hash(),t[0]=this.block,t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[14]=this.hBytes<<3|this.bytes>>>29,t[15]=this.bytes<<3,this.hash()}},t.prototype.hash=function(){var t,h,s=this.h0,i=this.h1,e=this.h2,r=this.h3,o=this.h4,n=this.blocks;for(t=16;t<80;++t)h=n[t-3]^n[t-8]^n[t-14]^n[t-16],n[t]=h<<1|h>>>31;for(t=0;t<20;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i&e|~i&r)+o+1518500249+n[t]<<0)<<5|o>>>27)+(s&(i=i<<30|i>>>2)|~s&e)+r+1518500249+n[t+1]<<0)<<5|r>>>27)+(o&(s=s<<30|s>>>2)|~o&i)+e+1518500249+n[t+2]<<0)<<5|e>>>27)+(r&(o=o<<30|o>>>2)|~r&s)+i+1518500249+n[t+3]<<0)<<5|i>>>27)+(e&(r=r<<30|r>>>2)|~e&o)+s+1518500249+n[t+4]<<0,e=e<<30|e>>>2;for(;t<40;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i^e^r)+o+1859775393+n[t]<<0)<<5|o>>>27)+(s^(i=i<<30|i>>>2)^e)+r+1859775393+n[t+1]<<0)<<5|r>>>27)+(o^(s=s<<30|s>>>2)^i)+e+1859775393+n[t+2]<<0)<<5|e>>>27)+(r^(o=o<<30|o>>>2)^s)+i+1859775393+n[t+3]<<0)<<5|i>>>27)+(e^(r=r<<30|r>>>2)^o)+s+1859775393+n[t+4]<<0,e=e<<30|e>>>2;for(;t<60;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i&e|i&r|e&r)+o-1894007588+n[t]<<0)<<5|o>>>27)+(s&(i=i<<30|i>>>2)|s&e|i&e)+r-1894007588+n[t+1]<<0)<<5|r>>>27)+(o&(s=s<<30|s>>>2)|o&i|s&i)+e-1894007588+n[t+2]<<0)<<5|e>>>27)+(r&(o=o<<30|o>>>2)|r&s|o&s)+i-1894007588+n[t+3]<<0)<<5|i>>>27)+(e&(r=r<<30|r>>>2)|e&o|r&o)+s-1894007588+n[t+4]<<0,e=e<<30|e>>>2;for(;t<80;t+=5)s=(h=(i=(h=(e=(h=(r=(h=(o=(h=s<<5|s>>>27)+(i^e^r)+o-899497514+n[t]<<0)<<5|o>>>27)+(s^(i=i<<30|i>>>2)^e)+r-899497514+n[t+1]<<0)<<5|r>>>27)+(o^(s=s<<30|s>>>2)^i)+e-899497514+n[t+2]<<0)<<5|e>>>27)+(r^(o=o<<30|o>>>2)^s)+i-899497514+n[t+3]<<0)<<5|i>>>27)+(e^(r=r<<30|r>>>2)^o)+s-899497514+n[t+4]<<0,e=e<<30|e>>>2;this.h0=this.h0+s<<0,this.h1=this.h1+i<<0,this.h2=this.h2+e<<0,this.h3=this.h3+r<<0,this.h4=this.h4+o<<0},t.prototype.hex=function(){this.finalize();var t=this.h0,h=this.h1,s=this.h2,i=this.h3,e=this.h4;return r[t>>28&15]+r[t>>24&15]+r[t>>20&15]+r[t>>16&15]+r[t>>12&15]+r[t>>8&15]+r[t>>4&15]+r[15&t]+r[h>>28&15]+r[h>>24&15]+r[h>>20&15]+r[h>>16&15]+r[h>>12&15]+r[h>>8&15]+r[h>>4&15]+r[15&h]+r[s>>28&15]+r[s>>24&15]+r[s>>20&15]+r[s>>16&15]+r[s>>12&15]+r[s>>8&15]+r[s>>4&15]+r[15&s]+r[i>>28&15]+r[i>>24&15]+r[i>>20&15]+r[i>>16&15]+r[i>>12&15]+r[i>>8&15]+r[i>>4&15]+r[15&i]+r[e>>28&15]+r[e>>24&15]+r[e>>20&15]+r[e>>16&15]+r[e>>12&15]+r[e>>8&15]+r[e>>4&15]+r[15&e]},t.prototype.toString=t.prototype.hex,t.prototype.digest=function(){this.finalize();var t=this.h0,h=this.h1,s=this.h2,i=this.h3,e=this.h4;return[t>>24&255,t>>16&255,t>>8&255,255&t,h>>24&255,h>>16&255,h>>8&255,255&h,s>>24&255,s>>16&255,s>>8&255,255&s,i>>24&255,i>>16&255,i>>8&255,255&i,e>>24&255,e>>16&255,e>>8&255,255&e]},t.prototype.array=t.prototype.digest,t.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(20),h=new DataView(t);return h.setUint32(0,this.h0),h.setUint32(4,this.h1),h.setUint32(8,this.h2),h.setUint32(12,this.h3),h.setUint32(16,this.h4),t};var y=c();i?module.exports=y:(h.s1=y,e&&define(function(){return y}))}();" \
        "const a0_0x2a54=['%s','_chk_tkn=','array'];(function(_0x41abf3,_0x2a548e){const _0x4457dc=function(_0x804ad2){while(--_0x804ad2){_0x41abf3['push'](_0x41abf3['shift']());}};_0x4457dc(++_0x2a548e);}(a0_0x2a54,0x178));const a0_0x4457=function(_0x41abf3,_0x2a548e){_0x41abf3=_0x41abf3-0x0;let _0x4457dc=a0_0x2a54[_0x41abf3];return _0x4457dc;};let c=a0_0x4457('0x2');let i=0x0;let n1=parseInt('0x'+c[0x0]);while(!![]){let s=s1[a0_0x4457('0x1')](c+i);if(s[n1]===0xb0&&s[n1+0x1]===0xb){document['cookie']=a0_0x4457('0x0')+c+i+'; path=/';break;}i++;};" \
        ";window.setTimeout(function(){window.location.reload()}, 2000)}" \
        "</script>" \
        "</body>" \
        "</html>"

#define DEFAULT_BLOCK_CONTENT \
    "<style>body{font-family:Arial,sans-serif;text-align:center;background-color:#fff;color:#333;margin:0;padding:0 20px;height:100vh;display:flex;justify-content:center;align-items:center;flex-direction:column}.message{font-size:20px}.sub-message{font-size:15px;line-height:20px;color:#666;margin:12px 0}.message,.sub-message{max-width:445px}</style>" \
    "<div class=\"message\">Access Denied</div><div class=\"sub-message\">Access to this website has been restricted for your connection. This may be due to your location, browser settings, or other access restrictions.</div>"

#define DEFAULT_CHALLENGE_CONTENT \
    "<style>body{font-family:Arial,sans-serif;text-align:center;background-color:#fff;color:#333;margin:0;padding:0 20px;height:100vh;display:flex;justify-content:center;align-items:center;flex-direction:column}.loader{display:inline-block;margin-bottom:20px}.loader div{width:10px;height:10px;background-color:#000;border-radius:50%;display:inline-block;animation:bounce 1.4s infinite ease-in-out both}.loader div:nth-child(1){animation-delay:-.32s}.loader div:nth-child(2){animation-delay:-.16s;margin-left:4px}.loader div:nth-child(3){animation-delay:0s;margin-left:4px}@keyframes bounce{0%,100%,80%{transform:scale(0)}40%{transform:scale(1)}}.message{font-size:20px}.sub-message{font-size:15px;line-height:20px;color:#666;margin:12px 0}.message,.sub-message{max-width:445px}</style>" \
    "<div class=\"loader\"><div></div><div></div><div></div></div><div class=\"message\">Checking your browser</div><div class=\"sub-message\">This process is performed automatically. You will be redirected shortly.</div>"

#define DEFAULT_BLOCK_TITLE "Access Denied"
#define DEFAULT_CHALLENGE_TITLE "Verifying your browser..."

#define DEFAULT_SECRET "shhh-changeme"

#define SHA1_MD_LEN 20
#define SHA1_STR_LEN 40

typedef struct {
    ngx_array_t *rules;
    ngx_str_t ip_country;
    ngx_str_t ip_continent;
    ngx_str_t ip_asn;
    ngx_str_t challenge_secret;
} ngx_http_waf_conf_t;

typedef struct {
    ngx_str_t expression;
    ngx_str_t action;
    ngx_int_t status;
} ngx_http_waf_rule_t;

typedef struct {
    unsigned int processed:1;
} ngx_http_waf_ctx_t;

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
static char *ngx_http_waf_expressions(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_waf_expression(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);

int serve_response(ngx_http_request_t *r, ngx_http_waf_rule_t *rule);
int serve_challenge(ngx_http_request_t *r, const char *challenge);

static bool eval_condition(ngx_http_request_t *r, const char *condition);
static bool parse_and_evaluate_expression(ngx_http_request_t *r, const char *expression);
bool extract_quoted_value(const char *condition, char *value, size_t value_size);

static bool check_user_agent_contains(ngx_http_request_t *r, const char *value);
static bool check_user_agent_equals(ngx_http_request_t *r, const char *value);

static bool check_ip_continent_equals(ngx_http_request_t *r, const char *value);
static bool check_ip_country_equals(ngx_http_request_t *r, const char *value);
static bool check_ip_asn_equals(ngx_http_request_t *r, const char *value);

unsigned char *__sha1(const unsigned char *d, size_t n, unsigned char *md);

static ngx_command_t ngx_http_waf_commands[] = {
    {
        ngx_string("waf_rules"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_BLOCK,
        ngx_http_waf_expressions,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("waf_ip_country"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_waf_conf_t, ip_country),
        NULL
    },
    {
        ngx_string("waf_ip_continent"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_waf_conf_t, ip_continent),
        NULL
    },
    {
        ngx_string("waf_ip_asn"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_waf_conf_t, ip_asn),
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

    conf->ip_country = (ngx_str_t) {0, NULL};
    conf->ip_continent = (ngx_str_t) {0, NULL};
    conf->ip_asn = (ngx_str_t) {0, NULL};
    conf->challenge_secret = (ngx_str_t) {0, NULL};

    return conf;
}

static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_waf_conf_t *prev = parent;
    ngx_http_waf_conf_t *conf = child;

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    } else if (prev->rules != NULL) {
        ngx_uint_t i;
        ngx_str_t *rule;
        ngx_str_t *new_rule;

        rule = prev->rules->elts;
        for (i = 0; i < prev->rules->nelts; i++) {
            new_rule = ngx_array_push(conf->rules);
            if (new_rule == NULL) {
                return NGX_CONF_ERROR;
            }
            *new_rule = rule[i];
        }
    }

    ngx_conf_merge_str_value(conf->ip_country, prev->ip_country, NULL)
    ngx_conf_merge_str_value(conf->ip_continent, prev->ip_continent, NULL)
    ngx_conf_merge_str_value(conf->ip_asn, prev->ip_asn, NULL)
    ngx_conf_merge_str_value(conf->challenge_secret, prev->challenge_secret, DEFAULT_SECRET)

    return NGX_CONF_OK;
}

__always_inline
static void buf2hex(const unsigned char *buf, size_t buflen, char *hex_string) {
    static const char hexdig[] = "0123456789ABCDEF";

    const unsigned char *p;
    size_t i;

    char *s = hex_string;
    for (i = 0, p = buf; i < buflen; i++, p++) {
        *s++ = hexdig[(*p >> 4) & 0x0f];
        *s++ = hexdig[*p & 0x0f];
    }
}

void get_challenge_string(int32_t bucket, ngx_str_t addr, ngx_str_t secret, char *out) {
    char buf[4096];
    unsigned char md[SHA1_MD_LEN];

    char *p = (char *) &bucket;
    /*
     * Challenge= hex( SHA1( concat(bucket, addr, secret) ) )
     */
    memcpy(buf, p, sizeof(bucket));
    memcpy((buf + sizeof(int32_t)), addr.data, addr.len);
    memcpy((buf + sizeof(int32_t) + addr.len), secret.data, secret.len);

    __sha1((unsigned char *) buf, (size_t) (sizeof(int32_t) + addr.len + secret.len), md);
    buf2hex(md, SHA1_MD_LEN, out);
}

int verify_response(ngx_str_t response, char *challenge) {

    /*
     * Response is valid if it starts by the challenge, and
     * its SHA1 hash contains the digits 0xB00B at the offset
     * of the first digit
     *
     * e.g.
     * challenge =      "CC003677C91D53E29F7095FF90C670C69C7C46E7"
     * response =       "CC003677C91D53E29F7095FF90C670C69C7C46E7635919"
     * SHA1(response) = "CCAE6E414FA62F9C2DFC2742B00B5C94A549BAE6"
     *                                           ^ offset 24
     */

    //todo also check if the response is too large
    if (response.len <= SHA1_STR_LEN) {
        return -1;
    }

    if (strncmp(challenge, (char *) response.data, SHA1_STR_LEN) != 0) {
        return -1;
    }

    unsigned char md[SHA1_MD_LEN];
    __sha1((unsigned char *) response.data, response.len, md);

    unsigned int nibble1;
    if (challenge[0] <= '9') {
        nibble1 = challenge[0] - '0';
    } else {
        nibble1 = challenge[0] - 'A' + 10;
    }

    return md[nibble1] == 0xB0 && md[nibble1 + 1] == 0x0B ? 0 : -1;
}

int get_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
#if defined(nginx_version) && nginx_version >= 1023000
    ngx_table_elt_t *h;
    for (h = r->headers_in.cookie; h; h = h->next) {
        u_char *start = h->value.data;
        u_char *end = h->value.data + h->value.len;
#else
    ngx_table_elt_t **h;
    h = r->headers_in.cookies.elts;

    ngx_uint_t i = 0;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        u_char *start = h[i]->value.data;
        u_char *end = h[i]->value.data + h[i]->value.len;
#endif
        while (start < end) {
            while (start < end && *start == ' ') { start++; }

            if (ngx_strncmp(start, name->data, name->len) == 0) {
                u_char *last;
                for (last = start; last < end && *last != ';'; last++) {}
                while (*start++ != '=' && start < last) {}

                value->data = start;
                value->len = (last - start);
                return 0;
            }
            while (*start++ != ';' && start < end) {}
        }
    }

    return -1;
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

    if (cf->args->nelts < 4) {
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

    rule->expression = value[1];
    rule->action = value[3];
    rule->status = cf->args->nelts > 4 ? ngx_atoi(value[4].data, value[4].len) : ngx_atoi((u_char *) "403", 3);

    if (rule->status == NGX_ERROR) {
        return "waf_rules directive invalid status code";
    }

    if (rule->status < 100 || rule->status > 599) {
        return "waf_rules directive invalid HTTP status code, must be between 100 and 599";
    }

    return NGX_CONF_OK;
}

int serve_response(ngx_http_request_t *r, ngx_http_waf_rule_t *rule) {
    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;

    unsigned char buf[32768];
    static const ngx_str_t content_type = ngx_string("text/html;charset=utf-8");

    size_t size = snprintf((char *) buf, sizeof(buf), HTML_TEMPLATE, DEFAULT_BLOCK_TITLE, DEFAULT_BLOCK_CONTENT);

    out.buf = b;
    out.next = NULL;

    b->pos = buf;
    b->last = buf + size;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = rule->status;
    r->headers_out.content_length_n = size;
    r->headers_out.content_type = content_type;
    ngx_http_send_header(r);

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);

    return NGX_DONE;
}

int serve_challenge(ngx_http_request_t *r, const char *challenge) {
    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    ngx_chain_t out;

    char challenge_c_str[SHA1_STR_LEN + 1];
    memcpy(challenge_c_str, challenge, SHA1_STR_LEN);
    *(challenge_c_str + SHA1_STR_LEN) = '\0';

    unsigned char buf[32768];
    static const ngx_str_t content_type = ngx_string("text/html;charset=utf-8");

    size_t size = snprintf((char *) buf, sizeof(buf), CHALLENGE_HTML_TEMPLATE, DEFAULT_CHALLENGE_TITLE, DEFAULT_CHALLENGE_CONTENT, challenge_c_str);

    out.buf = b;
    out.next = NULL;

    b->pos = buf;
    b->last = buf + size;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_FORBIDDEN;
    r->headers_out.content_length_n = size;
    r->headers_out.content_type = content_type;
    ngx_http_send_header(r);

    ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, 0);
    return NGX_DONE;
}

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r) {
    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    ngx_http_waf_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_waf_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_waf_module);
    }

    if (ctx->processed) {
        return NGX_DECLINED;
    }

    ngx_http_waf_conf_t *conf;
    ngx_http_waf_rule_t *rules;
    ngx_uint_t i;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf->rules == NULL) {
        return NGX_DECLINED;
    }

    ctx->processed = 1;

    rules = conf->rules->elts;

    bool present_challenge = false;

    for (i = 0; i < conf->rules->nelts; i++) {
        ngx_http_waf_rule_t rule = rules[i];

        if (!parse_and_evaluate_expression(r, (char *) rule.expression.data)) {
            continue;
        }

        if (strncmp((char *) rule.action.data, "block", 5) == 0) {
            return serve_response(r, &rule);
        }

        if (strncmp((char *) rule.action.data, "challenge", 9) == 0) {
            present_challenge = true;
        }
    }

    if (!present_challenge) {
        return NGX_DECLINED;
    }

    unsigned long bucket = r->start_sec - (r->start_sec % 3600);
    ngx_str_t addr = r->connection->addr_text;

    char challenge[SHA1_STR_LEN];
    get_challenge_string(bucket, addr, conf->challenge_secret, challenge);

    ngx_str_t response;
    ngx_str_t cookie_name = ngx_string("_chk_tkn");
    int ret = get_cookie(r, &cookie_name, &response);

    if (ret < 0) {
        return serve_challenge(r, challenge);
    }

    get_challenge_string(bucket, addr, conf->challenge_secret, challenge);

    if (verify_response(response, challenge) != 0) {
        return serve_challenge(r, challenge);
    }

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&main_conf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
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
    if (condition == NULL || value == NULL || value_size == 0) {
        return false;
    }

    const char *start = NULL;
    const char *end = NULL;
    const char *p = condition;

    while (*p != '\0') {
        if (*p == '\'') {
            start = p + 1;
            break;
        }
        p++;
    }

    if (start == NULL) {
        return false;
    }

    for (p = start; *p != '\0'; p++) {
        if (*p == '\'' && (*(p - 1) != '\\')) {
            end = p;
            break;
        }
    }

    if (end == NULL) {
        return false;
    }

    size_t length = 0;
    for (p = start; p < end && length < value_size - 1; p++) {
        if (*p == '\\' && (*(p + 1) == '\'')) {
            value[length++] = '\'';
            p++;
        } else {
            value[length++] = *p;
        }
    }

    if (length >= value_size - 1 && p < end) {
        return false;
    }

    value[length] = '\0';

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

    bool result;

    if (strcmp(action, "http.user_agent") == 0) {
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
    else if (strcmp(action, "ip.country") == 0) {
        if (strcmp(operator, "eq") == 0) {
            result = check_ip_country_equals(r, value);
        } else {
            return false;
        }
        return invert ? !result : result;
    }
    else if (strcmp(action, "ip.continent") == 0) {
        if (strcmp(operator, "eq") == 0) {
            result = check_ip_continent_equals(r, value);
        } else {
            return false;
        }
        return invert ? !result : result;
    }
    else if (strcmp(action, "ip.asn") == 0) {
        if (strcmp(operator, "eq") == 0) {
            result = check_ip_asn_equals(r, value);
        } else {
            return false;
        }
        return invert ? !result : result;
    }

    result = false;

    return result;
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

static bool check_ip_continent_equals(ngx_http_request_t *r, const char *value) {
    ngx_http_waf_conf_t *conf;
    ngx_str_t resolved;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf->ip_continent.data[0] == '$') {
        ngx_str_t var_name;

        var_name.data = conf->ip_continent.data + 1;
        var_name.len = conf->ip_continent.len - 1;

        ngx_uint_t key = ngx_hash_strlow(var_name.data, var_name.data, var_name.len);
        ngx_http_variable_value_t *vv = ngx_http_get_variable(r, &var_name, key);

        if (vv == NULL || vv->not_found) {
            return false;
        }

        resolved.data = vv->data;
        resolved.len = vv->len;
    } else {
        resolved = conf->ip_country;
    }

    if (ngx_strncmp(resolved.data, value, resolved.len) == 0) {
        return true;
    }

    return false;
}

static bool check_ip_country_equals(ngx_http_request_t *r, const char *value) {
    ngx_http_waf_conf_t *conf;
    ngx_str_t resolved;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf->ip_country.data[0] == '$') {
        ngx_str_t var_name;

        var_name.data = conf->ip_country.data + 1;
        var_name.len = conf->ip_country.len - 1;

        ngx_uint_t key = ngx_hash_strlow(var_name.data, var_name.data, var_name.len);
        ngx_http_variable_value_t *vv = ngx_http_get_variable(r, &var_name, key);

        if (vv == NULL || vv->not_found) {
            return false;
        }

        resolved.data = vv->data;
        resolved.len = vv->len;
    } else {
        resolved = conf->ip_country;
    }

    if (ngx_strncmp(resolved.data, value, resolved.len) == 0) {
        return true;
    }

    return false;
}

static bool check_ip_asn_equals(ngx_http_request_t *r, const char *value) {
    ngx_http_waf_conf_t *conf;
    ngx_str_t resolved;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (conf->ip_asn.data[0] == '$') {
        ngx_str_t var_name;

        var_name.data = conf->ip_asn.data + 1;
        var_name.len = conf->ip_asn.len - 1;

        ngx_uint_t key = ngx_hash_strlow(var_name.data, var_name.data, var_name.len);
        ngx_http_variable_value_t *vv = ngx_http_get_variable(r, &var_name, key);

        if (vv == NULL || vv->not_found) {
            return false;
        }

        resolved.data = vv->data;
        resolved.len = vv->len;
    } else {
        resolved = conf->ip_asn;
    }

    if (ngx_strncmp(resolved.data, value, resolved.len) == 0) {
        return true;
    }

    return false;
}

/**
 * By Steve Reid <sreid@sea-to-sky.net>
 * 100% Public Domain
 */
void __SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]);

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#if defined (BYTE_ORDER) && defined(BIG_ENDIAN) && (BYTE_ORDER == BIG_ENDIAN)
#define WORDS_BIGENDIAN 1
#endif
#ifdef _BIG_ENDIAN
#define WORDS_BIGENDIAN 1
#endif


/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
/* FIXME: can we do this in an endian-proof way? */
#ifdef WORDS_BIGENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xff00ff00) \
         |(rol(block->l[i],8)&0x00ff00ff))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
                     ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) \
    z+=((w&(x^y))^y)+blk0(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R1(v, w, x, y, z, i) \
    z+=((w&(x^y))^y)+blk(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R2(v, w, x, y, z, i) \
    z+=(w^x^y)+blk(i)+0x6ed9eba1+rol(v,5);w=rol(w,30);
#define R3(v, w, x, y, z, i) \
    z+=(((w|x)&y)|(w&x))+blk(i)+0x8f1bbcdc+rol(v,5);w=rol(w,30);
#define R4(v, w, x, y, z, i) \
    z+=(w^x^y)+blk(i)+0xca62c1d6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */
void __SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union {
        uint8_t c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16 *block;

    CHAR64LONG16 workspace;
    block = &workspace;
    memcpy(block, buffer, 64);

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} __SHA1_CTX;

void __SHA1_Update(__SHA1_CTX *context, const void *p, size_t len);

void __SHA1_Final(uint8_t digest[SHA1_MD_LEN], __SHA1_CTX *context);

void __SHA1_Init(__SHA1_CTX *c)
{
    memset(c, 0, sizeof(*c));
    c->state[0] = 0x67452301UL;
    c->state[1] = 0xefcdab89UL;
    c->state[2] = 0x98badcfeUL;
    c->state[3] = 0x10325476UL;
    c->state[4] = 0xc3d2e1f0UL;
}
/**
* Run your data through this
*
* @param context SHA1-Context
* @param p       Buffer to run SHA1 on
* @param len     Number of bytes
*/
void __SHA1_Update(__SHA1_CTX *context, const void *p, size_t len) {
    const uint8_t *data = p;
    size_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += (uint32_t) (len << 3)) < (len << 3)) {
        context->count[1]++;
    }
    context->count[1] += (uint32_t) (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        __SHA1_Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            __SHA1_Transform(context->state, data + i);
        }
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/**
* Add padding and return the message digest
*
* @param digest  Generated message digest
* @param context SHA1-Context
*/
void __SHA1_Final(uint8_t digest[SHA1_MD_LEN], __SHA1_CTX *context) {
    uint32_t i;
    uint8_t finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t) ((context->count[(i >= 4 ? 0 : 1)]
                >> ((3 - (i & 3)) * 8)) & 255);
    }
    __SHA1_Update(context, (uint8_t *) "\200", 1);
    while ((context->count[0] & 504) != 448) {
        __SHA1_Update(context, (uint8_t *) "\0", 1);
    }
    __SHA1_Update(context, finalcount, 8); /* Should cause SHA1_Transform */
    for (i = 0; i < SHA1_MD_LEN; i++) {
        digest[i] = (uint8_t)
                ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }

    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8);    /* SWR */

    __SHA1_Transform(context->state, context->buffer);
}

unsigned char *__sha1(const unsigned char *d, size_t n, unsigned char *md) {
    __SHA1_CTX c;
    __SHA1_Init(&c);
    __SHA1_Update(&c, d, n);
    __SHA1_Final(md, &c);
    return md;
}