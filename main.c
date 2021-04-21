#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "wirefilter.h"

char *r2str(const char *data, size_t length)
{
    char *s;
    s = malloc(length + 1);
    memset(s, 0, length + 1);
    strncpy(s, data, length);
    return s;
}

wirefilter_externally_allocated_str_t rstr(const char *data)
{
    wirefilter_externally_allocated_str_t str;
    str.data = data;
    str.length = strlen(data);
    return str;
}

int main(int argc, char **args)
{
    wirefilter_static_rust_allocated_str_t version;
    wirefilter_scheme_t *schema;
    wirefilter_externally_allocated_str_t name;
    wirefilter_type_t type;
    wirefilter_execution_context_t *context;
    wirefilter_externally_allocated_str_t rule;
    wirefilter_parsing_result_t result;
    wirefilter_filter_ast_t *ast;
    wirefilter_filter_t *filter;
    wirefilter_rust_allocated_str_t json;

    version = wirefilter_get_version();
    printf("version %s\n", r2str(version.data, version.length));

    // Create Schema
    schema = wirefilter_create_scheme();

    // Add Fields
    name = rstr("http.request.method");
    type = WIREFILTER_TYPE_BYTES;
    wirefilter_add_type_field_to_scheme(schema, name, type);
    name = rstr("http.user_agent");
    type = WIREFILTER_TYPE_BYTES;
    wirefilter_add_type_field_to_scheme(schema, name, type);
    name = rstr("ip.src.ipv4");
    type = WIREFILTER_TYPE_IP;
    wirefilter_add_type_field_to_scheme(schema, name, type);
    name = rstr("ip.src.ipv6");
    type = WIREFILTER_TYPE_IP;
    wirefilter_add_type_field_to_scheme(schema, name, type);
    name = rstr("ip.geoip.asnum");
    type = WIREFILTER_TYPE_INT;
    wirefilter_add_type_field_to_scheme(schema, name, type);

    // Create Context
    context = wirefilter_create_execution_context(schema);

    name = rstr("http.request.method");
    wirefilter_externally_allocated_byte_arr_t get_value;
    char value1[] = {"GET"};
    get_value.data = (unsigned char *)(value1);
    get_value.length = strlen(value1);

    wirefilter_add_bytes_value_to_execution_context(context, name, get_value);

    name = rstr("http.user_agent");
    char value2[] = {"GMozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36ET"};
    get_value.data = (unsigned char *)(value2);
    get_value.length = strlen(value2);
    wirefilter_add_bytes_value_to_execution_context(context, name, get_value);

    name = rstr("ip.src.ipv4");
    uint8_t value3[4] = {'1', '1', '1', '1'};
    get_value.data = (unsigned char *)(value2);
    get_value.length = strlen(value2);
    wirefilter_add_ipv4_value_to_execution_context(context, name, value3);

    // name = rstr("ip.src.ipv6");
    // uint8_t value3[12] = {'1', '1', '1', '1'};
    // get_value.data = (unsigned char *)(value2);
    // get_value.length = strlen(value2);
    // wirefilter_add_ipv4_value_to_execution_context(context, name, value3);

    name = rstr("ip.geoip.asnum");
    int value5 = 1111;
    get_value.data = (unsigned char *)(value2);
    get_value.length = strlen(value2);
    wirefilter_add_int_value_to_execution_context(context, name, value5);

    // Set Rules

    const char *rules[] = {
        "http.request.method eq \"GET\"",
        "http.request.method eq \"POST\"",
        "http.user_agent contains \"Macintosh\"",
        "http.user_agent contains \"MSIE\"",
        "ip.src.ipv4 in{1.1.1.1}",
        "ip.src.ipv4 in{1.1.1.0/24}",
        "not(ip.src.ipv4 in{1.1.1.0/24})",
        "ip.src.ipv4 eq 1.1.1.1",
        "ip.src.ipv4 == 1.1.1.1",
        "ip.geoip.asnum == 1111",
        "ip.geoip.asnum > 1111",
        "ip.geoip.asnum > 1110",
        "ip.geoip.asnum eq 1111",
        "ip.geoip.asnum eq 1112",
        "ip.geoip.asnum in{1111}",
        "ip.geoip.asnum in{1112 1002}",
        "not(ip.geoip.asnum in{1112 1002})",
        "ip.src.ipv4 in{1.1.1.0..1.1.1.255}",
        "ip.src.ipv4 in{1.1.1.10..1.1.1.255}",
        "ip.src.ipv4 in{1.0.0.0/24 10.0.0.0/24}",
        "ip.src.ipv4 in{1.0.0.0/24 10.0.0.0/24 1.1.1.0/24}",
        "ip.src.ipv6 in{2400:cb00::/32}",
        "http.request.method eq \"GET\" and ip.src.ipv4 in{1.1.1.0/24}",
        "http.request.method eq \"GET\" and ip.src.ipv4 in{10.1.1.0/24}",
        "http.request.method eq \"GET\" and ip.src.ipv4 in{10.1.1.0/24} or internal",
        "http.user_agent matches \"(?i)(mac|iphone)\"",
        "http.user_agent matches \"mac\"",
    };

    size_t n = (sizeof(rules) / sizeof(const char *));
    uint64_t h;

    for (size_t i = 0; i < n; i++)
    {
        rule = rstr(rules[i]);
        result = wirefilter_parse_filter(schema, rule);
        if (result.success != 0)
        {
            ast = result.ok.ast;
        }
        else
        {
            printf("parse error %s", r2str(result.err.msg.data, result.err.msg.length));
            continue;
        }

        filter = wirefilter_compile_filter(ast);
        h = wirefilter_get_filter_hash(ast);
        printf("hash %lld \n", h);

        json = wirefilter_serialize_filter_to_json(ast);
        printf("json %s \n", r2str(json.data, json.length));

        if (wirefilter_match(filter, context))
        {
            printf("match!!\n");
        }
        // printf("hash %" PRId64 "\n"", h);
    }

    // Free Schame
    wirefilter_free_scheme(schema);
    return 0;
}
