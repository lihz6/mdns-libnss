#ifndef _LNSS_MDNS_H
#define _LNSS_MDNS_H
#include <inttypes.h>
#include <sys/types.h>

// Maximum number of entries to return.
#define MAX_ENTRIES 16

typedef struct
{
    uint32_t address;
} ipv4_address_t;

typedef struct
{
    uint8_t address[16];
} ipv6_address_t;

typedef struct
{
    int af;
    union {
        ipv4_address_t ipv4;
        ipv6_address_t ipv6;
    } address;
    uint32_t scopeid;
} query_address_result_t;

typedef struct
{
    int count;
    query_address_result_t result[MAX_ENTRIES];
} query_address_result_list_t;

typedef enum
{
    MDNS_RESOLVE_RESULT_SUCCESS,
    MDNS_RESOLVE_RESULT_HOST_NOT_FOUND,
    MDNS_RESOLVE_RESULT_UNAVAIL
} mdns_resolve_result_t;

mdns_resolve_result_t mdns_resolve_name(int af, const char *name, query_address_result_list_t *result_list);

mdns_resolve_result_t mdns_resolve_address(int af, const void *data, char *name, size_t name_len);

#endif
