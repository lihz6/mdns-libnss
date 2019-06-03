#ifndef _LNSS_UTIL_H
#define _LNSS_UTIL_H
#include <inttypes.h>
#include <netdb.h>
#include <nss.h>
#include <resolv.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "rslv.h"

// Simple buffer allocator.
typedef struct
{
    char *next;
    char *end;
} buffer_t;

// Sets up a buffer.
void buffer_init(buffer_t *buf, char *buffer, size_t buflen);

// Allocates a zeroed, aligned chunk of memory of a given size from the buffer
// manager.
// If there is insufficient space, returns NULL.
void *buffer_alloc(buffer_t *buf, size_t size);

// Duplicates a string into a newly allocated chunk of memory.
// If there is insufficient space, returns NULL.
char *buffer_strdup(buffer_t *buf, const char *str);

// Macro to help with checking buffer allocation results.
#define RETURN_IF_FAILED_ALLOC(ptr) \
    if (ptr == NULL)                \
    {                               \
        *errnop = ERANGE;           \
        *h_errnop = NO_RECOVERY;    \
        return NSS_STATUS_TRYAGAIN; \
    }

int set_cloexec(int fd);
int ends_with(const char *name, const char *suffix);

// Returns true if we should try to resolve the name with mDNS.
//
// If mdns_allow_file is NULL, then this implements the "local" SOA
// check and two-label name checks similarly to the algorithm
// described at https://support.apple.com/en-us/HT201275. This means
// that if a unicast DNS server claims authority on "local", or if the
// user tries to resolve a >2-label name, we will not do mDNS resolution.
//
// The two heuristics described above are disabled if mdns_allow_file
// is not NULL.
int verify_name_allowed_with_soa(const char *name);

// Tells us if the name is not allowed unconditionally, allowed only
// if local_soa() returns false, or unconditionally allowed.
int verify_name_allowed(const char *name);

// Returns true if a DNS server claims authority over "local".
int not_local_soa(void);

int dot_count_before_local(const char *name);

// Returns `b.local` from `a.b.local`.
const char *strip_name_to_next_dot(const char *name);

// Converts from a name and addr into the hostent format, used by
// gethostbyaddr_r.
enum nss_status convert_name_and_addr_to_hostent(const char *name,
                                                 const void *addr, int len,
                                                 int af, struct hostent *result,
                                                 buffer_t *buf, int *errnop,
                                                 int *h_errnop);

// Converts from the userdata struct into the hostent format, used by
// gethostbyaddr3_r.
enum nss_status convert_userdata_for_name_to_hostent(const query_address_result_list_t *u,
                                                     const char *name, int af,
                                                     struct hostent *result,
                                                     buffer_t *buf, int *errnop,
                                                     int *h_errnop);

// Converts from the userdata struct into the gaih_addrtuple format, used by
// gethostbyaddr4_r.
enum nss_status convert_query_address_result_list_to_addrtuple(const query_address_result_list_t *u,
                                              const char *name,
                                              struct gaih_addrtuple **pat,
                                              buffer_t *buf, int *errnop,
                                              int *h_errnop);

// Appends a query_address_result to userdata.
void append_address_to_userdata(const query_address_result_t *result,
                                query_address_result_list_t *u);

#endif
