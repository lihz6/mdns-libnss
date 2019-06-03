#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "util.h"

int set_cloexec(int fd)
{
    int n;
    assert(fd >= 0);

    if ((n = fcntl(fd, F_GETFD)) < 0)
        return -1;

    if (n & FD_CLOEXEC)
        return 0;

    return fcntl(fd, F_SETFD, n | FD_CLOEXEC);
}

int ends_with(const char *name, const char *suffix)
{
    size_t ln, ls;
    assert(name);
    assert(suffix);

    if ((ls = strlen(suffix)) > (ln = strlen(name)))
        return 0;

    return strcasecmp(name + ln - ls, suffix) == 0;
}

int verify_name_allowed_with_soa(const char *name)
{
    int count = verify_name_allowed(name);
    if (count && not_local_soa())
    {
        return count;
    }
    return 0;
}

int verify_name_allowed(const char *name)
{
    assert(name);
    if (strlen(name) >= NI_MAXHOST)
    {
        return 0;
    }
    if (ends_with(name, ".local") || ends_with(name, ".local."))
        return dot_count_before_local(name);
    return 0;
}

int not_local_soa(void)
{
    struct __res_state state;
    int result;
    unsigned char answer[NS_MAXMSG];

    result = res_ninit(&state);
    if (result == -1)
        return 0;
    result =
        res_nquery(&state, "local", ns_c_in, ns_t_soa, answer, sizeof answer);
    res_nclose(&state);
    return result <= 0;
}

int dot_count_before_local(const char *name)
{
    // Start with single label.
    assert(name);
    int count = 0;
    size_t i, len;

    len = strlen(name) - 1;
    // Count all dots not in the last place.
    for (i = 0; i < len; i++)
    {
        if (name[i] == '.')
            count++;
    }

    return count;
}

const char *strip_name_to_next_dot(const char *name)
{
    assert(name);
    size_t i, len;
    len = strlen(name);
    for (i = 1; i < len; i++)
    {
        if (name[i - 1] == '.')
            return name + i;
    }
    return NULL;
}

enum nss_status convert_name_and_addr_to_hostent(const char *name,
                                                 const void *addr, int len,
                                                 int af, struct hostent *result,
                                                 buffer_t *buf, int *errnop,
                                                 int *h_errnop)
{
    // Set empty list of aliases.
    result->h_aliases = (char **)buffer_alloc(buf, sizeof(char **));
    RETURN_IF_FAILED_ALLOC(result->h_aliases);

    // Set official name.
    result->h_name = buffer_strdup(buf, name);
    RETURN_IF_FAILED_ALLOC(result->h_name);

    // Set addrtype and length.
    result->h_addrtype = af;
    result->h_length = len;

    // Initialize address list of length 1, NULL terminated.
    result->h_addr_list = buffer_alloc(buf, 2 * sizeof(char **));
    RETURN_IF_FAILED_ALLOC(result->h_addr_list);

    // Copy the address.
    result->h_addr_list[0] = buffer_alloc(buf, len);
    RETURN_IF_FAILED_ALLOC(result->h_addr_list[0]);
    memcpy(result->h_addr_list[0], addr, len);

    return NSS_STATUS_SUCCESS;
}

enum nss_status convert_userdata_for_name_to_hostent(const query_address_result_list_t *u,
                                                     const char *name, int af,
                                                     struct hostent *result,
                                                     buffer_t *buf, int *errnop,
                                                     int *h_errnop)
{
    size_t address_length =
        af == AF_INET ? sizeof(ipv4_address_t) : sizeof(ipv6_address_t);

    // Set empty list of aliases.
    result->h_aliases = (char **)buffer_alloc(buf, sizeof(char **));
    RETURN_IF_FAILED_ALLOC(result->h_aliases);

    // Set official name.
    result->h_name = buffer_strdup(buf, name);
    RETURN_IF_FAILED_ALLOC(result->h_name);

    // Set addrtype and length.
    result->h_addrtype = af;
    result->h_length = address_length;

    // Initialize address list, NULL terminated.
    result->h_addr_list = buffer_alloc(buf, (u->count + 1) * sizeof(char **));
    RETURN_IF_FAILED_ALLOC(result->h_addr_list);

    // Copy the addresses.
    for (int i = 0; i < u->count; i++)
    {
        char *addr = buffer_alloc(buf, address_length);
        RETURN_IF_FAILED_ALLOC(addr);
        memcpy(addr, &u->result[i].address, address_length);
        result->h_addr_list[i] = addr;
    }

    return NSS_STATUS_SUCCESS;
}

enum nss_status convert_query_address_result_list_to_addrtuple(const query_address_result_list_t *u,
                                                               const char *name,
                                                               struct gaih_addrtuple **pat,
                                                               buffer_t *buf, int *errnop,
                                                               int *h_errnop)
{

    // Copy name to buffer (referenced in every result address tuple).
    char *buffer_name = buffer_strdup(buf, name);
    RETURN_IF_FAILED_ALLOC(buffer_name);

    struct gaih_addrtuple *tuple_prev = NULL;
    for (int i = 0; i < u->count; i++)
    {
        const query_address_result_t *result = &u->result[i];
        struct gaih_addrtuple *tuple;
        if (tuple_prev == NULL && *pat)
        {
            // The caller has provided a valid initial location in *pat,
            // so use that as the first result. Without this, nscd will
            // segfault because it assumes that the buffer is only used as
            // an overflow.
            // See
            // https://lists.freedesktop.org/archives/systemd-devel/2013-February/008606.html
            tuple = *pat;
            memset(tuple, 0, sizeof(*tuple));
        }
        else
        {
            // Allocate a new tuple from the buffer.
            tuple = buffer_alloc(buf, sizeof(struct gaih_addrtuple));
            RETURN_IF_FAILED_ALLOC(tuple);
        }

        size_t address_length = result->af == AF_INET ? sizeof(ipv4_address_t)
                                                      : sizeof(ipv6_address_t);

        // Assign the (always same) name.
        tuple->name = buffer_name;

        // Assign actual address family of address.
        tuple->family = result->af;

        // Copy address.
        memcpy(&(tuple->addr), &(result->address), address_length);

        // Assign interface scope id
        tuple->scopeid = result->scopeid;

        if (tuple_prev == NULL)
        {
            // This is the first tuple.
            // Return the start of the list in *pat.
            *pat = tuple;
        }
        else
        {
            // Link the new tuple into the previous tuple.
            tuple_prev->next = tuple;
        }

        tuple_prev = tuple;
    }

    return NSS_STATUS_SUCCESS;
}

static char *aligned_ptr(char *p)
{
    uintptr_t ptr = (uintptr_t)p;
    if (ptr % sizeof(void *))
    {
        p += sizeof(void *) - (ptr % sizeof(void *));
    }
    return p;
}

void buffer_init(buffer_t *buf, char *buffer, size_t buflen)
{
    // next always points to an aligned location.
    buf->next = aligned_ptr(buffer);
    // end is one past the buffer.
    buf->end = buffer + buflen;
}

void *buffer_alloc(buffer_t *buf, size_t size)
{
    // Zero-length allocations always succeed with non-NULL.
    if (size == 0)
    {
        return buf; // Just a convenient non-NULL pointer.
    }

    char *alloc_end = buf->next + size;
    if (alloc_end > buf->end)
    {
        // No more memory in the buffer.
        return NULL;
    }

    // We have enough space. Set up the next aligned pointer and return
    // the current one, zeroed.
    char *current = buf->next;
    buf->next = aligned_ptr(alloc_end);
    memset(current, 0, size);
    return current;
}

char *buffer_strdup(buffer_t *buf, const char *str)
{
    char *result = buffer_alloc(buf, strlen(str) + 1);
    if (result == NULL)
    {
        return NULL;
    }
    strcpy(result, str);
    return result;
}

void append_address_to_userdata(const query_address_result_t *result,
                                query_address_result_list_t *u)
{
    assert(result && u);

    if (u->count >= MAX_ENTRIES)
        return;

    memcpy(&(u->result[u->count]), result, sizeof(*result));
    u->count++;
}
