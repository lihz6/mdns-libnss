#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>

#include "rslv.h"
#include "mdns.h"
#include "util.h"

#define WHITESPACE " \t"

#define BUFFERSIZE 2048

void print_buffer(const unsigned char *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf(" %02X", buffer[i]);
        if (i % 2)
        {
            putchar('\n');
        }
    }
}

mdns_resolve_result_t mdns_resolve_name(int af, const char *const hostname, query_address_result_list_t *result_list)
{
    const int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    unsigned char buffer[BUFFERSIZE], *puffer;
    const char nodename[NI_MAXHOST];
    struct sockaddr_in sock_addr;
    struct timeval timeout;
    // struct ip_mreq mreq;
    socklen_t addr_len;
    ssize_t readsize;
    if (0 > sockfd)
    {
        perror("socket creation failed");
        close(sockfd);
        return MDNS_RESOLVE_RESULT_UNAVAIL;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));
    memset(&sock_addr, 0, sizeof(struct sockaddr_in));

    // Filling server information
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(5353);
    sock_addr.sin_addr.s_addr = inet_addr("224.0.0.251");
    addr_len = sizeof(struct sockaddr_in);
    readsize = make_query_packet(af, hostname, buffer);
    if (readsize != sendto(sockfd, buffer, readsize, 0, (struct sockaddr *)&sock_addr, addr_len))
    {
        perror("sendto failed");
        close(sockfd);
        return MDNS_RESOLVE_RESULT_UNAVAIL;
    }
    for (;;)
    {
        readsize = recvfrom(sockfd, buffer, BUFFERSIZE, 0, (struct sockaddr *)&sock_addr, &addr_len);
        if (0 < readsize)
        {
            close(sockfd);
            return MDNS_RESOLVE_RESULT_UNAVAIL;
        }
        struct dns_header_t *dns_header = (struct dns_header_t *)buffer;
        dns_header->ANCOUNT = DECOUNT(dns_header->ANCOUNT);
        if (!dns_header->ANCOUNT || !IS_DNSFLAG(DNSFLAG_RESPD_NO_ORROR))
        {
            continue;
        }
        puffer = buffer + sizeof(struct dns_header_t);
        while (dns_header->ANCOUNT--)
        {
            uint16_t decoded = htons(*(uint16_t *)puffer);
            if (decoded & 0xC000)
            {
                pull_hostname(buffer + (decoded & 0x3FFF), nodename);
                puffer += sizeof(uint16_t);
            }
            else
            {
                puffer = pull_hostname(puffer, nodename);
            }
            if (strcmp(hostname, nodename))
            {
                puffer += 10 + htons(*(uint16_t *)(puffer + 8));
                continue;
            }
            else
            {
                query_address_result_t address_result;
                if (af != AF_INET6 && *(uint16_t *)puffer == QTYPE_A)
                {
                    address_result.af = AF_INET;
                    memcmp(&address_result.address, puffer + 10, htons(*(uint16_t *)(puffer + 8)));
                    append_address_to_userdata(&address_result, result_list);
                }
            }
        }
        close(sockfd);
        return MDNS_RESOLVE_RESULT_SUCCESS;
    }
    close(sockfd);
    return MDNS_RESOLVE_RESULT_HOST_NOT_FOUND;
}

static FILE *open_socket(void)
{
    int fd = -1;
    struct sockaddr_un sa;
    FILE *f = NULL;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        goto fail;

    set_cloexec(fd);

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, "MDNS_SOCKET", sizeof(sa.sun_path) - 1);
    sa.sun_path[sizeof(sa.sun_path) - 1] = 0;

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto fail;

    if (!(f = fdopen(fd, "r+")))
        goto fail;

    return f;

fail:
    if (fd >= 0)
        close(fd);

    return NULL;
}

static mdns_resolve_result_t mdns_resolve_name_with_socket(FILE *f, int af, const char *name, query_address_result_t *result)
{
    char *p;
    char ln[256];

    fprintf(
        f, "RESOLVE-HOSTNAME%s %s\n", af == AF_INET ? "-IPV4" : "-IPV6", name);
    fflush(f);

    if (!(fgets(ln, sizeof(ln), f)))
    {
        return MDNS_RESOLVE_RESULT_UNAVAIL;
    }

    openlog("nss-mdns", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_NOTICE, "Receive data: %s", ln);
    closelog();

    if (ln[0] != '+')
    {
        return MDNS_RESOLVE_RESULT_HOST_NOT_FOUND;
    }

    result->af = af;

    p = ln + 1;
    p += strspn(p, WHITESPACE);

    /* Store interface number */
    result->scopeid = (uint32_t)strtol(p, NULL, 0);
    p += strcspn(p, WHITESPACE);
    p += strspn(p, WHITESPACE);

    /* Skip protocol */
    p += strcspn(p, WHITESPACE);
    p += strspn(p, WHITESPACE);

    /* Skip host name */
    p += strcspn(p, WHITESPACE);
    p += strspn(p, WHITESPACE);

    /* Cut off end of line */
    *(p + strcspn(p, "\n\r\t ")) = 0;

    if (inet_pton(af, p, &(result->address)) <= 0)
    {
        return MDNS_RESOLVE_RESULT_UNAVAIL;
    }

    return MDNS_RESOLVE_RESULT_SUCCESS;
}

mdns_resolve_result_t mdns_resolve_address(int af, const void *data, char *name, size_t name_len)
{
    return MDNS_RESOLVE_RESULT_UNAVAIL;
}
