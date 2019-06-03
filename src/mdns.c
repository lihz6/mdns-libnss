#include <sys/socket.h>
#include <sys/types.h>
#include "mdns.h"

unsigned char *push_hostname(unsigned char *buffer, const char *hostname)
{
    unsigned char *position = buffer++;
    for (;;)
    {
        switch (*buffer++ = *hostname++)
        {
        case '\0':
            *position = buffer - position - 2;
            return buffer;
        case '.':
            *position = buffer - position - 2;
            position = buffer - 1;
        }
    }
}

ssize_t make_query_packet(int af, const char *hostname, unsigned char *const buffer)
{
    unsigned char *puffer;
    struct dns_header_t *dns_header = (struct dns_header_t *)buffer;
    dns_header->ID = 0;
    dns_header->DNSFLAG = DNSFLAG_QUERY;
    // dns_header->QDCOUNT = ENCOUNT(1 or 2); see below
    dns_header->ANCOUNT = 0;
    dns_header->NSCOUNT = 0;
    dns_header->ARCOUNT = 0;
    puffer = push_hostname(buffer + sizeof(struct dns_header_t), hostname);
    if (af != AF_INET6)
    {
        *(uint16_t *)puffer = QTYPE_A;
        *(uint16_t *)(puffer + 2) = QCLASS_CONST;
        puffer += 4;
    }
    if (af != AF_UNSPEC)
    {
        dns_header->QDCOUNT = ENCOUNT(1);
    }
    else
    {
        dns_header->QDCOUNT = ENCOUNT(2);
        *(uint16_t *)puffer = htons(0xC00C);
        puffer += 2;
    }
    if (af != AF_INET)
    {
        *(uint16_t *)puffer = QTYPE_AAAA;
        *(uint16_t *)(puffer + 2) = QCLASS_CONST;
        puffer + 4;
    }
    return puffer - buffer;
}

unsigned char *pull_hostname(unsigned char *buffer, char *hostname)
{
    for (;;)
    {
        unsigned char length = *buffer++;
        while (length--)
        {
            *hostname++ = *buffer++;
        }
        if (*buffer)
        {
            *hostname++ = '.';
        }
        else
        {
            *hostname = '\0';
            return buffer + 1;
        }
    }
}