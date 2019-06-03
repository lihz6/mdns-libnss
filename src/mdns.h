#include <sys/types.h>
#include <stdint.h>

#define DNSFLAG_QUERY htons(0x0100)
#define DNSFLAG_RESPD_NO_ORROR htons(0x8400)
#define IS_DNSFLAG(dnsflag) ((dns_header->DNSFLAG & dnsflag) == dnsflag)

#define ENCOUNT(count) htons(count)
#define DECOUNT(count) ntohs(count)

#define QTYPE_AAAA htons(0x001C)
#define QTYPE_A htons(0x0001)
#define QCLASS_CONST htons(0x0001)
// DNS header structure
// #pragma pack(push, 1)
struct dns_header_t
{
    uint16_t ID;
    // unsigned char QR : 1;
    // unsigned char OPCODE : 4;
    // unsigned char AA : 1;
    // unsigned char TC : 1;
    // unsigned char RD : 1;
    // unsigned char RA : 1;
    // unsigned char Z : 3;
    // unsigned char RCODE : 4;
    uint16_t DNSFLAG;
    uint16_t QDCOUNT; // number of question entries
    uint16_t ANCOUNT; // number of answer entries
    uint16_t NSCOUNT; // number of authority entries
    uint16_t ARCOUNT; // number of resource entries
};
struct question_t
{
    uint16_t QTYPE;
    uint16_t QCLASS;
};

extern unsigned char *push_hostname(unsigned char *buffer, const char *hostname);
extern ssize_t make_query_packet(int af, const char *hostname, unsigned char *const buffer);
extern unsigned char *pull_hostname(unsigned char *buffer, char *hostname);