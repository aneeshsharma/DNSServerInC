#include <bits/stdint-uintn.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef __DNS_H
#define __DNS_H

struct DNSHeader {
    uint16_t    ID;
    
    uint8_t     QR;
    uint8_t     OPCODE;
    uint8_t     AA;
    uint8_t     TC;
    uint8_t     RD;
    uint8_t     RA;
    uint8_t     Z;
    uint8_t     RCODE;

    uint16_t    QDCOUNT;
    uint16_t    ANCOUNT;
    uint16_t    NSCOUNT;
    uint16_t    ARCOUNT;
};

struct LabelSequence {
    char*                   label;
    size_t                  length;
    struct LabelSequence*   next;
};

struct DNSQuestion {
    struct LabelSequence*   labels;
    uint16_t                type;
    uint16_t                _class;
    struct DNSQuestion*     next;
};

struct DNSPreamble {
    struct LabelSequence*   labels;
    uint16_t                type;
    uint16_t                _class;
    uint32_t                TTL;
    uint16_t                len;
};

struct DNSRecord {
    struct DNSPreamble  preamble;
    uint32_t            IP;
    struct DNSRecord*   next;
};

struct DNSPacket {
    struct DNSHeader    header;
    struct DNSQuestion* question;
    struct DNSRecord*   answer;
    struct DNSRecord*   authority;
    struct DNSRecord*   additional;
};

typedef struct DNSHeader DNSHeader;
typedef struct LabelSequence LabelSequence;
typedef struct DNSQuestion DNSQuestion;
typedef struct DNSPreamble DNSPreamble;
typedef struct DNSRecord DNSRecord;
typedef struct DNSPacket DNSPacket;

// Convert a big endian 2-byte number to uint16_t
uint16_t getWord(char* address);
uint8_t getBits(uint8_t data, int start, int end);
void printLabels(LabelSequence* labels);

void getDNSHeader(char* buffer, DNSPacket* packet);
LabelSequence* getLabel(char* buffer, int* index, size_t size);
DNSQuestion* getQuestion(char* buffer, int* index, size_t size);

DNSPacket* getDNSPacket(char* buffer, size_t size);

char* writeDNSPacket(DNSPacket* packet, size_t* len);

#endif
