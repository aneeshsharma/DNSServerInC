#include <bits/stdint-uintn.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef __DNS_H
#define __DNS_H

#define TYPE_NS     2
#define TYPE_A      1
#define TYPE_CNAME  5
#define TYPE_AAAA   28

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

struct DNSRecord {
    struct LabelSequence*   labels;
    uint16_t                type;
    uint16_t                _class;
    uint32_t                TTL;
    uint16_t                len;

    uint8_t*                data;
    struct LabelSequence*   ns;
    struct LabelSequence*   cname;
    uint32_t                IP;
    uint64_t                IPv6;
    struct DNSRecord*       next;
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
typedef struct DNSRecord DNSRecord;
typedef struct DNSPacket DNSPacket;

// Convert a big endian 2-byte number to uint16_t
uint16_t getWord(char* address);
uint8_t getBits(uint8_t data, int start, int end);
uint32_t getDoubleWord(char* address);


void getDNSHeader(char* buffer, DNSPacket* packet);
LabelSequence* getLabel(char* buffer, int* index, size_t size);
DNSQuestion* getQuestion(char* buffer, int* index, size_t size);

DNSRecord* getRecordList(char* buffer, int* index, size_t n, size_t size); 
DNSQuestion* getQuestionList(char* buffer, int* index, size_t n, size_t size);


DNSPacket* getDNSPacket(char* buffer, size_t size);

void printLabels(LabelSequence* labels);
void printIP(DNSRecord* record);
void printIP6(DNSRecord* record); 
void printRecord(DNSRecord* record); 
void printDNS(DNSPacket* packet); 


char* writeDNSPacket(DNSPacket* packet, size_t* len);

#endif
