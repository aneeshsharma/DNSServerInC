#include <bits/stdint-uintn.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef __DNS_H
#define __DNS_H

// Type numbers of various record types
#define TYPE_NS     2
#define TYPE_A      1
#define TYPE_CNAME  5
#define TYPE_AAAA   28

#define BUFFER_SIZE 1024

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

// Utility functions
uint8_t getBits(uint8_t data, int start, int end);

uint16_t getWord(char* address);
uint32_t getDoubleWord(char* address);
uint64_t getQuadWord(char* address);

void writeWord(char* buffer, uint16_t word); 
void writeDoubleWord(char* buffer, uint32_t word);
void writeQuadWord(char* buffer, uint64_t word);

int getLength(LabelSequence* label); 
void getLabelString(LabelSequence* labels, char* buffer);

void getIPString(uint8_t* IP, char* str);
void IPStringToBinary(char* str, uint8_t* IP);

// Decoding functions
void getDNSHeader(char* buffer, DNSPacket* packet);
LabelSequence* getLabel(char* buffer, int* index, size_t size);
DNSQuestion* getQuestion(char* buffer, int* index, size_t size);
DNSRecord* getRecordList(char* buffer, int* index, size_t n, size_t size); 
DNSQuestion* getQuestionList(char* buffer, int* index, size_t n, size_t size);
DNSPacket* getDNSPacket(char* buffer, size_t size);


// Printing functions
void printLabels(LabelSequence* labels);
void printIP(DNSRecord* record);
void printIP6(DNSRecord* record); 
void printRecord(DNSRecord* record); 
void printDNS(DNSPacket* packet);


// Encoding functions
void writeLabels(LabelSequence* labels, char* buffer, int* index, size_t size);

void setRecordDataSize(DNSRecord* record);

void writeHeader(DNSPacket* packet, char* buffer, int* index, size_t size);
void writeQuestion(DNSQuestion* question, char* buffer, int* index, size_t size);
void writeRecord(DNSRecord* record, char* buffer, int* index, size_t size);
char* writeDNSPacket(DNSPacket* packet, size_t* size); 


// Resolving functions
DNSPacket* createQuestion(LabelSequence* label, uint16_t type); 
char* findIP(DNSPacket* packet, char* name); 
char* queryDNS(LabelSequence* label, char* ns, uint16_t type); 
char* getNS(LabelSequence* labels); 
DNSPacket* createResponse(uint16_t id, char* ip, uint16_t type, DNSQuestion* question); 
DNSPacket* resolve(DNSPacket* packet);

#endif
