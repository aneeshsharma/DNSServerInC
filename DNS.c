#include "DNS.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

uint8_t getBits(uint8_t data, int start, int end) {
    uint8_t mask = 0;
    for (int i = 0; i < 8; i++) {
        if (i <= start && i >= end) {
            mask |= 1 << i;
        }
    }

    uint8_t digits = data & mask;

    return digits >> end;
}

uint16_t getWord(char* address) {
    uint16_t a = *address;
    uint16_t b = *(address + 1);
    a &= 0xff;
    b &= 0xff;
    return a << 8 | b;
}

uint32_t getDoubleWord(char* address) {
    uint32_t a = getWord(address);
    uint32_t b = getWord(address + 2);
    a &= 0xffff;
    b &= 0xffff;
    return a << 16 | b;
}

uint64_t getQuadWord(char* address) {
    uint64_t a = getDoubleWord(address);
    uint64_t b = getDoubleWord(address + 4);
    a &= 0xffffffff;
    b &= 0xffffffff;
    return a << 32 | b;
}

void getDNSHeader(char* buffer, DNSPacket* packet) {
    packet->header.ID = getWord(buffer);
    
    packet->header.QR       = getBits(*(buffer + 2), 7, 7);
    packet->header.OPCODE   = getBits(*(buffer + 2), 6, 3);
    packet->header.AA       = getBits(*(buffer + 2), 2, 2);
    packet->header.TC       = getBits(*(buffer + 2), 1, 1);
    packet->header.RD       = getBits(*(buffer + 2), 0, 0);

    packet->header.RA       = getBits(*(buffer + 3), 7, 7);
    packet->header.Z        = getBits(*(buffer + 3), 6, 4);
    packet->header.RCODE    = getBits(*(buffer + 3), 3, 0);

    packet->header.QDCOUNT  = getWord(buffer + 4);
    packet->header.ANCOUNT  = getWord(buffer + 6);
    packet->header.NSCOUNT  = getWord(buffer + 8);
    packet->header.ARCOUNT  = getWord(buffer + 10);

    packet->question = NULL;
    packet->answer = NULL;
    packet->additional = NULL;
    packet->authority = NULL;
}

void printLabels(LabelSequence* labels) {
    if (!labels)
        return;
    printf("%s.", labels->label);
    printLabels(labels->next);
}

LabelSequence* getLabel(char* buffer, int* index, size_t size) {
    int n = *(buffer + *index);
    
    if (n == 0) {
        *index += 1;
        return NULL;
    }
    
    LabelSequence* label;

    if ((n & 0xc0) == 0xc0) {
        int pos = getWord(buffer + *index);

        *index += 2;
        pos ^= 0xc000;
        
        label = getLabel(buffer, &pos, size);
        
        
        //LabelSequence* curr = label;
        //while (curr->next)
        //    curr = curr->next;
        
        //curr->next = getLabel(buffer, index, size);
        
        return label;
    } else {
        *index += 1;

        label = (LabelSequence*) malloc(sizeof(LabelSequence));
        
        label->label = calloc(n + 1, sizeof(char));
        label->length = n;
        
        strncpy(label->label, buffer + *index, n);
        
        int n_index = *index + n;
        label->next = getLabel(buffer, &n_index, size);
        *index = n_index;

        return label;
    }
}

DNSQuestion* getQuestion(char* buffer, int* index, size_t size) {
    DNSQuestion* question = (DNSQuestion*) malloc(sizeof(DNSQuestion));

    question->labels = getLabel(buffer, index, size);

    question->type = getWord(buffer + *index);
    *index += 2;
    question->_class = getWord(buffer + *index);
    *index += 2;

    return question;
}

DNSRecord* getRecord(char* buffer, int* index, size_t size) {
    DNSRecord* record = (DNSRecord*) malloc(sizeof(DNSRecord));


    record->labels = getLabel(buffer, index, size);


    record->type = getWord(buffer + *index);
    *index += 2;
    record->_class = getWord(buffer + *index);
    *index += 2;
    record->TTL = getDoubleWord(buffer + *index);
    *index += 4;
    record->len = getWord(buffer + *index);
    *index += 2;

    record->data = (uint8_t*) calloc(record->len + 1, sizeof(uint8_t));

    for (int i = 0; i < record->len; i++) {
        record->data[i] = buffer[*index + i];
    }

    if (record->type == TYPE_NS) {
        int n_index = *index;
        record->ns = getLabel(buffer, &n_index, size);
    }
    
    if (record->type == TYPE_CNAME) {
        int n_index = *index;
        record->cname = getLabel(buffer, &n_index, size);
    }
    record->IP = 0;
    record->IPv6 = 0;

    if (record->len == 4) {
        record->IP = getDoubleWord(buffer + *index);
    } else if (record->len == 8) {
        record->IPv6 = getDoubleWord(buffer + *index);
    }

    *index += record->len;
    
    return record;
}

DNSRecord* getRecordList(char* buffer, int* index, size_t n, size_t size) {
    DNSRecord* record;
    DNSRecord* result;
    
    if (n <= 0)
        return NULL;

    int flag = 0;
    for (int i = 0; i < n; i++) {
        if (!flag) {
            result = getRecord(buffer, index, size);
            record = result;
            flag = 1;
        } else {
            record->next = getRecord(buffer, index, size);
            record = record->next;
        }
    }

    return result;
}

DNSQuestion* getQuestionList(char* buffer, int* index, size_t n, size_t size) {
    DNSQuestion* question;
    DNSQuestion* result;
        
    if (n <= 0)
        return NULL;


    int flag = 0;
    for (int i = 0; i < n; i++) {
        if (!flag) {
            result = getQuestion(buffer, index, size);
            question = result;
            flag = 1;
        } else {
            question->next = getQuestion(buffer, index, size);
            question = question->next;
        }
    }

    return result;
}

DNSPacket* getDNSPacket(char* buffer, size_t size) {
    DNSPacket* packet = (DNSPacket *) malloc(sizeof(DNSPacket));
    
    getDNSHeader(buffer, packet);
    // Start decoding after header
    // Header size is 12 bytes
    int index = 12;

    packet->question = getQuestionList(buffer, &index, packet->header.QDCOUNT, size);
    
    packet->answer = getRecordList(buffer, &index, packet->header.ANCOUNT, size);
    
    packet->authority = getRecordList(buffer, &index, packet->header.NSCOUNT, size);

    packet->additional = getRecordList(buffer, &index, packet->header.ARCOUNT, size);

    return packet;
}

void printIP(DNSRecord* record) {
    uint8_t a = *(record->data);
    uint8_t b = *(record->data + 1);
    uint8_t c = *(record->data + 2);
    uint8_t d = *(record->data + 3);
    printf("%u.%u.%u.%u", a, b, c, d);
}

void printIP6(DNSRecord* record) {
    printf("%x %x", getDoubleWord((char*) record->data), getDoubleWord((char*) record->data + 4));
}

void printRecord(DNSRecord* record) {
    if (!record)
        return;
    if (record->type == TYPE_A) {
        printLabels(record->labels);
        printf("\tA\t");
        printIP(record);
        printf("\n");
    } else if (record->type == TYPE_NS){
        printLabels(record->labels);
        printf("\tNS\t");
        printLabels(record->ns);
        printf("\n");
    } else if (record->type == TYPE_CNAME) {
        printLabels(record->labels);
        printf("\tCNAME\t");
        printf("\n");
    } else if (record->type == TYPE_AAAA) {
        printLabels(record->labels);
        printf("\tAAAA\t");
        printIP6(record);
        printf("\n");
    } else {
        printf("UNKNOWN RECORD TYPE %d\n", record->type);
    } 
}

void printDNS(DNSPacket* packet) {
    printf("DNS Packet\n");
    printf("Header\n");
    printf("ID\t-\t%x\n", packet->header.ID);
    printf("QDCOUNT\t-\t%d\n", packet->header.QDCOUNT);
    printf("ANCOUNT\t-\t%d\n", packet->header.ANCOUNT);
    printf("NSCOUNT\t-\t%d\n", packet->header.NSCOUNT);
    printf("ARCOUNT\t-\t%d\n", packet->header.ARCOUNT);

    printf("\nQuestions-\n");
    DNSQuestion* q = packet->question;
    while (q) {
        printLabels(q->labels);
        printf("\n");
        q = q->next;
    }

    printf("\nAnswers-\n");
    DNSRecord* ans = packet->answer;
    while (ans) {
        printRecord(ans);
        ans = ans->next;
    }

    printf("\nAuthority-\n");
    ans = packet->authority;
    while (ans) {
        printRecord(ans);
        ans = ans->next;
    }

    printf("\nAdditional-\n");
    ans = packet->additional;
    while (ans) {
        printRecord(ans);
        ans = ans->next;
    }
}

