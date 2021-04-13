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
    b &= 0xff;
    return a << 8 | b;
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
}

void printLabels(LabelSequence* labels) {
    if (!labels)
        return;
    printf("%s\n", labels->label);
    printLabels(labels->next);
}

LabelSequence* getLabel(char* buffer, int* index, size_t size) {
    int n = *(buffer + *index);
    
    if (n == 0)
        return NULL;

    *index += 1;
    
    LabelSequence* label = (LabelSequence*) malloc(sizeof(LabelSequence));
    label->label = calloc(n + 1, sizeof(char));

    label->length = n;
    label->next = NULL;
    strncpy(label->label, buffer + *index, n);

    *index += n;

    return label;
}

DNSQuestion* getQuestion(char* buffer, int* index, size_t size) {
    DNSQuestion* question = (DNSQuestion*) malloc(sizeof(DNSQuestion));

    LabelSequence* label;
    LabelSequence* curr;
    int flag = 0;
    do {
        label = getLabel(buffer, index, size);
        
        if (!flag) {
            question->labels = label;
            curr = label;
            flag = 1;
        } else {
            curr->next = label;
            curr = label;
        }
    } while(label);

    question->type = getWord(buffer + *index);
    *index += 2;
    question->_class = getWord(buffer + *index);
    *index += 2;

    return question;
}

DNSPacket* getDNSPacket(char* buffer, size_t size) {
    DNSPacket* packet = (DNSPacket *) malloc(sizeof(DNSPacket));

    getDNSHeader(buffer, packet); 

    // Start decoding after header
    // Header size is 12 bytes
    int index = 12;

    packet->question = getQuestion(buffer, &index, size);

    return packet;
}


