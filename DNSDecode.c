#include "DNS.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

    record->IP = 0;
    record->IPv6 = 0;
    record->ns = NULL;
    record->cname = NULL;

    if (record->type == TYPE_NS) {
        int n_index = *index;
        record->ns = getLabel(buffer, &n_index, size);
    } else if (record->type == TYPE_CNAME) {
        int n_index = *index;
        record->cname = getLabel(buffer, &n_index, size);
    } else if (record->type == TYPE_A) {
        record->IP = getDoubleWord(buffer + *index); 
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
            if (*index > size)
                return NULL;
            record = result;
            flag = 1;
        } else {
            if (*index > size)
                return NULL;
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
            if (*index > size)
                return NULL;
            question = result;
            flag = 1;
        } else {
            if (*index > size)
                return NULL;
            question->next = getQuestion(buffer, index, size);
            question = question->next;
        }
    }

    return result;
}

DNSPacket* getDNSPacket(char* buffer, size_t size) {
    DNSPacket* packet = (DNSPacket *) malloc(sizeof(DNSPacket));
    
    getDNSHeader(buffer, packet); 

    int flag = 0;
    if (packet->header.QDCOUNT > 32)
        flag = 1;
    if (packet->header.ANCOUNT > 32)
        flag = 1;
    if (packet->header.NSCOUNT > 32)
        flag = 1;
    if (packet->header.ARCOUNT > 32)
        flag = 1;
    if (flag) {
        return NULL;
    }
    // Start decoding after header
    // Header size is 12 bytes
    int index = 12;

    packet->question = getQuestionList(buffer, &index, packet->header.QDCOUNT, size);
    
    packet->answer = getRecordList(buffer, &index, packet->header.ANCOUNT, size);
    
    packet->authority = getRecordList(buffer, &index, packet->header.NSCOUNT, size);

    packet->additional = getRecordList(buffer, &index, packet->header.ARCOUNT, size);

    return packet;
}


