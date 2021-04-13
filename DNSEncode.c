#include "DNS.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bits/stdint-uintn.h>

void writeLabels(LabelSequence* labels, char* buffer, int* index, size_t size) {
    int i = *index;
    if (!labels) {
        *(buffer + i++) = 0;
        *index = i;
    } else {
        *(buffer + i++) = labels->length;

        strncpy(buffer + i, labels->label, labels->length);
        
        i += labels->length;
        
        *index = i;

        writeLabels(labels->next, buffer, index, size);
    }
}

void writeHeader(DNSPacket* packet, char* buffer, int* index, size_t size) {
    DNSHeader header = packet->header;
    int i = *index;

    writeWord(buffer + i, header.ID);
    i += 2;

    *(buffer + i++) = header.QR << 7 | header.OPCODE << 3
                        | header.AA << 2 | header.TC << 1 | header.RD;

    *(buffer + i++) = header.RA << 7 | header.Z << 4 | header.RCODE;

    writeWord(buffer + i, header.QDCOUNT);
    i += 2;
    writeWord(buffer + i, header.ANCOUNT);
    i += 2;
    writeWord(buffer + i, header.NSCOUNT);
    i += 2;
    writeWord(buffer + i, header.ARCOUNT);
    i += 2;

    *index = i;
}

void writeQuestion(DNSQuestion* question, char* buffer, int* index, size_t size) {
    while(question) {
        int i = *index;
        
        writeLabels(question->labels, buffer, &i, size);

        writeWord(buffer + i, question->type);
        i += 2;

        writeWord(buffer + i, question->_class);
        i += 2;
        
        *index = i;
        question = question->next;
    }
}


void setRecordDataSize(DNSRecord* record) {
    if (record->type == TYPE_A) {
        record->len = 4;
    } else if (record->type == TYPE_AAAA) {
        record->len = 8;
    } else if (record->type == TYPE_CNAME) {
        record->len = getLength(record->cname);
    } else if (record->type == TYPE_NS) {
        record->len = getLength(record->ns);
    }
}

void writeRecord(DNSRecord* record, char* buffer, int* index, size_t size) {
    while(record) {
        int i = *index;

        setRecordDataSize(record);

        writeLabels(record->labels, buffer, &i, size);

        writeWord(buffer + i, record->type);
        i += 2;

        writeWord(buffer + i, record->_class);
        i += 2;

        writeDoubleWord(buffer + i, record->TTL);
        i += 4;

        writeWord(buffer + i, record->len);
        i += 2;

        if (record->type == TYPE_A) {
            writeDoubleWord(buffer + i, record->IP);
            i += 4;
        } else if (record->type == TYPE_AAAA) {
            writeQuadWord(buffer + i, record->IPv6);
            i += 8;
        } else if (record->type == TYPE_NS) {
            writeLabels(record->ns, buffer, &i, size);
        } else if (record->type == TYPE_CNAME) {
            writeLabels(record->cname, buffer, &i, size);
        } else {
            strncpy(buffer + i, (char*) record->data, record->len);
            i += record->len;
        }

        *index = i;
        record = record->next; 
    }
}

int checkRecordList(DNSRecord** record) { 
    printf("Checking...\n");
    int count = 0;
    DNSRecord* curr = *record;
    if (!curr)
        return 0;
    int flag = 0;
    while (curr->next) {
        flag = 0;
        printf("Record type: %d\n", curr->next->type);
        if (curr->next->type == TYPE_AAAA)
            flag = 1;

        if (curr->next->type == TYPE_A)
            flag = 1;

        if (curr->next->type == TYPE_CNAME)
            flag = 1;

        if (curr->next->type == TYPE_NS)
            flag = 1;
        
        if (!flag)
            curr->next = curr->next->next;
        else
            count++;

        curr = curr->next;
    }

    curr = *record;
    flag = 0;
    if (curr->type == TYPE_AAAA)
        flag = 1;

    if (curr->type == TYPE_A)
        flag = 1;

    if (curr->type == TYPE_CNAME)
        flag = 1;

    if (curr->type == TYPE_NS)
        flag = 1;

    if (!flag)
        *record = curr->next;
    else
        count++;

    return count;
}

void checkRecords(DNSPacket* packet) {
    packet->header.ANCOUNT = checkRecordList(&packet->answer);
    packet->header.NSCOUNT = checkRecordList(&packet->authority);
    packet->header.ARCOUNT = checkRecordList(&packet->additional);
}

char* writeDNSPacket(DNSPacket* packet, size_t* size) {
    //checkRecords(packet);

    char* buffer = (char*) calloc(BUFFER_SIZE, sizeof(char));

    int index = 0;

    writeHeader(packet, buffer, &index, BUFFER_SIZE);

    writeQuestion(packet->question, buffer, &index, BUFFER_SIZE);

    writeRecord(packet->answer, buffer, &index, BUFFER_SIZE);
    writeRecord(packet->authority, buffer, &index, BUFFER_SIZE);
    writeRecord(packet->additional, buffer, &index, BUFFER_SIZE);

    *size = index + 1;

    return buffer;
}

