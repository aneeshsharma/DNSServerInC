#include "DNS.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bits/stdint-uintn.h>

void writeLabels(LabelSequence* labels, char* buffer, int* index, size_t size) {
    // TODO: Write labels to the buffer
}

void writeHeader(DNSPacket* packet, char* buffer, int* index, size_t size) {
    // TODO: Write the header to the buffer
}

void writeQuestion(DNSQuestion* packet, char* buffer, int* index, size_t size) {
    // TODO: Write questions to the buffer
}

void writeRecord(DNSRecord* record, char* buffer, int* index, size_t size) {
    // TODO: Write record to the buffer
}

char* writeDNSPacket(DNSPacket* packet, size_t* size) {
    char* buffer = (char*) calloc(BUFFER_SIZE, sizeof(char));
    *size = BUFFER_SIZE;

    int index = 0;
    
    writeHeader(packet, buffer, &index, BUFFER_SIZE);

    writeQuestion(packet->question, buffer, &index, BUFFER_SIZE);

    writeRecord(packet->answer, buffer, &index, BUFFER_SIZE);
    writeRecord(packet->authority, buffer, &index, BUFFER_SIZE);
    writeRecord(packet->additional, buffer, &index, BUFFER_SIZE);

    return buffer;
}

