#include "DNS.h"
#include <stdlib.h>
#include <stdio.h>

uint8_t getBits(uint8_t data, int start, int end) {
    uint8_t mask = 0;
    for (int i = 0; i < 8; i++) {
        if (i >= start && i <= end) {
            mask |= 1 << i;
        }
    }
    return mask;
}

void getDNSHeader(char* buffer, DNSPacket* packet) {
    packet->header.ID = *((uint16_t*) buffer);
    
    packet->header.QR       = getBits(*(buffer + 2), 7, 7);
    packet->header.OPCODE   = getBits(*(buffer + 2), 6, 3);
    packet->header.AA       = getBits(*(buffer + 2), 2, 2);
    packet->header.TC       = getBits(*(buffer + 2), 1, 1);
    packet->header.RD       = getBits(*(buffer + 2), 0, 0);

    packet->header.RA       = getBits(*(buffer + 3), 7, 7);
    packet->header.Z        = getBits(*(buffer + 3), 6, 4);
    packet->header.RCODE    = getBits(*(buffer + 3), 3, 0);

    packet->header.QDCOUNT  = *((uint16_t*) buffer + 4);
    packet->header.ANCOUNT  = *((uint16_t*) buffer + 6);
    packet->header.NSCOUNT  = *((uint16_t*) buffer + 8);
    packet->header.ARCOUNT  = *((uint16_t*) buffer + 10);
}

DNSPacket* getDNSPacket(char* buffer, size_t size) {
    DNSPacket* packet = (DNSPacket *) sizeof(DNSPacket);

    getDNSHeader(buffer, packet);
    


    return NULL;
}


