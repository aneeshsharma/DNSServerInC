#include "DNS.h"
#include <stdint.h>
#include <bits/stdint-uintn.h>

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

