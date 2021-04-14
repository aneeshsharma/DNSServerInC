#include "DNS.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <bits/stdint-uintn.h>

void printLabels(LabelSequence* labels) {
    if (!labels)
        return;
    printf("%s.", labels->label);
    printLabels(labels->next);
}

void printIP(DNSRecord* record) {
    uint8_t a = *(record->data);
    uint8_t b = *(record->data + 1);
    uint8_t c = *(record->data + 2);
    uint8_t d = *(record->data + 3);
    printf("%u.%u.%u.%u", a, b, c, d);
}

void printIP6(DNSRecord* record) {
    for (int i = 0; i < 16; i += 2) {
        printf("%x:", getWord((char*)record->data + i));
    }
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
        printLabels(record->cname);
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
        printf("\t%d\t", q->type);
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

