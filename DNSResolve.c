#include "DNS.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bits/stdint-uintn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

DNSPacket* createQuestion(LabelSequence* label, uint16_t type) {
    DNSPacket* query = (DNSPacket*) malloc(sizeof(DNSPacket));

    query->header.ID = rand() % 0xffff;
    query->header.QR = 0;
    query->header.OPCODE = 0;
    query->header.AA = 0;
    query->header.TC = 0;
    query->header.RD = 1;
    query->header.QDCOUNT = 1;

    query->question = (DNSQuestion*) malloc(sizeof(DNSQuestion));

    query->question->labels = label;
    query->question->type = type;
    query->question->_class = 1;

    return query;
}

char* findIP(DNSPacket* packet, char* name) {
    DNSRecord* record = packet->additional;

    while (record) {
        if (record->type == TYPE_A) {
            char ns[256];
            getLabelString(record->labels, ns);
            if (strcmp(ns, name)) {
                char* ip = (char*) calloc(17, sizeof(char));
                getIPString(record->data, ip);
                return ip;
            }
        }
        record = record->next;
    }

    return NULL;
}

char* queryDNS(LabelSequence* label, char* ns, uint16_t type) {
    if (!ns)
        return NULL;
    int sock_fd;
    struct sockaddr_in dns_address;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Error opening socket\n");
        return NULL;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&dns_address, 0, sizeof(dns_address));

    dns_address.sin_family = AF_INET;
    dns_address.sin_port = htons(53);
    
    inet_pton(AF_INET, ns, &dns_address.sin_addr);

    DNSPacket* question = createQuestion(label, type);

    //printDNS(question);


    size_t len = 0;
    char* question_buffer = writeDNSPacket(question, &len);

    int retries = 0;
    size_t recv_len;
    socklen_t sock_len;
    char response_buffer[BUFFER_SIZE];
    while(retries < 10) {
        sendto(sock_fd, (char*)question_buffer, len, MSG_CONFIRM, (struct sockaddr*)&dns_address, sizeof(dns_address));

        recv_len = recvfrom(sock_fd, (char*)response_buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&dns_address, &sock_len);
        
        retries++;

        if (recv_len > 0) {
            break;
        }
        printf("Retrying %d...\n", retries);
    }


    DNSPacket* response = getDNSPacket(response_buffer, recv_len);

    if (!response) {
        return NULL;
    }

    //printDNS(response);    

    if (response->header.ANCOUNT <= 0) {
        printf("No name servers found\n");
        return NULL;
    }

    char* ip = NULL;
    if (response->answer->type == TYPE_NS) {
        char* new_ns = calloc(256, sizeof(char));
        getLabelString(response->answer->ns, new_ns);

        ip = findIP(response, new_ns);
    } else if (response->answer->type == TYPE_A) {
        ip = calloc(17, sizeof(char));
        getIPString(response->answer->data, ip);
    }

    return ip;
}

char* getNS(LabelSequence* labels) {
    if (!labels) {
        return "8.8.8.8";
    }

    char* ns = getNS(labels->next);


    return queryDNS(labels, ns, TYPE_NS);
}

DNSPacket* createResponse(uint16_t id, char* ip, uint16_t type, DNSQuestion* question) {
    DNSPacket* response = (DNSPacket*) malloc(sizeof(DNSPacket));

    response->header.ID = id;
    response->header.QR = 1;
    response->header.OPCODE = 0;
    response->header.AA = 0;
    response->header.TC = 0;
    response->header.RD = 1;
    response->header.RA = 1;
    response->header.Z = 0;
    response->header.RCODE = ip ? 0 : 2;

    response->header.QDCOUNT = 1;
    response->header.ANCOUNT = ip ? 1 : 0;

    response->question = question;

    if (ip) {
        uint8_t* data = calloc(4, sizeof(uint8_t));
        IPStringToBinary(ip, data);

        response->answer = (DNSRecord*) malloc(sizeof(DNSRecord));

        response->answer->labels = question->labels;
        response->answer->type = type;
        response->answer->_class = 1;
        response->answer->TTL = 0x05ff;
        response->answer->len = 4;
        response->answer->data = data;
        response->answer->IP = getDoubleWord((char*) data);
    }

    return response;
}

DNSPacket* resolve(DNSPacket* packet) {
    int retry = 0;
    while(1) {
        printf("trying to resolve %d...\n", retry);
        
        if (strcmp(packet->question->labels->label, "www") == 0) {
            packet->question->labels = packet->question->labels->next;
        }

        char* ns = getNS(packet->question->labels);
        printf("Nameserver- %s\n", ns);


        char* ip = queryDNS(packet->question->labels, ns, TYPE_A);

        printf("IP - %s\n", ip);
        if (ip || retry > 10)
            return createResponse(packet->header.ID, ip, TYPE_A, packet->question);
        retry++;
    }
}
