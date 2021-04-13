#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "DNS.h"

#define PORT 7000

void hr() {
    for (int i = 0; i < 50; i++) {
        printf("-");
    }
    printf("\n");
}

int main()
{
    int sock_fd, dns_fd;
    char buffer[BUFFER_SIZE];

    struct sockaddr_in server_address, client_address, dns_address;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Couldn't create socket!");
        exit(EXIT_FAILURE);
    }

    if ((dns_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Couldn't create socket!");
        exit(EXIT_FAILURE);
    }

    memset(&server_address, 0, sizeof(server_address));
    memset(&client_address, 0, sizeof(client_address));
    memset(&dns_address, 0, sizeof(dns_address));

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    dns_address.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &dns_address.sin_addr);
    dns_address.sin_port = htons(53);
    

    if (bind(sock_fd, (const struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        perror("Couldn't bind socket");
        exit(EXIT_FAILURE);
    }

    socklen_t len;
    int recv_len;

    len = sizeof(client_address);

    while (1)
    {
        printf("Waiting\n");
        recv_len = recvfrom(sock_fd, (char *)buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&client_address, &len);

        buffer[recv_len] = '\0';

        DNSPacket* packet = getDNSPacket(buffer, recv_len);
        
        printDNS(packet);
        hr();

        printf("Rencoding...\n");
        size_t size;
        char* response = writeDNSPacket(packet, &size);

        printf("Querying DNS...\n");
        sendto(dns_fd, (char*)response, BUFFER_SIZE, MSG_CONFIRM, (struct sockaddr*)&dns_address, sizeof(dns_address));

        free(response);

        printf("Query sent\n");
        recv_len = recvfrom(dns_fd, (char*)buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&dns_address, &len);

        buffer[recv_len] = '\0';

        printf("Received response\n");

        DNSPacket* packet2 = getDNSPacket(buffer, recv_len);

        printDNS(packet2);
        hr();

        printf("Rencoding...\n");
        size_t size2;
        response = writeDNSPacket(packet2, &size2);

        printDNS(packet2);

        printf("Sending response...\n");
        sendto(sock_fd, response, size2, MSG_CONFIRM, (struct sockaddr*)&client_address, sizeof(client_address));

        free(response);
    }
    return 0;
}
