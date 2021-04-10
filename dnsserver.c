#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 7000
#define BUFFER_SIZE 1024

int main()
{
    int sock_fd;
    char buffer[BUFFER_SIZE];

    struct sockaddr_in server_address, client_address;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Couldn't create socket!");
        exit(EXIT_FAILURE);
    }

    memset(&server_address, 0, sizeof(server_address));
    memset(&client_address, 0, sizeof(client_address));

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);

    if (bind(sock_fd, (const struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        perror("Couldn't bind socket");
        exit(EXIT_FAILURE);
    }

    int len, recv_len;

    len = sizeof(client_address);

    while (1)
    {
        printf("Waiting\n");
        recv_len = recvfrom(sock_fd, (char *)buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *)&client_address, &len);

        buffer[recv_len] = '\0';

        printf("Message received: %s\n", buffer);

        sendto(sock_fd, (const char *)buffer, strlen(buffer), MSG_CONFIRM, (const struct sockaddr *)&client_address, len);

        printf("Server response sent!\n");
    }
    return 0;
}