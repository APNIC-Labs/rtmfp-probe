#include <config.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "rtmfp.h"

int main(int argc, char **argv) {
    int index;
    char *port = NULL;
    int c;

    while ((c = getopt(argc, argv, "l:")) != -1) {
        switch (c) {
            case 'l':
                port = optarg;
                break;
            case '?':
                if (optopt == 'l')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
        }
    }

    for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);

    if (port != NULL) {
        struct addrinfo hints, *res;
        int sockfd;

        // get host info, make socket, bind it
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;      // v4-only service
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;
        getaddrinfo(NULL, port, &hints, &res);
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        bind(sockfd, res->ai_addr, res->ai_addrlen);

        printf("Listening forever on port %d\n", ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port));

        RtmfpService *service = rtmfpInitialise(sockfd);

        while (1) {
            rtmfpReadDatagram(service);
        }
    }

    return 0;
}
