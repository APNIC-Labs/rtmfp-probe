#include <config.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "rtmfp.h"

int main(int argc, char **argv) {
    int index;
    char *port = "1935";
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
        struct addrinfo hints, *res, *rp;
        int sockfd;

        // get host info, make socket, bind it
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        int s;
        if ((s = getaddrinfo(NULL, port, &hints, &res)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
            return EXIT_FAILURE;
        }

        for (rp = res; rp != NULL; rp = rp->ai_next) {
            sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sockfd == -1) continue;
            if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
                break;
            close(sockfd);
        }

        if (rp == NULL) {
            fprintf(stderr, "Could not bind service\n");
            return EXIT_FAILURE;
        }

        int bound_port = -1;
        switch (rp->ai_family) {
            case AF_INET:
                printf("v4 ");
                bound_port = ntohs(((struct sockaddr_in *)rp->ai_addr)->sin_port);
                break;
            case AF_INET6:
                printf("v6 ");
                bound_port = ntohs(((struct sockaddr_in6 *)rp->ai_addr)->sin6_port);
                break;
        }
        
        printf("Listening forever on port %d\n", bound_port);

        freeaddrinfo(res);

        RtmfpService *service = rtmfpInitialise(sockfd);

        while (1) {
            rtmfpReadDatagram(service);
        }
    }

    return 0;
}
