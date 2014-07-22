#include <config.h>

#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>
#include <sys/poll.h>

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
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        int s;
        if ((s = getaddrinfo(NULL, port, &hints, &res)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
            return EXIT_FAILURE;
        }

        int nfds = 0;
        for (rp = res; rp != NULL; rp = rp->ai_next) nfds++;

        struct pollfd fds[nfds];

        for (nfds = 0, rp = res; rp != NULL; rp = rp->ai_next) {
            fds[nfds].fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fds[nfds].fd == -1) {
                perror("socket");
                return EXIT_FAILURE;
            }
            fds[nfds].events = POLLIN;
            if (bind(fds[nfds].fd, rp->ai_addr, rp->ai_addrlen) != 0) {
                if (errno != EADDRINUSE) {
                    perror("bind");
                    return EXIT_FAILURE;
                }
                close(fds[nfds].fd);
                continue;
            }
            nfds++;
        }

        freeaddrinfo(res);

        RtmfpService *service = rtmfpInitialise();

        while (1) {
            int n = poll(fds, nfds, -1);
            for (int i = 0; n > 0 && i < nfds; i++) {
                if (fds[i].revents & POLLIN) {
                    rtmfpReadDatagram(service, fds[i].fd);
                }
            }
        }
    }

    return 0;
}
