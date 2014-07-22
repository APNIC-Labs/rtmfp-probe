#ifndef _rtmfp_h
#define _rtmfp_h

#include <stdint.h>

typedef struct RtmfpService RtmfpService;

/* Return the number of reply bytes used, or 0 for no reply, or -1 for message not handled */
typedef int (UserDataHandler)(uint8_t *payload, int length, uint8_t *reply, int replySpace);

// Create a new RtmfpService
RtmfpService *rtmfpInitialise();

// Destroy a service
void rtmfpDestroy(RtmfpService *service);

// Add a handler to a created service
void rtmfpAddHandler(RtmfpService *service, uint8_t type, UserDataHandler *handler);

// Read a datagram for a service
int rtmfpReadDatagram(RtmfpService *service, int fd);

#endif
