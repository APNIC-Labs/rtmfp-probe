#ifndef _rtmp_h
#define _rtmp_h

#include <stdint.h>

#define AMF0    0x14
#define AMF3    0x11

typedef struct RTMPCommand {
    uint8_t *commandName;          // not NUL terminated, so not a char*
    uint16_t commandNameLength;
    uint8_t transactionId[8];      // a double in network byte order, if you want the number value
    uint8_t amfType;               // AMF0/AMF3
    uint8_t *arguments;            // unparsed blob of AMF0/3
    int argumentLength;            // how big is that blobby, in the message?
} RTMPCommand;

int RTMP_Command_Parse(RTMPCommand *command, uint8_t *buffer, int length);

#endif
