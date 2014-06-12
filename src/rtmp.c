#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "rtmp.h"

int
RTMP_Command_Parse(RTMPCommand *command, uint8_t *buffer, int length)
{
    if (length < 5) return -1;  // truncated message
    command->amfType = buffer[0];
    buffer += 5; length -= 5;
    switch (command->amfType) {
        case AMF0:
            break;
        case AMF3:
            if (length < 1 || buffer[0] != 0) return -1;      // missing AMF3 marker
            buffer++; length--;
            break;
        default:
            return -1;
    }

    if (length < 4) return -1;          // truncated

    if (buffer[0] != 2) return -1;      // missing command name string
    command->commandNameLength = ntohs(*(uint16_t *)(buffer+1));
    if (command->commandNameLength > length - 3) return -1; // truncated
    command->commandName = buffer + 3;
    buffer = buffer + 3 + command->commandNameLength;
    length = length - 3 - command->commandNameLength;

    if (length < 9) return -1;
    memcpy(command->transactionId, buffer+1, 8);

    command->arguments = buffer + 9;
    command->argumentLength = length - 9;

    return 0;
}

/* Example AMF3 command block
  11:00:00:00:45:00:02:00:0b:73:65:74:50:65:65:72    ....E....setPeer
  49:6e:66:6f:00:00:00:00:00:00:00:00:00:05:02:00    Info............
  13:32:30:33:2e:31:31:39:2e:34:32:2e:32:30:3a:35    .203.119.42.20:5
  35:39:34:39:02:00:2b:5b:32:30:30:31:3a:64:63:30    5949..+[2001:dc0
  3a:61:30:30:30:3a:34:3a:33:65:30:37:3a:35:34:66    :a000:4:3e07:54f
  66:3a:66:65:31:62:3a:35:66:61:64:5d:3a:35:35:39    f:fe1b:5fad]:559
  35:30:02:00:2a:5b:32:30:30:31:3a:64:63:30:3a:61    50..*[2001:dc0:a
  30:30:30:3a:34:3a:63:63:37:3a:62:63:38:61:3a:33    000:4:cc7:bc8a:3
  37:36:63:3a:35:35:38:66:5d:3a:35:35:39:35:30
*/

#define _rtmp_h
