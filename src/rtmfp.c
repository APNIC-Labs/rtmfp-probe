#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "rtmfp.h"

// "Adobe Systems 02"
const uint8_t defaultSessionKey[16] = {
    0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x73, 0x20, 0x30, 0x32
};

struct RtmfpService {
    int fd;

    int errno;
    char *errmsg;

    // The bare minimum needed to know about each conversation
    struct Session {
        uint32_t remoteId;
        uint8_t encryptKey[32];
        uint8_t decryptKey[32];
    } sessions[1<<16];

    uint16_t nextSessionId;     // this wraps to re-use old sessions, at ~1k sessions per second, each session lasts ~65s
};

typedef struct Request {
    RtmfpService *service;
    struct Session *session;

    union {
        struct {
            uint8_t timeCritical         :1; // "TC"
            uint8_t timeCriticalReverse  :1; // "TCR"
            uint8_t reserved             :2; // "rsv"
            uint8_t timestampPresent     :1; // "TS"
            uint8_t timestampEchoPresent :1; // "TSE"
            uint8_t mode                 :2; // "MOD"
        } __attribute__((packed)) flags;
        uint8_t byteval;
    } flags;

    // response packet
    uint8_t response[512];
    int rlength;
} Request;

const char *defaultKey = "Adobe Systems 02";

// Create a new RtmfpService
RtmfpService *rtmfpInitialise(int fd)
{
    RtmfpService *service = malloc(sizeof(RtmfpService));
    if (!service) return NULL;

    service->fd = fd;
    service->errno = 0;
    service->errmsg = NULL;
    service->sessions[0].remoteId = 0;
    memcpy(service->sessions[0].encryptKey, defaultKey, 16);
    memcpy(service->sessions[0].decryptKey, defaultKey, 16);
    service->nextSessionId = 1;

    return service;
}

// Destroy a service
void rtmfpDestroy(RtmfpService *service) {
    free(service);
}

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("  NULL");
    else {
        printf("  ");
        size_t i = 0;
        for (; i<len-1;++i)
            printf("%02x%s", *p++, (i % 16 == 15) ? "\n  " : ":");
        printf("%02x\n", *p++);
    }
}

static DH *get_dh1024()
{
    static unsigned char dh1024_p[] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
        0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
        0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
        0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
        0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
        0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
        0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
        0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
        0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
        0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE6,0x53,0x81,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };
    static unsigned char dh1024_g[] = { 0x02 };

    DH *dh;

    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
    dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
    { DH_free(dh); return(NULL); }
    return(dh);
}

/* I don't know if this will be right if size is not a multiple of two */
/* So if checksums are mysteriously failing, it's because the author did not test this */
/* Or even really put much thought into it, given packets should be padded to a multiple of 16 bytes */
static uint16_t ip_checksum(uint8_t *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1) {
        cksum += *((uint16_t *)buffer);
        size -= 2;
        buffer += 2;
    }
    if (size) cksum += *buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (uint16_t)(~cksum);
}

#define _error(msg, code) { request->service->errno = code; request->service->errmsg = msg; return code; }

/**** The following block of functions provide RTMFP packet construction capabilities ****/

static int initPacket(Request *request, uint8_t **bufptr, int *remaining) {
    if (*remaining < 20) return 0;       // need at least space for session ID and one crypto block

    // 250Hz clock, truncated to last 16 bits
    uint16_t timestamp = (clock() * 250 / CLOCKS_PER_SEC) & 0xffff;

    uint8_t flags = (3 - (request->flags.flags.mode % 3));

    int consumed = 0;
    consumed += 4;                      // skip ssid, can't write it yet
    consumed += 2;                      // skip checksum, can't compute it yet
    (*bufptr)[consumed++] = flags;      // invert responder/initiator, echo startup
    //(*bufptr)[consumed++] = timestamp >> 8;
    //(*bufptr)[consumed++] = timestamp & 0xff;

    (*bufptr) += consumed;
    (*remaining) -= consumed;

    return 1;
}

// it is a prerequisite that there must be at least 15 bytes available at the end of a buffer on input
static int finalisePacket(Request *request, uint8_t *buffer, int *length) {
    if (*length < 5) return 0;          // can't handle a NULL packet, sorry

    int padding = (16 - (*length - 4) % 16) % 16;

    // there's always 4 unencrypted bytes up front
    // and the remainder must be a multiple of 16 for encryption
    // so pad to that size
    memset(buffer + *length, 0xff, padding);
    *length += padding;

    // Write the checksum in
    uint16_t chksum = ip_checksum(buffer + 6, *length - 6);
    *(uint16_t *)(buffer + 4) = chksum;

    // Encrypt the packet
    unsigned char iv[16];
    bzero(iv, 16);
    AES_KEY key;
    AES_set_encrypt_key(request->session->encryptKey, 128, &key);
    printf("Encrypting packet with key:\n"); hex_print(request->session->encryptKey, 16);
    AES_cbc_encrypt(buffer+4, buffer+4, *length-4, &key, iv, AES_ENCRYPT);

    // Write the scrambled SSID in
    uint32_t *words = (uint32_t *)buffer;
    words[0] = request->session->remoteId ^ words[1] ^ words[2];

    return 1;
}

static int vlu_write(int value, uint8_t **bufptr, int *remaining) {
    if (value > 0x3fff) return 0; // because I draw the limit at a packet that large in UDP

    if (value > 0x7f) {
        **bufptr = (value >> 7) | 0x80;
        (*bufptr)++;
        (*remaining)--;
    }

    **bufptr = value & 0x7f;
    (*bufptr)++;
    (*remaining)--;

    return 1;
}

/**** The following block of functions provide RTMFP packet interpretation capabilities ****/

/* so side effect, such stateful */
static int vlu_read(uint8_t **bufptr, int *remaining) {
    int value = 0;
    while ((*remaining) > 0 && (**bufptr) & 0x80) {
        value = (value << 7) + ((**bufptr) & 0x7f);
        (*remaining)--;
        (*bufptr)++;
    }
    if ((*remaining) > 0) {
        value = (value << 7) + ((**bufptr) & 0x7f);
        (*remaining)--;
        (*bufptr)++;
    }

    return value;
}

/* Initiator Hello chunk - introduce self to other */
static int handle_IHello(Request *request, uint8_t *payload, int length) {
    int epdLength = vlu_read(&payload, &length);
    if (length < epdLength) _error("truncated IHello chunk", 0);

    // We need this bit for the RHello, but the endpoint discriminator is just noise to us
    uint8_t *tag = payload + epdLength;
    int tagLength = length - epdLength;

    if (tagLength == 0) _error("truncated IHello chunk", 0);

    uint8_t *bufptr = request->response;
    int remaining = sizeof(request->response);

    if (!initPacket(request, &bufptr, &remaining) || remaining < 3) _error("out of space", 0);

    bufptr[0] = 0x70;           // RHello type

    // Store a marker to where the length will be written later
    uint16_t *lengthptr = (uint16_t *)(bufptr + 1);
    int payloadLength = remaining - 3;

    // Skip over type+length to the data 
    bufptr += 3;
    remaining -= 3;

    // oh god side effects oh god
    if (remaining < 2 || !vlu_write(tagLength, &bufptr, &remaining) || remaining < tagLength)
        _error("out of space", 0);

    memcpy(bufptr, tag, tagLength);
    bufptr += tagLength;
    remaining -= tagLength;

    if (remaining < 41) _error("out of space", 0);

    /* Write out a 'random' cookie */
    *bufptr++ = 0x40;
    if (RAND_pseudo_bytes(bufptr, 0x40) < 0) _error("no entropy", 0);
    bufptr += 0x40;
    remaining -= 0x41;

    /* Write out the server certificate = 71 bytes of data
     * ancillary data option            = 2 bytes
     * extra randomness x64             = 66 bytes
     * supports ephemeral DH group 2    = 3 bytes
     */
    if (remaining < 71) _error("out of space", 0);

    *bufptr++ = 0x01;
    *bufptr++ = 0x0a;
    *bufptr++ = 0x41;
    *bufptr++ = 0x0e;
    if (RAND_pseudo_bytes(bufptr, 0x40) < 0) _error("no entropy", 0);
    bufptr += 0x40;
    *bufptr++ = 0x02;
    *bufptr++ = 0x15;
    *bufptr++ = 0x02;
    remaining -= 71;

    *lengthptr = htons(payloadLength - remaining);

    request->rlength = sizeof(request->response) - remaining;
    if (remaining < 15 || !finalisePacket(request, request->response, &request->rlength))
        _error("finalisation failed", 0);

    return 1;
}

// Find a DH key within an option list
static int find_dhkey(uint8_t *data, int length, int type, int group, int endOnMarker, uint8_t **payload, int *payloadSize)
{
    // Look through the initiator certificate for a static key option in group 2
    while (length > 0) {
        int optionLength = vlu_read(&data, &length);
        if (optionLength == 0 && endOnMarker) return 1;
        if (optionLength == 0) continue;
        if (optionLength > length) return 0;

        /* Start reading only in this option's allocated space */
        uint8_t *option = data;
        data += optionLength;
        length -= optionLength;

        int opttype = vlu_read(&option, &optionLength);
        if (opttype != type) continue; // only want static DH key options now

        int optgroup = vlu_read(&option, &optionLength);
        if (optgroup != group) continue;  // only want DH group 2 keys

        *payload = option;
        *payloadSize = optionLength;
        break;
    }
    return 1;
}

/* Initiator Initial Keying chunk - crypto exchange, session establishment */
int handle_IIKeying(Request *request, uint8_t *payload, int length) {
    // allocate a session ID
    uint32_t sessionId = request->service->nextSessionId++;

    if (length < 4) _error("truncated IIKeying chunk", 0);

    uint32_t remoteId = *((uint32_t *)payload);
    payload += 4; length -= 4;

    int cookieLength = vlu_read(&payload, &length);
    if (cookieLength != 0x40) _error("invalid IIKeying cookie", 0);
    if (cookieLength >= length) _error("truncated IIKeying chunk", 0);
    length -= cookieLength;
    payload += cookieLength;

    // The remote public key to use - to be found in the payload from here
    uint8_t *dh_key_option = NULL;
    int dh_key_size = 0;

    int certLength = vlu_read(&payload, &length);
    uint8_t *certificate = payload;
    if (certLength < 0) _error("invalid IIKeying certificate length", 0);
    if (certLength >= length) _error("truncated IIKeying chunk", 0);
    length -= certLength; payload += certLength;

    // Look through the initiator certificate for a static key option in group 2
    if (!find_dhkey(certificate, certLength, 0x1d, 2, 1, &dh_key_option, &dh_key_size))
        _error("invalid certificate block in IIKeying chunk", 0);

    int skicLength = vlu_read(&payload, &length);
    uint8_t *skic = payload;
    if (skicLength < 0) _error("invalid IIKeying components length", 0);
    if (skicLength >= length) _error("truncated IIKeying chunk", 0);
    length -= skicLength; payload += skicLength;

    // Look through the key components for an ephemeral key
    if (!find_dhkey(skic, skicLength, 0x0d, 2, 0, &dh_key_option, &dh_key_size))
        _error("invalid component block in IIKeying chunk", 0);

    if (dh_key_option == NULL) _error("no DH key found in IIKeying chunk", 0);

    // Convert bytes to a BIGNUM
// allocation
    BIGNUM *them = BN_bin2bn(dh_key_option, dh_key_size, NULL);

    // Generate my ephemeral key
// allocation
    DH *myKey = get_dh1024();
    if (!DH_generate_key(myKey)) {
        DH_free(myKey);
        BN_free(them);
        _error("DH key generation failed", 0);
    }
    int keySize = DH_size(myKey);
// allocation
    unsigned char *sharedKey = malloc(keySize);
    keySize = DH_compute_key(sharedKey, them, myKey);
    // if keySize == -1, fail
    printf("Shared key:\n"); hex_print(sharedKey, keySize);

    // the skic points now to the SKFC component of the crypto exchange
    // the SKNC component needs to be populated

    uint8_t sknc[512];
    int pubKeySize = BN_num_bytes(myKey->pub_key);
    if (sizeof(sknc) - pubKeySize < 11) {
        free(sharedKey);
        DH_free(myKey);
        BN_free(them);
        _error("Ephemeral public key is unexpectedly huge", 0);
    }
    sknc[0] = 0x03; sknc[1] = 0x1a; sknc[2] = 0x00; sknc[3] = 0x00;     // never HMAC
    sknc[4] = 0x02; sknc[5] = 0x1e; sknc[6] = 0x00;                     // never SSN
    int skncSize = sizeof(sknc) - 7;
    uint8_t *skncp = sknc + 7;
    vlu_write(pubKeySize + 2, &skncp, &skncSize);
    *(skncp++) = 0x0d; skncSize--;
    *(skncp++) = 0x02; skncSize--;
    skncSize -= BN_bn2bin(myKey->pub_key, skncp);
    skncSize = sizeof(sknc) - skncSize; // convert from remaining bytes to used bytes

    unsigned char hmac_pad[32];
    unsigned char encrypt_hmac[32];
    unsigned char decrypt_hmac[32];

    // encryptKey = HMAC-256(sharedKey, HMAC-256(SKFC, SKNC))
    HMAC(EVP_sha256(), skic, skicLength, sknc, skncSize, hmac_pad, NULL);
    HMAC(EVP_sha256(), sharedKey, keySize, hmac_pad, 32, encrypt_hmac, NULL);

    // decryptKey = HMAC-256(sharedKey, HMAC-256(SKNC, SKFC))
    HMAC(EVP_sha256(), sknc, skncSize, skic, skicLength, hmac_pad, NULL);
    HMAC(EVP_sha256(), sharedKey, keySize, hmac_pad, 32, decrypt_hmac, NULL);

    printf("SKNC:\n");
    hex_print(sknc, skncSize);
    printf("SKFC:\n");
    hex_print(skic, skicLength);
    printf("Created keys:\n");
    hex_print(encrypt_hmac, 16);
    hex_print(decrypt_hmac, 16);

    //printf("Compute keys: SKNC\n");
    //hex_print(sknc, skncSize);
    //printf("Compute keys: SKFC\n");
    //hex_print(skic, skicLength);

    // Free up all the ephemeral data so errors become easier to handle
    free(sharedKey);
    DH_free(myKey);
    BN_free(them);

    // Now construct the response packet
    uint8_t *bufptr = request->response;
    int remaining = sizeof(request->response);

    if (!initPacket(request, &bufptr, &remaining) || remaining < 3) _error("out of space", 0);

    int lengthLength = skncSize > 0x7f ? 2 : 1;
    int chunkLength = 4 /* ssid */ + lengthLength /*skrcLength*/ +skncSize /* skrc */ + 1 /* signature */;

    // RIKeying type = 0x78
    *(bufptr++) = 0x78; remaining--;
    *((uint16_t *)bufptr) = htons(chunkLength);
    bufptr += 2; remaining -= 2;
    *((uint32_t *)bufptr) = (sessionId);
    bufptr += 4; remaining -= 4;
    vlu_write(skncSize, &bufptr, &remaining);
    memcpy(bufptr, sknc, skncSize); bufptr += skncSize; remaining -= skncSize;
    *bufptr = 'X'; remaining--;

    /* Initialise the new session, and switch into it */
    request->session = request->service->sessions + sessionId;
    request->session->remoteId = remoteId;
    memcpy(request->session->encryptKey, defaultSessionKey, 16); // need to encrypt this packet with the default key
    memcpy(request->session->decryptKey, decrypt_hmac, 16);

    request->rlength = sizeof(request->response) - remaining;
    if (remaining < 15 || !finalisePacket(request, request->response, &request->rlength))
        _error("finalisation failed", 0);

    /* Switch encryption key for future packets */
    memcpy(request->session->encryptKey, encrypt_hmac, 16);

    return 1;
}

int handle_UserData(Request *request, uint8_t *payload, int length)
{
    if (length < 4) _error("truncated UserData packet", 0);

    uint8_t flags = *(payload++); length -= 1;
    if ((flags & 0x80) == 0) _error("OPT flag MUST be set on UserData for RTMP", 0);

    if (length < 3) _error("truncated UserData packet", 0);
    int flowID = vlu_read(&payload, &length);
    int seqN = vlu_read(&payload, &length);
    int fsnOffset = vlu_read(&payload, &length);

    // Start constructing a reply, though we might just throw it all away anyway
    uint8_t *bufptr = request->response;
    int remaining = sizeof(request->response);
    if (!initPacket(request, &bufptr, &remaining) || remaining < 3) _error("out of space", 0);

    // Data Acknowledgement chunk
    bufptr[0] = 0x51;
    uint16_t *lengthptr = (uint16_t *)(bufptr + 1);
    int payloadLength = remaining - 3;
    bufptr += 3; remaining -= 3;
    vlu_write(flowID, &bufptr, &remaining);
    vlu_write(63, &bufptr, &remaining);
    vlu_write(seqN, &bufptr, &remaining);
    *lengthptr = htons(payloadLength - remaining);

    // UserData response chunk
    bufptr[0] = 0x10;
    bufptr[3] = 0x80; // flags: OPT
    lengthptr = (uint16_t *)(bufptr + 1);
    payloadLength = remaining - 3;
    bufptr += 4; remaining -= 4;

    // Merely echoing the other end's values here would be highly risky in a real service, but the expected flow in this
    // specific context is a single response to a single message
    vlu_write(flowID, &bufptr, &remaining);     // flow ID: use the same as the other end to "cheap" sync
    vlu_write(seqN, &bufptr, &remaining);       // sequence number: hopefully the same as the other end
    vlu_write(1, &bufptr, &remaining);          // no resends, no future messages planned, but I can't say zero :-)

    while (1) {
        if (length < 3) _error("truncated UserData packet", 0);
        int optlen = vlu_read(&payload, &length);
        if (optlen == 0) break;
        if (length < optlen) _error("truncated UserData packet", 0);
        uint8_t *option = payload;
        payload += optlen; length -= optlen;
        int opt = vlu_read(&option, &optlen);

        if (opt == 0x00) {
            // if it's not an RTMP packet, TODO: abort the connection

            // echo metadata back - share a stream ID with the remote end
            vlu_write(optlen + 1, &bufptr, &remaining);
            vlu_write(opt, &bufptr, &remaining);
            memcpy(bufptr, option, optlen);
            bufptr += optlen; remaining -= optlen;
        }
    }

    // Add a return flow association
    int optlen = 2 + (flowID > 0x7f ? 1 : 0);
    vlu_write(optlen, &bufptr, &remaining);  // opt length
    vlu_write(0x0a, &bufptr, &remaining);    // opt type
    vlu_write(flowID, &bufptr, &remaining);  // flow ID

    // end of option list
    vlu_write(0, &bufptr, &remaining);

    if (length < 5) _error("truncated RTMP packet in UserData chunk", 0);

    // payload now points to an RTMP packet
    uint8_t rtmpType = *payload;
    payload += 5; length -= 5;
    switch (rtmpType) {
        case 0x14:      // Invoke
            if (length < 3) _error("truncated RTMP packet in UserData chunk", 0);
            // if the next 10 bytes are 02:00:07:63:6f:6e:6e:65:63:74 this is a "connect" call
            if (length >= 10 && memcmp(payload, "\x02\x00\x07""connect", 10) == 0) {
                // arguments etc don't matter, just fill in a _result object
                char result[] = "\x14\x00\x00\x00\x00"          // invoke, timestamp
                                "\x02\x00\x07_result"           // command name
                                "\x00\x3f\xf0\0\0\0\0\0\0"      // transaction ID 1.0
                                "\x03\x00\x00\x09"              // connection properties (none)
                                "\x03\x00\x00\x09";             // response values (none)
                memcpy(bufptr, result, sizeof(result) - 1);
                bufptr += sizeof(result) - 1; remaining -= sizeof(result) - 1;
                printf("responding to connect call\n");
            } else {
                printf("Unrecognised RTMP invoke call\n");
                hex_print(payload, length > 15 ? 15 : length);
                return 1;  // just bail, don't know, won't respond
            }
            break;
        default:
            // just ignore it
            printf("Unknown RTMP packet type 0x%02x\n", rtmpType);
            return 0;
    }

    *lengthptr = htons(payloadLength - remaining);

    request->rlength = sizeof(request->response) - remaining;
    printf("response, pre-encryption/padding/checksum/length:\n");
    hex_print(request->response, request->rlength);
    printf("end response\n");
    if (remaining < 15 || !finalisePacket(request, request->response, &request->rlength))
        _error("finalisation failed", 0);

    return 1;
}

struct ChunkHandler {
    uint8_t type;
    int (*handler)(Request *, uint8_t *, int);
} chunkHandlers[] = {
    { 0x10, handle_UserData },
    { 0x30, handle_IHello },
    { 0x38, handle_IIKeying },
    { 0, NULL }
};

int chunk_process(Request *request, uint8_t **bufptr, int *remaining) {
    struct ChunkHandler *handler = chunkHandlers;

    request->rlength = 0;

    if (*remaining == 0) return 0;

    uint8_t type = **bufptr;

    if (type == 0xff) { // padding
        (*bufptr)++;
        (*remaining)--;
        return 1;
    }

    uint16_t length = ntohs(*((uint16_t *)(*bufptr + 1)));
    uint8_t *payload = *bufptr + 3;

    (*bufptr) += length + 3;
    (*remaining) -= length + 3;

    while (handler->handler != NULL) {
        if (handler->type == type) {
            return handler->handler(request, payload, length);
        }
        handler++;
    }

    printf("Unknown chunk type 0x%02x\n", type);
    return -1;
}

// Read a datagram for a service
int rtmfpReadDatagram(RtmfpService *service)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int bytes;
    int remaining;
    uint8_t buffer[4096];
    uint8_t *bufptr = buffer;
    uint32_t words[3];

    addrlen = sizeof(addr);
    bytes = recvfrom(service->fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addrlen);

    if (bytes < 4) return -1;

    int copysize = 12;
    if (copysize > bytes) copysize = bytes;
    bzero(words, sizeof(words));
    memcpy(words, buffer, copysize);

    words[0] = words[0] ^ words[1] ^ words[2];

    Request request;
    request.service = service;
    request.session = service->sessions + (words[0] & 0xffff);

    printf("Remote client is sending a message for session ID %d\n", words[0]);

    if (bytes % 16 != 4) {
        printf("datagram is not a multiple of 16 bytes!\n");
        return -1;
    }

    // TODO: don't try to decrypt any appended HMAC verification bytes on the end of the datagram, it won't work anyway

    unsigned char iv[16];
    AES_KEY key;
    printf("AES decryption key:\n");
    hex_print(request.session->decryptKey, 16);
    AES_set_decrypt_key(request.session->decryptKey, 128, &key);
    bzero(iv, 16);
    AES_cbc_encrypt(buffer+4, buffer+4, bytes-4, &key, iv, AES_DECRYPT);
    printf("Decrypted block:\n");
    hex_print(buffer, bytes);

    bufptr = buffer + 4;
    remaining = bytes - 4;

    uint16_t checksum = ip_checksum(bufptr+2, remaining - 2);
    if (checksum != ((uint16_t *)bufptr)[0]) {
        printf("Invalid checksum received\n");
        return -1;
    }
    remaining -= 2;
    bufptr += 2;

    // The flags are bit-reversed, crazy, so we apply just as much crazy unreversing them
    request.flags.byteval = ((*bufptr * 0x0802LU & 0x22110LU) | (*bufptr * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 

    printf("Flags: TC:%d TCR:%d rsv:%d TS:%d TSE:%d MOD:%d\n",
            request.flags.flags.timeCritical, request.flags.flags.timeCriticalReverse, request.flags.flags.reserved,
            request.flags.flags.timestampPresent, request.flags.flags.timestampEchoPresent, request.flags.flags.mode);

    bufptr += 1;
    remaining -= 1;

    int skip = request.flags.flags.timestampPresent * 2 + request.flags.flags.timestampEchoPresent * 2;
    bufptr += skip;
    remaining -= skip;

    // chunk processing
    request.service->errmsg = NULL;
    while (chunk_process(&request, &bufptr, &remaining)) {
        if (request.rlength > 0) {
            sendto(service->fd, request.response, request.rlength, 0, (struct sockaddr *)&addr, addrlen);
            //printf("%d bytes of data:\n", request.rlength);
            //hex_print(request.response, request.rlength);
        }
    }
    if (request.service->errmsg) {
        printf("error: %s\n", request.service->errmsg);
    }

    return remaining;
}

