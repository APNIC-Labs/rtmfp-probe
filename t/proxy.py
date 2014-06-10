#!/usr/bin/env python

from dh import DiffieHellman
import crypto

import socket
import struct
from binascii import hexlify, unhexlify

UDP_IP='50.57.70.211'
UDP_PORT=1935 #macromedia-fcs

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', 1935))
print 'Client listening on port ' + str(sock.getsockname()[1])

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

def prep(msg, ssid, mode, key):
    msg = struct.pack("!B", mode) + msg
    if (len(msg)+2) % 16 != 0:
        msg = msg + '\xff' * (16 - (len(msg)+2) % 16)
    chksum = checksum(msg)
    msg = struct.pack("=H", chksum) + msg
    msg = crypto.encrypt(msg, key)
    words = struct.unpack("!LL", msg[:8])
    ssid = ssid ^ words[0] ^ words[1]
    msg = struct.pack("!L", ssid) + msg
    return msg

def unwrap(msg, key):
    data = { }
    words = struct.unpack("!LLL", msg[:12])
    data['ssid'] = words[0] ^ words[1] ^ words[2]
    orig = msg[4:]
    msg = crypto.decrypt(msg[4:], key)
    print 'decrypted:', repr(msg)
    chksum = checksum(msg[2:])
    if chksum != struct.unpack('=H', msg[:2])[0]:
        msg = crypto.decrypt(orig, crypto.DEFAULT_KEY)
        print "invalid checksum", data['ssid'], repr(orig), hexlify(orig), repr(msg)
        chksum = checksum(msg[2:])
        if chksum == struct.unpack('=H', msg[:2])[0]:
            print "default crypto key message"
        return None
    flags = ord(msg[2])
    print 'Flags:', hex(flags)
    msg = msg[3:]
    if flags & 4: msg = msg[2:]
    if flags & 8: msg = msg[2:]
    data['flags'] = flags
    chunks = []
    while len(msg) > 3:
        if msg[0] == '\xff':
            msg = msg[1:]
            continue
        (chtype, chlength) = struct.unpack("!BH", msg[:3])
        chunks.append((chtype, chlength, msg[3:chlength+3]))
        msg = msg[chlength+3:]
    data['chunks'] = chunks
    return data

def packl(lnum, padmultiple=1):
    """Packs the lnum (which must be convertable to a long) into a
       byte string 0 padded to a multiple of padmultiple bytes in size. 0
       means no padding whatsoever, so that packing 0 result in an empty
       string.  The resulting byte string is the big-endian two's
       complement representation of the passed in long."""

    if lnum == 0:
       return b'\0' * padmultiple
    elif lnum < 0:
       raise ValueError("Can only convert non-negative numbers.")
    s = hex(lnum)[2:]
    s = s.rstrip('L')
    if len(s) & 1:
       s = '0' + s
    s = unhexlify(s)
    if (padmultiple != 1) and (padmultiple != 0):
       filled_so_far = len(s) % padmultiple
       if filled_so_far != 0:
          s = b'\0' * (padmultiple - filled_so_far) + s
    return s

def vread(msg):
    value = 0
    while len(msg) > 0 and ord(msg[0]) & 0x80 != 0:
        value = value << 7
        value = value + (ord(msg[0]) & 0x7f)
        msg = msg[1:]
    if len(msg) > 0:
        value = value << 7
        value = value + (ord(msg[0]) & 0x7f)
        msg = msg[1:]
    return (value, msg)

def vwrite(value):
    if value <= 0: return '\0'
    msg = ''
    flag = 0
    while value > 0:
        msg = chr((value & 0x7f) | flag) + msg
        flag = 0x80
        value = value >> 7
    return msg

cekey = crypto.DEFAULT_KEY
cdkey = crypto.DEFAULT_KEY
sekey = crypto.DEFAULT_KEY
sdkey = crypto.DEFAULT_KEY
caddr = None
while True:
    msg, addr = sock.recvfrom(1024)
    print repr(msg)
    dkey = cdkey
    ekey = sekey
    target = (UDP_IP, UDP_PORT)
    if addr[0] == UDP_IP:
        dkey = sdkey
        ekey = cekey
        target = caddr
    else:
        caddr = addr
    words = struct.unpack("!LLL", msg[:12])
    ssid = words[0] ^ words[1] ^ words[2]
    msg = crypto.decrypt(msg[4:], dkey)
    # if it's a crypto exchange, replace it with my keying material
    print addr
    msg = crypto.encrypt(msg, ekey)
    words = struct.unpack("!LL", msg[:8])
    ssid = ssid ^ words[0] ^ words[1]
    msg = struct.pack("!L", ssid) + msg
    sock.sendto(msg, target)

#epd = "\x16\x15\x0artmpf://cc.rtmfp.net"

#IHello = prep("\x30" + struct.pack('!H', len(epd) + 16) + epd + "0123456789ABCDEF", 0, 3, crypto.DEFAULT_KEY)
#sock.sendto(IHello, (UDP_IP, UDP_PORT))

#msg, addr = sock.recvfrom(1024)
#data = unwrap(msg, crypto.DEFAULT_KEY)
#assert(data is not None)
#assert(len(data['chunks']) == 1)
#RHello = data['chunks'][0]
#if RHello[0] != 0x70: print hexlify(msg), data
#assert(RHello[0] == 0x70)
#assert(RHello[1] == len(RHello[2]))
#(taglen, msg) = vread(RHello[2])
#assert(taglen == 16)
#assert(msg[:16] == '0123456789ABCDEF')
#(cookielen, msg) = vread(msg[16:])
#cookie = msg[:cookielen]

# ignore RHello options, the server will be using an ephemeral key
#dh = DiffieHellman()
#pcert = '\x1d\x02' + packl(dh.publicKey)
#pcert = vwrite(len(pcert)) + pcert
#sknc = '\x02\x1d\x02\x03\x1a\x00\x00\x02\x1e\x00'
#msg = '1234' + vwrite(cookielen) + cookie + vwrite(len(pcert)) + pcert + vwrite(len(sknc)) + sknc + 'X'

#IIKeying = prep("\x38" + struct.pack('!H', len(msg)) + msg, 0, 3, crypto.DEFAULT_KEY)
#sock.sendto(IIKeying, (UDP_IP, UDP_PORT))

#msg, addr = sock.recvfrom(1024)
#data = unwrap(msg, crypto.DEFAULT_KEY)
#assert(data is not None)
#assert(len(data['chunks']) == 1)
#RIKeying = data['chunks'][0]
#assert(RIKeying[0] == 0x78)
#assert(RIKeying[1] == len(RIKeying[2]))
#remote_ssid = struct.unpack('!L', RIKeying[2][:4])[0]
#(skfcLength, msg) = vread(RIKeying[2][4:])
#skfc = msg[:skfcLength]
#kdata = skfc
#shared = None
#while len(kdata) > 3:
    #(optlen, kdata) = vread(kdata)
    #(opttype, odata) = vread(kdata[:optlen])
    #if opttype == 0x0d:
        #(_, odata) = vread(odata) # group ID
        #dh.genKey(long(hexlify(odata), 16))
        #shared = packl(dh.sharedSecret)
    #kdata = kdata[optlen:]
#assert(shared is not None)
#print 'sknc:', hexlify(sknc)
#print 'skfc:', hexlify(skfc)
#print 'shared:', hexlify(shared)
#(enc,dec) = crypto.makeKeys(sknc, skfc, shared)
#print hexlify(enc), hexlify(dec)

# we're up and running, send an RTMP message
#invokeConnect = ('\x80' + # flags
                #'\x02\x01\x01' + # flow ID, seq#, fnsOffset
                #'\x05\x00TC\x04\x00\x00' + # metadata option
                #'\x14\x00\x00\x00\x00' + # RTMP.Invoke(AMF0)
                #'\x02\x00\x07connect' + # connect
                #'\x00\x3f\xf0\x00\x00\x00\x00\x00\x00' + # 1.0
                #'\x03' + # {
                #'\x00\x03app\x02\x00\x00' + # app: ""
                #'\x00\x00\x09') # }
#Invoke = prep('\x10' + struct.pack('!H', len(invokeConnect)) + invokeConnect, remote_ssid, 1, enc)
#sock.sendto(Invoke, (UDP_IP, UDP_PORT))

#while True:
    #msg, addr = sock.recvfrom(1024)
    #data = unwrap(msg, dec)
    #print 'RTMP response:', data
    #for ch in data['chunks']:
        #if ch[0] == 0x10: # UserData, acknowledge
            #bobs = ch[2][1:]
            #(fid, bobs) = vread(bobs)
            #(seq, bobs) = vread(bobs)
            #echo = vwrite(fid) + '\x7f' + vwrite(seq)
            #ack = ('\x51\x00' + vwrite(len(echo)) + echo)
            #Ack = prep(ack, remote_ssid, 1, enc)
            #sock.sendto(Ack, (UDP_IP, UDP_PORT))
