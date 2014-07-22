RTFMP Probing
=============

This program provides a UDP service implementing a sufficient amount of the
Flash RTMFP protocol to determine the client IP bindings of the machine on
which a Flash SWF is executing.

The RTMFP protocol is documented through an IETF draft:

    http://tools.ietf.org/html/rfc7016

And the Flash-specific profile for thie protocol here:

    http://tools.ietf.org/html/draft-thornburgh-rtmfp-flash

This implementation is _partial_.  It has bad behaviours that a 'real' server
or client should never do.  It has a fixed limit of 16k concurrent connections
to make it effectively stateless; if there are more than 16k connections held
open at once, the more recent ones will overwrite the older ones and cause
packet decryption to fail.

Compiling
---------

``` bash
autoreconf -i
./configure
make
```

You will need OpenSSL development headers for the crypto functions, and the
GNU autotools.

Running
-------

    src/rtmfprobe [-l <port>]

Runs forever, listening on the given port, or port 1935 if none specified.

Components
----------

The main body of code is in src/, where main.c reads arguments and creates
sockets, rtmp.c parses the RTMP contents of the flows, and rtmfp.c handles
the RTMFP conversation.

In h/ is a sample Haxe script and its output SWF file for connecting to an
RTMFP Probe service and echoing the addresses to the Flash console.

In t/ is a number of Python scripts for testing.  crypto.py provides the RTMFP
packet crypto services, dh.py provides for a Diffie-Hellman key exchange,
qry.py does a rather raw and messy RTMFP query and dump, and proxy.py is an
unfinished man-in-the-middle proxy for inspecting flows.

