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
