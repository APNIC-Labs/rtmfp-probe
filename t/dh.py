
#!/usr/bin/env python

from binascii import hexlify
import hashlib

# If a secure random number generator is unavailable, exit with an error.
try:
    import Crypto.Random.random
    secure_random = Crypto.Random.random.getrandbits
except ImportError:
    import OpenSSL
    secure_random = lambda x: long(hexlify(OpenSSL.rand.bytes(x>>3)), 16)

class DiffieHellman(object):
    """
    An implementation of the Diffie-Hellman protocol.
    This class uses the 1024-bit MODP Group (Group 2) from RFC somethingorother

    """

    prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF 
    generator = 2

    def __init__(self):
        """
        Generate the public and private keys.
        """
        self.privateKey = self.genPrivateKey(257)
        self.publicKey = self.genPublicKey()

    def genPrivateKey(self, bits):
        """
        Generate a private key using a secure random number generator.
        """
        return secure_random(bits)

    def genPublicKey(self):
        """
        Generate a public key X with g**x % p.
        """
        return pow(self.generator, self.privateKey, self.prime)

    def checkPublicKey(self, otherKey):
        """
        Check the other party's public key to make sure it's valid.
        Since a safe prime is used, verify that the Legendre symbol is equal to one.
        """
        if(otherKey > 2 and otherKey < self.prime - 1):
            if(pow(otherKey, (self.prime - 1)/2, self.prime) == 1):
                return True
        return False

    def genSecret(self, privateKey, otherKey):
        """
        Check to make sure the public key is valid, then combine it with the
        private key to generate a shared secret.
        """
        if(self.checkPublicKey(otherKey) == True):
            sharedSecret = pow(otherKey, privateKey, self.prime)
            return sharedSecret
        else:
            raise Exception("Invalid public key.")

    def genKey(self, otherKey):
        """
        Derive the shared secret, then hash it to obtain the shared key.
        """
        self.sharedSecret = self.genSecret(self.privateKey, otherKey)
        s = hashlib.sha256()
        s.update(str(self.sharedSecret))
        self.key = s.digest()

    def getKey(self):
        """
        Return the shared secret key
        """
        return self.key

    def showParams(self):
        """
        Show the parameters of the Diffie Hellman agreement.
        """
        print "Parameters:"
        print
        print "Prime: ", self.prime
        print "Generator: ", self.generator
        print "Private key: ", self.privateKey
        print "Public key: ", self.publicKey
        print

    def showResults(self):
        """
        Show the results of a Diffie-Hellman exchange.
        """
        print "Results:"
        print
        print "Shared secret: ", self.sharedSecret
        print "Shared key: ", hexlify(self.key)
        print

if __name__=="__main__":
    """
    Run an example Diffie-Hellman exchange 
    """

    a = DiffieHellman()
    b = DiffieHellman()

    a.genKey(b.publicKey)
    b.genKey(a.publicKey)

    if(a.getKey() == b.getKey()):
        print "Shared keys match."
        print "Key:", hexlify(a.key)
    else:
        print "Shared secrets didn't match!"
        print "Shared secret: ", a.genSecret(b.publicKey)
        print "Shared secret: ", b.genSecret(a.publicKey)

