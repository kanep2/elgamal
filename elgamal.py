#from Crypto.PublicKey.pubkey import *
#from Crypto import Random
from Crypto.Util import number
from random import randint
from random import getrandbits
from random import randrange
import math
import os

class publicKey(object):
	def __init__(self, p, g, x):
		self.p = p
		self.g = g
		self.x = x

#generates random numbers and checks them with 
#miller rabin until a prime is found
def findPrime(bits, t):
	while 1:
		num = getrandbits(bits)
		if millerRabin(num, 5):
			return num

#returns true if n is prime with the
#defree of certainty t
def millerRabin(n, t):
	if n % 2 == 0:
		return False
	k = 0
	m = n - 1
	while m % 2 == 0:
	    k += 1
	    m //= 2
	i = 0
	while i < t: 
	    i += 1
	    x = pow(randrange(2, n - 1), m, n)
	    if x != 1:
	        j = 0
	        while x != n - 1:  
	            if j == k - 1:
	                return False
	            else:
	                j += 1
	                x = pow(x, 2, n)
	return True

#find a generator for the cyclic group 
#created by the prime number p
def getGen(p):
    while 1:
        g = randint(2, p-1)
        if pow(g, (p-1) // 2, p) != 1:
            if pow(g, (p-1) // ((p-1) // 2), p) != 1:
                return g

#generates publick and private keys for P1
def p1getKeys(bits):
	p = findPrime(bits, 5)
	g = getGen(p)
	a = randint(1, p-2)
	x = pow(g, a, p)
	return publicKey(p, g, x), a

#generates publick and private keys for P2
def p2getKeys(r):
	cliKey = publicKey(int(r[0]), int(r[1]), int(r[2]))
	myKey = randint(1, cliKey.p-2)
	pubKey = pow(cliKey.g, myKey, cliKey.p)
	return cliKey, myKey, pubKey

#find mod inverse using the extended euclidian algorithm
def modi(n, m):
    gcd, a, b = exteuc(n, m)
    if gcd > 1:
        print('inverse not found')
        raise ValueError
    else:
        return a % m

#extended euclidian algorithm
def exteuc(n, m):
    if n == 0:
        return m, 0, 1
    else:
        gcd, b, a = exteuc(m % n, n)
        r = (m // n) * b
        a = a - r
        return gcd, a, b

#encryps the AES Key using the partners 
#public key and your prive key
def encrypt(theirx, mya, aesKey, p):
    k = pow(theirx, mya, p)
    c = (k * aesKey) % p
    return c
#finds the same key that the person encrpying 
#found then uses the mod inv to decrypt c
def decrypt(theirx, mya, c, p):
	k = pow(theirx, mya, p)
	inv = modi(k, p) 
	return (inv * c) % p


