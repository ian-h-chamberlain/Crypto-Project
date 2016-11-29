from random import randint
from Crypto.Random import random
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Computes x^e%m
def expmod(x,e,m):
    X = x
    E = e
    Y = 1
    while E > 0:
        if E % 2 == 0:
            X = (X * X) % m
            E = E//2
        else:
            Y = (X * Y) % m
            E = E - 1
    return Y
# Calculates the multiplicative inverse of b mod n
def mulinv(b, n):
    return number.inverse(b,n)
#wrapper for easy change of random number generator
def getRandInt(a,b):
    return random.randint(a,b)
#uses paillier encryption to encrypt a random number r (for ZKP)
def palEncryptRan(public_key):
    n = public_key.n
    g = public_key.g
    n2 = n*n
    r = getRandInt(0,n)
    s = getRandInt(0,n)
    u = expmod(g,r,n2)*expmod(s,n,n2)% n2
    return u,r,s
#uses paillier encryption to encrypt the number ptxt
def palEncrypt(public_key,ptxt):
    n = public_key.n
    g = public_key.g
    n2 = n*n
    x = getRandInt(0,n)
    c = expmod(g,ptxt,n2)*expmod(x,n,n2)% n2
    return c, x
#Constructs a challenge for ZKP
def makeChallenge(A):
    return getRandInt(0,A-1)
#prepares answer to the challenge e from the BB
def answerChallenge(public_key,vote,e,x,r,s):
    n = public_key.n
    g = public_key.g
    n2 = n*n
    v = r-e*vote
    exp = (r-e*vote)/n
    xe = expmod(x,e,n2)
    w = s*mulinv(xe,n2)*expmod(g,exp,n2) %n2
    return v,w
#Checks if the voter correctly responded to the challenge
def checkChallenge(public_key,u,e,c,v,w):
    n = public_key.n
    g = public_key.g
    n2 = n*n
    ans = (expmod(g,v,n2)*expmod(c,e,n2)%n2)*expmod(w,n,n2)%n2
    return ans==u
#Uses the private key to decrypt a paillier encrypted value
def palDecrypt(private_key,value):
    return private_key.raw_decrypt(value)

#Generates a public/private key using RSA
def createRSAkeys():
    rkey = RSA.generate(2048)
    ukey = rkey.publickey()
    return ukey,rkey
def rsaEncrypt(key,message):
    cipher = PKCS1_OAEP.new(key)

    return cipher.encrypt(str(message).encode('ascii'))
def rsaDecrypt(key,ciphertext):
    cipher = PKCS1_OAEP.new(key)
    return int(cipher.decrypt(ciphertext).decode())
