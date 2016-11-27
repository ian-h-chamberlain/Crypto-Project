from random import randint
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
#Iterative algorithm for Euclidean's Algorithm 
def xgcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0
# x = mulinv(b) mod n, (x * b) % n == 1
def mulinv(b, n):
    g, x, _ = xgcd(b, n)
    if g == 1:
        return x % n
#wrapper for easy change of random number generator
def getRandInt(a,b):
    return randint(a,b)
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

def palDecrypt(private_key,value):
    return private_key.raw_decrypt(value)
