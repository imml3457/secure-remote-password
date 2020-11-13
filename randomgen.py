import hashlib
import math
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util import number

#simple function to get a random #-bit prime number
def getprime(n):
    a = 4
    while(not number.isPrime(a)):
        a = random.getrandbits(n)
    return a

p = 4
#making sure the randomly generated prime number is crypto safe
while(not number.isPrime(p)):
    p = (2 * getprime(512)) + 1


print(p)
#generate a from urandom
a = os.urandom(64)
a = int.from_bytes(a, byteorder="big")
print(a)