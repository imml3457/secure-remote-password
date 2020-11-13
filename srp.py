import math
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util import number

#adapted from aes with some minor tweaks.
#the tweaks is mostly just adding the modulo of p
def power(g, x, p): 
    total = 1
    #get initial modulo
    g = g % p    
    while (x > 0): 
        #multiply the total taken from the writeup
        if (x & 1):
            total = (total * g) % p 
        #getting each lower exponent
        g = (g * g) % p 
        x >>= 1    
    return total
#generated from the randomgen.py file
#generated p and a securely
p = 233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407
a = 11404519032958518180836407600457081349019200004009362525842220213858255908835286333034402409371096324237560382493036241850993507330010974533825121744178773
ga = power(5, a, p)
#find ga and convert passwd and salt into a byte array
passwd = 'epileptical'
passwd_as_bytes = passwd.encode('ascii')
salt = '7cb51a69'
saltbytes = bytes.fromhex(salt)
tempx = saltbytes + passwd_as_bytes
#hash the initial x value
hashedstring = hashlib.sha256(tempx).digest()
#the other 999 hashes for x
for i in range(0, 999):
    hashedstring = hashlib.sha256(hashedstring).digest()
#x turned into a int
intx = int.from_bytes(hashedstring, byteorder='big', signed=False)
#convert p and g to byte arrays
B = 76901940193958479587539567064202248756425946865304556314111546892989603025005306749963090983061805335322582904859756770463191889219037179889946065190542144894087986679042956200618326423421069518814350500994817959820313025371599732807278168729501663000048772621349271879516062492095052186226361172000851084657
g = 5
ptemp = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big')
gtemp = g.to_bytes((g.bit_length() + 7) // 8, byteorder='big')

#calculate k
k = hashlib.sha256(ptemp + gtemp).digest()
intk = int.from_bytes(k, byteorder='big', signed=False)
v = power(g, intx, p)
#finding gb
gb = B - (intk * v)
realgb = gb % p

#convert ga and gb into byte arrays
gah = ga.to_bytes((ga.bit_length() + 7) // 8, byteorder='big')
gbh = realgb.to_bytes((realgb.bit_length() + 7) // 8, byteorder='big')
#hashing to find u
u = hashlib.sha256(gah+gbh).digest()
intu = int.from_bytes(u, byteorder='big', signed=False)

exp = a + (intu * intx)
sharedkey = power(realgb, exp, p)

hashedp = hashlib.sha256(ptemp).digest()
hashedg = hashlib.sha256(gtemp).digest()

inthp = int.from_bytes(hashedp, byteorder='big', signed=False)
inthg = int.from_bytes(hashedg, byteorder='big', signed=False)
#finding shared key 
sharedkeybytes = sharedkey.to_bytes((sharedkey.bit_length() + 7) // 8, byteorder='big')
#prereqs for finding m1
#lots of conversions to byte arrays 
xoredpg = inthp ^ inthg
bytepg = xoredpg.to_bytes((xoredpg.bit_length() + 7) // 8, byteorder='big')
netid = 'imulet'
netidbytes = netid.encode('ascii')
hashednetid = hashlib.sha256(netidbytes).digest()

m1hasher = bytepg + hashednetid + saltbytes + gah + gbh + sharedkeybytes

m1 = hashlib.sha256(m1hasher).digest()

m1hex = m1.hex()
#similar method to find m2
m2hasher = gah + m1 + sharedkeybytes

m2 = hashlib.sha256(m2hasher).digest()

m2hex = m2.hex()
print(m2hex)
