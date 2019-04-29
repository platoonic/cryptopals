#
#
#	Cryptopals Challenge
#	Set 1
#
#

import base64,binascii,string

##Functions I didn't write

def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


#### General functions

#HEX to base64 and vice versa
def hex_to_base64(hexa):
	binary = binascii.unhexlify(hexa)
	return base64.b64encode(binary)

def base64_to_hex(msg):
	msg = base64.b64decode(msg)
	return binascii.hexlify(msg).decode()


#Decrypt Single-Byte XOR cipher
#y = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
def sbxor(y):
	messages = []
	y = binascii.unhexlify(y)
	for letter in range(256):
		message = [chr(a ^ letter) for a in y]
		if(all(ord(c) < 128 for c in "".join(message))):
			messages.append("".join(message))
	if(messages):
		return max(messages,key=lambda b: b.count(' '))
	else:
		return 0

def sbxor_key(y):
	messages = []
	y = binascii.unhexlify(y)
	for letter in range(256):
		message = [chr(a ^ letter) for a in y]
		if(all(ord(c) < 128 for c in "".join(message))):
			messages.append(["".join(message),chr(letter)])
	if(messages):
		key =  max(messages,key=lambda b: b[0].count(' '))
		return key[1]
	else:
		return 0

##challenge 4

file = open("4.txt","r")
messages = []
for line in file.readlines():
	line = line.strip('\n')
	message = sbxor(line)
	if(message): 
		messages.append(message.strip('\n'))

print(max(messages,key=lambda b: b.count(' ')))


##challenge 5

#Repeating-key XOR encryption

def rkxor_encrypt(message,key):
	encrypted = ""

	for i,t in enumerate(message):
		encrypted += chr(ord(t) ^ ord(key[i%3]))

	return binascii.hexlify(encrypted.encode())


#message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
#key = "ICE"

#print(rkxor_encrypt(message,key))

def edit_distance(str1,str2):
	str1 = tobits(str1)
	str2 = tobits(str2)
	edit_distance = 0

	for indx,byte in enumerate(str1):
		if(byte != str2[indx]):
			edit_distance += 1

	return edit_distance

#message = "YiROCk8gUwY1C1IJCAACEU8QRSxORTBSHQYGTlQJC1lOBAAXRTpCUh0FDxhU"
file = open("6.txt","r")
message = binascii.unhexlify(base64_to_hex(file.read())).decode()

KEYSIZE = 2
edit_distances = []
while(KEYSIZE <= 40):
	#KEYSIZE = 5
	c = 0
	ed = 0
	while c < KEYSIZE:
		if(c+KEYSIZE < len(message)):
			ed += edit_distance(message[c],message[c+KEYSIZE])
			#print(message[c])
		else:
			break
		c += 1
	edit_distances.append(ed/KEYSIZE)
	KEYSIZE += 1

#print(edit_distances)
KEYLENGTH = KEYSIZE + edit_distances.index(min(edit_distances)) - 39
KEYLENGTH = 15
#KhalidMagdyKhalil
result = []
key = 0
while key < KEYLENGTH:
	m = ""
	#m = "Kdy"
	counter = key
	while counter < len(message):
		m += message[counter]
		counter += KEYLENGTH

	#print(m)
	#print(key)
	result.append(sbxor_key(binascii.hexlify(m.encode()).decode()))
	key += 1

#print(result)
#print(KEYLENGTH)





































