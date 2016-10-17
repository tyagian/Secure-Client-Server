#!/usr/bin/env python

import socket, threading, sys, getopt, re, time, thread, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from random import randint
from random import randrange
import hashlib
import getpass

# Diffie-Hellman constants 
p = 45215679089341564880983468793221
g = 2
DH_KEY_DICT = {}
DH_KEY = ""
MY_DH_SECRET = {}

# generates DH parameter. 
# Returns : Integer
def generate_DH_parameter(uid):
	global MY_DH_SECRET
	a = MY_DH_SECRET[uid] = randrange(1,100)
	param_a = (g**a) % p
	return param_a

# forms a DH shared secret from the given secret and the second parameter
# Returns : Integer
def construct_DH_shared_secret(secret, param2, uid):
	shared_secret = (param2**int(secret)) % p
	return shared_secret

# gives the current time in seconds since epoc
# Returns: None
def timeNow():
	global ts
	ts = time.time()

# checks for replay by checking if the timestamp is older than 5 seconds
# Returns: None
def checkReplay(timestamp):
	timeNow()
	if (int(timestamp)+5) > ts:
		c=2
	else:
		print "replay"

# computes the 256 bits SHA2 hash of the given input
# Returns: Hex-string
def hash(pas):
	hash_obj = hashlib.sha256(pas)
	return hash_obj.hexdigest()

# handles communication between 2 clients
# Returns: None
def listen():
	global establishedkeys
	while(1):
		d = udpsock.recvfrom(1024)
		m =  re.split(r'%%%%',d[0])
		if m[0]=='1':
			#data from server encrypted with symkey of destination(user+new key+timeslot)
			data=symdec(m[2],sus)
			m1 =  re.split(r'&&&',data)
			checkReplay(int(float(m1[2])))
			try:
				a=establishedkeys.index(m1[0])
			except ValueError:
				a=-1

			#removing previous keys	
			if a>=0:
				del establishedkeys[a]
				del establishedkeys[a]
			establishedkeys.extend((m1[0],gensymkey(m1[1])))
			param2 = generate_DH_parameter(m[1])

			#generating DH shared key
			global DH_KEY
			DH_SHARED_SECRET = construct_DH_shared_secret(MY_DH_SECRET[m[1]], int(m[3]), m[1])
			DH_KEY = hashlib.sha256(str(DH_SHARED_SECRET))
			DH_KEY = DH_KEY.hexdigest()
			DH_KEY = DH_KEY[0:32]
			DH_KEY_DICT[m[1]] = DH_KEY
			ind = establishedkeys.index(m[1])

			#sending DH parameter to client
			client_DH_message = symenc(str(param2), establishedkeys[ind+1])
			client_DH_message = '2' +'%%%%' +username +'%%%%' +client_DH_message
			udpsock.sendto(client_DH_message, d[1])
			
		elif m[0]=='2':
			ind = establishedkeys.index(m[1])
			data = symdec(m[2], establishedkeys[ind+1])
			other_parameter = int(data)
			test = int(param1) * int(other_parameter)

			#generating key from DH secret
			DH_SECRET = construct_DH_shared_secret(MY_DH_SECRET[m[1]], int(other_parameter), m[1])
			DH_KEY = hashlib.sha256(str(DH_SECRET))
			DH_KEY = DH_KEY.hexdigest()
			DH_KEY = DH_KEY[0:32]
			DH_KEY_DICT[m[1]] = DH_KEY
	
			m1=symenc(message_for_client,DH_KEY)
			udpsock.sendto(username+'%%%%'+m1, d[1])

		else:
			#display message 
			ind=establishedkeys.index(m[0])
			m1=symdec(m[1],DH_KEY_DICT[m[0]])
			print "Message received from " +m[0]+ ' : ' +m1
		
# encrypts the given input message using RSA
# Returns: Hex-string
def encode(message):
	serverkey='server'
	global private_key_server,public_key_server
	with open("%s" % serverkey, "rb") as key_file:
		private_key_server = serialization.load_pem_private_key(
			key_file.read(), password=None, backend=default_backend())
		public_key_server = private_key_server.public_key()
		pem = public_key_server.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo)
		ciphertext = public_key_server.encrypt(
			message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),label=None))

		return ciphertext

# verifies the signature of a signed message
# Returns: None
def verifysign(signature,originalmessage):
	verifier = public_key_server.verifier(signature,padding.PSS(mgf=padding.MGF1(hashes.SHA1()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA1())
	verifier.update(originalmessage)

# generates a new symmetric key by using SHA2 hashing
# Returns: None
def generatesymkey():
	#symmetric key with server
	global sus
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(str.encode(str(symkey)))
	sus=digest.finalize()

# generates a symmetric key for every message using SHA2 hashing
# Returns: Hex-string
def gensymkey(num):
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(str.encode(str(num)))
	k=digest.finalize()
	#return symmetric key for a random number num
	return k

# encrypts a given message using the given key using AES algorithm
# Returns: String
def symenc(msg,key):
	#symmetric encryption for all communication between client and client
	backend = default_backend()
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	length = 16 - (len(msg) % 16)
	msg = msg+chr(97)*length
	if length<10:
		lent="0"+str(length)
	if length>9:
		lent=str(length)
	symencrypted=encryptor.update(msg) + encryptor.finalize()
	return symencrypted+lent+iv

# decrypts given message using given key using AES algorithm
# RETURNS: String
def symdec(msg,key):
	backend = default_backend()
	iv=msg[-16:]
	msg=msg[:-16]
	length=int(msg[-2:])
	msg=msg[:-2]
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = cipher.decryptor()
	decoded=decryptor.update(msg) + decryptor.finalize()
	decoded = decoded[:-length]
	return decoded

# checks for a challenge by multiplying 2 numbers 
# Retruns: maybe String
def challenge():
	raw_input("Press any key to start? ")
	star='a'
	msg=encode(str(star))
	s.send(msg)
	data=s.recv(4096)
	m =  re.split(r'&&&',data)
	verifysign(m[0]+'&&&'+m[1],m[2])
	reply=int(m[0])*int(m[1]) 
	reply=encode(str(reply))
	s.send(reply)
	data=s.recv(4096)
	m =  re.split(r'&&&',data)
	verifysign(m[0],m[1])
	if "Challenge" in m[0]:
		return 'invalid'

# checks in the cleint with the server and initiates client to client communication
# Returns: String
def login() :
	global username
	username = raw_input("Enter your username: ")
	timeNow()
	#sending Connect Username Time
	if not username:
		return 'invalid'
	if not username.isalnum():
		return 'invalid'
	msg = 'connect'+str(username)+'&&&'+str(ts)

	#locking with server public key
	msg=encode(msg)
	s.send(msg)

	#receiving signed response from server having salt and timestamp
	data=s.recv(4096)
	m =  re.split(r'&&&',data)
	verifysign(m[0]+'&&&'+m[1],m[2])
	if 'registered' in data:
		print m[0]
		return "invalid"

	# Removing salt
	checkReplay(int(float(m[1])))
	while(1):
		pass1 = getpass.getpass("Enter your password: ")
		if not pass1 and not pass1.isalpha():
			print "Password cannot be blank and cannot have spaces"
			continue
		else:
			break

	timeNow()
	randnum=randint(1,100)
	l1=["server",randnum]
	dhserverkey= g**randnum % p

	#sending User+Pass+salt+time+dhkey
	password = str(username) + '&&&' + hash(str(pass1) + str(m[0])) + '&&&' + str(ts) + '&&&' + str(dhserverkey) + '&&&' + str(udpsockport)
	password = encode(password)
	s.sendall(password)

	#receive decision from server
	data=s.recv(4096)
	print data 
	if "Invalid" in data:
		return "invalid"
	s.send('ok')

	#receive dh key from server
	data=s.recv(4096)
	m =  re.split(r'&&&',data)
	verifysign(m[0]+'&&&'+m[1],m[2])
	checkReplay(int(float(m[1])))
	global symkey
	symkey=(int(m[0])) ** randnum % p
	return "sucess"
 
#main function
if __name__ == "__main__":
	 
	if(len(sys.argv) < 3) :
		print 'Usage : python tcpclient.py IP-OF-SERVER PORT-OF-SERVER'
		sys.exit()
	 
	#taking inputs for IP and PORT from command line inputs 
	host = sys.argv[1]
	port = int(sys.argv[2])
	establishedkeys=[]
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	udpsock.bind(('', 0))
	udpsockport=udpsock.getsockname()[1]
	s.settimeout(10)
	 
	# connect to remote host
	try :
		s.connect((host, port))
	except socket.error as err :
		print 'Unable to connect to server. Error: ' +str(err)
		sys.exit()
	 
	print 'Connected to server. Start sending messages'

	#checking for challenge-response
	while(1):
		status=challenge()
		if status=='invalid':
			continue
		else:
			break

	#logging client in
	while(1):
		status=login()
		if status=='invalid':
			continue
		else:
			thread.start_new_thread(listen,())
			generatesymkey()
			break

	#handling client functions
	while (1):
		userinput = raw_input("<you>")
		userinput = str(userinput)
		timeNow()

		#list command for listing online users
		if userinput=="list":
			data=symenc(userinput+'&&&'+str(ts),sus)
			s.send(data)
			data=s.recv(4096)
			data=symdec(data,sus)
			print data

		#for sending data to another user
		elif userinput=="send":
			print("Please follow specified format 'send username data'")
			continue
		elif "send" in userinput:
			data=userinput.split(' ',2)
			if len(data) < 3:
				print("Please follow specified format 'send username data'")
				continue
			message_for_client = str(data[2])

			#sending "send+user" to server
			data1=data[0]+' '+data[1]+'&&&'+str(ts)
			data1=symenc(data1,sus)
			s.send(data1)

			#removing message
			data=' '.join(data[2:len(data)])

			#revceiving response from server
			datarecv=s.recv(4096)
			datarecv=symdec(datarecv,sus)
			if "yourself" in datarecv:
				print datarecv	
				continue
			if "not exist" in datarecv:
				print datarecv
				continue

			#receiving IP+ UDP Port+ Timestamp+ Destination Username+ New Sym Key+ 
			#(Source username + new key)encrypted with symkey of destination with server
			m =  re.split(r'&&&',datarecv)
			checkReplay(int(float(m[2])))
			try:
				a=establishedkeys.index(m[3])
			except ValueError:
				a=-1
			if a>=0:
				del establishedkeys[a]
				del establishedkeys[a]
			establishedkeys.extend((m[3],gensymkey(m[4])))
			
			#send DH parameter to other client
			param1 = generate_DH_parameter(m[3])
			udpsock.sendto('1'+'%%%%'+username+'%%%%'+m[5] +'%%%%' +str(param1), (m[0], int(m[1])))
			time.sleep(0.1)
	
		else:
			print "Invalid input"
			continue

			
