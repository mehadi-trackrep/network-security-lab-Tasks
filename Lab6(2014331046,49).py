import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import os
from Crypto.Hash import SHA256
import time

print("\n\n== Welcome in Programming Symmetric & Asymmetric Crypto machanisms ==\n\n")

def padding(text):
	l = len(text)
	v = l%16
	a = 16 - v
	ans = text
	for i in range(a):
		ans = ans + '0'
	return ans

while(1):

	print('Enter "0" for Exit')
	print('Enter "1" for AES encryption and decryption')
	print('Enter "2" for RSA encryption and decryption')
	print('Enter "3" for RSA Signature')
	print('Enter "4" for SHA-256 hashing\n\n')

	try:
		command = int(input())
	except:
		print("----------- Invalid command -------------\n")
		continue

	if command > 4:
		print("----------- Invalid command -------------\n")
		continue
	if command == 0:
		break

	then = time.time() #Time before the operations start

	if command == 1:
		### link: https://techtutorialsx.com/2018/04/09/python-pycrypto-using-aes-128-in-ecb-mode/
		from Crypto.Cipher import AES
		print('Enter 1 for ECB mode')
		print('Enter 2 for CBC mode\n')

		mode = int(input())

		if mode == 1:
			print('Enter 1 for key length = 128')
			print('Enter 2 for key length = 256\n')
			k = int(input())
			if k == 1:
				##ECB Mode
				key128 = 'abcdefghijklmnop'
				print('Please, enter your Plain text')
				plain_text = input()
				l = len(plain_text)
				plain_text = padding(plain_text)
				# plain_text = 'TechTutorialsX!!TechTutorialsX!!'
				cipher = AES.new(key128, AES.MODE_ECB)
				cipher_text =cipher.encrypt(plain_text)

				print ("==> The Cipher text: ",cipher_text)
				decipher = AES.new(key128, AES.MODE_ECB)
				d = decipher.decrypt(cipher_text)
				print("==> Decrypted text: ", d[0:l], "\n")
				now = time.time()
				print("It took: ", now-then, " seconds", "\n")
			else:
				key256 = 'abcdefghijklmnop1234569874123658'
				print('Please, enter your Plain text')
				plain_text = input()
				l = len(plain_text)
				plain_text = padding(plain_text)
				cipher = AES.new(key256, AES.MODE_ECB)
				cipher_text =cipher.encrypt(plain_text)
				print ("==> The cipher text: ",cipher_text)
				decipher = AES.new(key256, AES.MODE_ECB)
				d = decipher.decrypt(cipher_text)
				print("==> Decrypted text: ",d[0:l], "\n")
				now = time.time()
				print("It took: ", now-then, " seconds", "\n")
		else:
			print('Enter 1 for key length = 128')
			print('Enter 2 for key length = 256\n')
			k = int(input())
			if k == 1:
				key128 = 'abcdefghijklmnop'
				print('Please, enter your Plain text')
				plain_text = input()
				l = len(plain_text)
				plain_text = padding(plain_text)
				print(len(plain_text))
				iv = os.urandom(16)
				cipher = AES.new(key128, AES.MODE_CBC, iv)
				cipher_text = cipher.encrypt(plain_text)
				print ("==> The cipher text: ",cipher_text)
				decipher = AES.new(key128, AES.MODE_CBC, iv)
				d = decipher.decrypt(cipher_text)
				print("==> Decrypted text: ", d[0:l], "\n")
				now = time.time()
				print("It took: ", now-then, " seconds", "\n")
			else:
				key256 = 'abcdefghijklmnop1234569874123658'
				print('Please, enter your Plain text')
				plain_text = input()
				l = len(plain_text)
				plain_text = padding(plain_text)
				iv = os.urandom(16)
				cipher = AES.new(key256, AES.MODE_CBC, iv)
				cipher_text = cipher.encrypt(plain_text)
				print ("==> The cipher text: ",cipher_text)
				decipher = AES.new(key256, AES.MODE_CBC, iv)
				d = decipher.decrypt(cipher_text)
				print("==> Decrypted text: ", d[0:l], "\n")
				now = time.time()
				print("It took: ", now-then, " seconds", "\n")
	elif command == 2:
		#link: https://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python

		random_generator = Random.new().read
		key = RSA.generate(1024, random_generator) #generate pub and priv key

		##Key generation ....
		publickey = key.publickey()
		private_key = key.exportKey()

		f = open ('public_key.txt', 'w')
		f.write(str(publickey)) #write ciphertext to file
		f.close()
		f = open ('private_key.txt', 'w')
		f.write(str(private_key)) #write ciphertext to file
		f.close()

		print('Please, enter your message')

		message = input()
		ecrypted_message = publickey.encrypt(message.encode('utf-8'), 32)

		print ('==> Encrypted message: ', ecrypted_message) #ciphertext
		f = open ('RSA_encryption.txt', 'w')
		f.write(str(ecrypted_message)) #write ciphertext to file
		f.close()

		#decrypted code below
		f = open('RSA_encryption.txt', 'r')
		ecrypted_message = f.read()
		decrypted_message = key.decrypt(ast.literal_eval(str(ecrypted_message)))

		print ('==> Decrypted message: ', decrypted_message, "\n")
		now = time.time()
		print("It took: ", now-then, " seconds", "\n")

		##Save the encrypted and decrypted message...
		f = open ('RSA_encryption.txt', 'w')
		f.write("==> Encrypted mesage: " + str(ecrypted_message))
		f.write("\n\n==> Decrypted mesage: " + str(decrypted_message))
		f.close()

	elif command == 3:
		print('Please, enter your message')
		message = input()
		message = message.encode('utf-8')

		f = open ('message.txt', 'w')##message save..
		f.write(str(message))
		f.close()

		hash = SHA256.new(message).digest()

		random_generator = Random.new().read
		key = RSA.generate(1024, random_generator) #generate pub and priv key
		##Key generation ....
		publickey = key.publickey()
		privatekey = key.exportKey()

		ecrypted_message = publickey.encrypt(hash, 32)

		f = open ('ecrypted_message.txt', 'w')##encrypted message save
		f.write(str(ecrypted_message))
		f.close()


	## Now in signing.. message and encrypted message transmit hobe... ekhon receiver a jodi transmitted 'message' and
	## 'decrypted message' same hote hobe.. na hole bujhte hobe.. intruder message change kore dice...
		f = open ('message.txt', 'r')
		m=f.read()
		f.close()

		f = open ('ecrypted_message.txt', 'r')
		h = f.read()
		f.close()

		decrypted_message = key.decrypt(ast.literal_eval(str(h)))##Decrypt the encrypted message
		l = len(m)
		x = m[2:l-1]
		hh = SHA256.new(x.encode('utf-8')).digest()

		if decrypted_message == hh:
		    print("Successful signing\n")
		else:
		    print("Temparing signing\n")
		now = time.time()
		print("It took: ", now-then, " seconds", "\n")

	else:
		print('Please, enter your message')
		message = input()
		print("==> SHA256 Hashed value of the message: ", SHA256.new(message.encode('utf-8')).hexdigest(), "\n")
		now = time.time()
		print("It took: ", now-then, " seconds", "\n\n")
