# import libraries
import os
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
import zlib
import filetype

# Pad object, blockes are padded with the character "{"
pad_obj = "{"

# ****************AES functions***************************

# Pad function, calculates the number of padding characters need
# 	appends the characters to the block
def pad(s, block_size):
	mod_func = len(s) % block_size
	padding = s + (block_size - mod_func) * pad_obj
	return padding

# Unpad function, removes the additional padded characters 
def unpad(s):
	pad_index = s.find(pad_obj)
	res = s[:pad_index]
	return res

# Hash function, takes the entered password and produces a hash value using SHA256
# 	the key is then extracted from the generated hash
def hashing_pass():
	password = input("Please enter the password: ")
	hash_object = SHA256.new(password.encode('utf-8'))
	key = hash_object.digest()
	return key

# Enryption function
def encrypt_aes():
	#Size of each block in the AES encryption/decryption process, 16-byte
	block_size = AES.block_size
	# generate random IV of length 16-byte
	iv = os.urandom(block_size)

	#load files 
	loop = True
	while loop: 
		try: 
			file1 = input("[Enc AES] Please enter the plain-text filename: ")
			file1 = file1.strip()
			pt_file = open(file1, "r")
		except Exception as e:
			print(e)
		else: 
			# assign the mesaage in the pt text file
			# end loop
			msg = pt_file.read()
			loop = False	

	#save to a existing file if exists, else create a new file
	file2 = input("[Enc AES] Please enter the cipher-text file name: ")
	file2 = file2.strip()
	ct_file = open(file2, "w")

	# generating the key using the SHA256 hash function
	key = hashing_pass()

	# create cipher config
	ciph = AES.new(key, AES.MODE_CBC, iv)

	# pad the message and create cipher text
	cipher_text = ciph.encrypt(pad(msg, block_size).encode('utf-8'))

	# convert from bytes to hex and store in the ct text file
	ct_file.write(cipher_text.hex() + "\n" + iv.hex())

	# show process completed
	print("success")

	# close the loaded files
	pt_file.close()
	ct_file.close()

# decryption function
def decrypt_aes():
	# load files 
	loop  = True
	while loop:
		try: 	
			file1 = input("[Dec AES] Please enter the cipher-text filename: ")
			file1 = file1.strip()
			ct_file = open(file1, "r")
			lines = ct_file.readlines()
		except Exception as e:
			print(e)
		else:
			loop = False

	# convert data from hex to byte
	iv = bytes.fromhex(lines[1])
	msg = bytes.fromhex(lines[0])

	#save to a existing file if exists, else create a new file
	file2 = input("[Dec AES] Please enter the plain-text file name: ")
	file2 = file2.strip()
	pt_file = open(file2, "w")

	loop = True
	while loop:
		try:
			# generate the key using the SHA256 hash function
			key = hashing_pass()
			# create decryption config
			deciph = AES.new(key, AES.MODE_CBC, iv)
			# create plain text from the cipher 
			plain = deciph.decrypt(msg).decode('utf-8')
		except Exception as e:
			print("Wrong password, please try again")
		else:
			loop = False
	# unpad the decrypted message
	res = unpad(plain)

	# write the decrypted message to the pt text file 
	pt_file.write(res)

	# show process completd
	print("success")

	# close loaded files
	pt_file.close()
	ct_file.close()

# integrity check function
def int_check_aes():

	# load ciphertext file
	loop  = True
	while loop:
		try:
			file1 = input("[Int -check] Please enter the cipher-text filename: ")
			file1 = file1.strip()
			ct_file = open(file1, "r")
			lines = ct_file.readlines()
		except Exception as e:
			print(e)
		else:
			loop = False
	

	# convert data from hex to byte
	iv = bytes.fromhex(lines[1])
	msg = bytes.fromhex(lines[0])

	# load hash file
	loop = True
	while loop:
		try: 
			file2 = input("[Int -check] Please enter the hash filename: ")
			file2 = file2.strip()
			hash_file = open(file2, "r")
			hash_file_data = hash_file.read()
		except Exception as e: 
			print(e)
		else: 
			loop = False

	# generate key from password
	loop = True
	while loop:
		try:
			# generate the key using the SHA256 hash function
			key = hashing_pass()
			# create decryption config
			deciph = AES.new(key, AES.MODE_CBC, iv)
			# create plain text from the cipher 
			plain = deciph.decrypt(msg).decode('utf-8')
		except Exception as e:
			print("Wrong password, please try again")
		else:
			loop = False


	# unpad
	unpadded_plain = unpad(plain)

	# generate sha256 hash value for the decrypted text
	hash_obj = SHA256.new(unpadded_plain.encode('utf-8'))
	hash_output = hash_obj.hexdigest()

	# integrity check, comparing the generated hash value with the one provided
	# 	results: 1 = match, 0 = do not match
	if hash_output == hash_file_data:
		print(1)
	else: 
		print(0)

	# close loaded files
	ct_file.close()
	hash_file.close()

# ********************PKCs functions******************************
# key generation function
def rsa_keys():
	#Generate a public/ private key pair using 2048 bits key length
	random_generator = Random.new().read
	key = RSA.generate(2048, random_generator)
	private_k = key.exportKey("PEM")
	public_k = key.publickey().exportKey("PEM")

	file = open("public.pem", "wb")
	file.write(public_k)
	file.close()

	file = open("private.pem", "wb")
	file.write(private_k)
	file.close() 

# encryption function
def enc_pkc():
	# public_key, private_key = rsa_keys()
	
	# load file to be encrypted
	loop = True
	while loop: 
		try: 
			filename = input("[Enc PKC] Please enter the filename for encryption: ")
			file = filename.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			msg = file.read()
			file.close()
			loop = False


	loop = True
	while loop: 
		try: 
			file = input("[Enc PKC] Please enter the Public Key: ")
			file = file.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# end loop
			pub_key= file.read()
			file.close()
			loop = False

	msg = zlib.compress(msg)
	
	
	pub_key = PKCS1_OAEP.new(RSA.importKey(pub_key))
	# 2048 bits = 256 bytes, 256 - 42  = 214 (required for PKCS1_OAEP)
	packet_size = 214
	init_position = 0 
	loop = True
	encrypted_msg = b''
	
	loop = True
	while loop:
		packet = msg[init_position: init_position + packet_size]
		
		if len(packet) % packet_size != 0:
			loop = False
			packet+= " ".encode('utf-8') * (packet_size - len(packet))

		encrypted_msg+= pub_key.encrypt(packet)

		# reposition the pointer to the end of the previous packet
		init_position+= packet_size

	text = ""
	elem = 0
	while filename[elem] != ".":
		text+= filename[elem]
		elem+= 1

	text = text + ".enc"
	# save the encrypted massage to local file
	file = open(text, "wb")
	file.write(encrypted_msg)
	file.close()

	print("Successfully completed") 

# decryption function
def dec_pkc():

	loop = True
	while loop: 
		try: 
			filename = input("[Enc PKC] Please enter the filename for decryption: ")
			file = filename.strip()
			if filename[-3:] != 'enc':
				raise Exception("Please select a file with '.enc' format")
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			msg = file.read()
			file.close()
			loop = False

	loop = True
	while loop: 
		try: 
			file = input("[Dec PKC] Please enter the Private Key:  ")
			file = file.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			prv_key = file.read()
			file.close()
			loop = False

	prv_key = PKCS1_OAEP.new(RSA.importKey(prv_key))

	packet_size = 256
	init_position = 0 
	decrypted_msg = b''

	while init_position < len(msg):
		packet = msg[init_position: init_position + packet_size]
		

		decrypted_msg+= prv_key.decrypt(packet)

		# set the init value to the end of the previous packet
		init_position+= packet_size
	decrypted_msg = zlib.decompress(decrypted_msg)

	kind = filetype.guess(decrypted_msg)

	text = ""
	elem = 0
	while filename[elem] != ".":
		text+= filename[elem]
		elem+= 1

	title = "dec-" + text + "." + kind.extension

	# save the decrypted massage to local file
	file = open(title, "wb")
	file.write(decrypted_msg)
	file.close()

	print("Successfully completed")
	# print(decrypted_msg)


# digital sign function
def ds_pkc():
	
	loop = True
	while loop: 
		try: 
			filename = input("[DS PKC] Please enter the filename of Digital Sign: ")
			file = filename.strip()
			if filename[-3:] != 'enc':
				raise Exception("Please select a file with '.ds' format")
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			msg = file.read()
			file.close()
			loop = False

	text = ""
	elem = 0
	while filename[elem] != ".":
		text+= filename[elem]
		elem+= 1

	text+= '.ds' 

	loop = True
	while loop: 
		try: 
			filename = input("[DS PKC] Please enter the Private Key filename: ")
			file = filename.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			prv_key = file.read()
			file.close()
			loop = False

	sig = PKCS1_v1_5.new(RSA.importKey(prv_key))

	hash_obj = SHA256.new(msg)
	ds = sig.sign(hash_obj)

	# save the encrypted massage to local file
	file = open(text, "wb")
	file.write(ds)
	file.close()

	print("Successfully completed") 


# verification function ofr digital sign
def ver_pkc():
	loop = True
	while loop: 
		try: 
			prv_filename = input("[Ver PKC] Please enter the Digital Sign filename: ")
			file = prv_filename.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			signature = file.read()
			file.close()
			loop = False


	loop = True
	while loop: 
		try: 
			prv_filename = input("[Ver PKC] Please enter the Verification filename: ")
			file = prv_filename.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			msg = file.read()
			file.close()
			loop = False


	loop = True
	while loop: 
		try: 
			prv_filename = input("[Ver PKC] Please enter the Public Key filename: ")
			file = prv_filename.strip()
			file= open(file, "rb")
		except Exception as e:
			print(e)
		else: 
			# assign the content of the entere file to messsage (msg)
			# end loop
			pub_key = file.read()
			file.close()
			loop = False

	sig = PKCS1_v1_5.new(RSA.importKey(pub_key))
	hash_obj = SHA256.new(msg)

	verific = sig.verify(hash_obj, signature)

	if verific == True:
		print(1, " [Valid]")
	else:
		print(0, " [Invalid]")

# ***********************User menu functions**************************
# main menu
def mode_select(): 
	text = '''\nWelcome to the Cryptographic toolbox.
	Please choose one of the following modes by typing:
	'aes' for Symmetric AES cryptography
	'pkc' for Assymetric RSA cryptography 
	'exit' to exit\n >>> '''

	try: 
		mode = input(text).strip().lower()	
	except Exception as e:
		print(e)
	else:
		if mode == "aes":
			aes()
			main()
		elif mode == "pkc":
			rsa_keys()
			pkc()
			main()
		elif mode == "exit":
			print('Exited')
			sys.exit()
		else:
			print("\nError: Invalid command, please enter a valid command")
			mode_select()

# aes cryptography functions
def aes():
	text = '''\n[AES Mode] Please type: 
	'enc aes' for encryption 
	'dec aes' for decryption 
	'int -check' for integrity check
	'main' to go to the main menu\n >>> '''

	try: 
		task = input(text).strip().lower()	
	except Exception as e:
		print(e)
	else:
		if task == "enc aes":
			encrypt_aes()
			aes()
		elif task == "dec aes":
			decrypt_aes()
			aes()
		elif task == "int -check":
			int_check_aes()
			aes()
		elif task == "main":
			main()
		else:
			print("\nError: Invalid command, please enter a valid command")
			aes()

# pkc cryptography functions
def pkc():
	text = '''\n[PKC Mode] Please type: 
	'enc' for encryption 
	'dec' for decryption 
	'ds' for creating digital signature
	'verify' for veryfying a document
	'main' to go to the main menu\n >>> '''

	try: 
		task = input(text).strip().lower()	
	except Exception as e:
		print(e)
	else:
		if task == "enc":
			enc_pkc()
			pkc()
		elif task == "dec":
			dec_pkc()
			pkc()
		elif task == "ds":
			ds_pkc()
			pkc()
		elif task == "verify":
			ver_pkc()
			pkc()
		elif task == "main":
			main()
		elif task == "exit":
			print("Exited")
		else:
			print("\nError: Invalid command, please enter a valid command")
			pkc()

# main function
def main(): 
	mode_select()


#call the main funciton 
main()