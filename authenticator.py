#!/bin/python
#2024-10-06 Erik Johnson - EkriirkE
#Read AndOTP backup JSON, display codes.  Press prefex to get scannable QR
import json
import pyotp
import time
import os
import threading
import readchar
import urllib

running=True
if 1:	#Encrypted backup
	import getpass
	import hashlib
	from Crypto.Cipher import AES

	with open("authenticator.json.aes","rb") as f:data=f.read()
	iter=int.from_bytes(data[:4],"big")
	salt=data[4:16]
	iv=data[16:28]
	tag=data[-16:]
	while running:
		passw=getpass.getpass().encode()
		key=hashlib.pbkdf2_hmac("sha1",passw,salt,iter,32)
		aes=AES.new(key,AES.MODE_GCM,nonce=iv)
		try:
			auth=json.loads(aes.decrypt_and_verify(data[28:-16],tag))
			break
		except Exception as e:print(e)
else:	#Plaintext backup
	with open("authenticator.json","r") as f:auth=json.load(f)

def thread_keys():
	global running,sleep
	while running:
		try:
			c=readchar.readchar()
			if c in (readchar.key.ESC,"\x03"):running=False
		except:break
		i=keys.find(c)
		if 0<=i<len(auth):
			url=f"otpauth://totp/{urllib.parse.quote(auth[i]['label'])}?secret={auth[i]['secret']}&issuer={auth[i]['issuer']}"
			os.system(f'qrencode -o- -d 300 -s 10 "{url}" | display &')
	running=False
	sleep.set()
thr=threading.Thread(target=thread_keys)
thr.start()
sleep=threading.Event()

keys="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
while running:
	os.system("clear")
	i=0
	for a in auth:
		otp=pyotp.TOTP(a["secret"])
		print(f"{keys[i]}\t{a['issuer']:>20}\t{otp.now()}\t{a['label']}")
		i+=1
	print()
	while running:
		t=59-time.localtime().tm_sec
		print(f"\rNext refresh in {t}...  ",end="")
		#time.sleep(1)
		sleep.wait(1)
		if not t:break

os.system("clear")
running=False
