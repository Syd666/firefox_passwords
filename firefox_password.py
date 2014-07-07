# Windows firefox password recovery tool.
# Author : Aditya Sharma

from ctypes import *
import ctypes
import struct
import sys
import os
import glob
import re
import time
import base64
import getpass
import getopt
import os
import csv


firefox = r'C:\Program Files (x86)\Mozilla Firefox'
os.environ['PATH'] = ';'.join([firefox, os.environ['PATH']])
libnss = ctypes.CDLL(os.path.join(firefox, 'nss3.dll'))

#create password structs

class SECItem(Structure):
	_field = [('type', c_uint), ('data', c_void_p), ('len', c_uint)]

class secuPWData(Structure):
	_fields_ = [('source',c_ubyte),('data',c_char_p)]

(SECWouldBlock,SECFailure,SECSuccess)=(-2,-1,0)
(PW_NONE,PW_FROMFILE,PW_PLAINTEXT,PW_EXTERNAL)=(0,1,2,3)

#load nss dll
def getpass():
	path = find_path_to_dir()
	firefox = r'C:\Program Files (x86)\Mozilla Firefox'
	os.environ['PATH'] = ';'.join([firefox, os.environ['PATH']])
	libnss = ctypes.CDLL(os.path.join(firefox, 'nss3.dll'))
	libnss.PK11_GetInternalKeySlot.restype=c_void_p
	libnss.PK11_CheckUserPassword.argtypes=[c_void_p, c_char_p]
	libnss.PK11_Authenticate.argtypes=[c_void_p, c_int, c_void_p]

	pwdata = secuPWData()
	pwdata.source = PW_NONE
	pwdata.data=0
		
	uname = SECItem()
	passwd = SECItem()
	dectext = SECItem()

	for user in path:
			signonfiles = glob.glob(user+os.sep+"signons*.*")
			for signonfile in signonfiles:
					(filepath,filename) = os.path.split(signonfile)
					filetype = re.findall('\.(.*)',filename)[0]
					if filetype.lower() == "sqlite":
							readDB(filepath,filename)
					else:
							print "Unhandled Signons File: %s" % filename
							print "---Skipping---"


def readDB(dbpath, dbname):
	
	if libnss.NSS_Init(dbpath)!=0:
		print "Error Initalizing NSS_Init,\n"
		

	

	keySlot = libnss.PK11_GetInternalKeySlot()
	#use getpass() to get password if master password has been set
	libnss.PK11_CheckUserPassword(keySlot,"")
	libnss.PK11_Authenticate(keySlot, True, 0)

	import sqlite3
	conn = sqlite3.connect(dbpath+os.sep+dbname)
	c = conn.cursor()
	c.execute("SELECT * FROM moz_logins;");fh = open('passwords.csv', 'w')
	#csv handle to a file
		
	for row in c:
		writer = csv.writer(fh)
		string = ["Site:"] + str(row[1]) + " ";
		uname.data  = cast(c_char_p(base64.b64decode(row[6])),c_void_p)
		uname.len = len(base64.b64decode(row[6]));
		passwd.data = cast(c_char_p(base64.b64decode(row[7])),c_void_p)
		passwd.len=len(base64.b64decode(row[7]))
		if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
			errorlog(row,userpath+os.sep+dbname)
		string = string + ["Username: "] + [string_at(dectext.data,dectext.len)] + " "
		if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
		    errorlog(row,userpath+os.sep+dbname)
		string = string + ["Password:"] + [string_at(dectext.data,dectext.len)]
		writer.writerow(string)
	c.close()
	conn.close()
	libnss.NSS_Shutdown()
		
def errorlog(row,path):
	fh = open('error.log','w')
	fh.write(libnss.PORT_GetError())
	fh.write("\nSite:  %s"%row[1])
	fh.write("\nUsername: %s"%row[6])
	fh.write("\nPassword: %s \n" %row[7])
	fh.write("-----END-----")
	fh.close()
		
def find_path_to_dir():
	appdata = os.getenv("APPDATA")
	dir = appdata + os.sep + "/Mozilla/Firefox/Profiles/"
	listdir = os.listdir(dir)
	res = []
	for user in listdir:
		if os.path.isdir(dir + os.sep + user):
			res.append(dir + os.sep + user)
	return res
def main():
	
	getpass()

if __name__ == "__main__":
	main()
	
