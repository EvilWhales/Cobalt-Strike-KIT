import sys

xor_key_list = [0x86]

def xor(data, key):

	return bytes(bytearray((
	    (data[i] ^ key for i in range(0,len(data))
	))))
    

if(len(sys.argv) != 2):
	print("Usage: " + str(sys.argv[0]) + "  <filename to encrypt>") 
	exit()

with open(str(sys.argv[1]), "rb") as shellcodeFileHandle:
    shellcodeBytes = bytearray(shellcodeFileHandle.read())
transformedShellcode = shellcodeBytes


for each_key in xor_key_list:
    transformedShellcode = xor(transformedShellcode, each_key)

with open("result.bin", "wb") as shellcodeFileHandle:
    shellcodeFileHandle.write(transformedShellcode)
    
