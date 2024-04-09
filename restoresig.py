#!/usr/bin/env python3

f = ""
try:
	f = open('debug.dmp', 'rb')
except FileNotFoundError:
    print("Can't find dump file. Is it in the same directory?")
    exit()
    
full_data = f.read()
f.close()
	
valid_signature = bytes([0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00]) # The bytes for a valid minidump signature
restored = valid_signature + full_data[8:] # Restore corrupted bytes to valid minidump signature

with open('debug.dmp', 'wb') as f: # Write readable data
    f.write(restored)

print("File signature restored. Try opening it with Mimikatz now :)")