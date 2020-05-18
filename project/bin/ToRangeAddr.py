import sys;

ip = sys.argv[1]

bytes = ip.split(".")

final = bytes[0] + '.' + bytes[1] + '.' + bytes[2] + '.' + "0-255"

print(final)
