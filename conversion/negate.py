import sys

def hexxor(a, b):    # xor two hex strings of the same length
    return "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(a, b)])

a = 'fffffffe'
b = sys.argv[1]

print(hexxor(a,b))
