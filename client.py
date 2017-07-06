import socket
import elgamal as elg
from Crypto.Cipher import AES
import struct


HOST, PORT = "localhost", 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
padding = '{'
#adds padding to data sent under AES encryption
#so that it is always a multiple of 32
pad = lambda x: x + (32 - len(x) % 32) * padding

try:
    #kicks off elgamal by generating public
    #and private keys from a 256 prime number.
    #the public key is sent to the server and 
    #we wait for an aes key
    pubKey, privKey = elg.p1getKeys(256)
    sock.connect((HOST, PORT))
    sock.sendall(bytes('%d\n' % pubKey.p + '%d\n' % pubKey.g + '%d' % pubKey.x))
    print('1')
    #serKey = str(sock.recv(1024)).strip()
    #encKey = str(sock.recv(1024)).strip()
    serKey = sock.recv(1024)
    encKey = sock.recv(1024)


    #after receiving the key we can convert it back to 
    #its original form and begin communicated via aes with
    #the server
    print('2')
    aesInt = elg.decrypt(int(serKey), privKey, int(encKey), pubKey.p)
    aesHex = "%08x" % aesInt
    aesKey = aesHex.strip().decode('hex')
    print('3')
    obj = AES.new(aesKey, AES.MODE_CFB, 'This is an IV456')
    message = 'hey whats up?'
    ciphertext = obj.encrypt(pad(message))
    print 
    print 'plaintext: ' + message
    sock.sendall(bytes(ciphertext))
    print 'sent:      ' + ciphertext
    reply = str(sock.recv(1024)).strip()
    print 
    print 'received:  ' + reply
    print 'plaintext: ' + obj.decrypt(reply).rstrip(padding)


finally:
    sock.close()

