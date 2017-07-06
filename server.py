import SocketServer
import elgamal as elg
from Crypto.Cipher import AES
import os

padding = '{'
#adds padding to data sent under AES encryption
#so that it is always a multiple of 32
pad = lambda x: x + (32 - len(x) % 32) * padding

class MyTCPHandler(SocketServer.BaseRequestHandler):
    
    #handles clients connecting to the server. after receiving a 
    #public key from a client the appropriate keys will be generated
    #on our end and an encrypted aes key will be sent to them
    def handle(self):        
        self.data = self.request.recv(1024).strip()
        print (self.data)
        print('1')
        pubKey, aesKey, encKey = createKeys(self.data)
        print pubKey
        print aesKey
        print encKey
        self.request.sendall('%d' % pubKey)
        self.request.sendall('%d' % encKey)
        print('2')
        #we have sent all information necessary for
        #and now are waiting for an aes encrypted message
        self.data = self.request.recv(1024).strip()    
        print 
        print 'received:  ' + self.data
        obj = AES.new(aesKey, AES.MODE_CFB, 'This is an IV456')
        print 'plaintext: ' + obj.decrypt(self.data).rstrip(padding)
        message = 'yo yo yo hows it going?'
        ciphertext = obj.encrypt(pad(message))
        self.request.sendall(ciphertext)
        print 
        print 'plaintext: ' + message
        print 'sent:      ' + ciphertext

#uses public key from client to generate a public 
#and private keys. An AES key is also generated and
#converted to an in so that it can be easily encrypted 
#with elgamal
def createKeys(data):   
    cliKey, myKey, pubKey = elg.p2getKeys(data.split())
    aesKey = os.urandom(16)
    aesInt = int(aesKey.encode('hex'), 16)
    encKey = elg.encrypt(cliKey.x, myKey, aesInt, cliKey.p)
    return pubKey, aesKey, encKey

#etablishes client socket
if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
    server.serve_forever()

    