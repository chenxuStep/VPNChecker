import socket
from OpenSSL import SSL
import pandas as pd
import ssl
import sys
import dns.resolver
sys.path.append('')
import  toolFunction
from scapy.all import *
from warnings import simplefilter
simplefilter(action='ignore', category=FutureWarning)


class application_layer_probes():
    
    def __init__(self) -> None:
        self.filePath = 'data/application_layer_probing_res/'
    
    '''
    Description: Collect the SSTP response from the specified IP address
    Param : ip and prot
    Return: response
    '''    
    def sstp_probe(self,ip, port=443):

        request = 'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n' + \
            'Host: %s\r\n' % ip + \
            'SSTPCORRELATIONID: {5a433238-8781-11e3-b2e4-4e6d617021}\r\n' + \
            'Content-Length: 18446744073709551615\r\n\r\n'

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        ssl_sock = ssl.wrap_socket(sock)

        try:            
            ssl_sock.connect((ip, port))

            # Send the request
            ssl_sock.sendall(request.encode())

            # Receive the response
            response = ssl_sock.recv(4096).decode()
            # Check the response
            if 'HTTP/1.1 200' in response and '18446744073709551615' in response:
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'sstp.csv')
                return
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,response],self.filePath+'sstp.csv')
            
        except socket.error as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'sstp.csv')
        finally:
            sock.close()


    '''
    Description: Collect the PPTP response from the specified IP address
    Param : ip and prot
    Return: response
    ''' 
    def pptp_probe(self,ip, port=1723):
        payload = b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + \
            b"\x00\x01\x00\x00\x01\x00\x00\x00" + \
            b"\x00\x00\x00\x01\x00\x00\x00\x01" + \
            b"\xff\xff\x00\x01" + \
            b"\x6a\x6b\x6c\x6d" + \
            b"\x00" *64 + \
            b"\x5a\x5b\x5c\x5d" + \
            b"\x00" *64 
        
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        try:
            sock.connect((ip, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            hex_str = ""
            for byte in response:
                hex_str += f"{byte:02x}"
            if hex_str.startswith("009c00011a2b3c4d"):
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'pptp.csv')
                return
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,response],self.filePath+'pptp.csv')            
            
        except socket.error as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'pptp.csv')            
        finally:
            sock.close()


    '''
    Description: Collect the IPSec response from the specified IP address
    Param : ip and prot
    Return: response
    ''' 
    def ipsec_probe(self,ip, port=500):
        InitiatorSPI = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'        
        payload = InitiatorSPI + b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x0d\x00\x00\x5c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x50\x01\x01\x00\x02\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x00\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x0d\x00\x00\x18\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x04\x0d\x00\x00\x14\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x0d\x00\x00\x14\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f\x00\x00\x00\x14\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.connect((ip, port))
            
            sock.sendall(payload)

            response = sock.recv(4096)
            
            if InitiatorSPI in response: 
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'ipsec.csv')
                return                                        
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,response],self.filePath+'ipsec.csv')                                        
            
        except socket.error as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'ipsec.csv')                        
        finally:
            sock.close()
    
    '''
    Description: Collect the openVPN_UDP response from the specified IP address
    Param : ip and prot
    Return: response
    ''' 
    def openvpnUDP_probe(self,ip, port=1194):
        opcode = b'\x38' 
        sessionID = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        MessageLen = b'\x00'
        MessageID = b'\x00\x00\x00'
        payload = opcode + sessionID + MessageLen + MessageID 
        # print(payload)
        # response = b''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(5)
        try:
            sock.connect((ip, port))
            
            sock.sendall(payload)

            response = sock.recv(4096)  
            
            response_hex = ''.join(f'{byte:02x}' for byte in response)
            
            if response_hex[:2] == '40' and response_hex[-8:] == '00000000':                
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'/openvpnUDP.csv')
                return 
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,response],self.filePath+'/openvpnUDP.csv')
            
        except socket.error as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/openvpnUDP.csv')
        finally:
            sock.close()


    '''
    Description: Collect the openVPN_TCP response from the specified IP address
    Param : ip and prot
    Return: response
    '''
    def openvpnTCP_probe(self,ip, port=1194):
        packetLen = b'\x00\x0e'
        opcode = b'\x38' 
        sessionID = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        MessageLen = b'\x00'
        MessageID = b'\x00\x00\x00\x00'
        payload = packetLen + opcode + sessionID + MessageLen + MessageID 
    
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(5)
        try:
            sock.connect((ip, port))
            
            sock.sendall(payload)

            response = sock.recv(4096)  
        
            response_hex = ''.join(f'{byte:02x}' for byte in response)
            # print(response_hex)
            if response_hex[:6] == '001a40' and response_hex[-8:] == '00000000':
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'/openvpnTCP.csv')
                return
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,response],self.filePath+'/openvpnTCP.csv')
            
        except socket.error as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/openvpnTCP.csv')
        finally:
            sock.close()


    '''
    Description: Collect the tls response from the specified IP address
    Param : ip and prot
    Return: response
    '''
    def tls_probe(self,ip,port=443):   
        sock = None 
        try:
            sock = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.do_handshake()   
            toolFunction.csvWrite([ip,port,'success'],self.filePath+'/tls.csv')                          
        except Exception as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/tls.csv')
        finally:
            if sock is not None: 
                sock.close()
     
        
    
    '''
    Description: Collect the http response from the specified IP address
    Param : ip and prot
    Return: response
    '''
    def http_probe(self,ip, port=80):
        sock = None
        try:            
            sock = socket.create_connection((ip, port))
        
            request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip)
            
            sock.send(request.encode())

            response = sock.recv(1024)            
            if "HTTP/1.1" in response.decode():            
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'/http.csv')
                return
            # response = response.replace('\r', '').replace('\n', '')
            
            toolFunction.csvWrite([ip,port,response],self.filePath+'/http.csv')
            
        except socket.error as e:        
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/http.csv')
        finally:
            if sock is not None: 
                sock.close()


    '''
    Description: Collect the ssh response from the specified IP address
    Param : ip and prot
    Return: response
    '''
    def ssh_probe(self,ip, port=22):
        sock = None
        try:            
            sock = socket.create_connection((ip, port), timeout=3)
            
            server_banner = sock.recv(1024).decode().strip()

            if server_banner.startswith('SSH-'):
                # client_banner = server_banner + '\r\n'
                # sock.send(client_banner.encode())
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'/ssh.csv')
                return                
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,server_banner],self.filePath+'/ssh.csv')
        
        except socket.error as e:        
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/ssh.csv')
        finally:
            if sock is not None: 
                sock.close()


    '''
    Description: Collect the ftp response from the specified IP address
    Param : ip and prot
    Return: response
    '''
    def ftp_probe(self,ip, port=21):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((ip, port))
            response = sock.recv(1024)
            if 'Response: 220' in response:
                toolFunction.csvWrite([ip,port,'success'],self.filePath+'/ftp.csv')
                return
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,response],self.filePath+'/ftp.csv') 
                     
        except socket.error as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/ftp.csv')                
        finally:
            sock.close()
            


    '''
    Description: Collect the dns response from the specified IP address
    Param : ip and prot
    Return: response
    '''
    def dns_probe(self,ip,port=53, domain="google.com"):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.nameservers = [ip]
        try:
            answers = resolver.resolve(domain, "A")  # A record for domain
            # response = response.decode('utf-8').split('\n')
            toolFunction.csvWrite([ip,port,answers],self.filePath+'/dns.csv')                          

        except Exception as e:
            toolFunction.csvWrite([ip,port,str(e)],self.filePath+'/dns.csv')
            return
