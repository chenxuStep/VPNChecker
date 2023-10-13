
from warnings import simplefilter
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
from tomorrow import threads
import socket
from OpenSSL import SSL
import pandas as pd
import ssl
import os
import sys
import dns.resolver
sys.path.append('')
simplefilter(action='ignore', category=FutureWarning)



class PacketHandler():
    def __init__(self):

        self.endtime = ''
        self.flags = ''
        self.payload = b''

    #Description: Extract information from packet
    #Input Parm: packet
    #Output: endtime,flags,payload

    def handle_pkt(self, pkt):
        self.flags = ''
        self.payload = b''
        # convert timestamp to human readable format
        self.endtime = datetime.fromtimestamp(pkt.time)
        if TCP in pkt:  
            self.flags = pkt[TCP].flags
            if Raw in pkt:
                self.payload = pkt[Raw].load


class vpn_probe_script():
    def __init__(self) -> None:
        pass

    #Description: CSV file write function
    #Input Parm: column, writePath
    #Output: CSV file        
    def csvWrite(self,column,writePath):        
        res = pd.DataFrame(columns=(column))
        res.to_csv(writePath,index=False,mode='a',encoding='utf8')  


    #Description: SSTP Probe
    #Input Parm: host, port, writePath
    #Output: Response          
    def sstp(self, host, port=443, writePath):

        request = 'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n' + \
            'Host: %s\r\n' % host + \
            'SSTPCORRELATIONID: {5a433238-8781-11e3-b2e4-4e6d617021}\r\n' + \
            'Content-Length: 18446744073709551615\r\n\r\n'

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        ssl_sock = ssl.wrap_socket(sock)

        try:
            # Connect to the server
            ssl_sock.connect((host, port))

            # Send the request
            ssl_sock.sendall(request.encode())

            # Receive the response
            response = ssl_sock.recv(4096).decode()
            # Check the response
            if 'HTTP/1.1 200' in response and '18446744073709551615' in response:
                self.csvWrite(
                    [host, port, 'success'], writePath)

        except socket.error as e:
            pass

        finally:
            ssl_sock.close()

    #Description: PPTP Probe
    #Input Parm: host, port 
    #Output: Response 

    def pptp(self, host, port=1723, writePath):
        payload = b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + \
            b"\x00\x01\x00\x00\x01\x00\x00\x00" + \
            b"\x00\x00\x00\x01\x00\x00\x00\x01" + \
            b"\xff\xff\x00\x01" + \
            b"\x6a\x6b\x6c\x6d" + \
            b"\x00" * 64 + \
            b"\x5a\x5b\x5c\x5d" + \
            b"\x00" * 64

        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        try:
            sock.connect((host, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            hex_str = ""
            for byte in response:
                hex_str += f"{byte:02x}"
            if hex_str.startswith("009c00011a2b3c4d"):
                self.csvWrite(
                    [host, port, 'success'], writePath)

        except socket.error as e:
            pass

        finally:
            sock.close()


    #Description: IPSec Probe
    #Input Parm: host, port 
    #Output: Response 

    def IPSec(self, host, port=500, writePath):
        InitiatorSPI = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        payload = InitiatorSPI + b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x0d\x00\x00\x5c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x50\x01\x01\x00\x02\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x00\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x0d\x00\x00\x18\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x04\x0d\x00\x00\x14\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x0d\x00\x00\x14\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f\x00\x00\x00\x14\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            if InitiatorSPI in response:
                self.csvWrite(
                    [host, port, 'success'], writePath)

        except BaseException as e:
            pass

        finally:
            sock.close()

    #Description: openvpnUDP Probe
    #Input Parm: host, port 
    #Output: Response 

    def openvpnUDP(self, host, port=1194, writePath):
        opcode = b'\x38'
        sessionID = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        MessageLen = b'\x00'
        MessageID = b'\x00\x00\x00'
        payload = opcode + sessionID + MessageLen + MessageID
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(5)
        try:
            sock.connect((host, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            response_hex = ''.join(f'{byte:02x}' for byte in response)

            if response_hex[:2] == '40' and response_hex[-8:] == '00000000':
                self.csvWrite([host,port,'openvpnUDP'], writePath)

        except BaseException as e:
            pass

        finally:
            sock.close()

    #Description: openvpnTCP Probe
    #Input Parm: host, port 
    #Output: Response 
        
    def openvpnTCP(self, host, port=1194, writePath):
        packetLen = b'\x00\x0e'
        opcode = b'\x38'
        sessionID = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        MessageLen = b'\x00'
        MessageID = b'\x00\x00\x00\x00'
        payload = packetLen + opcode + sessionID + MessageLen + MessageID

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(5)
        try:
            sock.connect((host, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            response_hex = ''.join(f'{byte:02x}' for byte in response)
            # print(response_hex)
            if response_hex[:6] == '001a40' and response_hex[-8:] == '00000000':
                self.csvWrite(
                    [host, port, 'success'], writePath)

        except BaseException as e:
            pass

        finally:
            sock.close()


    #Description:TCP_Probe_1
    #Input Parm: host, port, payload 
    #Output: Response
    
    def TCP_Probe_1(self, host, port, payload, writePath):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(300)
        try:
            sock.connect((host, port))
            sock.sendall(payload)
            response = sock.recv(4096)
            self.csvWrite(
                [host, port, response, payload], writePath)
        except:
            pass
    
    #Description:TCP_Probe_2
    #Input Parm: host, port, payload 
    #Output: Response
        
    def TCP_Probe_2(self, host, port, payload, pktNum=1, pktTimeout=300):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(300)
        handler = PacketHandler()
        try:
            sock.connect((host, port))
            startTime = datetime.now()
            filterStr = "host " + host
            sock.sendall(payload)
            sniff(filter=filterStr, prn=handler.handle_pkt,
                  count=pktNum, timeout=pktTimeout)
            time.sleep(1)
            return startTime, handler.endtime, handler.flags, handler.payload

        except BaseException as e:
            pass
        finally:
            sock.close()

    #Description: guess FIN/RST threshold
    #Input Parm: host, port, writePath, default minLength,  default maxLength,  threshold
    #Output: Response
    def guess_threshold(self, host, port, writePath, min_val=0, max_val=64, f='R'):
        while min_val <= max_val:
            mid_val = (min_val + max_val) // 2

            payload = os.urandom(mid_val)

            startTime, endTime, flags, response_payload = self.TCP_collect_flag_and_response(
                host, port, payload)
            self.csvWrite([host, len(payload), int(
                (endTime-startTime).total_seconds()), flags, response_payload], writePath)

            if f in flags:
                max_val = mid_val - 1
            else:
                min_val = mid_val + 1

        if max_val == 64 and min_val > max_val:
            return self.guess_RST_threshold(host, port, 65, 1500)

        return max_val+1


    #Description: TLS probe
    #Input Parm: writePath, host, port
    #Output: Response

    def TLS(self, writePath, host, port=443):
        try:
            sock = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), socket.socket(
                socket.AF_INET, socket.SOCK_STREAM))
            sock.settimeout(5)
            sock.connect((host, port))
            sock.do_handshake()
            self.csvWrite([host, 'success'], writePath)
        except BaseException as e:
            self.csvWrite([host, str(e)], writePath)
        finally:
            sock.close()

    #Description: HTTP probe
    #Input Parm: writePath, host, port
    #Output: Response
            
    def check_http(self,writePath,host, port=80):
        try:
            sock = socket.create_connection((host, port))
            request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
            sock.send(request.encode())
            response = sock.recv(1024)

            if "HTTP/1.1" in response.decode():
                self.csvWrite([host, 'success'], writePath)
            self.csvWrite([host, response], writePath)

        except socket.error as e:
            self.csvWrite([host, str(e)], writePath)
        finally:
            sock.close()

    #Description: SSH probe
    #Input Parm: writePath, host, port
    #Output: Response

    def check_ssh(self,writePath, host, port=22):
        try:

            sock = socket.create_connection((host, port), timeout=3)
            server_banner = sock.recv(1024).decode().strip()

            if server_banner.startswith('SSH-'):
                client_banner = server_banner + '\r\n'
                sock.send(client_banner.encode())
                self.csvWrite([host, 'success'], writePath)
            
            self.csvWrite([host, server_banner], writePath)
        except socket.error as e:
            self.csvWrite([host, str(e)], writePath)
        finally:
            sock.close()


    #Description: FTP probe
    #Input Parm: writePath, host, port
    #Output: Response
    def check_ftp(self, writePath, host, port=21):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))
            response = sock.recv(1024)
            if 'Response: 220' in response:
                self.csvWrite([host, 'success'], writePath)
            self.csvWrite([host, response], writePath)
        
        except Exception as e:
            self.csvWrite([host, str(e)], writePath)
        finally:
            sock.close()

    #Description: dns probe
    #Input Parm: writePath, host, port
    #Output: Response

    def check_dns(self, ip, writePath, domain="google.com"):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        try:
            answers = resolver.resolve(domain, "A")  # A record for domain
            if answers:
                self.csvWrite( [ip, "success"], writePath)
            self.csvWrite( [ip, answers], writePath)
        except Exception as e:
            self.csvWrite([ip, str(e)], writePath)
    
    

    #Description: GET CN
    #Input Parm: writePath, host, port
    #Output: Response
        
    def openssl_tls_scan(self,writePath, host, port=443):
        cmd = f'echo | openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -noout -issuer -text'
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True)
        output = result.stdout

        # Find issuer
        issuer_match = re.search(r'issuer=(.*)', output)
        issuer = issuer_match.group(1) if issuer_match else 'Not found'

        # Find Subject Alternative Name
        san_match = re.search(
            r'X509v3 Subject Alternative Name:\s*(.*)', output)
        domainList = re.findall(r'DNS:([a-zA-Z0-9.*-]*)', output)
        # san = san_match.group(1) if san_match else 'Not found'
        # Find Not Before and Not After

        not_before_match = re.search(r'Before: (.*) GMT', output)
        not_after_match = re.search(r'After : (.*) GMT', output)
        expired = True
        if not_before_match and not_after_match:
            not_before = datetime.strptime(
                not_before_match.group(1), '%b %d %H:%M:%S %Y')
            not_after = datetime.strptime(
                not_after_match.group(1), '%b %d %H:%M:%S %Y')

            now = datetime.now()
            if not_before <= now <= not_after:
                expired = False
            else:
                expired = True
        else:
            not_before = not_after = 'Not found'
            expired = True

        self.csvWrite([issuer, domainList, expired],  writePath)
