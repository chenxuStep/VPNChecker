'''
Description: 
Author: chenxu
Date: 2023-06-16 14:37:45
LastEditTime: 2023-08-20 10:59:30
LastEditors: chenxu
'''
import socket
from OpenSSL import SSL
import pandas as pd
import ssl
import os
import sys
import dns.resolver
sys.path.append('')
import Code.toolFunction as toolFunction
from tomorrow import threads
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
from warnings import simplefilter
simplefilter(action='ignore', category=FutureWarning)

#用户分析TCP响应包
class PacketHandler():
    def __init__(self):
        # self.df = pd.DataFrame(columns=['Time', 'Flags', 'Payload'])
        self.endtime = ''
        self.flags = ''
        self.payload = b''

    def handle_pkt(self, pkt):
        self.flags = ''
        self.payload = b''
        self.endtime = datetime.fromtimestamp(pkt.time) # convert timestamp to human readable format
        if TCP in pkt:  # 检查数据包是否包含TCP层
            self.flags = pkt[TCP].flags
            if Raw in pkt:  # 检查数据包是否包含Payload（Raw）
                self.payload = pkt[Raw].load
 
#一系列探测函数
class vpn_probe_script():
    def __init__(self) -> None:
        self.vpnProtocolPath = 'probeResult/vpnProtocol.csv'
        self.tcp_only_Response = ''
        self.custom_payload = {
            'TcpGeneric': b'\x0d\x0a\x0d\x0a',
            'OneZero': b'\x00',
            'OneZero': b'\x00\x00',
            'Epmd': b'\x00\x01\x6e',
            'ssh': b'SSH-2.0-OpenSSH_8.1/r/n',
            'http': b'GET/HTTP/1.0 /r /n /r /n',
            'chromeTlS': b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x16\x12\x32\x09\x64\x7f\x5f\x8b\x7c\x75\xaa\x61\xe8\x91\xd1\xbe\x51\x35\x69\xe4\x09\x8e\xd0\xae\x39\xfd\x68\x44\x0e\xb0\xcd\x5e\x20\x86\x2c\xa9\xe6\x1b\xb1\x5c\x0a\xef\x74\x04\x73\x03\x79\x84\x13\x0f\xf5\x01\xf1\xfc\x6a\x54\x1a\xfc\x28\x67\x1b\xd2\x09\xd4\x23\x00\x20\x9a\x9a\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x01\x00\x01\x93\xea\xea\x00\x00\xff\x01\x00\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x1b\x00\x03\x02\x00\x02\x00\x23\x00\x00\x00\x12\x00\x00\x00\x0d\x00\x12\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x00\x2b\x00\x07\x06\x3a\x3a\x03\x04\x03\x03\x00\x2d\x00\x02\x01\x01\x00\x33\x00\x2b\x00\x29\xea\xea\x00\x01\x00\x00\x1d\x00\x20\x92\x82\x55\x1b\x53\x86\x34\xd7\x26\x1c\x82\x1e\xf4\xce\xb5\x2c\x67\x99\x7c\x46\x01\x6a\x6d\x19\x15\x28\x43\x66\x83\xb6\x99\x6f\x00\x17\x00\x00\x44\x69\x00\x05\x00\x03\x02\x68\x32\x00\x0b\x00\x02\x01\x00\x00\x00\x00\x13\x00\x11\x00\x00\x0e\x65\x78\x61\x6D\x70\x6C\x65\x31\x32\x33\x2E\x63\x6F\x6D\x00\x0a\x00\x0a\x00\x08\xea\xea\x00\x1d\x00\x17\x00\x18\x9a\x9a\x00\x01\x00\x00\x15\x00\xc9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'    
        }
        self.popular_protocol_response = 'probeResult/popular_protocol_response.csv'



    @threads(100)
    def sstp(self,host, port=443):

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
                toolFunction.csvWrite([host,port,'sstp'],self.vpnProtocolPath)
            
        except socket.error as e:
            pass

        finally:
            ssl_sock.close()


    @threads(100)
    def pptp(self,host, port=1723):
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
            sock.connect((host, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            hex_str = ""
            for byte in response:
                hex_str += f"{byte:02x}"
            if hex_str.startswith("009c00011a2b3c4d"):
                toolFunction.csvWrite([host,port,'pptp'],self.vpnProtocolPath)
            
        except socket.error as e:
            pass

        finally:
            sock.close()
        

    @threads(100)
    def IPSec(self,host, port=500):
        InitiatorSPI = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'        
        payload = InitiatorSPI + b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x0d\x00\x00\x5c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x50\x01\x01\x00\x02\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x00\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x0d\x00\x00\x18\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x04\x0d\x00\x00\x14\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x0d\x00\x00\x14\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f\x00\x00\x00\x14\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))
            
            sock.sendall(payload)

            response = sock.recv(4096)
            
            if InitiatorSPI in response:
                toolFunction.csvWrite([host,port,'ipsec'],self.vpnProtocolPath)
                
        except BaseException as e:
            pass
        
        finally:
            sock.close()

    
    def openvpnUDP(self,host, port=1194):
        opcode = b'\x38' 
        sessionID = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        MessageLen = b'\x00'
        MessageID = b'\x00\x00\x00'
        payload = opcode + sessionID + MessageLen + MessageID 
        # response = b''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(5)
        try:
            sock.connect((host, port))
            
            sock.sendall(payload)

            response = sock.recv(4096)  
            

            response_hex = ''.join(f'{byte:02x}' for byte in response)
            
            if response_hex[:2] == '40' and response_hex[-8:] == '00000000':
                print(response_hex)
                # toolFunction.csvWrite([host,port,'openvpnUDP'],self.vpnProtocolPath)
            
        
        except BaseException as e:
            pass

        finally:
            sock.close()

    # @threads(100)
    def openvpnTCP(self,host, port=1194):
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
                toolFunction.csvWrite([host,port,'openvpnTCP'],self.vpnProtocolPath)
            
        except BaseException as e:
            pass
    
        finally:
            sock.close()


    def TCP_only_collect_response(self,host,port,payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(60)
        try:
            sock.connect((host, port)) 
            sock.sendall(payload)   
            response = sock.recv(4096) 
            toolFunction.csvWrite([host,port,response,payload],self.tcp_only_Response)
        except:
            pass

        
    def TCP_collect_flag_and_response(self,host,port,payload,pktNum=1,pktTimeout=300):    
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(300)
        handler = PacketHandler()    
        try:
            sock.connect((host, port))  
            startTime = datetime.now()
            filterStr = "host " + host    
            sock.sendall(payload)
            sniff(filter=filterStr, prn=handler.handle_pkt, count=pktNum,timeout=pktTimeout)   
            time.sleep(1)
            return startTime,handler.endtime,handler.flags,handler.payload
                
        except BaseException as e:       
            pass
        finally:
            sock.close()


    def guess_RST_threshold(self,host, port, min_val=0, max_val=64):
        while min_val <= max_val:
            mid_val = (min_val + max_val) // 2

            payload = os.urandom(mid_val)

            startTime, endTime, flags, response_payload = self.TCP_collect_flag_and_response(host, port, payload)
            toolFunction.csvWrite([host,len(payload),int((endTime-startTime).total_seconds()),flags,response_payload],'log.csv')        

            if 'R' in flags:
                max_val = mid_val - 1
            else: 
                min_val = mid_val + 1

        if max_val == 64 and min_val > max_val:
            return self.guess_RST_threshold(host, port, 65, 2048)

        return max_val+1


    @threads(100)
    def nmapTLS(ip,port):
        try:
            command =  f"nmap -p {port} --script ssl-cert {ip} -Pn --host-timeout=5"
            output = subprocess.check_output(command, shell=True)
            # print(output.decode('utf-8'))
            #提取SAN
            san_target = re.search( r"Subject Alternative Name:(.*?)\|", output.decode('utf-8'), re.DOTALL)
            sanList = re.findall(r"DNS:(.*?)(?:, |$)", san_target.group(1))
            # print(san_match)
            
            cn_pattern = r"Subject: CN=(.*?)(?:,|$)"
            cn_match = re.search(cn_pattern, output.decode('utf-8'))
            cn = cn_match.group(1)

            #提取有效期的开始时间和结束时间
            not_before_pattern = r"Not valid before: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
            not_after_pattern = r"Not valid after:  (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"

            not_before_match = re.search(not_before_pattern, output.decode('utf-8'))
            not_after_match = re.search(not_after_pattern, output.decode('utf-8'))

            not_before = datetime.datetime.strptime(not_before_match.group(1), "%Y-%m-%dT%H:%M:%S")
            not_after = datetime.datetime.strptime(not_after_match.group(1), "%Y-%m-%dT%H:%M:%S")
            
            flag = "invalid"
            if datetime.datetime.now()>=not_before and datetime.datetime.now()<=not_after:
                flag = "valid"
        

            write_clo =[ip,port,cn,sanList,flag]
            df = pd.DataFrame(columns=(write_clo))
            df.to_csv('/home/wangchenxu/gitlab/probe/TLS_zx.csv',line_terminator="\n",index=False,mode='a',encoding='utf8')
        
        except BaseException as e:
            pass


    def TLS_python(ip,port=443):
        # 建立一个 SSL 连接
        try:
            sock = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.do_handshake()        
            sock.close()
        except BaseException as e:
            print(e)
            pass


    def check_http(host, port=80):
        try:
            # 创建一个socket
            sock = socket.create_connection((host, port))

            # 创建一个HTTP GET请求
            request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
            
            # 发送HTTP请求
            sock.send(request.encode())

            # 接收响应
            response = sock.recv(1024)
            
            if "HTTP/1.1" in response.decode():            
                return True
            else:            
                return False
            
        except socket.error as e:        
            return False
        finally:
            sock.close()

 
    @threads(100)
    def nmap_port_scan(self,ip):
        command = f"nmap -sS --open {ip} -Pn -n"
        try:         
            result = (os.popen(command)).read()
            portList = list()   
            pattern = r"(\d+/tcp)\s+open(?=\s)"
            matches = re.findall(pattern, result)       
            if matches:
                for port in matches:
                    port = int(port.split('/tcp')[0])
                    portList.append(port)
                write_clo =[ip,portList]
                df = pd.DataFrame(columns=(write_clo))
                df.to_csv('nmapscan.csv',index=False,mode='a',encoding='utf8')
            else:
                toolFunction.write('nmap_no_response.txt',ip)
        except:
            toolFunction.write('nmap_no_response.txt',ip)


    def check_ssh(self,host, port=22):
        try:
            # 创建一个socket
            sock = socket.create_connection((host, port), timeout=3)

            # 接收服务器的SSH协议头
            server_banner = sock.recv(1024).decode().strip()
            print(f"Received: {server_banner}")

            if server_banner.startswith('SSH-'):
                # 发送一个相同的协议头回服务器
                client_banner = server_banner + '\r\n'
                sock.send(client_banner.encode())
                print(sock.recv(1024))
                return True
            else:            
                return False
        except socket.error as e:        
            return False
        finally:
            sock.close()


    def getPtrRecord(self,ip):
        try:
            n = dns.reversename.from_address(ip)
            domain = str(dns.resolver.resolve(n,"PTR")[0])
            return domain 
        except:
            pass


    def check_ftp(self,ip, port=21):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((ip, port))
            response = sock.recv(1024)
            if 'Response: 220' in response:
                return True
                
        except Exception as e:
            print(f'Error: {e}')
        finally:
            sock.close()

    @threads(500)
    def check_dns_support(self,ip, domain="google.com"):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        try:
            answers = resolver.resolve(domain, "A")  # A record for domain
            if answers:                
                toolFunction.csvWrite([ip,"success"],'probeResult/dnsProbe.csv')
                return
        except Exception as e:
            toolFunction.csvWrite([ip,str(e)],'probeResult/dnsProbe.csv')
            return
    
        toolFunction.csvWrite([ip,"Unknown error"],'probeResult/dnsProbe.csv')


    def openssl_tls_scan(self,host,port=443):
        cmd = f'echo | openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -noout -issuer -text'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout
        
        # Find issuer
        issuer_match = re.search(r'issuer=(.*)', output)
        issuer = issuer_match.group(1) if issuer_match else 'Not found'

        # Find Subject Alternative Name
        san_match = re.search(r'X509v3 Subject Alternative Name:\s*(.*)', output)
        domainList = re.findall(r'DNS:([a-zA-Z0-9.*-]*)', output)
        # san = san_match.group(1) if san_match else 'Not found'    
        # Find Not Before and Not After

        not_before_match = re.search(r'Before: (.*) GMT', output)
        not_after_match = re.search(r'After : (.*) GMT', output)    
        expired = True
        if not_before_match and not_after_match:
            not_before = datetime.strptime(not_before_match.group(1), '%b %d %H:%M:%S %Y')
            not_after = datetime.strptime(not_after_match.group(1), '%b %d %H:%M:%S %Y')
            
            now = datetime.now()
            if not_before <= now <= not_after:
                expired = False
            else:
                expired = True
        else:
            not_before = not_after = 'Not found'
            expired = True
        
        toolFunction.csvWrite([ issuer, domainList,expired],'probeResult/openssl_CA.csv')        


    def Tcp_time(self,ip):
        portList = [443,80,1194,22,554,21,23]
        for port in portList:
            self.guess_RST_threshold(ip,port)
        
    


vpn_probe_script  = vpn_probe_script()
vpn_probe_script.openvpnUDP('185.159.159.148',443)