
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
import toolFunction
sys.path.append('')
simplefilter(action='ignore', category=FutureWarning)


class responseType():

    def dnsResponce():
        dnsData = pd.read_csv(r'sourceData\probe\res_dns.csv', names=[
                              'ip', 'protocol', 'res'])

        for index, row in dnsData.iterrows():
            if 'All nameservers failed to answer' in row['res']:
                row['res'] = 'failed to answer'
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 0], r'processData\responseType.csv')
            elif 'The resolution lifetime expired' in row['res']:
                row['res'] = 'timed out'
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 1], r'processData\responseType.csv')
            elif 'success' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 2], r'processData\responseType.csv')
            elif 'The DNS response does not contain an answer to the question' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 3], r'processData\responseType.csv')
            elif 'The DNS query name does not exist' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 4], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 5], r'processData\responseType.csv')

    def ftpResponce():
        dnsData = pd.read_csv(r'sourceData\probe\res_ftp.csv', names=[
                              'ip', 'protocol', 'res'])

        for index, row in dnsData.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 0], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 1], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 2], r'processData\responseType.csv')
            elif '220' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 3], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 4], r'processData\responseType.csv')
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 5], r'processData\responseType.csv')
            elif '421' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 6], r'processData\responseType.csv')
            elif '[Errno 101] Network is unreachable' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 7], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 8], r'processData\responseType.csv')

    def httpResponce():
        dnsData = pd.read_csv(r'sourceData\probe\res_http.csv', names=[
                              'ip', 'protocol', 'res'])

        for index, row in dnsData.iterrows():
            if 'HTTP/1.1' or 'HTTP/1.0' in row['res']:
                if '200 OK' in row['res']:
                    toolFunction.csvWrite(
                        [row['ip'], 'http', 0], r'processData\responseType.csv')
                    continue
                toolFunction.csvWrite(
                    [row['ip'], 'http', 1], r'processData\responseType.csv')
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 2], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 3], r'processData\responseType.csv')
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 4], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 5], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 6], r'processData\responseType.csv')

    def sshResponce():
        dnsData = pd.read_csv(r'sourceData\probe\res_ssh.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        for index, row in dnsData.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 1], r'processData\responseType.csv')
            elif 'SSH' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 2], r'processData\responseType.csv')
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 3], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 4], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 5], r'processData\responseType.csv')
            elif '[Errno 101] Network is unreachable' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 6], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 7], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 8], r'processData\responseType.csv')

    def openvpnTCP():
        dnsData = pd.read_csv(r'sourceData\probe\res_openvpnTCP.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        for index, row in dnsData.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 1], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 2], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                    toolFunction.csvWrite(
                        [row['ip'], 'openvpnTCP', 3], r'processData\responseType.csv')
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 4], r'processData\responseType.csv')
            elif '[Errno 101] Network is unreachable' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 5], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 6], r'processData\responseType.csv')
            elif 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 7], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 8], r'processData\responseType.csv')

    def openvpnUDP():
        dnsData = pd.read_csv(r'sourceData\probe\res_openvpnUDP.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        for index, row in dnsData.iterrows():
            if 'success' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 1], r'processData\responseType.csv')
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 2], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 3], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 4], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 5], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 6], r'processData\responseType.csv')

    def pptp():
        dnsData = pd.read_csv(r'sourceData\probe\res_pptp.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        for index, row in dnsData.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 1], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 2], r'processData\responseType.csv')
            elif 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 3], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 4], r'processData\responseType.csv')
            elif '[Errno 104] Connection reset by peer' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 5], r'processData\responseType.csv')
            elif 'timed out' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 6], r'processData\responseType.csv')
            elif '[Errno 101] Network is unreachable' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 7], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 8], r'processData\responseType.csv')

    def ipsec():
        dnsData = pd.read_csv(r'sourceData\probe\res_ipsec.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        for index, row in dnsData.iterrows():
            if 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 1], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 2], r'processData\responseType.csv')
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 3], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 4], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 5], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 6], r'processData\responseType.csv')

    def sstp():
        dnsData = pd.read_csv(r'sourceData\probe\res_sstp.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        a = list()
        for index, row in dnsData.iterrows():
            if 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 1], r'processData\responseType.csv')
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 2], r'processData\responseType.csv')
            elif 'EOF occurred in violation of protocol' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 3], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 4], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 5], r'processData\responseType.csv')
            elif '[SSL: UNSOLICITED_EXTENSION] unsolicited extension' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 6], r'processData\responseType.csv')
            elif '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 7], r'processData\responseType.csv')
            elif '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 8], r'processData\responseType.csv')
            elif '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 9], r'processData\responseType.csv')
            elif '[SSL: TLSV1_UNRECOGNIZED_NAME] tlsv1 unrecognized name' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 10], r'processData\responseType.csv')
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 11], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 12], r'processData\responseType.csv')

    def tls():
        dnsData = pd.read_csv(r'sourceData\probe\res_tls.csv', names=[
                              'ip', 'protocol', 'res'])
        dnsData = dnsData.fillna('unknow error')
        a = list()
        for index, row in dnsData.iterrows():
            if str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 1], r'processData\responseType.csv')
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 2], r'processData\responseType.csv')
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 3], r'processData\responseType.csv')
            elif 'EOF occurred in violation of protocol' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 4], r'processData\responseType.csv')
            elif 'SSL: SSLV3_ALERT_HANDSHAKE_FAILURE' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 5], r'processData\responseType.csv')
            elif 'The handshake operation timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 6], r'processData\responseType.csv')
            elif 'SSL: TLSV1_ALERT_INTERNAL_ERRORE' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 7], r'processData\responseType.csv')
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 8], r'processData\responseType.csv')
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 9], r'processData\responseType.csv')
            elif '[SSL: UNSOLICITED_EXTENSION]' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 10], r'processData\responseType.csv')
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 11], r'processData\responseType.csv')


class PacketHandler():
    def __init__(self):

        self.endtime = ''
        self.flags = ''
        self.payload = b''

    def handle_pkt(self, pkt):
        self.flags = ''
        self.payload = b''
        # convert timestamp to human readable format
        self.endtime = datetime.fromtimestamp(pkt.time)
        if TCP in pkt:  #
            self.flags = pkt[TCP].flags
            if Raw in pkt:
                self.payload = pkt[Raw].load


class vpn_probe_script():
    def __init__(self) -> None:
        pass

    def sstp(self, host, port=443):

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
                toolFunction.csvWrite(
                    [host, port, 'success'], self.vpnProtocolPath)

        except socket.error as e:
            pass

        finally:
            ssl_sock.close()


    def pptp(self, host, port=1723):
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
                toolFunction.csvWrite(
                    [host, port, 'success'], self.vpnProtocolPath)

        except socket.error as e:
            pass

        finally:
            sock.close()


    def IPSec(self, host, port=500):
        InitiatorSPI = b'\x1a\x23\x39\x98\x43\x58\x77\x2d'
        payload = InitiatorSPI + b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x0d\x00\x00\x5c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x50\x01\x01\x00\x02\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x00\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x04\x00\x02\x80\x03\x00\x03\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x00\x0e\x10\x0d\x00\x00\x18\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x04\x0d\x00\x00\x14\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x0d\x00\x00\x14\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f\x00\x00\x00\x14\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))

            sock.sendall(payload)

            response = sock.recv(4096)

            if InitiatorSPI in response:
                toolFunction.csvWrite(
                    [host, port, 'success'], self.vpnProtocolPath)

        except BaseException as e:
            pass

        finally:
            sock.close()

    def openvpnUDP(self, host, port=1194):
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


    def openvpnTCP(self, host, port=1194):
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
                toolFunction.csvWrite(
                    [host, port, 'success'], self.vpnProtocolPath)

        except BaseException as e:
            pass

        finally:
            sock.close()

    def TCP_only_collect_response(self, host, port, payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(300)
        try:
            sock.connect((host, port))
            sock.sendall(payload)
            response = sock.recv(4096)
            toolFunction.csvWrite(
                [host, port, response, payload], self.tcp_only_Response)
        except:
            pass

    def TCP_collect_flag_and_response(self, host, port, payload, pktNum=1, pktTimeout=300):
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

    def guess_RST_threshold(self, host, port, min_val=0, max_val=64):
        while min_val <= max_val:
            mid_val = (min_val + max_val) // 2

            payload = os.urandom(mid_val)

            startTime, endTime, flags, response_payload = self.TCP_collect_flag_and_response(
                host, port, payload)
            toolFunction.csvWrite([host, len(payload), int(
                (endTime-startTime).total_seconds()), flags, response_payload], 'log.csv')

            if 'R' in flags:
                max_val = mid_val - 1
            else:
                min_val = mid_val + 1

        if max_val == 64 and min_val > max_val:
            return self.guess_RST_threshold(host, port, 65, 1500)

        return max_val+1

    def TLS_python(ip, port=443):
        try:
            sock = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), socket.socket(
                socket.AF_INET, socket.SOCK_STREAM))
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.do_handshake()
            sock.close()
        except BaseException as e:
            print(e)
            pass

    def check_http(host, port=80):
        try:

            sock = socket.create_connection((host, port))
            request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
            sock.send(request.encode())
            response = sock.recv(1024)

            if "HTTP/1.1" in response.decode():
                return True
            else:
                return False

        except socket.error as e:
            return False
        finally:
            sock.close()

    def check_ssh(self, host, port=22):
        try:

            sock = socket.create_connection((host, port), timeout=3)
            server_banner = sock.recv(1024).decode().strip()

            if server_banner.startswith('SSH-'):

                client_banner = server_banner + '\r\n'
                sock.send(client_banner.encode())

                return True
            else:
                return False
        except socket.error as e:
            return False
        finally:
            sock.close()

    def getPtrRecord(self, ip):
        try:
            n = dns.reversename.from_address(ip)
            domain = str(dns.resolver.resolve(n, "PTR")[0])
            return domain
        except:
            pass

    def check_ftp(self, ip, port=21):
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


    def check_dns_support(self, ip, domain="google.com"):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        try:
            answers = resolver.resolve(domain, "A")  # A record for domain
            if answers:
                toolFunction.csvWrite(
                    [ip, "success"], 'probeResult/dnsProbe.csv')
                return
        except Exception as e:
            toolFunction.csvWrite([ip, str(e)], 'probeResult/dnsProbe.csv')
            return

        toolFunction.csvWrite([ip, "Unknown error"],
                              'probeResult/dnsProbe.csv')

    def openssl_tls_scan(self, host, port=443):
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

        toolFunction.csvWrite([issuer, domainList, expired],
                              'probeResult/openssl_CA.csv')
