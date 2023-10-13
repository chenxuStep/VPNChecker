#Description of Response Type

import pandas as pd


class responseType():
    def __init__(self) -> None:
        pass
    
    #Description: CSV file write function
    #Input Parm: column,writePath
    #Output: CSV file

    def csvWrite(self,column,writePath):        
        res = pd.DataFrame(columns=(column))
        res.to_csv(writePath,index=False,mode='a',encoding='utf8')    

    #Description: Response of DNS Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def dnsResponce(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])

        for index, row in data.iterrows():
            if 'All nameservers failed to answer' in row['res']:
                row['res'] = 'failed to answer'
                self.csvWrite(
                    [row['ip'], 'dns', 0], writePath)
            elif 'The resolution lifetime expired' in row['res']:
                row['res'] = 'timed out'
                self.csvWrite(
                    [row['ip'], 'dns', 1], writePath)
            elif 'success' in row['res']:
                self.csvWrite(
                    [row['ip'], 'dns', 2], writePath)
            elif 'The DNS response does not contain an answer to the question' in row['res']:
                self.csvWrite(
                    [row['ip'], 'dns', 3], writePath)
            elif 'The DNS query name does not exist' in row['res']:
                self.csvWrite(
                    [row['ip'], 'dns', 4], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'dns', 5], writePath)

    #Description: Response of FTP Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def ftpResponce(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 0], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 1], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 2], writePath)
            elif '220' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 3], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 4], writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 5], writePath)
            elif '[Errno 101] Network is unreachable' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ftp', 6], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'ftp', 7], writePath)

    #Description: Response of HTTP Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def httpResponce(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if 'HTTP/1.1' or 'HTTP/1.0' in row['res']:
                if '200 OK' in row['res']:
                    self.csvWrite(
                        [row['ip'], 'http', 0], writePath)
                    continue
                self.csvWrite(
                    [row['ip'], 'http', 1], writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'http', 2], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'http', 3], writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                self.csvWrite(
                    [row['ip'], 'http', 4], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'http', 5], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'http', 6], writePath)

    #Description: Response of SSH Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def sshResponce(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        for index, row in data.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 1], writePath)
            elif 'SSH' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 2], writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 3], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 4], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 5], writePath)
            elif '[Errno 101] Network is unreachable' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 6], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'ssh', 7], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'ssh', 8], writePath)

    #Description: Response of openvpnTCP Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def openvpnTCP(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        for index, row in data.iterrows():

            if '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 1], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 2], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                    self.csvWrite(
                        [row['ip'], 'openvpnTCP', 3], writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 4], writePath)
            elif '[Errno 101] Network is unreachable' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 5], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 6], writePath)
            elif 'success' == row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 7], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'openvpnTCP', 8], writePath)
    
    
    #Description: Response of openvpnUDP Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def openvpnUDP(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if 'success' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnUDP', 1], writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnUDP', 2], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnUDP', 3], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnUDP', 4], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'openvpnUDP', 5], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'openvpnUDP', 6], writePath)


    #Description: Response of pptp Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def pptp(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 1], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 2], writePath)
            elif 'success' == row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 3], writePath)
            elif '[Errno 113] No route to host' == row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 4], writePath)
            elif '[Errno 104] Connection reset by peer' == row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 5], writePath)
            elif 'timed out' == row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 6], writePath)
            elif '[Errno 101] Network is unreachable' == row['res']:
                self.csvWrite(
                    [row['ip'], 'pptp', 7], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'pptp', 8], writePath)


    #Description: Response of ipsec Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def ipsec(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if 'success' == row['res']:
                self.csvWrite(
                    [row['ip'], 'ipsec', 1], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'ipsec', 2], writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ipsec', 3], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ipsec', 4], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'ipsec', 5], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'ipsec', 6], writePath)


    #Description: Response of sstp Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def sstp(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        
        for index, row in data.iterrows():
            if 'success' == row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 1], writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 2], writePath)
            elif 'EOF occurred in violation of protocol' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 3], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 4], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 5], writePath)
            elif '[SSL: UNSOLICITED_EXTENSION] unsolicited extension' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 6], writePath)
            elif '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 7], writePath)
            elif '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 8], writePath)
            elif '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 9], writePath)
            elif '[SSL: TLSV1_UNRECOGNIZED_NAME] tlsv1 unrecognized name' in row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 10], writePath)
            elif str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'sstp', 11], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'sstp', 12], writePath)

    #Description: Response of tls Probe
    #Input Parm: File of Probe Result, File of Processed Result
    #Output: CSV file
    def tls(self,readPath,writePath):
        data = pd.read_csv(readPath, names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        
        for index, row in data.iterrows():
            if str(b'') == row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 1], writePath)
            elif 'timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 2], writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 3], writePath)
            elif 'EOF occurred in violation of protocol' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 4], writePath)
            elif 'SSL: SSLV3_ALERT_HANDSHAKE_FAILURE' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 5], writePath)
            elif 'The handshake operation timed out' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 6], writePath)
            elif 'SSL: TLSV1_ALERT_INTERNAL_ERRORE' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 7], writePath)
            elif '[Errno 113] No route to host' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 8], writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 9], writePath)
            elif '[SSL: UNSOLICITED_EXTENSION]' in row['res']:
                self.csvWrite(
                    [row['ip'], 'tls', 10], writePath)
            else:
                self.csvWrite(
                    [row['ip'], 'tls', 11], writePath)
