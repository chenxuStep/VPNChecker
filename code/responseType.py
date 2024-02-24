
'''
Description: Mapping the response information to type
Author: chenxu
Date: 2024-02-23 20:09:55
LastEditTime: 2024-02-24 14:56:22
LastEditors: chenxu
'''


import pandas as pd
import toolFunction


class mapping():
    def __init__(self) -> None:
        self.readPath = 'data/application_layer_probing_res/'
        self.writePath = 'data/application_layer_probing_res/responseType.csv'
        

    '''
    Description: Mapping DNS response content
    Param : 
    Return: CSV file
    '''    
    def dns_mapping(self):

        data = pd.read_csv(self.readPath+'dns.csv', names=['ip', 'protocol', 'res'])

        for index, row in data.iterrows():
            if 'All nameservers failed to answer' in row['res']:
                row['res'] = 'failed to answer'
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 0], self.writePath)
            elif 'The resolution lifetime expired' in row['res']:
                row['res'] = 'timed out'
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 1], self.writePath)
            elif 'success' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 2], self.writePath)
            elif 'The DNS response does not contain an answer to the question' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 3], self.writePath)
            elif 'The DNS query name does not exist' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 4], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'dns', 5], self.writePath)


    '''
    Description: Mapping FTP response content
    Param : 
    Return: CSV file
    '''
    def ftp_mapping(self):
        data = pd.read_csv(self.readPath+'ftp.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 0], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 1], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 2], self.writePath)
            elif '220' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 3], self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 4], self.writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 5], self.writePath)
            elif '[Errno 101] Network is unreachable' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 6], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'ftp', 7], self.writePath)

    

    '''
    Description: Mapping HTTP response content
    Param : 
    Return: CSV file
    '''
    def http_mapping(self):
        data = pd.read_csv(self.readPath+'http.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if 'HTTP/1.1' or 'HTTP/1.0' in row['res']:
                if '200 OK' in row['res']:
                    self.csvWrite(
                        [row['ip'], 'http', 0], self.writePath)
                    continue
                toolFunction.csvWrite(
                    [row['ip'], 'http', 1], self.writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 2], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 3], self.writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 4], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 5],self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'http', 6], self.writePath)

    

    '''
    Description: Mapping SSH response content
    Param : 
    Return: CSV file
    '''
    def ssh_mapping(self):
        data = pd.read_csv(self.readPath+'ssh.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        for index, row in data.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 1], self.writePath)
            elif 'SSH' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 2], self.writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 3],self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 4], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 5], self.writePath)
            elif '[Errno 101] Network is unreachable' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 6], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 7], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'ssh', 8], self.writePath)

    

    '''
    Description: Mapping openvpnTCP response content
    Param : 
    Return: CSV file
    '''
    def openvpnTCP_mapping(self):
        data = pd.read_csv(self.readPath+'openvpnTCP.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        for index, row in data.iterrows():

            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 1], self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 2], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                        [row['ip'], 'openvpnTCP', 3], self.writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 4], self.writePath)
            elif '[Errno 101] Network is unreachable' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 5], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 6], self.writePath)
            elif 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 7], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnTCP', 8], self.writePath)
    
    '''
    Description: Mapping openvpnUDP response content
    Param : 
    Return: CSV file
    '''
    def openvpnUDP_mapping(self):
        data = pd.read_csv(self.readPath+'openvpnUDP.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if 'success' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 1], self.writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 2], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 3], self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 4], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 5], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'openvpnUDP', 6], self.writePath)



    '''
    Description: Mapping PPTP response content
    Param : 
    Return: CSV file
    '''
    def pptp_mapping(self):
        data = pd.read_csv(self.readPath+'pptp.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 1], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 2], self.writePath)
            elif 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 3], self.writePath)
            elif '[Errno 113] No route to host' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 4], self.writePath)
            elif '[Errno 104] Connection reset by peer' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 5], self.writePath)
            elif 'timed out' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 6], self.writePath)
            elif '[Errno 101] Network is unreachable' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 7], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'pptp', 8], self.writePath)


    '''
    Description: Mapping IPSEC response content
    Param : 
    Return: CSV file
    '''
    def ipsec_mapping(self):
        data = pd.read_csv(self.readPath+'ipsec.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')

        for index, row in data.iterrows():
            if 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 1], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 2], self.writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 3], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 4], self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 5], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'ipsec', 6], self.writePath)


    '''
    Description: Mapping SSTP response content
    Param : 
    Return: CSV file
    '''
    def sstp_mapping(self):
        data = pd.read_csv(self.readPath+'sstp.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        
        for index, row in data.iterrows():
            if 'success' == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 1], self.writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 2], self.writePath)
            elif 'EOF occurred in violation of protocol' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 3], self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 4], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 5], self.writePath)
            elif '[SSL: UNSOLICITED_EXTENSION] unsolicited extension' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 6], self.writePath)
            elif '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 7], self.writePath)
            elif '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 8], self.writePath)
            elif '[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 9], self.writePath)
            elif '[SSL: TLSV1_UNRECOGNIZED_NAME] tlsv1 unrecognized name' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 10], self.writePath)
            elif str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 11], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'sstp', 12], self.writePath)

    '''
    Description: Mapping TLS response content
    Param : 
    Return: CSV file
    '''
    def tls_mapping(self):
        data = pd.read_csv(self.readPath+'tls.csv', names=['ip', 'protocol', 'res'])
        data = data.fillna('unknow error')
        
        for index, row in data.iterrows():
            if str(b'') == row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 1], self.writePath)
            elif 'timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 2], self.writePath)
            elif '[Errno 111] Connection refused' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 3], self.writePath)
            elif 'EOF occurred in violation of protocol' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 4], self.writePath)
            elif 'SSL: SSLV3_ALERT_HANDSHAKE_FAILURE' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 5], self.writePath)
            elif 'The handshake operation timed out' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 6], self.writePath)
            elif 'SSL: TLSV1_ALERT_INTERNAL_ERRORE' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 7], self.writePath)
            elif '[Errno 113] No route to host' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 8], self.writePath)
            elif '[Errno 104] Connection reset by peer' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 9], self.writePath)
            elif '[SSL: UNSOLICITED_EXTENSION]' in row['res']:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 10], self.writePath)
            else:
                toolFunction.csvWrite(
                    [row['ip'], 'tls', 11], self.writePath)
