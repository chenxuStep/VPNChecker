
import pandas as pd 
import toolFunction
from tomorrow import threads
import probes
import responseType



'''
Description: seed the application layer probe and collect the response 
Param : ip
Return: response information
'''
# @threads(5)
def application_layer_probing(application_layer_probes,ip):
    application_layer_probes.sstp_probe(ip)
    application_layer_probes.pptp_probe(ip)
    application_layer_probes.ipsec_probe(ip)
    application_layer_probes.openvpnUDP_probe(ip)
    application_layer_probes.openvpnTCP_probe(ip)
    
    application_layer_probes.tls_probe(ip)
    application_layer_probes.ssh_probe(ip)
    application_layer_probes.ftp_probe(ip)
    application_layer_probes.dns_probe(ip)
    application_layer_probes.http_probe(ip)

'''
Description: Mapping the response information to type
Param : 
Return: Mapping file
'''
def response_type_mappings(mapping):
    mapping.ipsec_mapping()
    mapping.openvpnTCP_mapping()
    mapping.openvpnUDP_mapping()
    mapping.pptp_mapping()
    mapping.sstp_mapping()
    
    mapping.dns_mapping()
    mapping.ftp_mapping()
    mapping.http_mapping()        
    mapping.ssh_mapping()
    mapping.tls_mapping()


'''
Description: Construct feature vector from responseType
Param : 
Return: RT feature of each server 
'''
def construct_rt_feature():
    data = pd.read_csv(r'data/application_layer_probing_res/responseType.csv',names=['ip','protocol','value'])
    protocol_order=['ftp','ssh','dns','http','tls','sstp','ipsec','pptp','openvpnUDP','openvpnTCP']
    pivot_result = data .pivot(index='ip', columns='protocol', values='value').reset_index()

    for protocol in protocol_order:
        if protocol not in pivot_result.columns:
            pivot_result[protocol] = None

    pivot_result = pivot_result[['ip'] + protocol_order]
    pivot_result.to_csv(r'data/feature/RT.csv',index=None)



if __name__ == '__main__':

    application_layer_probes = probes.application_layer_probes()  

    ipList = toolFunction.readTxt('data/test_ip.txt')
    for ip in ipList:
        application_layer_probing(application_layer_probes,ip)

    mapping = responseType.mapping()
    response_type_mappings(mapping)
    
    construct_rt_feature()

