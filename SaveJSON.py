import json

class Pachet():
    def __init__(self, Ethernet_src='', Ethernet_dst='', IP_dst='', IP_src='', IP_version='', IP_proto='', TCP_sport='',
                 TCP_dport='', UDP_sport='',
                 UDP_dport=''):
        self.Ethernet_dst = Ethernet_dst
        self.Ethernet_src = Ethernet_src
        self.IP_dst = IP_dst
        self.IP_src = IP_src
        self.IP_version = IP_version
        self.IP_proto = IP_proto
        self.TCP_sport = TCP_sport
        self.TCP_dport = TCP_dport
        self.UDP_sport = UDP_sport
        self.UDP_dport = UDP_dport


    def to_json(self):
        json_dic = {'Ethernet': {
                       'src': '',
                       'dst': '',
                   },
                   'IP': {'src': '',
                          'dst': '',
                          'version': '',
                          'proto': ''
                          },
                   'TCP': {'sport': '',
                           'dport': ''
                           },
                   'UDP': {'sport': '',
                           'dport': ''}
               }
        return json_dic


    def __str__(self, json_dict):
        return json.dumps(json_dict)


    def json_file(self, json_dict, path= 'file.json'):
        with open(path, 'a+') as outfile:
            json.dump(json_dict, outfile, indent=4, sort_keys=True)
            outfile.write("\n")





