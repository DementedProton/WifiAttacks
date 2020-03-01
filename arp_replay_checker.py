from scapy.all import *
import sys


def filter_dot11(packet: scapy.layers.dot11.Dot11):
    if type(packet) == scapy.layers.dot11.Dot11:
        return True


configuration_list = {}

request_count = 0

arp_packet_timestamp = 0

timeout = 1

class Dot11Packet:
    def __init__(self, packet: scapy.layers.dot11.Dot11):
        global request_count
        global arp_packet_timestamp
        global timeout
        if packet.haslayer(Dot11Beacon):
            self.src_mac = packet.addr2
            self.bssid = packet.addr3
            self.ssid = packet[Dot11Beacon][Dot11Elt].info.decode()
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            logging.info(f'[{current_time}] : Beacon sent by {self.bssid} for ssid {self.ssid}')
        if packet.haslayer(Dot11WEP):
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            if len(packet[Dot11WEP].wepdata) == 54: # it is an arp packet
                if arp_packet_timestamp == 0:
                    arp_packet_timestamp = packet.time
                elif (packet.time - arp_packet_timestamp) > .1:
                    request_count += 1
                    if packet.addr3 != 'ff:ff:ff:ff:ff:ff':
                        if request_count in range(30, 200) and (request_count % timeout == 0):
                            timeout += 10
                            logging.info(f'[{current_time}] : ({request_count}) Potential ARP Replay attack detected on {packet.addr3}')
                        if request_count > 200 and (request_count % timeout == 0):
                            timeout += 50
                            logging.error(f'[{current_time}] : ({request_count}) ARP Replay attack detected on {packet.addr3}, timeout: {timeout}')


def main():
    logging.basicConfig(format='[%(levelname)s] : %(message)s', filename=sys.argv[2], filemode='w',
                        level=logging.DEBUG)
    packets = scapy.all.rdpcap(sys.argv[1])
    arp_packets = packets.filter(filter_dot11)
    for packet in arp_packets:
        Dot11Packet(packet)


if __name__ == '__main__':
    main()