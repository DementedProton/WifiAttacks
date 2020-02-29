from scapy.all import *
import sys


def filter_dot11(packet: scapy.layers.dot11.Dot11):
    if type(packet) == scapy.layers.dot11.Dot11:
        return True


deauth_configuration_list = {}

disas_configuration_list = {}

class DeauthPacket:
    def __init__(self, sender, ts):
        self.sender = sender
        self.ts = ts
        self.count = 0


class Dot11Packet:
    def __init__(self, packet: scapy.layers.dot11.Dot11):
        if packet.haslayer(Dot11Beacon):
            self.src_mac = packet.addr2
            self.bssid = packet.addr3
            self.ssid = packet[Dot11Beacon][Dot11Elt].info.decode()
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            logging.info(f'[{current_time}] : Beacon sent by {self.bssid} for ssid {self.ssid}')
        elif packet.haslayer(Dot11Deauth):
            self.receiver = packet.addr1
            self.sender_bssid = packet.addr3
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            if self.receiver != self.sender_bssid:
                if self.receiver not in deauth_configuration_list:
                    deauth_configuration_list[self.receiver] = DeauthPacket(self.sender_bssid, packet.time)
                    logging.info(
                        f'[{current_time}] : Deauthentication packet sent by {self.sender_bssid} to {self.receiver} ')
                else:
                    if (packet.time - deauth_configuration_list[self.receiver].ts) > .007:
                        deauth_configuration_list[self.receiver].count += 1
                        if deauth_configuration_list[self.receiver].count > 3:
                            logging.error(f'[{current_time}] : ({deauth_configuration_list[self.receiver].count}) '
                                          f'Deauthentication Flood Attack detected on {self.receiver}. Posing from mac: {self.sender_bssid}')
                        else:
                            logging.info(f'[{current_time}] : Deauthentication packet sent by {self.sender_bssid} to {self.receiver} ')
        elif packet.haslayer(Dot11Disas):
            self.receiver = packet.addr1
            self.sender_bssid = packet.addr3
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            if self.receiver != self.sender_bssid:
                if self.receiver not in disas_configuration_list:
                    disas_configuration_list[self.receiver] = DeauthPacket(self.sender_bssid, packet.time)
                    logging.info(
                        f'[{current_time}] : Disassociation packet sent by {self.sender_bssid} to {self.receiver} ')
                else:
                    if (packet.time - disas_configuration_list[self.receiver].ts) > .007:
                        disas_configuration_list[self.receiver].count += 1
                        if disas_configuration_list[self.receiver].count >= 3:
                            logging.error(f'[{current_time}] : ({disas_configuration_list[self.receiver].count}) '
                                          f'Disassociation Flood Attack detected on {self.receiver}. Posing from mac: {self.sender_bssid}')
                        else:
                            logging.info(f'[{current_time}] : Disassociation packet sent by {self.sender_bssid} to {self.receiver} ')



def main():
    logging.basicConfig(format='[%(levelname)s] : %(message)s', filename=sys.argv[2], filemode='w',
                        level=logging.DEBUG)
    packets = scapy.all.rdpcap(sys.argv[1])
    arp_packets = packets.filter(filter_dot11)
    for packet in arp_packets:
        Dot11Packet(packet)


if __name__ == '__main__':
    main()