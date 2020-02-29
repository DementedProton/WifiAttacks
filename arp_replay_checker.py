from scapy.all import *
import sys


def filter_dot11(packet: scapy.layers.dot11.Dot11):
    if type(packet) == scapy.layers.dot11.Dot11:
        return True


configuration_list = {}


