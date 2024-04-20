# coding:UTF-8

from scapy.all import *
import collections
import time


# 时间流量图
def time_flow(PCAPS):
    time_flow_dict = collections.OrderedDict()
    start = PCAPS[0].time
    time_flow_dict[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(PCAPS[0].time))] = len(corrupt_bytes(PCAPS[0]))
    for pcap in PCAPS:
        timediff = pcap.time - start
        time_flow_dict[float('%.3f' % timediff)] = len(corrupt_bytes(pcap))
    return time_flow_dict


# 获取抓包主机的IP
def get_host_ip(PCAPS):
    ip_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            ip_list.append(pcap.getlayer(IP).src)
            ip_list.append(pcap.getlayer(IP).dst)
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip


# 数据流入流出统计
def data_flow(PCAPS, host_ip):
    data_flow_dict = {'IN': 0, 'OUT': 0}
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            if pcap.getlayer(IP).src == host_ip:
                data_flow_dict['OUT'] += 1
            elif pcap.getlayer(IP).dst == host_ip:
                data_flow_dict['IN'] += 1
            else:
                pass
    return data_flow_dict


# 访问IP地址统计
def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            dst = pcap.getlayer(IP).dst
            src = pcap.getlayer(IP).src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass
    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(), key=lambda d: d[1], reverse=False)
    # in_len_dict = sorted(in_len_dict.items(), key=lambda d:d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(), key=lambda d: d[1], reverse=False)
    # out_len_dict = sorted(out_len_dict.items(), key=lambda d:d[1], reverse=False)
    in_key_list = list()
    in_packet_list = list()
    in_len_list = list()
    for key, value in in_packet_dict:
        in_key_list.append(key)
        in_packet_list.append(value)
        valin = in_len_dict[key]
        in_len_list.append(valin)

    out_key_list = list()
    out_packet_list = list()
    out_len_list = list()
    for key, value in out_packet_dict:
        out_key_list.append(key)
        out_packet_list.append(value)
        valout = out_len_dict[key]
        out_len_list.append(valout)
    in_ip_dict = {'in_key': in_key_list, 'in_packet': in_packet_list, 'in_len': in_len_list, 'out_key': out_key_list,
                  'out_packet': out_packet_list, 'out_len': out_len_list}
    return in_ip_dict


# 常见协议流量统计
def iot_proto_flow(PCAPS):
    iot_proto_flow_dict = collections.OrderedDict()
    iot_proto_flow_dict['MQTT'] = 0
    iot_proto_flow_dict['MQTT/SSL'] = 0
    iot_proto_flow_dict['DICOM'] = 0
    for pcap in PCAPS:
        if pcap.haslayer(TCP):
            pcap_len = len(corrupt_bytes(pcap))
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 1883 or sport == 1883:
                iot_proto_flow_dict['MQTT'] += pcap_len
            elif dport == 8883 or sport == 8883:
                iot_proto_flow_dict['MQTT/SSL'] += pcap_len
            elif dport == 104 or sport == 104 or dport == 4242 or sport == 4242:
                iot_proto_flow_dict['DICOM'] += pcap_len
    return iot_proto_flow_dict


# 流量最多协议数量统计
def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data['Procotol']] += len(corrupt_bytes(pcap))
    return most_flow_dict
