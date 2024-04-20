import json
import collections
import tempfile
import sys


def mqtt_decode(mqtt_pcaps_dict):
    res = dict()
    mqtt_type_dict = {
        0: "Reserved",
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        5: "PUBREC",
        6: "PUBREL",
        7: "PUBCOMP",
        8: "SUBSCRIBE",
        9: "SUBACK",
        10: "UNSUBSCRIBE",
        11: "UNSUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
        15: "Reserved"
    }
    for count, pcapit in enumerate(mqtt_pcaps_dict.items(), 1):
        pcap = pcapit[1]
        res_temp = dict()
        res_temp['time'] = pcap['time']
        res_temp['Source'] = pcap['Source']
        res_temp['Destination'] = pcap['Destination']
        payload_data = pcap['others']
        payload_str = payload_data.load
        mqtt_head = payload_str[0]
        mqtt_res_len = payload_str[1]
        mqtt_head_bin_str = bin(mqtt_head)[2:].zfill(8)
        mqtt_type = mqtt_head >> 4
        res_temp['type'] = mqtt_type_dict[mqtt_type]
        # publish
        if mqtt_type == 3:
            mqtt_topic_len = int.from_bytes(payload_str[2:4], byteorder='big')
            res_temp['topic'] = payload_str[4:4 + mqtt_topic_len].decode('utf-8')
            res_temp['DUP'] = mqtt_head_bin_str[4]
            res_temp['QoS2'] = mqtt_head_bin_str[5:7]
            res_temp['RETAIN'] = mqtt_head_bin_str[7]
            if res_temp['QoS2'] == '00':
                mqtt_flex_head = mqtt_topic_len + 2
            else:
                mqtt_flex_head = mqtt_topic_len + 4
            res_temp['Properties_len'] = payload_str[2 + mqtt_flex_head]
            mqtt_payload = payload_str[3 + mqtt_flex_head:2 + mqtt_res_len]

            mqtt_payload_str = mqtt_payload.decode('utf-8')

            mqtt_payload_dict = json.loads(mqtt_payload_str)

            res_temp['message'] = mqtt_payload_dict
        res[count] = res_temp
    return res

def dicom_decode(dicom_pcaps_dict):
