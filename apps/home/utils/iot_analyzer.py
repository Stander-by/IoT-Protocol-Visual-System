import json
import collections
import tempfile
import sys


def mqtt_decode(mqtt_pcaps_dict):
    res = list()
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
    for pcapit in mqtt_pcaps_dict.items():
        res_temp = dict()
        pcap = pcapit[1]
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
                #res_temp['Message_Identifier'] = int.from_bytes(payload_str[4 + mqtt_topic_len,6 + mqtt_topic_len],byteorder='big')
                mqtt_flex_head = mqtt_topic_len + 4
            res_temp['Properties_len'] = payload_str[2 + mqtt_flex_head]
            mqtt_payload = payload_str[3 + mqtt_flex_head:2 + mqtt_res_len]
            mqtt_payload_str = mqtt_payload.decode('utf-8')
            mqtt_payload_dict = json.loads(mqtt_payload_str)
            res_temp['message'] = mqtt_payload_dict
        res.append(res_temp)
    return res

def dicom_decode(dicom_pcaps_dict):
    res = list()
    PDU_type_list ={
        1: "A-ASSOC-Request",
        2: "A-ASSOC-Accept",
        3: "A-ASSOC-Reject",
        4: "P-Data",
        5: "RELEASE-Request",
        6: "RELEASE-Response",
        7: "ABORT"
    }
    Item_Type_list = {
        16: "Application_Context",
        32: "Presentation_Context",
        33: "Presentation_Context_Reply",
        48: "Abstract_Syntax",
        64: "Transfer_Syntax",
        80: "User_Info",
        81: "Max_Length",
        82: "Implementation_Class_UID",
        85: "Implementation_Version"
    }
    PDV_Type_list = {
        0: "Command_Group_Length",
        2: "Affected_SOP_Class_UID",
    }
    items = list(dicom_pcaps_dict.values())
    for pcap in items:
        if not res:
            pcap['others'] = pcap['others'].load
            res.append(pcap)
        else:
            peek_pcap = res[-1]
            if peek_pcap['seq']+len(peek_pcap['others']) == pcap['seq']:
                peek_pcap = res.pop()
                merge_payload = peek_pcap['others']+(pcap['others'].load)
                pcap['others'] = merge_payload
                pcap['seq'] = peek_pcap['seq']
                res.append(pcap)
            else:
                pcap['others'] = pcap['others'].load
                res.append(pcap)
    for pcap in res:
        payload_byte = pcap['others']
        pcap['PDU_type'] = PDU_type_list[payload_byte[0]]
        pcap['PDU_len'] = int.from_bytes(payload_byte[2:6], byteorder='big')
        if payload_byte[0] == 1 or payload_byte[0] == 2 or payload_byte[0] == 3:
            pcap['Protocol_ver'] = int.from_bytes(payload_byte[6:8], byteorder='big')
            pcap['Called_AE_Title'] = payload_byte[10:26].decode('utf-8')
            pcap['Calling_AE_Title'] = payload_byte[26:42].decode('utf-8')
            # 42+ 2* 16 = 42 +32 = 74
            index = 74
            dict_temp = dict()
            while index < len(payload_byte):
                Item_type = Item_Type_list[payload_byte[index]]
                index = index + 2
                Item_len = int.from_bytes(payload_byte[index:index+2], byteorder='big')
                index = index + 2
                if Item_type == 'Application_Context':
                    Application_context_dict = dict()
                    Application_context_dict['Item_type'] = Item_type
                    Application_context_dict['Item_len'] = Item_len
                    Application_context_dict['DICOM_Application_Context_Name'] = payload_byte[index:index+Item_len].decode('utf-8')
                    index = index + Item_len
                    dict_temp[Item_type] = Application_context_dict
                elif Item_type == 'Presentation_Context' or Item_type == 'Presentation_Context_Reply':
                    Presentation_context_dict = dict()
                    Presentation_context_dict['Item_type'] = Item_type
                    Presentation_context_dict['Item_len'] = Item_len
                    Presentation_context_dict['Context_ID'] = payload_byte[index]
                    if Item_type == 'Presentation_Context_Reply':
                        Presentation_context_dict['Result'] = payload_byte[index+2]
                    Presentation_context_end = index + Item_len
                    index = index + 4
                    while index < Presentation_context_end:
                        Item_type_sub = Item_Type_list[payload_byte[index]]
                        index = index + 2
                        Item_len_sub = int.from_bytes(payload_byte[index:index + 2], byteorder='big')
                        index = index + 2
                        Presentation_context_dict[Item_type_sub] = payload_byte[index:index + Item_len_sub].decode('utf-8')
                        index = index + Item_len_sub
                    dict_temp[Item_type] = Presentation_context_dict
                elif Item_type == 'User_Info':
                    User_Info_dict = dict()
                    User_Info_dict['Item_type'] = Item_type
                    User_Info_dict['Item_len'] = Item_len
                    User_Info_end = index + Item_len
                    while index < User_Info_end:
                        Item_type_sub = Item_Type_list[payload_byte[index]]
                        index = index + 2
                        Item_len_sub = int.from_bytes(payload_byte[index:index + 2], byteorder='big')
                        index = index + 2
                        if Item_type_sub == 'Max_Length':
                            User_Info_dict[Item_type_sub] = int.from_bytes(payload_byte[index:index + Item_len_sub], byteorder='big')
                        else:
                            User_Info_dict[Item_type_sub] = payload_byte[index:index + Item_len_sub].decode('utf-8')
                        index = index + Item_len_sub
                    dict_temp[Item_type] = User_Info_dict
            pcap['Context'] = dict_temp
        elif payload_byte[0] == 4:
            dict_temp = dict()
            dict_temp['PDV_Length'] = int.from_bytes(payload_byte[6:10],byteorder='big')
            dict_temp['Context'] = payload_byte[10]
            dict_temp['Flags'] = payload_byte[11]
            dict_temp['PDV_Context'] = payload_byte[12:]
            pcap['Context'] = dict_temp
    return res