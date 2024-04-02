import json

def ascii2json(payload):
    res =
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
    mqtt_head = payload[0]
    mqtt_type = mqtt_head >> 4

