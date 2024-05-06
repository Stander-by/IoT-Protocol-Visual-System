# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from scapy.layers.inet import TCP

from apps.home import blueprint
from flask import render_template, request, flash, redirect, url_for, send_from_directory
from flask_login import login_required
from jinja2 import TemplateNotFound
from .forms import Upload
from .utils.upload_tools import *
from scapy.all import rdpcap
from .utils.pcap_decode import PcapDecode
from .utils.pcap_filter import *
from .utils.proto_analyzer import *
from .utils.flow_analyzer import *
from .utils.iot_analyzer import *
from .utils.data_extract import *
from .utils.ipmap import *

import os
import time
# from werkzeug import secure_filename

UPLOAD_FOLDER = './pcaps/upload/'
FILE_FOLDER = './pcaps/files/'
PDF_FOLDER = './pcaps/pdf/'
PD = PcapDecode()  # 解析器
PCAPS = None  # 数据包

@blueprint.route('/index')
@login_required
def index():
    return render_template('home/index.html', segment='index')


@blueprint.route('/upload', methods=['POST', 'GET'])
@login_required
def upload():
    filepath = UPLOAD_FOLDER
    upload = Upload()
    if request.method == 'GET':
        return render_template('home/index.html', segment='index')
    elif request.method == 'POST':
        pcap = upload.pcap.data
        pcapname = pcap.filename
        if allowed_file(pcapname):
            name1 = random_name()
            name2 = get_filetype(pcapname)
            global PCAP_NAME, PCAPS
            PCAP_NAME = name1 + name2
            try:
                pcap.save(os.path.join(filepath, PCAP_NAME))
                PCAPS = rdpcap(os.path.join(filepath, PCAP_NAME))
                flash('恭喜你,上传成功！')
                return render_template('home/index.html', segment='index')
            except Exception as e:
                flash('上传错误,错误信息:' + str(e))
                return render_template('home/index.html', segment='index')
        else:
            flash('上传失败,请上传允许的数据包格式!')
            return render_template('home/index.html', segment='index')


@blueprint.route('/update', methods=['POST', 'GET'])
@login_required
def update():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        if request.method == 'POST':
            seq = request.form.get('seq')
            for pkt in PCAPS:
                print(pkt.getlayer(TCP).seq)
                print(pkt.getlayer(TCP).payload)
                if int(seq) == pkt.getlayer(TCP).seq:
                    topic = request.form.get('topic')
                    dup = request.form.get('dup')
                    qos2 = request.form.get('QoS2')
                    retain = request.form.get('retain')
                    prolen = request.form.get('prolen')
                    message = request.form.get('message')
                    message = message.replace('\r', '')
                    message_identifier = request.form.get('message_identifier')
                    head_str = "0011" + dup + qos2 + retain
                    head_int = int(head_str, 2)
                    head_bytes = head_int.to_bytes(1, byteorder='big')
                    topic_byte = topic.encode('utf-8')
                    topic_len = len(topic_byte)
                    topic_len_byte = topic_len.to_bytes(2, byteorder='big')
                    message_byte = message.encode('utf-8')
                    prolen_byte = int(prolen).to_bytes(1, byteorder='big')
                    if message_identifier != '':
                        message_identifier_int = int(message_identifier)
                        message_identifier_byte = message_identifier_int.to_bytes(2, byteorder='big')
                        msg_len = len(topic_len_byte) + topic_len + len(message_byte) + len(prolen_byte) + len(message_identifier_byte)
                        msg_len_byte = msg_len.to_bytes(1, byteorder='big')
                        new_payload = b''.join(
                            [head_bytes, msg_len_byte, topic_len_byte, topic_byte, message_identifier_byte, prolen_byte,
                             message_byte])
                    else:
                        msg_len = len(topic_len_byte) + topic_len + len(message_byte) + len(prolen_byte)
                        msg_len_byte = msg_len.to_bytes(2, byteorder='big')
                        new_payload = b''.join([head_bytes, msg_len_byte, topic_len_byte, topic_byte, prolen_byte, message_byte])
                    pkt.getlayer(TCP).payload = new_payload
                    print(pkt.getlayer(TCP).payload)
                    break
            return redirect('/mqtt_data_extract')
        elif request.method == 'GET':
            return 'Save'

    # New_PCAP =[]
    # for pkt in PCAPS:
    #     if


@blueprint.route('/mqtt_data_extract', methods=['POST', 'GET'])
@login_required
def mqtt_data_extract():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        mqtt_pcaps = proto_filter(u'proto', 'MQTT', PCAPS, PD)
        mqtt_analyzer_pcaps_value_list = mqtt_decode(mqtt_pcaps)
        # mqtt_publish_list = list()
        # for pcap in mqtt_analyzer_pcaps_value_list:
        #     if pcap['type'] == 'PUBLISH':
        #         mqtt_publish_list.append(pcap)
        return render_template('./dataextract/mqtt_data_extract.html', segment='mqtt_data_extract',
                               mqtt_pcaps_list=mqtt_analyzer_pcaps_value_list)


@blueprint.route('/dicom_data_extract', methods=['POST', 'GET'])
@login_required
def dicom_data_extract():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        dicom_pcaps = proto_filter(u'proto', 'DICOM', PCAPS, PD)
        dicom_analyzer_pcaps_list = dicom_decode(dicom_pcaps)
        # dicom_analyzer_pcaps_value_list = list(dicom_analyzer_pcaps.values())
        # dicom_data_list = list()
        # for pcapdicom in dicom_analyzer_pcaps_value_list:
        #     if pcapdicom['PDU'] == 'P-DATA':
        #         dicom_data_list.append(pcapdicom)
    return render_template('./dataextract/dicom_data_extract.html', segment='dicom_data_extract',
                           dicom_data_list=dicom_analyzer_pcaps_list)


@blueprint.route('/database', methods=['POST', 'GET'])
@login_required
def database():
    global PCAPS, PD
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        # 将筛选的type和value通过表单获取
        filter_type = request.form.get('filter_type', type=str, default=None)
        value = request.form.get('value', type=str, default=None)
        # 如果有选择，通过选择来获取值
        if filter_type and value:
            pcaps = proto_filter(filter_type, value, PCAPS, PD)
        # 默认显示所有的协议数据
        else:
            pcaps = get_all_pcap(PCAPS, PD)
            mqtt_pcaps_raw = proto_filter(u'proto', 'MQTT', PCAPS, PD)
            mqtts_pcaps_raw = proto_filter(u'proto', 'MQTT/SSL', PCAPS, PD)
            dicom_pcaps_raw = proto_filter(u'proto', 'DICOM', PCAPS, PD)
        return render_template('./dataanalyzer/database.html', segment='database', pcaps=pcaps,
                               mqtt_pcaps=mqtt_pcaps_raw,
                               dicom_pcaps=dicom_pcaps_raw,
                               mqtts_pcaps=mqtts_pcaps_raw)


@blueprint.route('/protoanalyzer', methods=['POST', 'GET'])
@login_required
def protoanalyzer():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        data_dict = common_proto_statistic(PCAPS)
        pcap_len_dict = pcap_len_statistic(PCAPS)
        pcap_count_dict = most_proto_statistic(PCAPS, PD)
        http_dict = http_statistic(PCAPS)
        http_dict = sorted(http_dict.items(), key=lambda d: d[1], reverse=False)
        http_key_list = list()
        http_value_list = list()
        for key, value in http_dict:
            http_key_list.append(key)
            http_value_list.append(value)
        mqtt_dict = mqtt_statistic(PCAPS)
        mqtt_dict = sorted(mqtt_dict.items(), key=lambda d: d[1], reverse=False)
        mqtt_key_list = list()
        mqtt_value_list = list()
        for key, value in mqtt_dict:
            mqtt_key_list.append(key)
            mqtt_value_list.append(value)

        dicom_dict = dicom_statistic(PCAPS)
        dicom_dict = sorted(dicom_dict.items(), key=lambda d: d[1], reverse=False)
        dicom_key_list = list()
        dicom_value_list = list()
        for key, value in dicom_dict:
            dicom_key_list.append(key)
            dicom_value_list.append(value)

        dns_dict = dns_statistic(PCAPS)
        dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)

        mqtt_pcaps = proto_filter(u'proto', 'MQTT', PCAPS, PD)
        mqtt_analyzer_pcaps = mqtt_decode(mqtt_pcaps)

        return render_template('./dataanalyzer/protoanalyzer.html', segment='protoanalyzer',
                               data=list(data_dict.values()),
                               pcap_len=list(pcap_len_dict.values()),
                               pcap_keys=list(pcap_count_dict.keys()),
                               http_ip_list=http_key_list,
                               http_ip_value=http_value_list,
                               mqtt_ip_list=mqtt_key_list,
                               mqtt_ip_value=mqtt_value_list,
                               dicom_ip_list=dicom_key_list,
                               dicom_ip_value=dicom_value_list,
                               pcap_count=pcap_count_dict,
                               dns_dict=dns_dict,
                               mqtt_pcap_list=mqtt_analyzer_pcaps)


@blueprint.route('/flowanalyzer', methods=['POST', 'GET'])
@login_required
def flowanalyzer():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        time_flow_dict = time_flow(PCAPS)
        host_ip = get_host_ip(PCAPS)
        data_flow_dict = data_flow(PCAPS, host_ip)
        data_ip_dict = data_in_out_ip(PCAPS, host_ip)
        iot_proto_flow_dict = iot_proto_flow(PCAPS)
        most_flow_dict = most_flow_statistic(PCAPS, PD)
        most_flow_dict = sorted(most_flow_dict.items(),
                                key=lambda d: d[1], reverse=True)
        if len(most_flow_dict) > 10:
            most_flow_dict = most_flow_dict[0:10]
        most_flow_key = list()
        for key, value in most_flow_dict:
            most_flow_key.append(key)
        return render_template('./dataanalyzer/flowanalyzer.html', segment='flowanalyzer',
                               time_flow_keys=list(time_flow_dict.keys()),
                               time_flow_values=list(time_flow_dict.values()), data_flow=data_flow_dict,
                               ip_flow=data_ip_dict, most_flow_dict=most_flow_dict, iot_dict=iot_proto_flow_dict)


@blueprint.route('/ipmap/', methods=['POST', 'GET'])
@login_required
def ipmap():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        myip = getmyip()
        if myip:
            host_ip = get_host_ip(PCAPS)
            ipdata = get_ipmap(PCAPS, host_ip)
            geo_dict = ipdata[0]
            ip_value_list = ipdata[1]
            myip_geo = get_geo(myip)
            ip_value_list = [(list(d.keys())[0], list(d.values())[0])
                             for d in ip_value_list]
            return render_template('./dataanalyzer/ipmap.html', segment='ipmap', geo_data=geo_dict,
                                   ip_value=ip_value_list,
                                   mygeo=myip_geo)


@blueprint.route('/<template>')
@login_required
def route_template(template):
    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)
        # if segment == 'index.html':
        #     return redirect()
        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500


# Helper - Extract current page name from request
def get_segment(request):
    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
