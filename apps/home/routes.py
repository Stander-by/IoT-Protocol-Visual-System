# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

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
from .utils.mqtt_analyzer import *
from .utils.data_extract import *
import os

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
        return render_template('home/index.html',segment='index')
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
                return render_template('home/index.html',segment='index')
        else:
            flash('上传失败,请上传允许的数据包格式!')
            return render_template('home/index.html',segment='index')


@blueprint.route('/mqtt_data_extract', methods=['POST', 'GET'])
@login_required
def mqtt_data_extract():
    if PCAPS == None:
        flash("请先上传要分析的数据包!")
        return redirect(url_for('home_blueprint.upload'))
    else:
        mqtt_pcaps = proto_filter(u'proto', 'MQTT', PCAPS, PD)
        mqtt_analyzer_pcaps = mqtt_decode(mqtt_pcaps)
        mqtt_pcap_list = list(mqtt_analyzer_pcaps.values())
        mqtt_publish_list = list()
        for pcap in mqtt_pcap_list:
            if pcap['type'] == 'PUBLISH':
                mqtt_publish_list.append(pcap)
        return render_template('./dataextract/mqtt_data_extract.html', segment='mqtt_data_extract',mqtt_publish_list=mqtt_publish_list)



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
        return render_template('./dataanalyzer/database.html', segment='database',pcaps=pcaps, mqtt_pcaps=mqtt_pcaps_raw)


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
        mqtt_dict = mqtt_statistic(PCAPS)
        ip_list = set(http_dict.keys()).union(mqtt_dict.keys())
        for key in ip_list:
            if key not in http_dict.keys():
                http_dict[key] = 0
            if key not in mqtt_dict.keys():
                mqtt_dict[key] = 0
        ip_key_list = list()
        mqtt_value_list = list()
        http_value_list = list()
        for key, value in mqtt_dict.items():
            ip_key_list.append(key)
            mqtt_value_list.append(value)
            http_value = http_dict[key]
            http_value_list.append(http_value)
        dns_dict = dns_statistic(PCAPS)
        dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
        mqtt_pcaps = proto_filter(u'proto', 'MQTT', PCAPS, PD)
        mqtt_analyzer_pcaps = mqtt_decode(mqtt_pcaps)
        mqtt_pcap_list = list(mqtt_analyzer_pcaps.values())
        return render_template('./dataanalyzer/protoanalyzer.html',segment='protoanalyzer',data=list(data_dict.values()),
                               pcap_len=list(pcap_len_dict.values()), pcap_keys=list(pcap_count_dict.keys()),
                               ip_key=ip_key_list, http_value=http_value_list, mqtt_value=mqtt_value_list,
                               pcap_count=pcap_count_dict, dns_dict=dns_dict,
                               mqtt_pcap_list=mqtt_pcap_list)


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
        return render_template('./dataanalyzer/flowanalyzer.html', segment='flowanalyzer',time_flow_keys=list(time_flow_dict.keys()),
                               time_flow_values=list(time_flow_dict.values()), data_flow=data_flow_dict,
                               ip_flow=data_ip_dict, most_flow_dict=most_flow_dict, iot_dict=iot_proto_flow_dict)


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
