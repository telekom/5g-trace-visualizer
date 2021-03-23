import pandas as pd
import json_parser
import trace_visualizer
import logging
import os.path
import plotly.graph_objects as go
import bz2
import pickle
import xml.etree.ElementTree as ET
from lxml import etree
import collections


def parse_k8s_kpis_as_dataframe(filename):
    # Parses a KPI file consisting of several lines of raw KPIs as output by the following kubectl command
    # kubectl get - -raw / apis / metrics.k8s.io / v1beta1 / pods / >> kpidump.log
    d = json_parser.load_json_file(filename)

    df = pd.DataFrame(data=d)
    df = df.drop_duplicates(subset=['pod', 'container', 'namespace', 'timestamp'])
    df['pod+container'] = df['pod'] + '+' + df['container']

    # CPU is in full cores and memory in MB. Window in seconds
    # pd.set_option('display.max_rows', 100)
    # display(df)

    # Group KPIs per namespace
    data_to_plot = df.groupby(['timestamp', 'namespace']).sum().loc[:, ['cpu', 'memory']]
    data_to_plot['pod count'] = df.groupby(['timestamp', 'namespace']).agg({"pod": "nunique"})
    data_to_plot['container count'] = df.groupby(['timestamp', 'namespace']).agg({"pod+container": "nunique"})
    data_to_plot = data_to_plot.reset_index()

    return data_to_plot


def import_pcap_as_dataframe(pcap_files, http2_ports, wireshark_version, logging_level=logging.INFO):
    # Imports one or more pcap files as a dataframe with the packet parsing implemented in the trace_visualizer code

    # Accept either a single path or a list or paths
    if not type(pcap_files) is list:
        pcap_files = [pcap_files]
    current_verbosity_level = trace_visualizer.application_logger.level
    try:
        # Reduce verbosity
        trace_visualizer.application_logger.setLevel(logging_level)
        packets_df_list = []

        if len(pcap_files) == 0:
            return None

        for idx, file in enumerate(pcap_files):
            if os.path.exists(file):
                pdml_file = trace_visualizer.call_wireshark(wireshark_version, file, http2_ports)
                packet_descriptions = trace_visualizer.import_pdml(pdml_file, diagrams_to_output='raw')
                packets_df = pd.DataFrame(packet_descriptions,
                                          columns=['ip_src', 'ip_dst', 'frame_number', 'protocol', 'msg_description',
                                                   'timestamp', 'timestamp_offset'])
                packets_df['datetime'] = pd.to_datetime(packets_df['timestamp'], unit='s')
                packets_df['msg_description'] = packets_df['msg_description'].str.replace('\\n', '\n')
                packets_df['summary_raw'] = [trace_visualizer.packet_to_str(p).protocol for p in packet_descriptions]

                # Generate summary column
                packets_df['summary'] = packets_df.apply(_generate_summary_row, axis=1)

                packets_df['file'] = file
                packets_df['file_idx'] = idx
                packets_df_list.append(packets_df)

        # Consolidated packet list
        packets_df = pd.concat(packets_df_list, ignore_index=True)
        return packets_df
    except:
        return None
    finally:
        trace_visualizer.application_logger.setLevel(current_verbosity_level)


def _generate_summary_row(x):
    protocol = x['protocol']
    summary_raw = x['summary_raw']
    if protocol == 'NGAP':
        summary = 'NAS ' + \
                  summary_raw.replace('\\n', ',').replace('\n', '').replace('NGAP ', '').replace('NAS ', '').split(',')[
                      -1].strip()
    elif protocol == 'PFCP':
        summary = summary_raw.split('\\n')[-1].strip()
    elif protocol == 'HTTP/2':
        sbi_url_description = trace_visualizer.parse_sbi_type_from_url(summary_raw)
        if sbi_url_description is None:
            summary = ''
        else:
            summary = '{0}, {1}'.format(sbi_url_description.nf.capitalize(), sbi_url_description.call)
        # print('{0}->{1}'.format(summary_raw, summary))
    else:
        summary = ''
    return summary


def datetime_to_str(x):
    # Converts a datetime object to a string (needed for plotting labels from the DataFrame
    datetime_str = x.strftime('%H:%M:%S.%f')
    try:
        return datetime_str.str[:-3]
    except:
        return datetime_str


def generate_scatterplots_for_wireshark_traces(packets_df, filter_column=None, trace_name='Traffic trace', summary_column='summary', timestamp_column='timestamp', datetime_column='datetime', protocol_column='protocol', frame_number_column='frame_number'):
    # Generates a list of scatterplots based on the filtering criteria provided. e.g. if the filtering criteria is
    # 'file', it will generate one scatter plot per 'file' occurrence. If the provided filtering criteria is None, no
    # filter will be used
    
    if datetime_column not in packets_df:
        packets_df[datetime_column] = pd.to_datetime(packets_df[timestamp_column], unit='s')

    # Order by summary (y-axis) so that the axis values are nicely ordered without the need to do it by hand
    packets_df_plot = packets_df[packets_df[summary_column] != ''].sort_values(by=[protocol_column, summary_column])

    if filter_column is None:
        # Generate one single scatterplot
        data_text = 'Frame ' + packets_df_plot[frame_number_column] + ', ' + packets_df_plot[
            datetime_column].apply(datetime_to_str)

        # <extra></extra> removes the trace name
        scatterplot = go.Scatter(x=packets_df_plot[datetime_column],
                                 y=packets_df_plot[summary_column],
                                 mode='markers',
                                 name=trace_name,
                                 showlegend=True,
                                 line={'color': 'gray'},
                                 text=data_text,
                                 hovertemplate='%{text}, %{y}<extra></extra>')
        return scatterplot
    else:
        # Multiple scatterplots
        scatterplots = []
        subplot_criteria = packets_df_plot[filter_column].unique()
        for trace_file in subplot_criteria:
            packets_df_plot_file = packets_df_plot[packets_df_plot[filter_column] == trace_file]
            if len(subplot_criteria) == 1:
                data_text = 'Frame ' + packets_df_plot_file[frame_number_column] + ', ' + packets_df_plot_file[
                    datetime_column].apply(datetime_to_str)
            else:
                data_text = 'Frame ' + packets_df_plot_file['file_idx'].map(str) + '-' + packets_df_plot_file[
                    frame_number_column] + ', ' + packets_df_plot_file[datetime_column].apply(
                    lambda x: x.strftime('%H:%M:%S.%f')[:-3])
            scatterplot = go.Scatter(
                x=packets_df_plot_file[datetime_column],
                y=packets_df_plot_file[summary_column],
                mode='markers',
                name=trace_file,
                showlegend=True,
                line={'color': 'gray'},
                text=data_text,
                hovertemplate='%{text}, %{y}<extra></extra>')
            scatterplots.append(scatterplot)
        return scatterplots


def generate_shape_for_protocol(df, protocol, color, y_axis):
    # Generates a shape of a specified color spanning the specified protocols.
    # Assumes plotting ordered by protocol and then summary
    try:
        first_and_last_rows = df[df['protocol'] == protocol].iloc[[0, -1]]
        return {
                    'type': 'rect',
                    'xref': 'paper',
                    'yref': y_axis,
                    'x0': 0,
                    'x1': 1,
                    'y0': first_and_last_rows.iloc[0]['summary'],
                    'y1': first_and_last_rows.iloc[-1]['summary'],
                    'fillcolor': color,
                    'opacity': 0.3,
                    'line': {
                        'width': 0,
                    }
                }
    except:
        # Case where there are no such eintries
        return None


def get_protocol_shapes(packets_df, y_axis='y4'):
    # Returns shapes highlighting several protocols wherever there is a summary column
    packets_df_plot = packets_df[packets_df.summary != ''].sort_values(by=["protocol", "summary"])
    shapes = [ generate_shape_for_protocol(packets_df_plot, protocol, color, y_axis) for protocol, color in [ ('NGAP', '#8cd98c'), ('HTTP/2', '#b3b3b3'), ('PFCP', '#80b3ff')] ]
    shapes = [ shape for shape in shapes if shape is not None ]
    return shapes


def generate_scatterplot_for_k8s_kpis(data_to_plot, series_name, show_legend, data_text, series_color, plot_column):
    return go.Scatter(
        x=data_to_plot['timestamp'],
        y=data_to_plot[plot_column],
        mode='lines+markers',
        name=series_name,
        line_shape='spline',
        legendgroup=series_name,
        showlegend=show_legend,
        line={'color': series_color},
        text=data_text,
        hovertemplate = '%{text}: %{y:.2f} CPU')


def compressed_pickle(title, data):
    # Used to compress big DataFrames containing packet captures (hundreds of MBs otherwise)
    output_file = title + '.pbz2'
    logging.debug('Saving data to {0}'.format(output_file))
    with bz2.BZ2File(output_file, 'w') as f:
        pickle.dump(data, f)


def decompress_pickle(file):
    # Counterpart to the previous function
    data = bz2.BZ2File(file, 'rb')
    data = pickle.load(data)
    return data


parser = etree.XMLParser(recover=True)
ProtoDescription = collections.namedtuple('ProtoDescription',
                                          'timestamp ip_src, ip_dst, src_port, dst_port, payload, protocol_count frame_num')


def extract_proto_info(proto_info):
    # Wrote a new parse for UP packets
    # For N3:
    # [('ip', <Element proto at 0x1aa25606f40>),
    # ('udp', <Element proto at 0x1aa256069c0>),
    # ('gtp', <Element proto at 0x1aa255e3040>),
    # ('ip', <Element proto at 0x1aa255e3100>),
    # ('udp', <Element proto at 0x1aa255e3180>)]

    # For N6:
    # [('ip', <Element proto at 0x1aa255e36c0>),
    # ('udp', <Element proto at 0x1aa255e3c00>)]

    # Excluding geninfo
    proto_length = len(proto_info) - 1

    gen_info = proto_info[0][1]
    timestamp = float(gen_info.find("field[@name='timestamp']").attrib['value'])
    frame_nr = int(gen_info.find("field[@name='num']").attrib['show'])

    if proto_length < 5:
        # Outer IP header
        ip_proto = proto_info[1][1]
        ip_src = ip_proto.find("field[@name='ip.src']").attrib['show']
        ip_dst = ip_proto.find("field[@name='ip.dst']").attrib['show']
    else:
        # Inner IP header
        ip_proto = proto_info[4][1]
        ip_src = ip_proto.find("field[@name='ip.src']").attrib['show']
        ip_dst = ip_proto.find("field[@name='ip.dst']").attrib['show']

    udp_proto = proto_info[-1][1]
    try:
        src_port = udp_proto.find("field[@name='udp.srcport']").attrib['show']
        dst_port = udp_proto.find("field[@name='udp.dstport']").attrib['show']
        payload = udp_proto.find("field[@name='udp.payload']").attrib['value']
    except:
        # Maybe ICMP?
        src_port = ''
        dst_port = ''
        payload = udp_proto.find("field[@name='data']").attrib['value']
    return (timestamp, ip_src, ip_dst, src_port, dst_port, payload, proto_length, frame_nr)


def parse_packet(packet_str):
    parsed_packet = ET.fromstring(packet_str, parser=parser)
    protos = [(proto.attrib['name'], proto) for proto in parsed_packet if
              proto.attrib['name'] in ['geninfo', 'ip', 'udp', 'gtp', 'icmp']]
    try:
        parsed_protos = extract_proto_info(protos)
    except:
        logging.error('Could not parse frame:\n{0}'.format(packet_str))
        raise
    return parsed_protos


def read_xml_file_line_basis(xml_file):
    # This new function reads (potentially) very big PDML files containing packet traces where the focus is User Plane
    # (UP) with UDP (or ICMP) packets.
    # It is assumed that in order to measure one-way delay, each UP packet has a unique payload (this function
    # only reads the packets though).
    # Tested on my i7-7500U Laptop+SSD I got ca. 2GB PDML/minute parsing performace without much memory consumption
    # (ET.parse filled up the system memory completely)
    start_tag = '<packet>'
    end_tag = '</packet>'
    start_packet_identified = False
    captured_line = ''
    file_size = os.path.getsize(xml_file)
    file_size = round(file_size / (1024 * 1024.0), 2)
    packet_list = []
    logging.debug(f'Opening {xml_file}. Total size: {file_size} MB')
    with open(xml_file, 'r') as f:
        logging.debug(f'Opened {xml_file}')
        for line in f:  # 6
            if start_tag in line:
                start_packet_identified = True
            if start_packet_identified:
                captured_line += line
            if end_tag in line:
                captured_line += line
                start_packet_identified = False
                parsed_packet = parse_packet(captured_line)
                captured_line = ''
                packet_list.append(parsed_packet)

    df = pd.DataFrame(packet_list,
                      columns=['timestamp', 'ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'udp.payload',
                               'protocol_count', 'frame_nr'])
    return df
