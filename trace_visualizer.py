# 5g-trace-visualizer :- convert 5g wireshark data into an UML sequence diagram 
# Copyright (c) 2019, Josep Colom Ikuno, Deutsche Telekom AG 
# contact: opensource@telekom.de 
# This file is distributed under the conditions of the Apache-v2 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

import argparse
import collections
import logging
import os
import os.path
import os.path
import platform
import re
import string
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Pattern, Tuple

from packaging import version

import parsing.http
import yaml_parser
from parsing.common import PacketDescription, PacketType
from parsing.diameter_radius import get_diam_description, parse_diam_proto
from parsing.gtp import parse_gtpv2_proto, gtpv2_req_regex, gtpv2_message_type_regex
from parsing.http import parse_http_proto, http_rsp_regex, http_url_regex, http_method_regex
from parsing.icmp import parse_icmp_proto
from parsing.ipv6 import parse_ipv6_route_advertisement_proto
from parsing.nas import parse_nas_proto, nas_req_regex, nas_message_type_regex, ngap_message_type_regex
from parsing.pfcp import parse_pfcp_proto, pfcp_req_regex, pfcp_message_type_regex

application_logger = logging.getLogger()
application_logger.setLevel(logging.DEBUG)

wireshark_folder = 'wireshark'

ip_regex: Pattern[str] = re.compile(r'Src: ([\d\.:]*), Dst: ([\d\.:]*)')
nfs_regex = re.compile(r':path: \/(.*)\/v.*\/.*')
debug = False

# https://www.w3schools.com/colors/colors_picker.asp
color_actors = '#e6e6e6'
color_nas_req = '#8cd98c'
color_nas_rsp = '#c6ebc6'
color_http2_req = '#b3b3b3'
color_http2_rsp = '#e6e6e6'
color_pfcp_req = '#80b3ff'
color_pfcp_rsp = '#cce0ff'
color_gtpv2_req = '#fffc42'
color_gtpv2_rsp = '#fffd99'

color_diameter_radius_gtpprime = '#D6A4DE'

plant_uml_jar = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'plantuml.jar')

PacketDiagramDescription = collections.namedtuple(
    'PacketDiagramDescription',
    'description ip_src ip_dst protocol')


def packet_to_str(packet, simple_diagrams=False, force_show_frames='', show_timestamp=False):
    protocol = packet.protocols_str
    note_color = ''
    packet_str = ''
    if 'NGAP' in protocol:
        if nas_req_regex.search(packet.msg_description) is not None:
            note_color = ' {0}'.format(color_nas_req)
            protocol = 'NAS req.'
        else:
            note_color = ' {0}'.format(color_nas_rsp)
            protocol = 'NGAP msg. or NAS rsp.'

        # Search NGAP messages
        ngap_matches = ngap_message_type_regex.finditer(packet.msg_description)
        ngap_message_types = [ngap_match.group(1) for ngap_match in ngap_matches if ngap_match is not None]
        if len(ngap_message_types) > 0:
            ngap_seen = set()
            ngap_seen_add = ngap_seen.add
            ngap_message_types = ['NGAP {0}'.format(x) for x in ngap_message_types if
                                  not (x in ngap_seen or ngap_seen_add(x))]

        # Search NAS messages
        nas_matches = nas_message_type_regex.finditer(packet.msg_description)
        nas_message_types = [nas_match.group(1) for nas_match in nas_matches if nas_match is not None]
        if len(nas_message_types) > 0:
            # Remove duplicates: https://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-whilst-preserving-order
            nas_seen = set()
            nas_seen_add = nas_seen.add
            nas_message_types = ['NAS {0}'.format(x) for x in nas_message_types if
                                 not (x in nas_seen or nas_seen_add(x))]

        # Print msg. type
        joint_ngap_nas_msg_types = ngap_message_types + nas_message_types
        if len(joint_ngap_nas_msg_types) > 0:
            protocol = '{0}'.format(',\\n'.join(joint_ngap_nas_msg_types))

    elif 'HTTP' in protocol:
        # Some customized filtering based on what we have seen
        rsp_match = http_rsp_regex.search(packet.msg_description)
        req_match = http_url_regex.search(packet.msg_description)
        if ('404 page not found' in packet.msg_description) or (rsp_match is not None):
            note_color = ' {0}'.format(color_http2_rsp)
            if rsp_match is not None:
                protocol = '{0} {1} rsp.'.format(protocol, rsp_match.group(1))
            else:
                protocol = protocol + ' 404 rsp.'
        elif req_match is not None:
            note_color = ' {0}'.format(color_http2_req)
            protocol = protocol + ' req.'
        else:
            note_color = ' {0}'.format(color_http2_req)
            protocol = protocol + ' req. or rsp. (no HTTP/2 headers)'

        match = list(http_url_regex.finditer(packet.msg_description))
        if len(match) > 0:
            method = ''
            method_match_all = http_method_regex.finditer(packet.msg_description)
            protocols = []
            for idx, method_match in enumerate(method_match_all):
                method = '{0} '.format(method_match.group(1))
                url_split = match[idx].group(1).split('?')
                protocols.append('{0} {1}'.format(method, url_split[0]))
            protocol = '{0}\\n'.format(protocol) + '\\n'.join(protocols)

    elif 'PFCP' in protocol:
        if pfcp_req_regex.search(packet.msg_description) is not None:
            note_color = ' {0}'.format(color_pfcp_req)
            protocol = protocol + ' req.'
        else:
            note_color = ' {0}'.format(color_pfcp_rsp)
            protocol = protocol + ' rsp.'

        match = pfcp_message_type_regex.search(packet.msg_description)
        if match is not None:
            protocol = '{0}\\n{1}'.format(protocol, match.group(1))

    elif 'GTPv2' in protocol:
        if gtpv2_req_regex.search(packet.msg_description) is not None:
            note_color = ' {0}'.format(color_gtpv2_req)
            protocol = protocol + ' req.'
        else:
            note_color = ' {0}'.format(color_gtpv2_rsp)
            protocol = protocol + ' req., rsp. or notification'

        match = gtpv2_message_type_regex.search(packet.msg_description)
        if match is not None:
            protocol = '{0}\\n{1}'.format(protocol, match.group(1))

    elif 'Diameter' in protocol or 'RADIUS' in protocol or "GTP'" in protocol:
        note_color = ' {0}'.format(color_diameter_radius_gtpprime)
        protocol = get_diam_description(packet)

    if show_timestamp:
        try:
            dt_object = datetime.fromtimestamp(packet.timestamp)
            if dt_object.tzinfo is None:
                tz_str = ''
            else:
                tz_str = ' {0}'.format(dt_object.tzinfo)
            timestamp_hour = ' ({0}:{1}:{2}.{3}{4})'.format(dt_object.hour, dt_object.minute, dt_object.second,
                                                            dt_object.microsecond / 1000, tz_str)
        except:
            timestamp_hour = ''
        protocol = '{0}\\n+{1:.3f}s{2}'.format(protocol, packet.timestamp_offsett, timestamp_hour)

    frame_number = packet[2]
    packet_str = packet_str + '"{0}" -> "{1}": {2}, {3}\n'.format(packet.ip_src, packet.ip_dst, frame_number, protocol)
    packet_str = packet_str + '\nnote right{0}\n'.format(note_color)

    force_show_frames = [e.strip() for e in force_show_frames.split(',')]
    if simple_diagrams and frame_number not in force_show_frames:
        packet_payload = ''
    else:
        packet_payload = packet.msg_description

    if packet_payload != '':
        packet_str = packet_str + '**{0} to {1}**\n{2}\n'.format(packet.ip_src, packet.ip_dst, packet_payload)
    else:
        packet_str = packet_str + '**{0} to {1}**\n'.format(packet.ip_src, packet.ip_dst)
    packet_str = packet_str + 'end note\n'
    packet_str = packet_str + '\n'
    return PacketDiagramDescription(packet_str, packet.ip_src, packet.ip_dst, protocol)


def move_from_list_to_list(origin, destination, criteria):
    if criteria is None:
        to_move = origin.copy()
    else:
        to_move = []
        for e_criteria in criteria:
            to_move.extend([e for e in origin if e[2] == e_criteria])

    for e in to_move:
        destination.append(e)
        origin.remove(e)

    return len(to_move)


def order_participants(participants, packet_descriptions_str, force_order_str):
    # The order is UEs, AMF-NAS, AMF, SMF, NRF, UPF, AUSF, rest
    participants_ordered = []

    # UEs are the ones sending NAS registration requests
    ue_participants = set([packet[1] for packet in packet_descriptions_str if
                           'Registration request (0x41)' in packet[3] or 'PDU session establishment request (0xc1)' in
                           packet[3] or 'Deregistration request (UE originating) (0x45)' in packet[3]])

    # NFs
    amf_n1_participants = set([packet[2] for packet in packet_descriptions_str if 'NGAP req.' in packet[3]])
    amf_sbi_participants = set(
        [packet[2] for packet in packet_descriptions_str if ':path: /amf/' in packet[0] or ':path: /namf' in packet[0]])
    smf_sbi_participants = set(
        [packet[2] for packet in packet_descriptions_str if ':path: /smf/' in packet[0] or ':path: /nsmf' in packet[0]])
    smf_pfcp_participants = set([packet[1] for packet in packet_descriptions_str if 'PFCP req.' in packet[3]])
    upf_pfcp_participants = set([packet[2] for packet in packet_descriptions_str if 'PFCP req.' in packet[3]])
    ausf_sbi_participants = set([packet[2] for packet in packet_descriptions_str if
                                 ':path: /ausf/' in packet[0] or ':path: /nausf' in packet[0]])
    udm_sbi_participants = set(
        [packet[2] for packet in packet_descriptions_str if ':path: /udm/' in packet[0] or ':path: /nudm' in packet[0]])
    ndl_sbi_participants = set([packet[2] for packet in packet_descriptions_str if
                                ':path: /udr/' in packet[0] or ':path: /nudr' in packet[0] or ':path: /nudsf' in packet[
                                    0]])
    nrf_sbi_participants = set(
        [packet[2] for packet in packet_descriptions_str if ':path: /nrf/' in packet[0] or ':path: /nnrf' in packet[0]])

    # Order one-by-one
    participants = participants.copy()
    move_from_list_to_list(participants, participants_ordered, ue_participants)
    move_from_list_to_list(participants, participants_ordered, amf_n1_participants)
    move_from_list_to_list(participants, participants_ordered, amf_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, smf_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, smf_pfcp_participants)
    move_from_list_to_list(participants, participants_ordered, upf_pfcp_participants)
    move_from_list_to_list(participants, participants_ordered, ausf_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, udm_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, ndl_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, nrf_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, None)

    # Reorder participants with force_order list
    force_order = [e.strip() for e in force_order_str.split(',')]
    if len(force_order) > 0:
        logging.debug('Force-ordering participants: {0}'.format(force_order))
        new_participants_ordered = []
        for forced_participant_name in force_order:
            participants_to_move = [p[2] for p in participants_ordered if
                                    '"{0}"'.format(forced_participant_name) == p[1]]
            moved_n = move_from_list_to_list(participants_ordered, new_participants_ordered, participants_to_move)
        # Move rest
        move_from_list_to_list(participants_ordered, new_participants_ordered, None)
        participants_ordered = new_participants_ordered

    logging.debug('Final participant order: {0}'.format(participants_ordered))
    return participants_ordered


def output_puml(output_file,
                packet_descriptions,
                print_legend,
                participants=None,
                simple_diagrams=False,
                force_show_frames='',
                force_order='',
                show_timestamp=False):
    # Generate full packet descriptions first, as we first want to check participants
    packet_descriptions_str = [packet_to_str(packet, simple_diagrams, force_show_frames, show_timestamp) for packet in
                               packet_descriptions];

    logging.debug('Simple diagrams: {0}'.format(simple_diagrams))
    # Second pass if simple diagrams are wanted
    if simple_diagrams:
        packet_descriptions_str_for_ordering = [
            packet_to_str(packet, simple_diagrams=False, show_timestamp=show_timestamp) for packet in
            packet_descriptions]
    else:
        packet_descriptions_str_for_ordering = packet_descriptions_str

    participants = order_participants(participants, packet_descriptions_str_for_ordering, force_order)

    logging.debug('Outputting PlantUML file to {0}'.format(output_file))
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('@startuml\n')
        # Does not look good
        # f.write('title {0}\n'.format(file))
        # f.write('\n')

        # Formatting
        f.write('skinparam shadowing false\n')
        f.write('skinparam NoteBorderColor white\n')

        f.write('skinparam sequence {\n')
        f.write('    ArrowColor black\n')
        f.write('    LifeLineBorderColor black\n')
        f.write('    LifeLineBackgroundColor black\n')
        f.write('    ParticipantBorderColor white\n')
        f.write('    ParticipantBackgroundColor {0}\n'.format(color_actors))
        f.write('}\n')

        # Legend
        if print_legend:
            f.write('legend top left\n')
            for participant in participants:
                legend_str = '{0}: {1}\n'.format(participant[2], ', '.join(participant[3]))
                f.write(legend_str)
            f.write('endlegend\n')
            f.write('\n')

        # Participants
        for participant in participants:
            participant_str = '{0} {1}\n'.format(participant[0], participant[1])
            # Remove participant name if it contains ":", such as "::1"
            # This is due to PlantUML not being able to accept the ":" character in the "as" parameter
            participant_match = re.match(r'participant \"(.*)\" as (.*)', participant_str)
            if participant_match is not None and ':' in participant_match.group(2):
                logging.debug(
                    'Removing "{0}" because "as" parameter does not support colons'.format(
                        participant_str.replace('\n', '')))
            else:
                f.write(participant_str)
        f.write('\n')

        # Packets
        for packet in packet_descriptions_str:
            f.write(packet[0])

        f.write('@enduml\n')


def generate_new_participants(participants, new_packet_descriptions):
    # Source and destination as key
    packet_participants = set(
        [packet[0] for packet in new_packet_descriptions] + [packet[1] for packet in new_packet_descriptions])
    new_participants = []
    current_participants = {}
    for packet_participant in packet_participants:
        if packet_participant in current_participants:
            # Current IP, keep name as-is
            new_participants.append(current_participants[packet_participant])
        else:
            new_participants.append(('participant', '"{0}"'.format(packet_participant), packet_participant, {}, 0))

    return new_participants


def packet_sub(packet,
               mapping,
               idx,
               show_selfmessages=False):
    src = packet.ip_src
    dst = packet.ip_dst
    old_src = src
    old_dst = dst

    sub_done = False
    if src in mapping:
        src = mapping[src][idx]
        sub_done = True
    if dst in mapping:
        dst = mapping[dst][idx]
        sub_done = True

    # Clean up self-messages for clarity
    if (src == dst) and not show_selfmessages:
        return None

    # Return packet with substituted src and dst (e.g. pod name)
    if not sub_done:
        new_packet = PacketDescription(src, dst, packet.frame_number, packet.protocols_str, packet.msg_description,
                                       packet.timestamp, packet.timestamp_offsett)
    else:
        try:
            current_description = packet.msg_description
            if ' (IPs)\n' not in current_description:
                new_description = '{0} to {1} (IPs)\n{2}'.format(old_src, old_dst, packet.msg_description)
            else:
                new_description = packet.msg_description
        except:
            new_description = '{0} to {1} (IPs)\n{2}'.format(old_src, old_dst, packet.msg_description)
        new_packet = PacketDescription(src, dst, packet.frame_number, packet.protocols_str, new_description,
                                       packet.timestamp, packet.timestamp_offsett)
    return new_packet


def add_participants_if_not_there(new_participants, participants_to_extend):
    current_participants = [participant[1] for participant in participants_to_extend]
    participants_to_add = [participant for participant in new_participants if
                           participant[1] not in current_participants]
    participants_to_extend.extend(participants_to_add)


def substitute_pod_ips_with_name(participants, packet_descriptions, ip_to_pod_mapping, participants_to_append=None,
                                 show_selfmessages=False):
    return substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, 0, participants_to_append,
                                       show_selfmessages)


def substitute_pod_ips_with_namespace(participants, packet_descriptions, ip_to_pod_mapping, participants_to_append=None,
                                      show_selfmessages=False):
    return substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, 1, participants_to_append,
                                       show_selfmessages)


def substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, mapping_idx,
                                participants_to_append=None, show_selfmessages=False):
    new_packet_descriptions = [packet_f for packet_f in
                               [packet_sub(packet, ip_to_pod_mapping, mapping_idx, show_selfmessages) for packet in
                                packet_descriptions] if packet_f is not None]
    new_participants = generate_new_participants(participants, new_packet_descriptions)
    if participants_to_append is not None:
        add_participants_if_not_there(new_participants, participants_to_append)
    return new_participants, new_packet_descriptions


def map_vm_ips(output_to_generate, ip_to_vm_mapping, show_selfmessages=False):
    suffix = output_to_generate[0]
    packet_descriptions = output_to_generate[1]
    participants = output_to_generate[2]
    print_legend = output_to_generate[3]

    new_participants, new_packet_descriptions = substitute_ips_with_mapping(participants, packet_descriptions,
                                                                            ip_to_vm_mapping, 0,
                                                                            show_selfmessages=show_selfmessages)
    return (suffix, new_packet_descriptions, new_participants, print_legend)


def character_is_printable(x):
    return x in string.printable


def read_cleanup_and_load_pdml_file(file_path):
    # The exported PDML file may contain "gremlin characters" which the parse does NOT like. So first we have to cleanup
    logging.debug('Cleaning up PDML file {0}'.format(file_path))
    with open(file_path, 'r', encoding='utf8') as f:
        content = f.read()
        filtered_content = ''.join(filter(character_is_printable, content))
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(filtered_content)
    logging.debug('Finished cleaning up PDML file')
    logging.debug('Parsing PDML file {0}'.format(file_path))
    parsed_et = ET.parse(file_path)
    logging.debug('Finished parsing PDML file')
    return parsed_et


def import_pdml(file_paths,
                pod_mapping=None,
                limit=100,
                show_heartbeat=False,
                vm_mapping=None,
                ignorehttpheaders=None,
                diagrams_to_output='',
                simple_diagrams=False,
                force_show_frames='',
                force_order='',
                ignore_spurious_tcp_retransmissions=True,
                ignore_pfcp_duplicate_packets=True,
                show_timestamp=False,
                show_selfmessages=False,
                custom_packet_filter: str = None,
                custom_packet_filter_ip_labels: Tuple[str, str, str, str] = None):
    """
    Imports a PDML file
    :param custom_packet_filter: A custom filter that can be used in case your capture uses other packet formats
    (e.g. exports from proprietary and/or internal tools) such as proto[@name='ip'] or proto[@name='custom_protocol']
    :param custom_packet_filter_ip_labels: if custom_packet_filter is used, this specifies how the IP src and destination are parsed
    :param file_paths:
    :param pod_mapping:
    :param limit:
    :param show_heartbeat:
    :param vm_mapping:
    :param ignorehttpheaders:
    :param diagrams_to_output:
    :param simple_diagrams:
    :param force_show_frames:
    :param force_order:
    :param ignore_spurious_tcp_retransmissions:
    :param ignore_pfcp_duplicate_packets:
    :param show_timestamp:
    :param show_selfmessages:
    :return:
    """
    logging.debug('PDML file path(s): {0}'.format(file_paths))

    if ignorehttpheaders is None:
        ignorehttpheaders_list = []
    else:
        ignorehttpheaders_list = [e.strip() for e in ignorehttpheaders.split(',')]
        logging.debug('HTTP/2 headers to ignore: {0}'.format(ignorehttpheaders_list))

    # First file is the main PDML file. Rest are alternatives
    file_path = file_paths[0]
    if len(file_paths) > 1:
        alternative_file_paths = file_paths[1:]
    else:
        alternative_file_paths = []

    logging.debug('Importing main file {0}'.format(file_path))
    if not os.path.exists(file_path):
        logging.debug('File does not exist')
        return None
    tree = read_cleanup_and_load_pdml_file(file_path)
    root = tree.getroot()

    logging.debug('Importing {0} alternative files'.format(len(alternative_file_paths)))
    alternative_packet_iterators = []
    for alternative_file_path in alternative_file_paths:
        logging.debug('Alternative PDML file: {0}'.format(alternative_file_path))
        alternative_tree = read_cleanup_and_load_pdml_file(alternative_file_path)
        alternative_root = alternative_tree.getroot()
        alternative_packet_iterators.append(list(alternative_root.iter('packet')))

    # Check for packets with "showname="[Malformed Packet" and substitute with alternative version if so required
    filtered_root_packets = []
    logging.debug('Checking for malformed packets (can decode with more than one WS version)')
    for idx, packet in enumerate(root.iter('packet')):
        # Note that _ws.malformed is always in the packet root while _ws.expert errors are found within the packet
        packet_is_malformed = (packet.find("proto[@name='_ws.malformed']") is not None) or (
                packet.find(".//field[@name='_ws.expert']") is not None)
        if not packet_is_malformed:
            filtered_root_packets.append(packet)
        else:
            # Find candidate
            logging.debug('WARNING: Packet {0} is malformed'.format(idx))
            alternative_found = False
            for alternative_packet_iterator in alternative_packet_iterators:
                alternative_packet = alternative_packet_iterator[idx]
                alternative_packet_is_malformed = (alternative_packet.find("proto[@name='_ws.malformed']") is not None)
                if not alternative_packet_is_malformed:
                    logging.debug('Alternative for packet {0} found'.format(idx))
                    filtered_root_packets.append(alternative_packet)
                    alternative_found = True
                    continue
            # No candidate found
            if not alternative_found:
                logging.debug('Alternative for packet {0} not found. Using original packet'.format(idx))
                filtered_root_packets.append(packet)

    packet_descriptions = []
    destinations = set()

    if root.tag == 'pdml':
        logging.debug('Root tag is "pdml": OK')
    else:
        logging.debug('Root tag is "pdml": ERROR')
        return None

    last_pfcp_message = None
    first_timestamp = None
    for idx, packet in enumerate(filtered_root_packets):
        packet_type = PacketType.UNKNOWN
        frame_number = packet.find("proto[@name='geninfo']/field[@name='num']").attrib['show']
        # Extract timestamp
        try:
            frame_timestamp = float(packet.find("proto[@name='geninfo']/field[@name='timestamp']").attrib['value'])
            if first_timestamp is None:
                first_timestamp = frame_timestamp
        except:
            frame_timestamp = None

        # Fixes #1 and #3, thanks cfalcken!
        # I wonder what would happen if we have IP-in-IP with different IP versions, but I wonder if anyone will really do something like that...
        ipv4_protos = packet.findall("proto[@name='ip']")
        ipv6_protos = packet.findall("proto[@name='ipv6']")
        custom_protos = []
        if custom_packet_filter is not None and custom_packet_filter != '':
            try:
                custom_proto_filter_str = f"proto[@name='{custom_packet_filter}']"
                logging.debug(f"Applying custom packet filter {custom_proto_filter_str}")
                custom_protos = packet.findall(custom_proto_filter_str)
            except:
                logging.error(f"Could not apply custom packet filter {custom_proto_filter_str}")
        # Skip ARP and similars (see #3). Should only happen if you directly import a PDML file.
        if len(ipv4_protos) == 0 and len(ipv6_protos) == 0 and len(custom_protos) == 0:
            logging.debug('Skipping non-IP packet {0}'.format(idx))
            continue
        try:
            ip_showname = packet.findall("proto[@name='ip']")[-1].attrib['showname']
            packet_type = PacketType.IPv4
        except:
            try:
                ip_showname = packet.findall("proto[@name='ipv6']")[-1].attrib['showname']
                packet_type = PacketType.IPv6
            except:
                ip_showname = packet.findall(custom_proto_filter_str)[-1].attrib['showname']
                packet_type = PacketType.CUSTOM

        try:
            logging.debug('{0}: Frame {1}. Parsing as packet type {2}'.format(frame_number, ip_showname, packet_type))
            if packet_type != PacketType.CUSTOM:
                ip_match = ip_regex.search(ip_showname)
                ip_src = ip_match.group(1)
                ip_dst = ip_match.group(2)
            else:
                # Fake source/destination just as filler
                if (custom_packet_filter_ip_labels is not None) and (len(custom_packet_filter_ip_labels) >= 4):
                    filter_src = custom_packet_filter_ip_labels[0]
                    attr_src = custom_packet_filter_ip_labels[1]
                    filter_dst = custom_packet_filter_ip_labels[2]
                    attr_dst = custom_packet_filter_ip_labels[3]
                    ip_src = 'Unknown'
                    ip_dst = 'Unknown'
                    try:
                        filter_src_els = packet.findall('.//' + filter_src)
                        filter_dst_els = packet.findall('.//' + filter_dst)
                        ip_src = filter_src_els[-1].attrib[attr_src]
                        ip_dst = filter_dst_els[-1].attrib[attr_dst]
                    except:
                        traceback.print_exc()
                    logging.debug(f'Parsed custom protocol IP src: {ip_src}, IP dst: {ip_dst}')

        except:
            logging.debug('Skipped frame {0}'.format(frame_number))
            continue

        gtp_proto = packet.find("proto[@name='gtp']")
        if gtp_proto is not None:
            try:
                ip_showname = packet.findall("proto[@name='ip']")[-2].attrib['showname']
                packet_type = 'ipv4'
            except:
                ip_showname = packet.findall("proto[@name='ipv6']")[-2].attrib['showname']
                packet_type = 'ipv6'
            try:
                logging.debug('{0} (GTP): {1}'.format(frame_number, ip_showname))
                ip_match = ip_regex.search(ip_showname)
                ip_src = ip_match.group(1)
                ip_dst = ip_match.group(2)
            except:
                pass

        # For 5GC
        # Fix case (see free5GC trace) where there are several elements (not correct but well...)
        ngap_proto = packet.findall("proto[@name='ngap']")
        if len(ngap_proto) == 0:
            ngap_proto = None
        elif len(ngap_proto) == 1:
            ngap_proto = ngap_proto[0]

        # Support for several HTTP/2 proto elements
        http2_proto = packet.findall("proto[@name='http2']")
        if len(http2_proto) == 0:
            http2_proto = None
        elif len(http2_proto) == 1:
            http2_proto = http2_proto[0]

        # We found one trace where the PFCP protocol was signaled as ICMP, which messed with the trace
        pfcp_proto = packet.find(".//proto[@name='pfcp']")

        gtpv2_proto = packet.find("proto[@name='gtpv2']")

        # For IPv6 route advertisements
        route_advertisement_proto = packet.find("proto[@name='icmpv6']")
        # Only take into account if it is GTP encapsulated traffic
        if route_advertisement_proto is not None and gtp_proto is None:
            route_advertisement_proto = None

        # ICMP traffic
        icmp_proto = packet.find("proto[@name='icmp']")

        # For EPC
        diameter_proto = packet.find("proto[@name='diameter']")
        radius_proto = packet.find("proto[@name='radius']")
        gtpprime_proto = packet.find("proto[@name='gtpprime']")

        packet_has_http2 = False
        packet_has_ngap = False
        packet_has_pfcp = False
        packet_has_gtpv2 = False
        packet_has_ipv6_route_advertisement = False
        packet_has_icmp = False

        packet_has_diameter = False
        packet_has_radius = False
        packet_has_gtpprime = False

        protocols = []
        if ngap_proto is not None:
            packet_has_ngap = True
            protocols.append('NGAP')
        if http2_proto is not None:
            packet_has_http2 = True
            protocols.append('HTTP/2')
        if pfcp_proto is not None:
            packet_has_pfcp = True
            protocols.append('PFCP')
        if gtpv2_proto is not None:
            packet_has_gtpv2 = True
            protocols.append('GTPv2')
        if diameter_proto is not None:
            packet_has_diameter = True
            protocols.append('Diameter')
        if radius_proto is not None:
            packet_has_radius = True
            protocols.append('RADIUS')
        if gtpprime_proto is not None:
            packet_has_gtpprime = True
            protocols.append("GTP'")
        if route_advertisement_proto is not None:
            packet_has_ipv6_route_advertisement = True
            protocols.append("IPv6 route advertisement on N3")
        if icmp_proto is not None:
            packet_has_icmp = True
            if gtp_proto is None:
                # Unencapsulated
                protocols.append("ICMP")
            else:
                # Encapsulated
                protocols.append("GTP<ICMP>")
        if len(protocols) == 0:
            protocols_str = ''
        else:
            protocols_str = ','.join(protocols)

        # Fix strange case that sometimes PFCP messages are shown in the GUI as ICMP destination unreachable (no idea why this happens)
        if packet_has_pfcp and packet_has_icmp:
            logging.debug('Fixing wrong PFCP message shown as ICMP')
            packet_has_icmp = False

        if debug:
            logging.debug('Frame {0} ({4}): {1} to {2}, {3}'.format(idx, ip_src, ip_dst, protocols_str, frame_number))
        msg_description = ''
        if packet_has_http2:
            http2_request = parse_http_proto(frame_number, http2_proto, ignorehttpheaders_list,
                                             ignore_spurious_tcp_retransmissions, packet)
            if debug:
                logging.debug('SBI')
                logging.debug(http2_request)
            msg_description = http2_request
        if packet_has_ngap:
            nas_request = parse_nas_proto(frame_number, ngap_proto)
            if debug:
                logging.debug('NAS')
                logging.debug(nas_request)
            msg_description = nas_request
        if packet_has_gtpv2:
            gtpv2_request = parse_gtpv2_proto(frame_number, gtpv2_proto, show_heartbeat)
            if debug:
                logging.debug('GTPv2')
                logging.debug(gtpv2_request)
            msg_description = gtpv2_request
        if diameter_proto:
            diameter_request = parse_diam_proto(frame_number, diameter_proto, show_heartbeat)
            if debug:
                logging.debug('Diameter')
                logging.debug(diameter_request)
            msg_description = diameter_request
        if radius_proto:
            radius_request = parse_gtpv2_proto(frame_number, radius_proto, show_heartbeat)
            if debug:
                logging.debug('RADIUS')
                logging.debug(radius_request)
            msg_description = radius_request
        if gtpprime_proto:
            gtpprime_request = parse_gtpv2_proto(frame_number, gtpprime_proto, show_heartbeat)
            if debug:
                logging.debug("GTP'")
                logging.debug(gtpprime_request)
            msg_description = gtpprime_request
        if packet_has_pfcp:
            pfcp_request = parse_pfcp_proto(frame_number, pfcp_proto, show_heartbeat, ignore_pfcp_duplicate_packets,
                                            last_pfcp_message)
            last_pfcp_message = pfcp_request
            if debug:
                logging.debug('PFCP')
                logging.debug(pfcp_request)
            msg_description = pfcp_request
        if packet_has_ipv6_route_advertisement:
            ipv6_route_advertisement = parse_ipv6_route_advertisement_proto(frame_number, route_advertisement_proto)
            if debug:
                logging.debug('IPv6 route advertisement')
                logging.debug(ipv6_route_advertisement)
            msg_description = ipv6_route_advertisement
        if packet_has_icmp:
            icmp = parse_icmp_proto(frame_number, icmp_proto, gtp_proto)
            if debug:
                logging.debug('ICMP')
                logging.debug(icmp)
            msg_description = icmp

        # Calculate timestamp offsett
        if first_timestamp is not None:
            frame_offsett = frame_timestamp - first_timestamp
        else:
            frame_offsett = None

        # None are messages that are deliberately marked as fragments
        if msg_description is not None:
            packet_descriptions.append(
                PacketDescription(ip_src, ip_dst, frame_number, protocols_str, msg_description, frame_timestamp,
                                  frame_offsett))
        destinations.add(ip_dst)
        destinations.add(ip_src)

    all_destinations = dict([(d, set()) for d in destinations])

    # Hypothesis of what each IP is
    for packet_description in packet_descriptions:
        destination = packet_description.ip_dst
        description = packet_description.msg_description

        # SBI-based
        if (description is not None) and (description != ''):
            match = nfs_regex.search(description)
            if match is not None:
                all_destinations[destination].add(match.group(1))

        # NAS
        if 'NGAP' in packet_description.protocols_str:
            all_destinations[destination].add('N1')

    # Generate participant descriptions for description and add order (key)
    participants = []
    for destination, uses in all_destinations.items():
        participant_type = 'participant'
        participant_description = ''
        if len(uses) != 0:
            joined_uses = '\\n'.join(uses) + '\\n({0})'.format(destination)
            participants.append(
                (participant_type, '"{0}" as {1}'.format(joined_uses, destination), destination, uses, None))
        else:
            participants.append((participant_type, '"{0}"'.format(destination), destination, uses, None))

    # Participant sorting now moved to the end (PUML generation)
    # participants = sorted(participants, key=lambda x: x[4])

    # Three types of output: ip (plain), k8s_pod, k8s_namespace
    outputs_to_generate = {}
    outputs_to_generate['ip'] = ('', packet_descriptions, participants, False)  # Remove ugly legend

    if diagrams_to_output == 'raw':
        return packet_descriptions

    # Pod information if  available
    if pod_mapping is not None:
        logging.debug('Applying pod and pod namespace mapping')
        pod_mapping_list = pod_mapping.split(',')
        ip_to_pod_mapping = yaml_parser.load_yaml_list(pod_mapping_list)
        if ip_to_pod_mapping is not None:
            participants_per_pod, packet_descriptions_per_pod = substitute_pod_ips_with_name(participants,
                                                                                             packet_descriptions,
                                                                                             ip_to_pod_mapping,
                                                                                             show_selfmessages=show_selfmessages)
            participants_per_namespace, packet_descriptions_per_namespace = substitute_pod_ips_with_namespace(
                participants, packet_descriptions, ip_to_pod_mapping, show_selfmessages=show_selfmessages)
        outputs_to_generate['k8s_pod'] = ('_pod', packet_descriptions_per_pod, participants_per_pod, False)
        outputs_to_generate['k8s_namespace'] = (
            '_namespace', packet_descriptions_per_namespace, participants_per_namespace, False)

    if vm_mapping is not None:
        ip_to_vm_mapping = yaml_parser.load_yaml_vm(vm_mapping)
        outputs_to_generate = {k: map_vm_ips(output_to_generate, ip_to_vm_mapping, show_selfmessages=show_selfmessages)
                               for k, output_to_generate in outputs_to_generate.items()}

    # Generate PlantUML diagram
    dirname, file_name = os.path.split(file_path)
    file, ext = os.path.splitext(file_name)

    # Generate outputs for all of the generated mappings
    diagrams_to_output = [e.strip() for e in diagrams_to_output.split(',')]
    output_files = []
    for k, output_to_generate in outputs_to_generate.items():
        if k not in diagrams_to_output:
            logging.debug('Skipping generating Plant UML file for {0}'.format(k))
            continue
        logging.debug('Generating Plant UML file for {0}'.format(k))
        suffix = output_to_generate[0]
        packet_descriptions = output_to_generate[1]
        print_legend = output_to_generate[3]
        participants = output_to_generate[2]

        packet_descriptions_slices = [packet_descriptions[i:i + limit] for i in
                                      range(0, len(packet_descriptions), limit)]
        if len(packet_descriptions_slices) == 0:
            pass
        # All packets fit into one file
        elif len(packet_descriptions_slices) == 1:
            output_file = os.path.join(dirname, '{0}{1}.puml'.format(file, suffix))
            output_puml(output_file,
                        packet_descriptions_slices[0],
                        print_legend,
                        participants,
                        simple_diagrams,
                        force_show_frames,
                        force_order,
                        show_timestamp)
            output_files.append(output_file)
        # Several files (many messages)
        else:
            for counter, packet_descriptions_slice in enumerate(packet_descriptions_slices):
                output_file = os.path.join(dirname, '{0}{1}_{2:03d}.puml'.format(file, suffix, counter))
                output_puml(output_file,
                            packet_descriptions_slice,
                            print_legend,
                            participants,
                            simple_diagrams,
                            force_show_frames,
                            force_order,
                            show_timestamp)
                output_files.append(output_file)

    return output_files


def call_wireshark(wireshark_versions, platform, input_file_str, http2ports_string, mode=None, check_if_exists=False,
                   additional_protocols=None):
    wireshark_versions_list = [e.strip() for e in wireshark_versions.split(',')]
    output_files = []
    successful_wireshark_call = False
    for wireshark_version in wireshark_versions_list:
        if wireshark_version == 'latest':
            wireshark_version = get_wireshark_portable_last_version()
            if wireshark_version is None:
                logging.error('Could not find wireshark version(s) in {0} folder'.format(wireshark_folder))
                continue
            else:
                logging.info('Using latest version found: {0}'.format(wireshark_version))

        logging.debug('Preparing call for Wireshark version {0}'.format(wireshark_version))
        output_file = call_wireshark_for_one_version(
            wireshark_version,
            platform,
            input_file_str,
            http2ports_string,
            mode,
            check_if_exists,
            additional_protocols=additional_protocols
        )
        output_files.append(output_file)
        successful_wireshark_call = True

    if not successful_wireshark_call:
        logging.error(
            'Could not successfully call Wireshark to parse files. Input parameters: version={0}; input file(s)={1}; HTTP/2 ports={2}'
            .format(wireshark_versions, input_file_str, http2ports_string))
        exit(1)
    return output_files


def get_wireshark_portable_last_version():
    try:
        found_versions = [(version.parse(e.group(1)), e.group(1)) for e in
                          [re.search(r'WiresharkPortable_(.*)', e) for e in os.listdir(wireshark_folder) if
                           os.path.isdir(os.path.join(wireshark_folder, e))] if e is not None]
        found_versions.sort(reverse=True, key=lambda x: x[0])
        last_Version = found_versions[0][1]
        logging.debug('Wireshark last version found: {0}'.format(last_Version))
        return last_Version
    except:
        logging.error('Could not parse Wireshark versions from folder')
        traceback.print_exc()
    return None


def get_wireshark_portable_folder(wireshark_version):
    return os.path.join(os.path.dirname(
        os.path.realpath(__file__)),
        wireshark_folder,
        'WiresharkPortable_{0}'.format(wireshark_version),
        'App',
        'Wireshark')


def call_wireshark_for_one_version(
        wireshark_version,
        platform,
        input_file_str,
        http2ports_string,
        mode=None,
        check_if_exists=False,
        additional_protocols: str = None):
    logging.debug('Wireshark call for {0}. Version {1}, HTTP/2 ports: {2}'.format(input_file_str, wireshark_version,
                                                                                  http2ports_string))
    input_files = input_file_str.split(',')
    merged = False
    if len(input_files) > 1:
        filename, file_extension = os.path.splitext(input_files[0])
        output_filename = '{0}_{2}_merged{1}'.format(filename, file_extension, wireshark_version)
        mergecap_path = os.path.join(get_wireshark_portable_folder(wireshark_version), 'mergecap')
        if wireshark_version == 'OS' and (platform == 'Linux'):
            mergecap_path = "/usr/bin/mergecap"
        elif wireshark_version == 'OS' and (platform != 'Linux'):
            mergecap_path = 'mergecap'
        mergecap_command = [
            mergecap_path,
            '-w',
            output_filename,
        ]
        for input_filename in input_files:
            mergecap_command.append(input_filename)
        logging.debug('Merging pcap files to {0}'.format(output_filename))
        logging.debug(mergecap_command)
        subprocess.run(mergecap_command)
        input_file = output_filename
        merged = True
    else:
        input_file = input_files[0]

    filename, file_extension = os.path.splitext(input_file)
    if file_extension == '.pdml':
        logging.debug('No need to invoke tshark. PDML file already input')
        return input_file

    # Add option to not use a Wireshark portable version but rather the OS-installed one
    if wireshark_version == 'OS':
        if (platform == 'Linux'):
            tshark_path = "/usr/bin/tshark"
        else:
            tshark_path = os.path.join('tshark')
    else:
        tshark_path = os.path.join(get_wireshark_portable_folder(wireshark_version), 'tshark')
    logging.debug('tshark path: {0}'.format(tshark_path))

    # Add folder check to make more understandable error messages
    tshark_folder = get_wireshark_portable_folder(wireshark_version)
    if not os.path.isdir(tshark_folder) and not (platform == 'Linux') and (wireshark_version != 'OS'):
        raise FileNotFoundError('Could not find tshark on path {0}'.format(tshark_path))

    if not merged:
        output_file = '{0}_{1}.pdml'.format(filename, wireshark_version)
    else:
        output_file = '{0}.pdml'.format(filename)

    # tshark_command = '"{0}" -r "{1}" -2 -d tcp.port==8080,http2 -d tcp.port==3000,http2 -Y "(http2 and (http2.type == 0 || http2.type == 1)) or ngap or nas-5gs or pfcp" -T pdml -J "http2 ngap pfcp"'.format(tshark_path, input_file)
    # Some port combinations we saw so far from different vendors
    # Maybe as "to do" would be to add it as a command-line option
    logging.debug('Received HTTP/2 port list: {0}'.format(http2ports_string))
    port_list = http2ports_string.split(',')

    tshark_command = [
        tshark_path,
        '-r',
        input_file,
        '-2'
    ]

    # All this only needed if we are decoding 5G CP
    if mode is None:
        for port in port_list:
            tshark_command.append('-d')
            tshark_command.append('tcp.port=={0},http2'.format(port))

        if wireshark_version == 'OS':
            def retrieve_tshark_version(tshark_path_to_check):
                parsed_output = ''
                try:
                    tshark_version_command = tshark_path_to_check + " -v"
                    logging.debug('Checking installed tshark version: {0}'.format(tshark_version_command))
                    subprocess_ref = subprocess.Popen(tshark_version_command, shell=True, stdout=subprocess.PIPE)
                    subprocess_return = subprocess_ref.stdout.read()
                    parsed_output = subprocess_return.decode()
                    parsed_match = re.match(r'TShark \(Wireshark\) ([\d]{1,2}.[\d]{1,2}.[\d]{1,2})', parsed_output)
                    parsed_version = parsed_match.group(1)
                    logging.debug('Parsed tshark OS version {0}'.format(parsed_version))
                    return parsed_version
                except:
                    logging.debug('Could not parse tshark version for {0}'.format(tshark_path_to_check))
                    traceback.print_exc()
                    logging.debug('Retrieved output:\n{0}'.format(parsed_output))
                    return None

            tshark_os_version = retrieve_tshark_version(tshark_path)
            if tshark_os_version is not None:
                os_tshark_parsed = True
                wireshark_version = tshark_os_version
            else:
                os_tshark_parsed = False
        else:
            os_tshark_parsed = False

        # Add 5GS null ciphering decode (WS versions >=3)
        if not os_tshark_parsed:
            logging.debug('Using Wireshark version {0}'.format(wireshark_version))
        else:
            logging.debug('Using OS Wireshark version {0}'.format(wireshark_version))

        # Assume that a current Wireshark version is installed in the machine
        if wireshark_version == 'OS' or (version.parse(wireshark_version) >= version.parse('3.0.0')):
            logging.debug('Wireshark supports nas-5gs.null_decipher option. Applying')
            tshark_command.append('-o')
            tshark_command.append('nas-5gs.null_decipher: TRUE')
        else:
            logging.debug('Wireshark version <3.0.0. Not applying nas-5gs.null_decipher option. Applying')

    # Added disabling name resolution (see #2). Reference: https://tshark.dev/packetcraft/add_context/name_resolution/
    # Added GTPv2 for N26 messages and TCP to filter out spurious TCP retransmissions
    # Added ICMP becauspie it was observed that sometimes PFCP messages are put into the icmp <proto> tag
    protocols_to_include_in_pdml = 'http2 ngap pfcp gtpv2 tcp diameter radius gtpprime icmp icmpv6'
    if additional_protocols is not None and additional_protocols != '':
        protocols_to_include_in_pdml += ' ' + additional_protocols
    logging.debug(f'Protocols to include in PDML file: {protocols_to_include_in_pdml}')
    if mode is None:
        tshark_command.extend([
            '-Y',
            '(http2 and (http2.type == 0 || http2.type == 1)) or ngap or nas-5gs or pfcp or gtpv2 or diameter or radius or gtpprime or icmp or icmpv6.type == 134',
            '-T',
            'pdml',
            '-J',
            protocols_to_include_in_pdml,
            '-n'
        ])
    elif mode == 'UDP':
        tshark_command.extend([
            '-Y',
            'udp and not gtp',
            '-T',
            'pdml',
            '-J',
            'ip udp icmp',
            '-n'
        ])
    elif mode == 'GTP':
        tshark_command.extend([
            '-Y',
            'gtp and gtp.message==0xff',
            '-T',
            'pdml',
            '-J',
            'ip gtp udp icmp',
            '-n'
        ])

    logging.debug('Generating PDML files from PCAP to {0}'.format(output_file))
    logging.debug(tshark_command)

    if check_if_exists:
        if os.path.exists(output_file):
            logging.debug('Output file {0} exists. Skipping tshark call'.format(output_file))
            return output_file

    # Check if input file exists. If not, abort
    if not os.path.exists(input_file):
        logging.error('Could not find input file {0}, exiting'.format(input_file))
        exit(1)

    # Write PDML file
    with open(output_file, "w") as outfile:
        subprocess.run(tshark_command, stdout=outfile)

    logging.debug('Output {0}'.format(output_file))
    return output_file


def output_files_as_file(output_files, output_type: str = "svg"):
    """
    Outputs a UML diagram file by calling PlantUML
    :param output_type: A string specifying the output type. See https://plantuml.com/command-line#458de91d76a8569c for a list of supported types (e.g. svg, png, etc.)
    :param output_files: The files to be processed by PlantUML
    """
    for counter, output_file in enumerate(output_files):
        plant_uml_command = 'java -Djava.awt.headless=true -jar "{0}" "{1}"'.format(plant_uml_jar, output_file)
        if debug:
            plant_uml_command = '{0} -v'.format(plant_uml_command)
        generate_svg = '{0} -t{1}'.format(plant_uml_command, output_type)
        try:
            logging.debug('Generating {3} diagram {1}/{2}: {0}'.format(
                generate_svg,
                counter + 1,
                len(output_files),
                output_type.upper()))
            os.system(generate_svg)
        except:
            logging.debug('Could not generate {0} diagram'.format(output_type))
            traceback.print_exc()


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


if __name__ == '__main__':
    logging.debug('Searching for plantuml.jar under {0}'.format(plant_uml_jar))
    if os.path.exists(plant_uml_jar):
        logging.debug('Found plantuml.jar\n')
    else:
        logging.debug('NOT FOUND')
        logging.debug(
            "Please follow the instruction in README.md and go to http://plantuml.com/download to download PlantUML's JAR file")
        sys.exit(2)

    platform = platform.system()
    logging.debug('Platform system detected: {0}'.format(platform))

    parser = argparse.ArgumentParser(
        description='5G Wireshark trace visualizer for 5G protocol. Generates a .puml PlantUML file based on the specified PDML file. The output file is output in the same directory as the specified PDML file. Optionally, a Kubernetes pod file (YAML) can be used to further map trace IPs to pod names and namespaces')
    parser.add_argument('input', type=str,
                        help="path (relative or absolute) of PDML file or PCAP file. If PCAP file is chosen, Wireshark portable must be in the wireshark/ folder. For PCAP files, a comma-separated (no spaces!) string of PCAP file paths can be provided. In this case, mergecap will be automatically called and further processign will be done based on this merged capture file")
    parser.add_argument('-pods', type=str, required=False,
                        help="YAML pod descriptor file (path to the file) as output by kubectl get pods --all-namespaces -o yaml. A comma-separated (no spaces!) list of yaml files may also be provided. In this case, the IP/namespace mappings are merged. This merging feature is meant for when new IPs pop up. If the same IP is mapped to different pods in the different YAML files, only the last mapping will be kept")
    parser.add_argument('-debug', type=str2bool, required=False, help="More verbose output. Defaults to 'False'")
    parser.add_argument('-limit', type=int, required=False, default=100,
                        help="Maximum number of messages to show per diagram. If more are found, several partial diagrams will be generated. Default is 150. Note that setting this value to a too big value may cause a memory crash in PlantUML")
    parser.add_argument('-svg', type=str2bool, required=False, default=True,
                        help="Whether the PUML files should be converted to SVG. Requires Java and Graphviz installed, as it calls the included plantuml.jar file. Defaults to 'True'")
    parser.add_argument('-png', type=str2bool, required=False, default=False,
                        help="Whether the PUML files should be converted to PNG. Requires Java and Graphviz installed, as it calls the included plantuml.jar file. Defaults to 'False'")
    parser.add_argument('-showheartbeat', type=str2bool, required=False, default=False,
                        help='Whether to show PFCP and GTPv2 heartbeats in the diagram. Default is "False"')
    parser.add_argument('-ignore_spurious_tcp_retransmissions', type=str2bool, required=False, default=True,
                        help='Whether to ignore HTTP/2 packets marked by Wireshark as spurious TCP retransmissions. Default is "True"')
    parser.add_argument('-wireshark', type=str, required=False, default='none',
                        help="If other that 'none' (default), specifies a Wireshark portable version (or list of versions) to be used to decode the input file if that file is a not a PDML file. If more than one version specified, the first one will be used as main version. Other versions will be used as alternatives in case Wireshark reports a malformed packet. 'OS' can be used as version number if you do not want to use a specific Wireshark version but rather the OS-installed Wireshark/tshark version you have within your PATH. If you want to use the latest Wireshark portable version that can be found, use 'latest' as option")
    parser.add_argument('-http2ports', type=str, required=False,
                        default='32445,5002,5000,32665,80,32077,5006,8080,3000',
                        help="Comma-separated list (no spaces) of port numbers that are to be decoded as HTTP/2 by the Wireshark dissectors. Only applied for non-PDML inputs")
    parser.add_argument('-unescapehttp', type=str2bool, required=False, default=True,
                        help='Whether to unescape HTTP headers so that e.g. "target-plmn=%%7B%%22mcc%%22%%3A%%22405%%22%%2C%%22mnc%%22%%3A%%2205%%22%%7D" is shown as "target-plmn={"mcc":"405","mnc":"05"}". Defaults to "True"')
    parser.add_argument('-openstackservers', type=str, required=False,
                        help='YAML descriptor (path to the file) describing all of the VMs in the setup (i.e. server elements, each with a list of interfaces)')
    parser.add_argument('-ignorehttpheaders', type=str, required=False,
                        help='Comma-separated list of HTTP/2 headers to be omitted from the figures. e.g. "x-b3-traceid,x-b3-spanid" will not show these headers in the generated SVG files')
    parser.add_argument('-diagrams', type=str, required=False, default='ip,k8s_pod,k8s_namespace',
                        help='Comma-separated list of diagram types you want to output. Options: "ip": original IP-based packet trace, "k8s_pod": groups messages based on pod IP addresses, "k8s_namespace": groups messages based on namespace IP addresses. Defaults to "ip,k8s_pod,k8s_namespace"')
    parser.add_argument('-simple_diagrams', type=str2bool, required=False, default=False,
                        help="Whether to output simpler diagrams without a payload body. Defaults to 'False")
    parser.add_argument('-force_show_frames', type=str, required=False, default='',
                        help="Comma-separated list of frame numbers that even if using the simple_diagrams option you would want to be fully shown")
    parser.add_argument('-force_order', type=str, required=False, default='',
                        help="Comma-separated list of participant labels you want placed first in the diagram's participant list (if found in the trace, no effect if the participant is not found)")
    parser.add_argument('-ignore_pfcp_duplicate_packets', type=str2bool, required=False, default=True,
                        help='Whether to ignore PFCP retransmissions for better readability. Default is "True"')
    parser.add_argument('-show_timestamp', type=str2bool, required=False, default=False,
                        help='Whether you want to show the message timestamps in the diagram. Default is "False"')
    parser.add_argument('-show_selfmessages', type=str2bool, required=False, default=False,
                        help='Whether you want to show self-messages. You may want to turn this to "True" if you are running a trace on localhost. Default is "False"')
    parser.add_argument('-custom_packet_filter', type=str, required=False, default='',
                        help="Custom protocol filter to apply to only specific packets, i.e. applies proto[@name='custom_protocol_name'] when searching for packets in the PDML file")
    parser.add_argument('-custom_ip_src', type=str, required=False, default='',
                        help="If custom_packet_filter is used, the query for an element including the IP source, e.g. field[@name='field_with_ip']")
    parser.add_argument('-custom_ip_src_attribute', type=str, required=False, default='',
                        help="Where the actual value is placed, e.g. 'show'")
    parser.add_argument('-custom_ip_dst', type=str, required=False, default='',
                        help="If custom_packet_filter is used, the query for an element including the IP destination, e.g. field[@name='field_with_ip']")
    parser.add_argument('-custom_ip_dst_attribute', type=str, required=False, default='',
                        help="Where the actual value is placed, e.g. 'show'")

    args = parser.parse_args()

    if args.debug is not None:
        try:
            debug = bool(args.debug)
        except:
            pass

    print('5G Wireshark trace visualizer for 5G protocol')
    print('Input file: {0}'.format(args.input))
    print('Pods YAML file: {0}'.format(args.pods))
    print('Maximum messages per file: {0}'.format(args.limit))
    print('Debug: {0}'.format(args.debug))
    print('String un-escaping for HTTP requests: {0}'.format(args.unescapehttp))
    print('OpenStack servers file: {0}'.format(args.openstackservers))
    print('HTTP/2 headers to ignore: {0}'.format(args.ignorehttpheaders))
    print('Diagrams to output: {0}'.format(args.diagrams))
    print('Simple diagrams: {0}'.format(args.simple_diagrams))
    print('Force show frames if using simple diagrams: {0}'.format(args.force_show_frames))
    print('Show PFCP/GTPv2 heartbeat messages: {0}'.format(args.showheartbeat))
    print('Show HTTP/2 in spurious TCP retransmission messages: {0}'.format(args.ignore_spurious_tcp_retransmissions))
    print('Ignore PFCP packet duplicates: {0}'.format(args.ignore_pfcp_duplicate_packets))
    print('Show timestamp in diagram: {0}'.format(args.show_timestamp))
    print('Show self-messages: {0}'.format(args.show_selfmessages))
    if args.custom_packet_filter != '':
        print('Custom protocol filter: {0}'.format(args.custom_packet_filter))
    if args.custom_ip_src != '':
        print(f'Custom protocol IP src: {args.custom_ip_src}')
    if args.custom_ip_src_attribute != '':
        print(f'Custom protocol IP src attribute: {args.custom_ip_src_attribute}')
    if args.custom_ip_dst != '':
        print(f'Custom protocol IP dst: {args.custom_ip_dst}')
    if args.custom_ip_dst_attribute != '':
        print(f'Custom protocol IP dst attribute: {args.custom_ip_dst_attribute}')
    print()

    parsing.http.http2_string_unescape = args.unescapehttp

    input_file = args.input
    if args.wireshark != 'none':
        input_file = call_wireshark(args.wireshark, platform, input_file, args.http2ports,
                                    additional_protocols=args.custom_packet_filter)
    else:
        if not isinstance(input_file, str):
            print('\nERROR: PDML input only accepts one file')
            sys.exit(2)
        filename, file_extension = os.path.splitext(input_file)
        if file_extension != '.pdml':
            print(
                '\nERROR: Can only process .pdml files. Set the -wireshark <wireshark option> option if you want to process .pcap/.pcapng files. e.g. -wireshark "2.9.0"')
            sys.exit(2)
        # There is not support for multiple Wireshark versions if a PDML file is used as input
        input_file = [input_file]

    puml_files = import_pdml(
        input_file,
        args.pods,
        args.limit,
        args.showheartbeat,
        args.openstackservers,
        args.ignorehttpheaders,
        args.diagrams,
        args.simple_diagrams,
        args.force_show_frames,
        args.force_order,
        args.ignore_spurious_tcp_retransmissions,
        args.ignore_pfcp_duplicate_packets,
        args.show_timestamp,
        args.show_selfmessages,
        custom_packet_filter=args.custom_packet_filter,
        custom_packet_filter_ip_labels=(
            args.custom_ip_src, args.custom_ip_src_attribute, args.custom_ip_dst, args.custom_ip_dst_attribute)
    )

    if args.svg:
        print('Converting .puml files to SVG')
        output_files_as_file(puml_files)

    if args.png:
        print('Converting .puml files to PNG')
        output_files_as_file(puml_files, output_type='png')
