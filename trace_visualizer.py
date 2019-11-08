# 5g-trace-visualizer :- convert 5g wireshark data into an UML sequence diagram 
# Copyright (c) 2019, Josep Colom Ikuno, Deutsche Telekom AG 
# contact: opensource@telekom.de 
# This file is distributed under the conditions of the Apache-v2 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

import xml.etree.ElementTree as ET
import re
import json
import sys
import subprocess
import os
import os.path
import argparse
import traceback
import yaml_parser
import urllib.parse

ip_regex = re.compile(r'Src: ([\d\.]*), Dst: ([\d\.]*)')
nfs_regex = re.compile(r':path: \/(.*)\/v.*\/.*')
debug = False
ascii_non_printable = re.compile(r'[\x00-\x09\x0b-\x0c\x0e-\x1f]')

# https://www.w3schools.com/colors/colors_picker.asp
color_actors    = '#e6e6e6'
color_nas_req   = '#8cd98c'
color_nas_rsp   = '#c6ebc6'
color_http2_req = '#b3b3b3'
color_http2_rsp = '#e6e6e6'
color_pfcp_req  = '#80b3ff'
color_pfcp_rsp  = '#cce0ff'

pfcp_req_regex = re.compile(r'\"pfcp\.msg_type\": \".*[Rr]equest.*\"')
pfcp_message_type_regex = re.compile(r'\"pfcp\.msg_type\": \"Message Type: (.*)\"')

nas_req_regex           = re.compile(r'\"nas_5gs\..*message_type\": \".*[Rr]equest.*\"')
nas_message_type_regex  = re.compile(r'\"nas_5gs\..*message_type\": \"Message type: (.*)\"')

http_rsp_regex    = re.compile(r'status: ([\d]{3})')
http_url_regex    = re.compile(r':path: (.*)')
http_method_regex = re.compile(r':method: (.*)')

http2_string_unescape = False

def find_nas_proto(ngap_pdu):
    if ngap_pdu is None:
        return None
        
    # Return also NGAP information
    nas_messages = []
    for child in ngap_pdu:
      nas_messages.append(child)
    return nas_messages
    
    # Since sometimes the proto object is empty, I need to do this workaround
    plain_nas    = ngap_pdu.findall(".//field[@show='Plain NAS 5GS Message']")
    security_nas = ngap_pdu.findall(".//field[@show='Security protected NAS 5GS message']")

    all_nas = plain_nas
    if len(security_nas) > 0:
        all_nas.extend(security_nas)

    if len(all_nas) < 1:
        return None
    
    return all_nas

def xml2json(root):
    def recusiv(the_root):
        out = {}
        children_list      = list(the_root)
        number_of_children = len(children_list)
        for child in children_list:
            child_name = child.attrib["name"]
            number_of_grandchildren = len(list(child))
            if number_of_grandchildren > 0:
                if child_name not in out:
                    out[child_name] = []
                child_to_traverse = child

                # Recursively call this function
                data_to_append = recusiv(child_to_traverse)

                # Make the JSON smaller by removing non-useful tags
                if (child_name=='ngap.ProtocolIE_Field_element' or child_name=='') and (number_of_children == 1):
                    return data_to_append

                # Reduce arrays of length 1 in dictionary
                for key,value in data_to_append.items():
                    if len(value) == 1:
                        data_to_append[key] = value[0]

                # Reduce dictionaries of length 1 with empty key
                if (len(data_to_append) == 1) and ('' in data_to_append):
                    data_to_append = data_to_append['']

                out[child_name].append(data_to_append)
            else:
                out[child_name] = child.attrib["showname"]
        return out
    parsed_tree = recusiv(root)
    return parsed_tree

def nas_5g_proto_to_dict(nas_5g_proto):
    if (nas_5g_proto is None):
        return {}
    return xml2json(nas_5g_proto)

def parse_pfcp_proto(frame_number, nas_5g_proto, pfcp_heartbeat):
    try:
        if not pfcp_heartbeat:
            is_heartbeat_req  = nas_5g_proto.find("field[@name='pfcp.msg_type'][@value='01']")
            is_heartbeat_resp = nas_5g_proto.find("field[@name='pfcp.msg_type'][@value='02']")
            if (is_heartbeat_req is not None) or (is_heartbeat_resp is not None):
                print('Frame {0}: ignored PFCP heartbeat message'.format(frame_number))
                return None
    except:
        pass
    
    nas_5g_dict = nas_5g_proto_to_dict(nas_5g_proto)
    nas_5g_json_str = json.dumps(nas_5g_dict, indent=2, sort_keys=False)
    return nas_5g_json_str          

def parse_nas_proto(frame_number, el):
    ngap_pdu = el.find("field[@name='ngap.NGAP_PDU']")
    if ngap_pdu is None:
        return ''
    nas_5g_protos = find_nas_proto(ngap_pdu)
    if (nas_5g_protos is None) or (len(nas_5g_protos) == 0):
        return ''

    nas_5g_json_all = []
    for nas_5g_proto in nas_5g_protos:
        nas_5g_dict = nas_5g_proto_to_dict(nas_5g_proto)
        nas_5g_json_all.append(json.dumps(nas_5g_dict, indent=2, sort_keys=False))
    nas_5g_json_str = '\n'.join(nas_5g_json_all)
    return nas_5g_json_str

def parse_http_proto(frame_number, el):
    headers    = el.findall("field[@name='http2.stream']/field[@name='http2.type'][@showname='Type: HEADERS (1)']/../field[@name='http2.header']")
    data       = el.find("field[@name='http2.stream']/field[@name='http2.type'][@showname='Type: DATA (0)']/../field[@name='http2.data.data']")
    reassembly = el.find("field[@name='http2.stream']/field[@name='http2.type'][@showname='Type: DATA (0)']/../field[@name='http2.body.reassembled.in']")

    header_list = []
    if headers is not None:
        header_list = [(header.find("field[@name='http2.header.name']").attrib["show"], header.find("field[@name='http2.header.value']").attrib["show"]) for header in headers]

    # Return None if there are not headers and the data is reassembled later on (just a data fragment)
    if reassembly is not None:
        frame_number_for_reassembly = reassembly.attrib['show']
        if (len(header_list) == 0) and (frame_number_for_reassembly != frame_number):
            return None

    data_ascii = ''
    if (data is not None) and ((reassembly is None) or (frame_number_for_reassembly == frame_number)):
        try:
            data_hex = data.attrib['value']
            # Try first ascii decoding, then if it fails, the default one (UTF-8)
            http_data_as_hex = bytearray.fromhex(data_hex)
            try:
                data_ascii = http_data_as_hex.decode('ascii')
            except:
                data_ascii = http_data_as_hex.decode('utf_8')
            if data_ascii != '':
                # Cleanup non-printable characters
                cleaned_data_ascii = ascii_non_printable.sub(' ', data_ascii)
                data_ascii = cleaned_data_ascii
            try:
                # If JSON, format nicely
                parsed_json = json.loads(data_ascii)
                data_ascii  = json.dumps(parsed_json, indent=2, sort_keys=False)
            except:
                print('Frame {0}: could not parse HTTP/2 payload data as JSON'.format(frame_number))
        except:
            # If data is marked as missing, then there is no data
            print('Frame {0}: could not get HTTP/2 payload. Probably missing'.format(frame_number))
            pass

    http2_request = ''
    if len(header_list) > 0:
        if http2_string_unescape:
            http2_request = http2_request + '\n'.join(['{0}: {1}'.format(header[0],urllib.parse.unquote(header[1])) for header in header_list])
        else:
            http2_request = http2_request + '\n'.join(['{0}: {1}'.format(header[0],header[1]) for header in header_list])
    if (data_ascii != '') and (http2_request != ''):
        http2_request = http2_request + '\n\n'
    if data_ascii != '':
        http2_request = http2_request + data_ascii
    return http2_request

def generate_order(uses):
    use_order = ['AN', 'N1', 'amf', 'nnssf', 'nnrf', 'smf', 'udm', 'nausf', 'udr', 'udsf']
    if len(uses) == 0:
        return 0
    orders = []
    for idx,use in enumerate(uses):
        for order,category in enumerate(use_order):
            if category in use:
                orders.append(order+1)
                break
    if len(orders) == 0:
        orders = [ 0 ]
    return min(orders)

def packet_to_str(packet):
    protocol = packet[3]
    note_color = ''
    packet_str = ''
    if 'NGAP' in protocol:
        if nas_req_regex.search(packet[4]) is not None:
            note_color = ' {0}'.format(color_nas_req)
            protocol = protocol + ' req.'
        else:
            note_color = ' {0}'.format(color_nas_rsp)
            protocol = protocol + ' or NAS rsp.'

        matches = nas_message_type_regex.finditer(packet[4])
        message_types = [ match.group(1) for match in matches if match is not None ]
        if len(message_types) > 0:
            # Remove duplicates: https://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-whilst-preserving-order
            seen = set()
            seen_add = seen.add
            message_types = [ x for x in message_types if not (x in seen or seen_add(x))]
            protocol = '{0}\\n{1}'.format(protocol, '\\n'.join(message_types))
    elif 'HTTP' in protocol:
        # Some customized filtering based on what we have seen
        rsp_match = http_rsp_regex.search(packet[4])
        if ('404 page not found' in packet[4]) or (rsp_match is not None):
            note_color = ' {0}'.format(color_http2_rsp)
            if rsp_match is not None:
                protocol = '{0} {1} rsp.'.format(protocol, rsp_match.group(1))
            else:
                protocol = protocol + ' 404 rsp.'
        else:
            note_color = ' {0}'.format(color_http2_req)
            protocol = protocol + ' req.'

        match = http_url_regex.search(packet[4]) 
        if match is not None:
            method = ''
            method_match = http_method_regex.search(packet[4])
            if method_match is not None:
                method = '{0} '.format(method_match.group(1))
            url_split = match.group(1).split('?')
            protocol = '{0}\\n{1} {2}'.format(protocol, method, url_split[0])
    elif 'PFCP' in protocol:
        if pfcp_req_regex.search(packet[4]) is not None:
            note_color = ' {0}'.format(color_pfcp_req)
            protocol = protocol + ' req.'
        else:
            note_color = ' {0}'.format(color_pfcp_rsp)
            protocol = protocol + ' rsp.'

        match = pfcp_message_type_regex.search(packet[4]) 
        if match is not None:
            protocol = '{0}\\n{1}'.format(protocol, match.group(1))

    packet_str = packet_str + '"{0}" -> "{1}": {2}, {3}\n'.format(packet[0], packet[1], packet[2], protocol)
    packet_str = packet_str + '\nnote right{0}\n'.format(note_color)
    if packet[4] != '':
        packet_str = packet_str + '{0} to {1}\n{2}\n'.format(packet[0], packet[1], packet[4])
    else:    
        packet_str = packet_str + '{0} to {1}\n'.format(packet[0], packet[1])
    packet_str = packet_str + 'end note\n'
    packet_str = packet_str + '\n'
    return (packet_str, packet[0], packet[1], protocol )

def move_from_list_to_list(origin, destination, criteria):
    if criteria is None:
        to_move = origin.copy()
    else:
        to_move = []
        for e_criteria in criteria:
            to_move.extend([e for e in origin if e[2]==e_criteria])

    for e in to_move:
        destination.append(e)
        origin.remove(e)


def order_participants(participants, packet_descriptions_str):
    # The order is UEs, AMF-NAS, AMF, SMF, NRF, UPF, AUSF, rest
    participants_ordered = []

    # UEs are the ones sending NAS requests
    ue_participants = set([packet[1] for packet in packet_descriptions_str if 'NGAP req.' in packet[3]])

    # NFs
    amf_n1_participants   = set([packet[2] for packet in packet_descriptions_str if 'NGAP req.' in packet[3]])
    amf_sbi_participants  = set([packet[2] for packet in packet_descriptions_str if ':path: /amf/' in packet[0] or ':path: /namf' in packet[0]])
    smf_sbi_participants  = set([packet[2] for packet in packet_descriptions_str if ':path: /smf/' in packet[0] or ':path: /nsmf' in packet[0]])
    smf_pfcp_participants = set([packet[1] for packet in packet_descriptions_str if 'PFCP req.' in packet[3]])
    upf_pfcp_participants = set([packet[2] for packet in packet_descriptions_str if 'PFCP req.' in packet[3]])
    ausf_sbi_participants = set([packet[2] for packet in packet_descriptions_str if ':path: /ausf/' in packet[0] or ':path: /nausf' in packet[0]])
    udm_sbi_participants  = set([packet[2] for packet in packet_descriptions_str if ':path: /udm/' in packet[0] or ':path: /nudm' in packet[0]])
    udr_sbi_participants  = set([packet[2] for packet in packet_descriptions_str if ':path: /udr/' in packet[0] or ':path: /nudr' in packet[0]])
    nrf_sbi_participants  = set([packet[2] for packet in packet_descriptions_str if ':path: /nrf/' in packet[0] or ':path: /nnrf' in packet[0]])

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
    move_from_list_to_list(participants, participants_ordered, udr_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, nrf_sbi_participants)
    move_from_list_to_list(participants, participants_ordered, None)

    return participants_ordered

def output_puml(output_file, participants, packet_descriptions, print_legend):
    # Generate packet descriptions, as we first want to check participants
    packet_descriptions_str = [ packet_to_str(packet) for packet in packet_descriptions ];
    participants = order_participants(participants, packet_descriptions_str)

    print('Outputting PlantUML file to {0}'.format(output_file))
    with open(output_file, 'w') as f:
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
            f.write(participant_str)
        f.write('\n')

        # Packets
        for packet in packet_descriptions_str:
            f.write(packet[0])
            
        f.write('@enduml\n')

def generate_new_participants(participants, new_packet_descriptions):
    packet_participants = set([packet[0] for packet in new_packet_descriptions ] + [packet[1] for packet in new_packet_descriptions ])
    new_participants     = []
    current_participants = {}
    for current_participant in current_participants:
        current_participants[p[1]] = current_participant
    
    for packet_participant in packet_participants:
        if packet_participant in current_participants:
            # Current IP, keep name as-is
            new_participants.append(current_participants[packet_participant])
        else:
            new_participants.append(('participant', '"{0}"'.format(packet_participant), packet_participant, {}, 0))

    return new_participants

def packet_sub(packet, mapping, idx):
    src = packet[0]
    dst = packet[1]
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
    if src == dst:
        return None
    # Return packet with substituted src and dst (e.g. pod name)
    if not sub_done:
        new_packet = (src, dst, packet[2], packet[3], packet[4])
    else:
        try:
            current_description = packet[4]
            if ' (original)\n' not in current_description:
                new_description = '{0} to {1} (original)\n{2}'.format(old_src, old_dst, packet[4])
            else:
                new_description = packet[4]
        except:
            new_description = '{0} to {1} (original)\n{2}'.format(old_src, old_dst, packet[4])
        new_packet = (src, dst, packet[2], packet[3], new_description)
    return new_packet

def add_participants_if_not_there(new_participants, participants_to_extend):
    current_participants = [ participant[1] for participant in participants_to_extend ]
    participants_to_add  = [ participant for participant in new_participants if participant[1] not in current_participants ]
    participants_to_extend.extend(participants_to_add)

def substitute_pod_ips_with_name(participants, packet_descriptions, ip_to_pod_mapping, participants_to_append=None):
    return substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, 0, participants_to_append)

def substitute_pod_ips_with_namespace(participants, packet_descriptions, ip_to_pod_mapping, participants_to_append=None):
    return substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, 1, participants_to_append)

def substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, mapping_idx, participants_to_append=None):
    new_packet_descriptions = [ packet_f for packet_f in [ packet_sub(packet, ip_to_pod_mapping, mapping_idx) for packet in packet_descriptions ] if packet_f is not None ]
    new_participants = generate_new_participants(participants, new_packet_descriptions)
    if participants_to_append is not None:
        add_participants_if_not_there(new_participants, participants_to_append)
    return new_participants, new_packet_descriptions

def map_vm_ips(output_to_generate, ip_to_vm_mapping):
    suffix              = output_to_generate[0]
    packet_descriptions = output_to_generate[1]
    participants        = output_to_generate[2]
    print_legend        = output_to_generate[3]

    new_participants, new_packet_descriptions = substitute_ips_with_mapping(participants, packet_descriptions, ip_to_vm_mapping, 0)
    return (suffix, new_packet_descriptions, new_participants, print_legend)

def import_pdml(file_path, pod_mapping=None, limit=100, pfcp_heartbeat=False, vm_mapping=None):
    print('Importing {0}'.format(file_path))
    if not os.path.exists(file_path):
        print('File does not exist')
        return None
    tree = ET.parse(file_path)
    root = tree.getroot()

    packet_descriptions = []
    destinations = set()

    if root.tag == 'pdml':
        print('Root tag is "pdml": OK')
    else:
        print('Root tag is "pdml": ERROR')
        return None
    for idx,packet in enumerate(root.iter('packet')):
        frame_number = packet.find("proto[@name='geninfo']/field[@name='num']").attrib['show']
        ip_showname = packet.find("proto[@name='ip']").attrib['showname']
        ip_match = ip_regex.search(ip_showname)
        ip_src = ip_match.group(1)
        ip_dst = ip_match.group(2)

        ngap_proto  = packet.find("proto[@name='ngap']")
        http2_proto = packet.find("proto[@name='http2']")
        pfcp_proto  = packet.find("proto[@name='pfcp']")

        packet_has_http2 = False
        packet_has_ngap  = False
        packet_has_pfcp  = False

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
        if len(protocols) == 0:
            protocols_str = ''
        else:
            protocols_str = ','.join(protocols)

        if debug:
            print('Frame {0} ({4}): {1} to {2}, {3}'.format(idx, ip_src, ip_dst, protocols_str, frame_number))
        msg_description = ''
        if packet_has_http2:
            http2_request = parse_http_proto(frame_number, http2_proto)
            if debug:
                print('SBI')
                print(http2_request)
            msg_description = http2_request
        if packet_has_ngap:
            nas_request = parse_nas_proto(frame_number, ngap_proto)
            if debug:
                print('NAS')
                print(nas_request)
            msg_description = nas_request
        if packet_has_pfcp:
            pfcp_request = parse_pfcp_proto(frame_number, pfcp_proto, pfcp_heartbeat)
            if debug:
                print('PFCP')
                print(pfcp_request)
            msg_description = pfcp_request
        
        # None are messages that are deliberately marked as fragments
        if msg_description is not None:
            packet_descriptions.append((ip_src, ip_dst, frame_number, protocols_str, msg_description))
        destinations.add(ip_dst)
        destinations.add(ip_src)

    all_destinations = dict([(d,set()) for d in destinations])

    # Hypothesis of what each IP is
    for packet_description in packet_descriptions:
        destination = packet_description[1]
        description = packet_description[4]

        # SBI-based
        if (description is not None) and (description != ''):
            match = nfs_regex.search(description)
            if match is not None:
                all_destinations[destination].add(match.group(1))

        # NAS
        if 'NGAP' in packet_description[3]:
            all_destinations[destination].add('N1')

    # Generate participant descriptions for description and add order (key)
    participants = []
    for destination,uses in all_destinations.items():
        participant_type = 'participant'
        participant_description = ''
        if len(uses)!=0:
            joined_uses = '\\n'.join(uses) + '\\n({0})'.format(destination)
            participants.append((participant_type, '"{0}" as {1}'.format(joined_uses, destination), destination, uses, None)) # generate_order(uses)))
        else:
            participants.append((participant_type, '"{0}"'.format(destination),                     destination, uses, None)) #  generate_order(uses)))

    # Participant sorting now moved to the end (PUML generation)
    # participants = sorted(participants, key=lambda x: x[4])

    outputs_to_generate = [ ('', packet_descriptions, participants, True) ]

    # Pod information if  available
    if pod_mapping is not None:
        print('Applying pod and pod namespace mapping')
        pod_mapping_list = pod_mapping.split(',')
        ip_to_pod_mapping = yaml_parser.load_yaml_list(pod_mapping_list)
        if ip_to_pod_mapping is not None:
            participants_per_pod, packet_descriptions_per_pod             = substitute_pod_ips_with_name(participants, packet_descriptions, ip_to_pod_mapping)
            participants_per_namespace, packet_descriptions_per_namespace = substitute_pod_ips_with_namespace(participants, packet_descriptions, ip_to_pod_mapping)
        outputs_to_generate.append(('_pod', packet_descriptions_per_pod, participants_per_pod, False))
        outputs_to_generate.append(('_namespace', packet_descriptions_per_namespace, participants_per_namespace, False))

    if vm_mapping is not None:
        ip_to_vm_mapping = yaml_parser.load_yaml_vm(vm_mapping)
        outputs_to_generate = [ map_vm_ips(output_to_generate, ip_to_vm_mapping) for output_to_generate in outputs_to_generate ]

    # Generate PlantUML diagram
    dirname,file_name = os.path.split(file_path)
    file,ext = os.path.splitext(file_name)

    # Generate outputs for all of the generated mappings
    output_files = []
    for output_to_generate in outputs_to_generate:
        suffix              = output_to_generate[0]
        packet_descriptions = output_to_generate[1]
        participants        = output_to_generate[2]
        print_legend        = output_to_generate[3]

        packet_descriptions_slices = [packet_descriptions[i:i + limit] for i in range(0, len(packet_descriptions), limit)]
        if len(packet_descriptions_slices) == 0:
            pass
        elif len(packet_descriptions_slices) == 1:
            output_file = os.path.join(dirname, '{0}{1}.puml'.format(file, suffix))
            output_puml(output_file, participants, packet_descriptions_slices[0], print_legend)
            output_files.append(output_file)
        else:
            for counter,packet_descriptions_slice in enumerate(packet_descriptions_slices):
                output_file = os.path.join(dirname, '{0}{1}_{2:03d}.puml'.format(file, suffix, counter))
                output_puml(output_file, participants, packet_descriptions_slice, print_legend)
                output_files.append(output_file)

    return output_files

def call_wireshark(wireshark_version, input_file_str, http2ports_string):
    input_files = input_file_str.split(',')
    if len(input_files)>1:
        filename, file_extension = os.path.splitext(input_files[0])
        output_filename = '{0}_merged{1}'.format(filename, file_extension)
        mergecap_path = file_name = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'wireshark', 'WiresharkPortable_{0}'.format(wireshark_version), 'App', 'Wireshark', 'mergecap.exe')
        mergecap_command = [ 
            mergecap_path, 
            '-w', 
            output_filename,
        ]
        for input_filename in input_files:
            mergecap_command.append(input_filename)
        print('Merging pcap files to {0}'.format(output_filename))
        print(mergecap_command)
        subprocess.run(mergecap_command)
        input_file = output_filename
    else:
        input_file = input_files[0]

    filename, file_extension = os.path.splitext(input_file)
    if file_extension == '.pdml':
        print('No need to invoke tshark. PDML file already input')
        return input_file
    tshark_path = file_name = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'wireshark', 'WiresharkPortable_{0}'.format(wireshark_version), 'App', 'Wireshark', 'tshark.exe')
    output_file = '{0}.pdml'.format(filename)
    #tshark_command = '"{0}" -r "{1}" -2 -d tcp.port==8080,http2 -d tcp.port==3000,http2 -Y "(http2 and (http2.type == 0 || http2.type == 1)) or ngap or nas-5gs or pfcp" -T pdml -J "http2 ngap pfcp"'.format(tshark_path, input_file)
    # Some port combinations we saw so far from different vendors
    # Maybe as "to do" would be to add it as a command-line option
    port_list = http2ports_string.split(',')

    tshark_command = [ 
        tshark_path, 
        '-r', 
        input_file,
       '-2'
       ]

    for port in port_list:
        tshark_command.append('-d')
        tshark_command.append('tcp.port=={0},http2'.format(port))

    tshark_command.extend([ 
       '-Y',
       '(http2 and (http2.type == 0 || http2.type == 1)) or ngap or nas-5gs or pfcp',
       '-T',
       'pdml',
       '-J',
       'http2 ngap pfcp'
       ])

    print('Generating PDML files from PCAP to {0}'.format(output_file))
    print(tshark_command)
    with open(output_file, "w") as outfile:
        subprocess.run(tshark_command, stdout=outfile)
    return output_file

def output_files_as_svg(output_files):
    plant_uml_jar = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'plantuml.jar')
    for counter,output_file in enumerate(output_files):
        plant_uml_command = 'java -jar "{0}" "{1}"'.format(plant_uml_jar, output_file)
        if debug:
            plant_uml_command = '{0} -v'.format(plant_uml_command)
        generate_svg = '{0} -tsvg'.format(plant_uml_command)
        try:
            print('Generating SVG diagram {1}/{2}: {0}'.format(generate_svg, counter+1, len(output_files)))
            os.system(generate_svg)
        except:
            print('Could not generate SVG diagram')
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
    parser = argparse.ArgumentParser(
        description='5G Wireshark trace visualizer for 5G protocol. Generates a .puml PlantUML file based on the specified PDML file. The output file is output in the same directory as the specified PDML file. Optionally, a Kubernetes pod file (YAML) can be used to further map trace IPs to pod names and namespaces')
    parser.add_argument('input', type=str, help="path (relative or absolute) of PDML file or PCAP file. If PCAP file is chosen, Wireshark portable must be in the wireshark/ folder. For PCAP files, a comma-separated (no spaces!) string of PCAP file paths can be provided. In this case, mergecap will be automatically called and further processign will be done based on this merged capture file")
    parser.add_argument('-pods', type=str, required=False, help="YAML pod descriptor file (path to the file) as output by kubectl get pods --all-namespaces -o yaml. A comma-separated (no spaces!) list of yaml files may also be provided. In this case, the IP/namespace mappings are merged. This merging feature is meant for when new IPs pop up. If the same IP is mapped to different pods in the different YAML files, only the last mapping will be kept")
    parser.add_argument('-debug', type=str2bool, required=False, help="More verbose output. Defaults to 'False'")
    parser.add_argument('-limit', type=int, required=False, default=100, help="Maximum number of messages to show per diagram. If more are found, several partial diagrams will be generated. Default is 150. Note that setting this value to a too big value may cause a memory crash in PlantUML")
    parser.add_argument('-svg', type=str2bool, required=False, default=True, help="Whether the PUML files should be converted to SVG. Requires Java and Graphviz installed, as it calls the included plantuml.jar file. Defaults to 'True")
    parser.add_argument('-pfcpheartbeat', type=str2bool, required=False, default=False, help="Whether to show PFCP heartbeats in the diagram. Default is 'False'")
    parser.add_argument('-wireshark', type=str, required=False, default='none', help="If other that 'none' (default), specifies a Wireshark portable version to be used to decode the input file if that file is a not a PDML file")
    parser.add_argument('-http2ports', type=str, required=False, default='32445,5002,5000,32665,80,32077,5006,8080,3000', help="Comma-separated list (no spaces) of port numbers that are to be decoded as HTTP/2 by the Wireshark dissectors. Only applied for non-PDML inputs")
    parser.add_argument('-unescapehttp', type=str2bool, required=False, default=True, help='Whether to unescape HTTP headers so that e.g. "target-plmn=%%7B%%22mcc%%22%%3A%%22405%%22%%2C%%22mnc%%22%%3A%%2205%%22%%7D" is shown as "target-plmn={"mcc":"405","mnc":"05"}". Defaults to "True"')
    parser.add_argument('-openstackservers', type=str, required=False, help='YAML descriptor (path to the file) describing all of the VMs in the setup (i.e. server elements, each with a list of interfaces)')
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
    print()
    
    http2_string_unescape = args.unescapehttp
    input_file = args.input
    if args.wireshark != 'none':
        input_file = call_wireshark(args.wireshark, input_file, args.http2ports)
    else:
        if not isinstance(input_file, str):
            print('\nERROR: PDML input only accepts one file')
            sys.exit(2)
        filename, file_extension = os.path.splitext(input_file)
        if file_extension != '.pdml':
            print('\nERROR: Can only process .pdml files. Set the -wireshark <wireshark option> option if you want to process .pcap/.pcapng files. e.g. -wireshark "2.9.0"')
            sys.exit(2)

    output_pdml_files = import_pdml(input_file, args.pods, args.limit, args.pfcpheartbeat, args.openstackservers)

    if args.svg:
        print('Converting .puml files to SVG')
        output_files_as_svg(output_pdml_files)