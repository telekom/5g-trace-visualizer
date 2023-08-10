import logging
import os
import re
import string
import subprocess
import traceback
from typing import Tuple, Pattern
from xml.etree import ElementTree as ET

import pandas as pd
from packaging import version

import parsing.http
import utils.plantuml
import yaml_parser
from parsing.common import PacketType, PacketDescription
from parsing.diameter_radius import parse_diam_proto
from parsing.gtp import parse_gtpv2_proto
from parsing.http import parse_http_proto
from parsing.icmp import parse_icmp_proto
from parsing.ipv6 import parse_ipv6_route_advertisement_proto
from parsing.nas import parse_nas_proto
from parsing.pfcp import parse_pfcp_proto
from utils.plantuml import output_puml

wireshark_folder = 'wireshark'
ip_regex: Pattern[str] = re.compile(r'Src: ([\d\.:]*), Dst: ([\d\.:]*)')
nfs_regex = re.compile(r':path: \/(.*)\/v.*\/.*')


def get_wireshark_portable_folder(wireshark_version) -> str:
    """
    Returns a Wireshar (portable) executable of the given version
    :param wireshark_version: The target Wireshark version
    :return: The location of the Wireshark executable of the given version
    """
    return os.path.join(os.path.dirname(
        os.path.realpath(__file__)),
        '..',
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
                custom_packet_filter_ip_labels: Tuple[str, str, str, str] = None,
                debug=False) -> list[str]:
    """
    Imports a PDML file
    :param debug: Whether debug output is to be output
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
    :return: The path of the output PUML diagrams
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

    packet_descriptions: list[PacketDescription] = []
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

        # Fix strange case that sometimes PFCP messages are shown in the GUI as ICMP destination unreachable (no idea
        # why this happens)
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

        # Calculate timestamp offset
        if first_timestamp is not None:
            frame_offset = frame_timestamp - first_timestamp
        else:
            frame_offset = None

        # None are messages that are deliberately marked as fragments
        if msg_description is not None:
            packet_descriptions.append(
                PacketDescription(
                    ip_src, ip_dst,
                    frame_number,
                    protocols_str,
                    msg_description,
                    frame_timestamp, frame_offset))
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


def read_cleanup_and_load_pdml_file(file_path) -> ET.ElementTree:
    """
    Imports a given PDML file and returns a ElementTree after performing some cleanup of the input file
    :param file_path: Location of a PDML file
    :return: ElementTree containing the parsed PDML file's contents
    """
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


def character_is_printable(x) -> bool:
    """
    Returns whether a character is printable
    :param x: a Character
    :return: True/False
    """
    return x in string.printable


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


def substitute_pod_ips_with_namespace(participants, packet_descriptions, ip_to_pod_mapping, participants_to_append=None,
                                      show_selfmessages=False):
    return substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, 1, participants_to_append,
                                       show_selfmessages)


def substitute_pod_ips_with_name(participants, packet_descriptions, ip_to_pod_mapping, participants_to_append=None,
                                 show_selfmessages=False):
    return substitute_ips_with_mapping(participants, packet_descriptions, ip_to_pod_mapping, 0, participants_to_append,
                                       show_selfmessages)


def add_participants_if_not_there(new_participants, participants_to_extend):
    current_participants = [participant[1] for participant in participants_to_extend]
    participants_to_add = [participant for participant in new_participants if
                           participant[1] not in current_participants]
    participants_to_extend.extend(participants_to_add)


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


def import_pcap_as_dataframe(
        pcap_files,
        http2_ports,
        wireshark_version,
        logging_level=logging.INFO,
        remove_pdml=False,
        debug=False):
    # Imports one or more pcap files as a dataframe with the packet parsing implemented in the trace_visualizer code

    # Accept either a single path or a list or paths
    if not type(pcap_files) is list:
        pcap_files = [pcap_files]
    application_logger = logging.getLogger()
    current_verbosity_level = application_logger.level
    try:
        # Reduce verbosity
        application_logger.setLevel(logging_level)
        packets_df_list = []

        if len(pcap_files) == 0:
            return None

        for idx, file in enumerate(pcap_files):
            if os.path.exists(file):
                pdml_file = call_wireshark(wireshark_version, file, http2_ports)
                packet_descriptions = import_pdml(pdml_file, diagrams_to_output='raw', debug=debug)
                packets_df = pd.DataFrame(packet_descriptions,
                                          columns=['ip_src', 'ip_dst', 'frame_number', 'protocol', 'msg_description',
                                                   'timestamp', 'timestamp_offset'])
                packets_df['datetime'] = pd.to_datetime(packets_df['timestamp'], unit='s')
                packets_df['msg_description'] = packets_df['msg_description'].str.replace('\\n', '\n')
                packets_df['summary_raw'] = [utils.plantuml.packet_to_str(p).protocol for p in packet_descriptions]

                # Generate summary column
                packets_df['summary'] = packets_df.apply(_generate_summary_row, axis=1)

                packets_df['file'] = file
                packets_df['file_idx'] = idx
                packets_df_list.append(packets_df)
                if remove_pdml:
                    logging.debug('Removing file(s) {0}'.format(', '.join(pdml_file)))
                    for e in pdml_file:
                        os.remove(e)

        # Consolidated packet list
        packets_df = pd.concat(packets_df_list, ignore_index=True)
        return packets_df
    except:
        return None
    finally:
        application_logger.setLevel(current_verbosity_level)


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
        sbi_url_descriptions = parsing.http.parse_sbi_type_from_url(summary_raw)
        if sbi_url_descriptions is None:
            summary = ''
        else:
            summary = '\n'.join(
                ['{0} {1}'.format(sbi_url_description.method, sbi_url_description.call) for sbi_url_description in
                 sbi_url_descriptions])
    else:
        summary = ''
    return summary
