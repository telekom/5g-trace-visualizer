# 5g-trace-visualizer :- convert 5g wireshark data into an UML sequence diagram 
# Copyright (c) 2019, Josep Colom Ikuno, Deutsche Telekom AG 
# contact: opensource@telekom.de 
# This file is distributed under the conditions of the Apache-v2 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

import argparse
import logging
import os.path
import platform
import sys

import parsing.http
from utils.files import add_folder_to_file_list
from utils.plantuml import output_files_as_file, plant_uml_jar
from utils.wireshark import import_pdml, call_wireshark

application_logger = logging.getLogger()
application_logger.setLevel(logging.DEBUG)

debug = False


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
    parser.add_argument('-folder', type=str, required=False, default='',
                        help="Specifies a folder, such that all path references are relative to this folder")

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
    if args.folder != '':
        print(f'Root folder for files: {args.folder}')
        args.input = add_folder_to_file_list(args.input, args.folder)
        args.pods = add_folder_to_file_list(args.pods, args.folder)
        args.openstackservers = add_folder_to_file_list(args.openstackservers, args.folder)
        print('  New Input file: {0}'.format(args.input, args.folder))
        print('  New Pods YAML file: {0}'.format(args.pods))
        print('  New OpenStack servers file: {0}'.format(args.openstackservers))
    print()

    parsing.http.http2_string_unescape = args.unescapehttp

    input_file = args.input
    if args.wireshark != 'none':
        input_file = call_wireshark(
            args.wireshark,
            platform,
            input_file,
            args.http2ports,
            additional_protocols=args.custom_packet_filter
        )
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
            args.custom_ip_src, args.custom_ip_src_attribute, args.custom_ip_dst, args.custom_ip_dst_attribute),
        debug=debug
    )

    if args.svg:
        print('Converting .puml files to SVG')
        output_files_as_file(puml_files, debug=debug)

    if args.png:
        print('Converting .puml files to PNG')
        output_files_as_file(puml_files, output_type='png', debug=debug)
