import logging
import os
import re
import traceback
from datetime import datetime
from typing import NamedTuple

from parsing.common import PacketDescription
from parsing.diameter_radius import get_diam_description
from parsing.gtp import gtpv2_req_regex, gtpv2_message_type_regex
from parsing.http import http_rsp_regex, http_url_regex, http_method_regex
from parsing.nas import nas_req_regex, ngap_message_type_regex, nas_message_type_regex
from parsing.pfcp import pfcp_req_regex, pfcp_message_type_regex

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


class PacketDiagramDescription(NamedTuple):
    """Describes a packet description in PlantUML"""
    description: str
    ip_src: str
    ip_dst: str
    protocol: str


# The path of the PlantUML file
plant_uml_jar = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'plantuml.jar')


def output_files_as_file(output_files, output_type: str = "svg", debug=False):
    """
    Outputs a UML diagram file by calling PlantUML
    :param debug: Whether debug otuput is desired
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


def packet_to_str(packet: PacketDescription, simple_diagrams=False, force_show_frames='', show_timestamp=False) \
        -> PacketDiagramDescription:
    """
    Converts the packet data to a textual description for the PlantUML diagram
    :param packet: The packet
    :param simple_diagrams: Whether a simple diagram is to be output instead of a full one
    :param force_show_frames: Comma-separated list if frames to force-show
    :param show_timestamp: Whether to show the timestamp
    :return: The textual packet representation
    """
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
