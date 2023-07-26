import logging
import re

import yaml

from parsing.nas import nas_5g_proto_to_dict


def get_diam_description(packet):
    '''
        Return diameter packet description as follow:
        Command-Code + Application-Id + Session-Id
    '''
    short_commands = {
        "274 Abort-Session": "274 AS",
        "275 Session-Termination": "275 ST",
        "280 Device-Watchdog": "280 DW",
    }
    diam_commandcode_regex = re.compile(r"diameter\.cmd\.code:\s+'Command\s+Code:\s+(.+)'")
    diam_application_regex = re.compile(r"diameter\.applicationId:\s+'ApplicationId:\s+(.+)'")
    diam_request_regex = re.compile(r"diameter\.flags\.request:\s+'(\d)")
    diam_session_regex = re.compile(r"diameter\.Session-Id:\s+'Session-Id:\s+(.+)'")

    # print('--------------------------')
    # print(packet.msg_description)
    # print('--------------------------')

    command_code = diam_commandcode_regex.search(packet.msg_description)
    application = diam_application_regex.search(packet.msg_description)
    session = diam_session_regex.search(packet.msg_description)
    # Command-Code not contain Request or Answer property.
    # Add it manually at the end of Command-Code
    command_postfix = 'A'
    if diam_request_regex.search(packet.msg_description).group(1) == '1':
        command_postfix = 'R'

    command = command_code.group(1) if command_code else ''
    # fix Command-Code full name, change to short acronym
    if command in short_commands:
        command = short_commands[command]

    application_id = application.group(1) if application else ''
    session_id = '\\nSession-Id: ' + session.group(1) if session else ''
    # Truncate Session-Id if it too long
    if len(session_id) > 70:
        session_id = session_id[0:35] + '...' + session_id[len(session_id) - 1:len(session_id) - 16:-1]

    description = 'Diameter, {0}{1} {2}{3}'.format(command, command_postfix, application_id, session_id)
    return description


def parse_diam_proto(frame_number, diam_pdu, show_heartbeat):
    if diam_pdu is None:
        return ''

    # Option to ignore heartbeats
    try:
        if not show_heartbeat:
            is_heartbeat = diam_pdu.find("field[@name='diameter.applicationId'][@value='00000000']")
            if (is_heartbeat is not None):
                logging.debug('Frame {0}: ignored Diameter heartbeat message'.format(frame_number))
                return None
    except:
        pass

    # Dump message content
    diam_pdu_dict = nas_5g_proto_to_dict(diam_pdu)
    nas_5g_json_str = yaml.dump(diam_pdu_dict, indent=4, width=1000, sort_keys=False)

    return nas_5g_json_str
