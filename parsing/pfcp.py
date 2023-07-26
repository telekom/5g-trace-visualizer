import logging
import re

import yaml

from parsing.nas import nas_5g_proto_to_dict


def parse_pfcp_proto(frame_number, nas_5g_proto, pfcp_heartbeat, ignore_pfcp_duplicate_packets, last_pfcp_message):
    try:
        if not pfcp_heartbeat:
            is_heartbeat_req = nas_5g_proto.find("field[@name='pfcp.msg_type'][@value='01']")
            is_heartbeat_resp = nas_5g_proto.find("field[@name='pfcp.msg_type'][@value='02']")
            if (is_heartbeat_req is not None) or (is_heartbeat_resp is not None):
                logging.debug('Frame {0}: ignored PFCP heartbeat message'.format(frame_number))
                return None
    except:
        pass

    nas_5g_dict = nas_5g_proto_to_dict(nas_5g_proto)
    nas_5g_json_str = yaml.dump(nas_5g_dict, indent=4, width=1000, sort_keys=False)

    if ignore_pfcp_duplicate_packets and (last_pfcp_message is not None):
        try:
            # Last lines may have added metadata regarding the reply
            lines_to_consider = [e for e in nas_5g_json_str.split('\n') if
                                 ('pfcp.response_in:' not in e) and ('pfcp.response_to:' not in e) and (
                                         'pfcp.response_time:' not in e)]
            pfcp_message_to_compare_minus_last_line = '\n'.join(lines_to_consider)
            if (last_pfcp_message == pfcp_message_to_compare_minus_last_line) or (last_pfcp_message == nas_5g_json_str):
                logging.debug('Frame {0}: ignored duplicated PFCP message (same as previous one)'.format(frame_number))
                return None
        except:
            pass

    return nas_5g_json_str


pfcp_req_regex = re.compile(r'pfcp\.msg_type: .*[Rr]equest.*')
pfcp_message_type_regex = re.compile(r"pfcp\.msg_type: 'Message [tT]ype: (.*)'")
