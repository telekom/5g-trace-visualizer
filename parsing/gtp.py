import logging
import re

import yaml

from parsing.nas import nas_5g_proto_to_dict

gtpv2_req_regex = re.compile(r"gtpv2\.message_type: '.*[Rr]equest.*'")
gtpv2_message_type_regex = re.compile(r"gtpv2\.message_type: 'Message [tT]ype: (.*)'")

def parse_gtpv2_proto(frame_number, gtpv2_pdu, show_heartbeat):
    if gtpv2_pdu is None:
        return ''

    # Option to ignore heartbeats
    try:
        if not show_heartbeat:
            is_heartbeat_req = gtpv2_pdu.find("field[@name='gtpv2.message_type'][@value='01']")
            is_heartbeat_resp = gtpv2_pdu.find("field[@name='gtpv2.message_type'][@value='02']")
            if (is_heartbeat_req is not None) or (is_heartbeat_resp is not None):
                logging.debug('Frame {0}: ignored GTPv2 heartbeat message'.format(frame_number))
                return None
    except:
        pass

    # Dump message content
    gtpv2_pdu_dict = nas_5g_proto_to_dict(gtpv2_pdu)
    nas_5g_json_str = yaml.dump(gtpv2_pdu_dict, indent=4, width=1000, sort_keys=False)

    return nas_5g_json_str

