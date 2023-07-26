import logging
import re
import traceback

import yaml
from lxml.etree import Element

from parsing.common import xml2json

nas_req_regex = re.compile(r"nas_5gs\..*message_type: '.*[Rr]equest.*'")
nas_message_type_regex = re.compile(r"nas_5gs\..*message_type: 'Message [tT]ype: (.*)'")
ngap_message_type_regex = re.compile(r"ngap.procedureCode: 'procedureCode: id-(.*)'")


def parse_nas_proto_el(frame_number, el: Element, multipart_proto=False):
    if not multipart_proto:
        ngap_pdu = el.find("field[@name='ngap.NGAP_PDU']")
    else:
        ngap_pdu = el
    if ngap_pdu is None:
        return ''
    nas_5g_protos = find_nas_proto(ngap_pdu)
    if (nas_5g_protos is None) or (len(nas_5g_protos) == 0):
        return ''

    nas_5g_json_all = []
    for nas_5g_proto in nas_5g_protos:
        nas_5g_dict = nas_5g_proto_to_dict(nas_5g_proto)
        nas_5g_json_all.append(yaml.dump(nas_5g_dict, indent=4, width=1000, sort_keys=False))
    nas_5g_json_str = '\n'.join(nas_5g_json_all)

    # Add NGAP PDU session to the transcription
    try:
        nas_5g_json_str = 'NGAP-PDU: {0}\n{1}'.format(ngap_pdu.attrib['value'], nas_5g_json_str)
    except:
        try:
            # Some newer Wireshark versions may already include the parsed message
            nas_5g_json_str = 'NGAP-PDU: {0}\n{1}'.format(ngap_pdu.find('field').attrib['value'], nas_5g_json_str)
        except:
            logging.error('Frame {0}: Could not add NGAP PDU session payload'.format(frame_number))
            traceback.print_exc()

    return nas_5g_json_str


def parse_nas_proto(frame_number, el, multipart_proto=False):
    if not isinstance(el, list):
        return parse_nas_proto_el(frame_number, el, multipart_proto)

    all_json = [parse_nas_proto_el(frame_number, e, multipart_proto) for e in el]
    return '\n'.join(all_json)


def nas_5g_proto_to_dict(nas_5g_proto):
    if (nas_5g_proto is None):
        return {}
    return xml2json(nas_5g_proto)


def find_nas_proto(ngap_pdu: Element) -> list[Element]:
    if ngap_pdu is None:
        return None

    # Return also NGAP information
    nas_messages = []
    for child in ngap_pdu:
        nas_messages.append(child)
    return nas_messages

    # Since sometimes the proto object is empty, I need to do this workaround
    plain_nas = ngap_pdu.findall(".//field[@show='Plain NAS 5GS Message']")
    security_nas = ngap_pdu.findall(".//field[@show='Security protected NAS 5GS message']")

    all_nas = plain_nas
    if len(security_nas) > 0:
        all_nas.extend(security_nas)

    if len(all_nas) < 1:
        return None

    return all_nas


