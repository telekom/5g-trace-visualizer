import collections
import json
import logging
import re
import traceback
import urllib.parse

import yaml
from lxml.etree import Element

import parsing.mime_multipart
from parsing.common import xml2json

# HTTP/2 data fragments
packet_data_fragments = {}

http2_string_unescape = True

max_ascii_length_for_json_param = 250
max_ascii_length_for_http_payload = 5000
sbi_regex = re.compile(
    r'(?P<protocol>HTTP/2)?[ ]*([\w\.]+[\\n]+)?[ ]*(?P<method>POST|GET|PATCH|DELETE|PUT)?[ ]*(?P<url>/.*)')
imsi_cleaner = re.compile(r'imsi-[\d]+')
pdu_session_id_cleaner = re.compile(r'/[\d]+')
multiple_slash_cleaner = re.compile(r'/[/]+')
sbiUrlDescription = collections.namedtuple('SbiDescription', 'method call')
ascii_non_printable = re.compile(r'[\x00-\x09\x0b-\x0c\x0e-\x1f]')

http_payload_for_stream = re.compile(r'HTTP/2 stream ([\d]+) payload')
http_rsp_regex = re.compile(r'status: ([\d]{3})')
http_url_regex = re.compile(r':path: (.*)')
http_method_regex = re.compile(r':method: (.*)')

def parse_http_proto_stream(
        frame_number,
        stream_el: Element,
        ignorehttpheaders_list,
        http2_proto_el: Element,
        boundary_dict):
    stream_id_el = stream_el.find("field[@name='http2.streamid']")
    if stream_id_el is None:
        return None
    stream_id = stream_id_el.attrib['show']

    headers = stream_el.findall(
        "field[@name='http2.type'][@showname='Type: HEADERS (1)']/../field[@name='http2.header']")
    data = stream_el.find("field[@name='http2.type'][@showname='Type: DATA (0)']/../field[@name='http2.data.data']")
    former_fragments = stream_el.find("field[@name='http2.body.fragments']")

    # Filter out frames such as SETTINGS
    if len(headers) == 0 and (data is None):
        return None

    # Filter out empty DATA frames if there are no headers
    if (len(headers) == 0) and (data is not None) and (data.attrib['size'] == '0'):
        logging.debug('Frame {0}: Stream {1}, empty DATA frame'.format(frame_number, stream_id))
        return None

    # If there is reassembly, where it is to be reassembled
    # <field name="http2.body.reassembled.in" showname="Reassembled body in frame: 11" size="0" pos="192" show="11"/>
    reassembly_frame = stream_el.find(
        "field[@name='http2.type'][@showname='Type: DATA (0)']/../field[@name='http2.body.reassembled.in']")
    if reassembly_frame is not None:
        reassembly_frame = reassembly_frame.attrib['show']
    fragmented_packet = reassembly_frame is not None

    header_list = []
    if len(headers) > 0:
        header_list.append(('HTTP/2 stream', '{0}'.format(stream_id)))
        header_list.extend([(header.find("field[@name='http2.header.name']").attrib["show"],
                             header.find("field[@name='http2.header.value']").attrib["show"]) for header in headers])

    boundary = None

    # Return None if there are no headers and the data is reassembled later on (just a data fragment)
    # Save fragment for later reassembly
    if reassembly_frame is not None:
        added_current_fragment_to_cache = add_http2_fragment(reassembly_frame, stream_id, data, frame_number)
    else:
        # No reassembly
        reassembly_frame = frame_number

    data_ascii = ''
    json_data = False

    if (data is not None) and ((reassembly_frame == frame_number) or (former_fragments is not None)):
        try:
            prior_data = ''
            current_data = data.attrib['value']

            try:
                # Get, concatenate and clear cache for fragments for this frame number
                former_fragments = get_http2_fragments(frame_number, stream_id)
                # Seen sometimes that the fragments are repeated in the http2.data.data part
                if len(former_fragments) > 0:
                    if former_fragments[-1].attrib['value'] == current_data:
                        former_fragments = former_fragments[0:-2]

                prior_data = ''.join([data.attrib['value'] for data in former_fragments])
                logging.debug(
                    'Frame {0}: Joined {1} prior HTTP/2 fragments'.format(frame_number, len(former_fragments)))
            except:
                logging.debug('Could not join HTTP/2 fragments in frame {0}'.format(frame_number))
                traceback.print_exc()

            data_hex = prior_data + current_data
            multipart_lengths = []

            def hex_string_to_ascii(
                    http_data_as_hexstring,
                    remove_content_type=False,
                    return_original_if_not_json=False,
                    try_json_formatting=True
            ):
                http_data_as_hex = bytearray.fromhex(http_data_as_hexstring)
                ascii_str = ''
                try:
                    ascii_str = http_data_as_hex.decode('ascii')
                except:
                    ascii_str = http_data_as_hex.decode('utf_8', errors="ignore")

                # If we do not clean up these characters, PlantUML won't be able to display the text
                if ascii_str != '':
                    # Cleanup non-printable characters
                    cleaned_ascii_str = ascii_non_printable.sub(' ', ascii_str)
                    ascii_str = cleaned_ascii_str
                    if remove_content_type:
                        ascii_str = ascii_str.strip().rstrip()
                        to_remove = 'Content-Type: application/json'
                        if ascii_str.startswith(to_remove):
                            ascii_str = ascii_str[len(to_remove):]

                if not try_json_formatting:
                    return ascii_str

                try:
                    # If JSON, format nicely
                    parsed_json = json.loads(ascii_str)

                    # Limit JSON parameter length for nicer output
                    try:
                        parsed_json = filter_long_json_params(parsed_json, max_ascii_length_for_json_param)
                    except:
                        logging.debug('Frame {0}: Error filtering long JSON parameters'.format(frame_number))

                    ascii_str = json.dumps(parsed_json, indent=2, sort_keys=False)
                    json_data = True
                except Exception as e:
                    logging.debug(
                        'Frame {0}: could not parse HTTP/2 payload data as JSON. Parsed string: "{1}" and found error: "{2}"'.format(
                            frame_number, ascii_str, str(e)))
                    if return_original_if_not_json:
                        return http_data_as_hexstring
                    traceback.print_stack()
                return ascii_str

            # ToDo: Improve this part
            # Read boundary information from HTTP2 proto element
            # try:
            #    boundary_el = http2_proto_el.findall(".//field[@name='mime_multipart.first_boundary']")
            #    if len(boundary_el) != 0:
            #        boundary_attr = boundary_el[0].attrib['show'].strip()
            #        boundary = ''.join(filter(lambda x: x in string.printable, boundary_attr))
            #        boundary = boundary[2:] # We do not need the first two '-'
            #        logging.debug("Frame{0}: Found boundary in HTTP2 Protocol element: {1}".format(frame_number, boundary))
            #    for part in http2_proto_el.findall(".//field[@name='mime_multipart.part']"):
            #        total_size = int(part.attrib['size'])
            #        payload_size = int(part.find(".//proto").attrib['size'])
            #        multipart_lengths.append((total_size-payload_size, payload_size))
            #except:
            #    pass

            # Try to auto-detect MIME multipart payloads in packets with no HTTP/2 headers (e.g. headers sent in another
            # packet.
            # Since the boundary data is anyway in the HEADERS frame in the packet, we would not be able to read it
            # while in the DATA frame, so I made this part independent of the boundary variable
            if boundary is None and len(headers) == 0:
                data_ascii = hex_string_to_ascii(data_hex, try_json_formatting=True, return_original_if_not_json=True)
                try:
                    # Parses the ASCII-converted frame and returns a list of MIME multipart messages that it found
                    m_all = parsing.mime_multipart.parse_multipart_mime(data_ascii)
                    # logging.debug(data_ascii)

                    if m_all is not None and len(m_all) > 0:
                        boundary = m_all[0].boundary
                        # (header length, payload length)
                        multipart_lengths = [(len(m.header), len(m.payload)) for m in m_all]

                        def parse_content_id(a_str):
                            if a_str is None:
                                return "No Content ID"
                            return a_str

                        multipart_descriptions = []
                        multipart_ids = []
                        for m in m_all:
                            # We need this to properly display the message content
                            multipart_descriptions.append(
                                '\n'.join(['{0}: {1}'.format(h.name, h.value) for h in m.mime_headers]))
                            # We need this to search (if present) add already-dissected protocol data
                            multipart_ids.append(parsing.mime_multipart.find_header('Content-Id', m))

                        logging.debug(
                            'Found {1} MIME-multiparts by scanning payload. Boundary: "{0} ({3} bytes)".\n  Parts found: {2}'.format(
                                boundary,
                                len(m_all),
                                ', '.join(multipart_descriptions),
                                len(boundary * 2)))
                except:
                    logging.debug('Exception searching for boundary')
                    traceback.print_exc()
                    pass

            # Try first ASCII decoding, then if it fails, the default one (UTF-8)
            if boundary is not None:
                json_data = True
                boundary_hex = ''.join('{00:x}'.format(ord(c)) for c in boundary)
                logging.debug('Frame {0}: Processing multipart message. Boundary= {1} (0x{2})'.format(frame_number,
                                                                                                      boundary,
                                                                                                      boundary_hex))

                # Get the other parsed protocols
                mime_parts = http2_proto_el.findall("proto[@name='mime_multipart']/field[@name='mime_multipart.part']")
                logging.debug('Frame {0}: Found {1} MIME parts by scanning data dissected by Wireshark'.format(
                    frame_number,
                    len(mime_parts),
                    boundary))

                data_ascii = ''

                # Use always boundary scan because it works quite well now
                if boundary is not None:
                    logging.debug(
                        'Manual boundary parsing. Using boundary {0} (0x{1})'.format(
                            boundary, boundary_hex))

                    try:
                        logging.debug(
                            'Total payload length: {0} bytes, {1} characters. Length: {2}'.format(
                                len(data_hex),
                                len(data_ascii),
                                ', '.join(['{0} (header)/{1} (payload)'.format(e[0], e[1]) for e in multipart_lengths])
                            ))

                        # Add '--' to the boundary and get rid of starting and end trails
                        split_str = '2d2d' + boundary_hex
                        split_payload = data_hex.split(split_str)[1:-1]
                        # Adjust length as per the length found by the regex
                        split_payload_clean = []
                        for idx, payload in enumerate(split_payload):
                            try:
                                header_length = multipart_lengths[idx][0] * 2
                                length_to_cut = header_length - len(split_str)
                                logging.debug('Removing {0} additional bytes'.format(length_to_cut))
                                payload_clean = payload[length_to_cut:]

                                def rchop(s, suffix):
                                    if suffix and s.endswith(suffix):
                                        return s[:-len(suffix)]
                                    return s

                                payload_clean = rchop(payload_clean, '0d0a')

                                # See if we can find a dissected protocol under this ID
                                # XPath query: //proto[@name='mime_multipart']//field[@name='mime_multipart.header.content-id' and @show='n1SmMsg']/../proto
                                dissected_protocol_text = ''
                                try:
                                    current_description = multipart_descriptions[idx]
                                except:
                                    current_description = ''
                                try:
                                    # Search for an existing parsed protocol (may or may not be present)
                                    # Needed to adapt the XPath query because LXML only supports a subset, see
                                    # https://docs.python.org/3/library/xml.etree.elementtree.html#xpath-support
                                    matching_mime_multipart_proto = http2_proto_el.find(
                                        ".//field[@name='mime_multipart.header.content-id'][@show='{0}']/../proto".format(
                                            current_description
                                        ))
                                    protocol_data_to_show = xml2json(matching_mime_multipart_proto)

                                    # for MIME Multipart encoding binary NAS messages, this is empty
                                    if protocol_data_to_show is not None:
                                        formatted_json_data = yaml.dump(protocol_data_to_show, indent=4, width=1000, sort_keys=False)
                                        dissected_protocol_text = '\n\nParsed protocol data:\n' + formatted_json_data
                                except:
                                    logging.debug('Frame {0}: Dissected protocol not found'.format(frame_number))
                                    traceback.print_exc()

                                # Final assembly of display text
                                payload_clean_assembled = '{0}\n{1}{2}'.format(
                                    current_description,
                                    hex_string_to_ascii(payload_clean, return_original_if_not_json=True),
                                    dissected_protocol_text
                                )

                                # This text may contain text such as:
                                # Content-Type: application/vnd.3gpp.5gnas
                                # Content-Id: n1ContentId1
                                # 2e0501c211000901000631310101fe05061000041000042905010a0a0ae0220101790006052041010105250c0b6d7763356764656d6f6474
                                split_payload_clean.append(payload_clean_assembled)
                            except:
                                logging.error(
                                    f'Error processing multipart message (idx={idx}). Multipart lengths: {multipart_lengths}. Split payload={split_payload}')
                                traceback.print_exc()
                        data_ascii = '\n\n'.join(split_payload_clean)
                        data_ascii = 'Parsed multipart payload by parsing payload\nBoundary: {1}\n\n{0}'.format(
                            data_ascii, boundary)
                        # logging.debug(data_ascii)
                    except:
                        logging.debug('Could not manually parse payload')
                        traceback.print_exc()

        except:
            # If data is marked as missing, then there is no data
            logging.debug('Frame {0}: could not get HTTP/2 payload. Probably missing'.format(frame_number))
            traceback.print_exc()
            pass

    if fragmented_packet and (reassembly_frame != frame_number):
        data_ascii = 'HTTP/2 stream {0}: payload reassembled in Frame {1}'.format(stream_id, reassembly_frame)
    elif data_ascii != '':
        data_ascii = 'HTTP/2 stream {0} payload\n'.format(stream_id) + data_ascii

    # Do not print too long lines
    if (len(data_ascii) > max_ascii_length_for_http_payload) and not json_data:
        original_length = len(data_ascii)
        data_ascii = data_ascii[0:max_ascii_length_for_http_payload]
        data_ascii += '\n[...]\n{0} characters truncated'.format(original_length - len(data_ascii))
        logging.debug('Frame {0}: Truncated too long payload message')

    # Filter out HTTP/2 headers that are in the exclude list
    header_list = [header for header in header_list if header[0] not in ignorehttpheaders_list]

    http2_request = ''
    if len(header_list) > 0:
        if http2_string_unescape:
            unescaped_headers = '\n'.join(
                ['{0}: {1}'.format(header[0], urllib.parse.unquote(header[1])) for header in header_list])
            http2_request = http2_request + unescaped_headers
        else:
            http2_request = http2_request + '\n'.join(
                ['{0}: {1}'.format(header[0], header[1]) for header in header_list])

    if (data_ascii != '') and (http2_request != ''):
        http2_request = http2_request + '\n\n'
    if data_ascii != '':
        http2_request = http2_request + data_ascii

    # Escape creole syntax and hyperlinks
    http2_request = http2_request.replace('--', '~--')
    http2_request = http2_request.replace('**', '~**')
    http2_request = http2_request.replace(']]', '&#93;]')
    return http2_request


def add_http2_fragment(frame_number, stream_id, fragment, current_frame_number):
    if (frame_number is None) or (stream_id is None):
        logging.debug(
            'Frame {0}: cannot add fragment for frame {1}, stream {2}'.format(current_frame_number, frame_number,
                                                                              stream_id))
        return False
    fragment_list = get_http2_fragments(frame_number, stream_id)
    fragment_list.append(fragment)
    logging.debug(
        'Frame {0}: {3} fragments for frame {1} stream {2}'.format(current_frame_number, frame_number, stream_id,
                                                                   len(fragment_list)))
    return True


def parse_http_proto(
        frame_number,
        el: Element,
        ignorehttpheaders_list,
        ignore_spurious_tcp_retransmissions,
        packet: Element):
    if not isinstance(el, list):
        return parse_http_proto_el(frame_number, el, ignorehttpheaders_list, ignore_spurious_tcp_retransmissions,
                                   packet)

    all_json = [
        parse_http_proto_el(frame_number, e, ignorehttpheaders_list, ignore_spurious_tcp_retransmissions, packet) for e
        in el]
    return '\n'.join(all_json)


def parse_http_proto_el(
        frame_number, el: Element,
        ignorehttpheaders_list,
        ignore_spurious_tcp_retransmissions,
        packet: Element):
    # Option to ignore TCP spurious retransmissions
    try:
        if ignore_spurious_tcp_retransmissions:
            is_tcp_spurious = packet.find(
                "proto[@name='tcp']/field[@name='tcp.analysis']/field[@name='tcp.analysis.flags']/field[@name='_ws.expert'][@showname='Expert Info (Note/Sequence): This frame is a (suspected) spurious retransmission']")
            if is_tcp_spurious is not None:
                logging.debug('Frame {0}: ignored spurious TCP retransmission'.format(frame_number))
                return None
    except:
        pass

    boundary_dict = {}  # Currently not supported over several frames. Will add if needed
    streams = el.findall("field[@name='http2.stream']")
    parsed_streams = [parse_http_proto_stream(frame_number, stream, ignorehttpheaders_list, el, boundary_dict) for
                      stream in streams]
    parsed_streams = [e for e in parsed_streams if e is not None]
    parsed_streams = [format_http2_line_breaks(e) for e in parsed_streams]

    # Remove duplicated lines (there may be several DATA frames showing the same metadata)
    seen = set()
    result = []
    for item in parsed_streams:
        if item not in seen:
            seen.add(item)
            result.append(item)

    payload_stream_matches = [http_payload_for_stream.match(e) for e in result]
    scan_list = list(enumerate(payload_stream_matches))
    scan_list.reverse()
    result_final = [None] * len(result)
    streams_seen = set()

    for idx, match in scan_list:
        if match is None:
            result_final[idx] = result[idx]
        else:
            stream_id = match.group(1)
            if stream_id not in streams_seen:
                streams_seen.add(stream_id)
                result_final[idx] = result[idx]
            else:
                logging.debug(
                    'Frame {0}: multiple DATA frames for stream {1}. frame {2} in HTTP/2 frame'.format(frame_number,
                                                                                                       stream_id,
                                                                                                       idx))
                result_final[idx] = ''

    result_final = [e for e in result_final if e != '']
    full_text = '\n'.join(result_final)
    # Fix for #29 In case a HTTP/2 message has "HEADERS" only and no "DATA", the SVG is not correct since there is a
    # missing newline char in the uml file. For example: "SMF" -> "AMF2": 91. HTTP/2 204 rsp. note right of "SMF"
    # #e6e6e6 SMF to AMF2 10.206.108.92 to 10.206.108.67 (IPs) HTTP/2 stream: 37 :status: 204end note In front of
    # "end note" the newline is missing.
    # Thanks @rtommy
    if not full_text.endswith('\n'):
        full_text = full_text + '\n'
    return full_text


def format_http2_line_breaks(e):
    # Do not add a line separator if it is only a one-lines
    if e.count('\n') > 1:
        return e + '\n'
    return e


def get_http2_fragments(frame_number, stream_id):
    if frame_number not in packet_data_fragments:
        packet_data_fragments[frame_number] = {}
    stream_fragments = packet_data_fragments[frame_number]
    if stream_id not in stream_fragments:
        stream_fragments[stream_id] = []

    return stream_fragments[stream_id]


def parse_sbi_type_from_url(sbi_str):
    # Examples:
    # POST  /nsmf-pdusession/v1/sm-contexts
    # GET  /nudm-sdm/v1/imsi-234100000000000/sm-data
    # HTTP/2 200 rsp.
    # POST  /nudm-sdm/v1/imsi-234100000000000/sdm-subscriptions
    # HTTP/2 req.\\nDELETE  /nudm-uecm/v1/imsi-234100000000000/registrations/smf-registrations/6
    # HTTP/2 req.\\nPOST  /nsmf-pdusession/v1/sm-contexts
    # HTTP/2 req.\\nPUT  /nausf-auth/v1/ue-authentications/0/5g-aka-confirmation
    match = sbi_regex.match(sbi_str)
    if match is None:
        return None
    try:
        named_groups = match.groupdict()
        method = named_groups['method']
        url = named_groups['url']
        cleaned_url = imsi_cleaner.sub('', url)
        cleaned_url = pdu_session_id_cleaner.sub('', cleaned_url)
        cleaned_url = multiple_slash_cleaner.sub('/', cleaned_url)

        # In some cases multiple inputs may pollute the output. Clean-up here and hope that nothing breaks ;)
        split_output = cleaned_url.split('\\n')
        if len(split_output) == 1:
            return [sbiUrlDescription(method, split_output[0])]

        logging.debug('HTTP/2 frame contains more than one HEADERS frame: {0}'.format(cleaned_url))
        cleaned_url = []
        cleaned_url.append(sbiUrlDescription(method, split_output[0]))
        for e in split_output[1:]:
            match = sbi_regex.match(e)
            if match is None:
                return None
            named_groups = match.groupdict()
            method = named_groups['method']
            url = named_groups['url']
            _cleaned_url = imsi_cleaner.sub('', url)
            _cleaned_url = pdu_session_id_cleaner.sub('', _cleaned_url)
            _cleaned_url = multiple_slash_cleaner.sub('/', _cleaned_url)
            cleaned_url.append(sbiUrlDescription(method, _cleaned_url))
        logging.debug('Cleaned-up summary: {0}'.format(cleaned_url))
        return cleaned_url
    except:
        traceback.print_exc()
        return None


def filter_long_json_params(parsed_json, max_ascii_length_for_json_param):
    parsed_json_list = list(parsed_json.items())
    for k, v in parsed_json_list:
        done_something = False
        if isinstance(v, dict):
            v = filter_long_json_params(v, max_ascii_length_for_json_param)
            done_something = True
        elif isinstance(v, str):
            if len(v) > max_ascii_length_for_json_param:
                v = '{0}[...] Truncated to {1} chars. Total length: {2}'.format(v[0:max_ascii_length_for_json_param],
                                                                                max_ascii_length_for_json_param, len(v))
                done_something = True
        if done_something:
            parsed_json[k] = v

    return parsed_json

