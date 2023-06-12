import re
from typing import NamedTuple

boundary_regex = r"--(?P<boundary>[a-zA-Z0-9 \/\._]+)[\n\r]+"
mime_part_regex = r"(?P<content_headers>(Content-[a-zA-Z0-9\-]+: ([a-zA-Z0-9 \/\.]+)[\n\r]*)+)"

separate_header_and_payload_regex = re.compile(
    r"(?P<header>" + boundary_regex + mime_part_regex + r")(?P<payload>.*)")
separate_header_and_payload_without_boundary_regex = re.compile(
    r"(?P<header>" + mime_part_regex + r")(?P<payload>.*)")

content_headers_regex = re.compile(r"(?P<name>Content-[a-zA-Z0-9\-]+): (?P<value>[a-zA-Z0-9 \/\.]+)[\n\r]*")


class MimeHeader(NamedTuple):
    name: str
    value: str


class MultipartMimeMessage(NamedTuple):
    boundary: str
    header: str
    payload: str
    mime_headers: list[MimeHeader]


def parse_multipart_mime(
        input_str: str,
        single_part=False) -> list[MultipartMimeMessage]:
    """
    Parses a MIME Multipart message
    :param single_part: Whether the string is only one part (i.e. no boundary part)
    :param input_str: The string containing the MIME multipart message(s)
    :return: A list of parsed structures containing the message contents
    """
    if input_str is None or input_str == '':
        return None
    if not single_part:
        regex_to_use = separate_header_and_payload_regex
    else:
        regex_to_use = separate_header_and_payload_without_boundary_regex
    # print(regex_to_use)
    # print(input_str)
    input_matches = list(regex_to_use.finditer(input_str))
    if input_matches is None or len(input_matches) == 0:
        return None
    return_mime_messages = []
    for input_match in input_matches:
        content_headers = separate_content_headers(input_match.group('content_headers'))
        if len(content_headers) == 0:
            return None
        if single_part:
            boundary = None
        else:
            boundary = input_match.group('boundary')
        return_mime_messages.append(MultipartMimeMessage(
            boundary,
            input_match.group('header'),
            input_match.group('payload'),
            content_headers))

    return return_mime_messages


def separate_content_headers(headers_match: str) -> list[MimeHeader]:
    """
    Returns a dictionary containing all the Multipart MIME
    :param headers_match: A list of MIME headers in the same order they were found. note that the header names are CAPITALIZED AS TITLES
    """
    if headers_match is None or headers_match == '':
        return []
    parsed_headers = [MimeHeader(m.group('name').title(), m.group('value')) for m in
                      content_headers_regex.finditer(headers_match)]
    return parsed_headers


def find_header(header_name: str, mime_message: MultipartMimeMessage) -> str:
    """
    Searches for a given header in the MIME message
    :param header_name: The header name we are searching for
    :param mime_message: The MIME message
    :return: the header value. An empty string if none is found
    """
    if mime_message is None:
        return None
    for header in mime_message.mime_headers:
        if header.name == header_name:
            return header.value
    return ''
