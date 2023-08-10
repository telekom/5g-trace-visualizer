import collections
import logging
import xml
from enum import Enum
from typing import NamedTuple
from xml.etree import ElementTree as ET


def xml2json(root: xml.etree.ElementTree.Element) -> dict:
    """
    Parse XML ElementTree to dictionary
    :param root: The element root to be parsed
    :return: A Dictionary containing the parsed element structure for which some attributes are shown.
    None if nothing was parsed
    """
    def recursiv(the_root: xml.etree.ElementTree.Element):
        # No need to do anything if the list is empty
        if the_root is None:
            return None
        out = {}
        children_list = list(the_root)
        number_of_children = len(children_list)
        child_name_counter = {}
        for child in children_list:
            child_name = child.attrib["name"]
            # logging.debug(f'Element name: {child_name}')
            # Avoid '' child name if possible
            if child_name == '' and 'show' in child.attrib:
                child_name = child.attrib['show']

            number_of_grandchildren = len(list(child))

            # In some cases, you can have repeated keys, e.g. several TACs, see #28
            original_child_name = child_name
            if child_name not in child_name_counter:
                child_name_counter[child_name] = 1
            else:
                child_name_counter[child_name] = child_name_counter[child_name] + 1
                child_name = '{0} ({1})'.format(child_name, child_name_counter[child_name])

            if number_of_grandchildren > 0:
                if child_name not in out:
                    out[child_name] = []
                child_to_traverse = child

                # Recursively call this function
                data_to_append = recursiv(child_to_traverse)

                # Make the JSON smaller by removing non-useful tags
                if (original_child_name == 'ngap.ProtocolIE_Field_element' or original_child_name == '') and (
                        number_of_children == 1):
                    return data_to_append

                # Reduce arrays of length 1 in dictionary
                for key, value in data_to_append.items():
                    if len(value) == 1:
                        data_to_append[key] = value[0]

                # Reduce dictionaries of length 1 with empty key
                if (len(data_to_append) == 1) and ('' in data_to_append):
                    data_to_append = data_to_append['']

                out[child_name].append(data_to_append)
            else:
                try:
                    if 'showname' in child.attrib:
                        field_content = child.attrib["showname"]
                    elif 'show' in child.attrib:
                        field_content = child.attrib["show"]
                    else:
                        field_content = ''

                    out[child_name] = field_content
                except:
                    logging.debug('ERROR: could not find "showname" attribute for following element')
                    child_str = ET.tostring(child)
                    logging.debug(child_str)
                    out[child_name] = 'ERROR'
        return out

    parsed_tree = recursiv(root)
    return parsed_tree


class PacketDescription(NamedTuple):
    """Describes a packet for the PlantUML visualization"""
    ip_src: str
    ip_dst: str
    frame_number: str
    protocols_str: str
    msg_description: str
    timestamp: float
    timestamp_offsett: float


class PacketType(Enum):
    """Describes Packet types"""
    UNKNOWN = 0
    IPv4 = 1
    IPv6 = 2
    CUSTOM = 3
