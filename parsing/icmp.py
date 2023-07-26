import yaml

from parsing.nas import nas_5g_proto_to_dict


def parse_icmp_proto(frame_number, protocol, gtp_proto=None):
    if protocol is None:
        return ''

    # Dump message content
    icmp_type = protocol.find("field[@name='icmp.type'][@value]")
    if icmp_type is not None:
        icmp_type = icmp_type.attrib['value']

        try:
            description = protocol.find("field[@name='icmp.type'][@showname]").attrib['showname']
        except:
            description = ''

        try:
            description = '{0} seq={1}/{2}'.format(description,
                                                   protocol.find("field[@name='icmp.seq'][@show]").attrib['show'],
                                                   protocol.find("field[@name='icmp.seq_le'][@show]").attrib['show'])
        except:
            pass

        if icmp_type == '00':
            return description
        if icmp_type == '03':
            return description
        if icmp_type == '05':
            return description
        if icmp_type == '08':
            return description

        protocol_dict = nas_5g_proto_to_dict(protocol)
        json_str = yaml.dump(protocol_dict, indent=4, width=1000, sort_keys=False)
        return json_str
