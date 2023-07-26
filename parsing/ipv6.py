import yaml

from parsing.nas import nas_5g_proto_to_dict


def parse_ipv6_route_advertisement_proto(frame_number, protocol):
    if protocol is None:
        return ''

    # Dump message content
    protocol_dict = nas_5g_proto_to_dict(protocol)
    json_str = yaml.dump(protocol_dict, indent=4, width=1000, sort_keys=False)

    return json_str
