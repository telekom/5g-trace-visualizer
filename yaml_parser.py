# 5g-trace-visualizer :- convert 5g wireshark data into an UML sequence diagram 
# Copyright (c) 2019, Josep Colom Ikuno, Deutsche Telekom AG 
# contact: opensource@telekom.de 
# This file is distributed under the conditions of the Apache-v2 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

import yaml
import json
import traceback

# Speedup https://stackoverflow.com/questions/18404441/why-is-pyyaml-spending-so-much-time-in-just-parsing-a-yaml-file
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

def load_yaml_list(file_path_list):
    mappings = [ load_yaml(file_path) for file_path in file_path_list ]
    if len(mappings)>1:
        for mapping in mappings[1:]:
            mappings[0].update(mapping)
    return mappings[0]

def load_yaml(file_path):
    loaded_yaml = None
    with open(file_path, mode='rb') as file:
        loaded_yaml = yaml.load(file, Loader=Loader)
    if loaded_yaml is None:
        return {}
    # Parse all pods and check the IPs of all pods
    pods = [ item for item in loaded_yaml["items"] if item["kind"]=='Pod' ]

    ip_to_pod_mapping = {}
    for pod in pods:
        try:
            metadata = pod['metadata']
            if 'annotations' not in metadata:
                continue

            pod_name      = metadata['name']
            pod_namespace = metadata['namespace']
            annotations = metadata['annotations']
            if 'cni.projectcalico.org/podIP' in annotations:
                pod_ip = annotations['cni.projectcalico.org/podIP'][0:-3]
                ip_to_pod_mapping[pod_ip] = (pod_name, pod_namespace)
            
            if 'k8s.v1.cni.cncf.io/networks-status' in annotations:
                network_status_str = annotations['k8s.v1.cni.cncf.io/networks-status']
                try:
                    network_status = json.loads(network_status_str)
                except:
                    continue
                list_of_ips = [ item['ips'] for item in network_status if 'ips' in item ]
                # See https://stackoverflow.com/questions/952914/how-to-make-a-flat-list-out-of-list-of-lists
                ips = [item for sublist in list_of_ips for item in sublist]
                for ip in ips:
                    ip_to_pod_mapping[ip] = (pod_name, pod_namespace)
        except:
            traceback.print_exc()
            print('Could not parse IPs from pod metadata')
    # Mapping of IPs to pod/namespace
    return ip_to_pod_mapping

def load_yaml_vm(file_path):
    loaded_yaml = None
    with open(file_path, mode='rb') as file:
        loaded_yaml = yaml.load(file, Loader=Loader)
    if loaded_yaml is None:
        return {}
    if 'servers' not in loaded_yaml:
        return {}

    ip_to_server_mapping = {}
    servers = loaded_yaml['servers']
    for server_name,server_data in servers.items():
            if 'interfaces' not in server_data:
                continue
            interfaces = server_data['interfaces']
            if interfaces is None:
                continue
            try:
                for interface_name,interface_data in interfaces.items():
                    ip_address = interface_data['fixed']
                    if (ip_address is not None) and (ip_address != ''):
                        # Use tuple so that we can reuse other functions
                        ip_addresses = ip_address.split(',')
                        for e in ip_addresses:
                            try:
                                ip_to_server_mapping[e.strip()] = (server_name,)
                            except:
                                traceback.print_exc()
                                print('Could not parse IPs from VM metadata for IP {0} and server {1}'.format(e, server_name))
            except:
                traceback.print_exc()
                print('Could not parse IPs from VM metadata for server {0}'.format(server_name))
    # Mapping of IPs to VM names
    return ip_to_server_mapping