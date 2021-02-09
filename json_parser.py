import json
import traceback
import dateutil.parser

def load_json_file(filename):
    d = get_k8s_json_kpi_dict()

    with open(filename) as f:
        lines = f.readlines()
    for line in lines:
        add_k8s_json_k8s_kpis_to_dict(line, d)

    return d

def get_k8s_json_kpi_dict():
    return {
        'pod': [],
        'container': [],
        'namespace': [],
        'timestamp': [],
        'window': [],
        'cpu': [],
        'memory': []
    }


def add_k8s_json_k8s_kpis_to_dict(json_str, d):
    try:
        parsed_json = json.loads(json_str)
    except:
        traceback.print_exec()
    items = parsed_json['items']
    timestamp = None
    for item in items:
        pod_name = item['metadata']['name']
        namespace = item['metadata']['namespace']
        # Use same timestamp for all entries to avoid strange behavior
        if timestamp is None:
            timestamp = item['timestamp']
        window = item['window']
        containers = item['containers']
        if window[-1] == 's':
            window = window[0:-1]
        window = int(window)
        for container in containers:
            container_name = container['name']
            cpu = container['usage']['cpu']
            memory = container['usage']['memory']
            # Originally in nano-cores. converting to full cores
            if cpu[-1] == 'n':
                cpu = float(cpu[0:-1]) / 1000000000
            else:
                # Case of "Zero"
                cpu = float(cpu)
            # Originally in KiB. Converting to GB
            if memory[-2:] == 'Ki':
                memory = memory[0:-2]
                memory = float(memory) * 1000 / 1024 / 1024 / 1024
            elif memory[-2:] == 'Mi':
                memory = memory[0:-2]
                memory = float(memory) * 1000 * 1000 / 1024 / 1024 / 1024
            else:
                # Case of "Zero"
                memory = float(memory)
            d['pod'].append(pod_name)
            d['container'].append(container_name)
            d['namespace'].append(namespace)
            d['timestamp'].append(dateutil.parser.isoparse(timestamp))
            # d['timestamp'].append(timestamp)
            d['window'].append(window)
            # Originally in nano-cores. converting to full cores
            d['cpu'].append(cpu)
            # In MB
            d['memory'].append(memory)
