# 5g-trace-visualizer with free5gc-compose

This is a example using 5g-trace-visualizer to trace message call flow on free5gc-compose

The different between compose version and origin version is that free5gc originally run on localhost. It's difficultly to trace the sender of 5g call flow.

With the compose version (NF deploy on different container), we can easily trace message flow sending procedure.

## Related IP

server.yaml shows the related IP address for each NF and interfaces.

## Command

The command used to generate the svg file as below:

```
python3 5g-trace-visualizer/trace_visualizer.py -wireshark "OS" -http2ports "29507,38408,29504,29531,29509,29502,29510,29503,29518" -show_selfmessages True -openstackservers ./server.yaml  -limit 300 ./f5gc5.pcap

python3 5g-trace-visualizer/trace_visualizer.py -wireshark "OS" -http2ports "29507,38408,29504,29531,29509,29502,29510,29503,29518" -simple_diagrams True -show_selfmessages True -openstackservers ./server.yaml  -limit 300 ./free5gc-compose.pcap # Simplify version
```

