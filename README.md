![OPBLogo](https://github.com/user-attachments/assets/dafa7a9a-b875-4d62-8c70-2fb5424892b2)


# Open Packet Broker


Open Packet Broker is a software tool designed to capture and redirect network traffic based on user-defined rules. It is useful for network security, traffic analysis, and traffic mirroring between network interfaces.

## Features

- **TCP Flag Filtering:** Filters packets based on TCP flags like SYN, ACK, RST, etc.
- **Protocol Filtering:** Filters packets based on protocols like TCP, UDP, and ICMP.
- **VLAN ID Filtering:** Filters packets based on a specific VLAN ID.
- **String Matching:** Filters packets containing a specific string in their payload.
- **Exclude Mode:** Allows exclusion of certain traffic from being forwarded based on specified rules.
- **Dynamic Rule Loading:** Rules can be dynamically updated from a configuration file during runtime.
- **Priority and Time-Based Rules:** Supports rules with priority levels and time-based activation windows.
- **Logging:** Logs significant events and packet matching activity.

## Dependencies

- **libpcap:** Packet capture library.
- **pthread:** POSIX threads library for multithreading support.

To install the necessary dependencies on Ubuntu, use the following commands:

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

## Installation and Compilation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/packet-broker.git
cd packet-broker
```

2. Compile the source code:
```bash
gcc -o packet_broker packet_broker.c -lpcap -lpthread
```

3. Create a rules configuration file:
- Create a file named 'rules.conf' in the same directory as the binary.
- Example rules.conf:
```bash
# Example Rules
ens33,0,0,0,0,0,0,ens38   # Redirect all traffic from ens33 to ens38
ens33,S,80,TCP,0,0,0,ens34  # Redirect TCP traffic with SYN flag set on port 80 from ens33 to ens34
ens33,0,0,UDP,100,0,0,ens39  # Redirect UDP traffic on VLAN 100 from ens33 to ens39
ens33,0,0,TCP,0,login,0,ens40  # Redirect TCP traffic containing "login" in the payload from ens33 to ens40
```
! Please remove comments from example reules

## Usage
1. Run the Packet Broker:
```bash
./packet_broker
```
2. Monitoring Logs:
- Logs are written to 'packet_broker.log'.
- You can view the logs using:
```bash
tail -f packet_broker.log
```
3. Stopping the Packet Broker:
- To stop the Packet Broker, simply kill the process or use a stop command if integrated with a service.

## Example Configuration
Here is an example of how rules might be configured:
```bash
# Interface, TCP Flags, Destination Port, Protocol, VLAN ID, String Match, Exclude, Output Interface
ens33,0,0,0,0,0,0,ens38   # Redirect all traffic
ens33,S,80,TCP,0,0,0,ens34  # SYN flag set on port 80, TCP traffic only
ens33,0,0,UDP,100,0,0,ens39  # VLAN 100 UDP traffic only
ens33,0,0,TCP,0,login,0,ens40  # Redirect traffic containing "login"
```
## How It Works
1. Packet Capture: Packet Broker captures network traffic from a specified interface.
2. Rule Matching: Each packet is evaluated against the rules defined in rules.conf.
3. Packet Redirection: If a packet matches a rule, it is redirected to the specified output interface.
4. Logging: All matching and significant events are logged to a file.

## Use Cases
The Packet Broker designed in this project offers essential functionality for efficient network traffic management. It enables organizations to manage, filter, and mirror traffic, making it a valuable tool in network security operations, particularly for SOC environments and IT infrastructure monitoring. Below are some practical use cases leveraging the features of this packet broker:

1. Traffic Mirroring for Multi-tool Integration
The Packet Broker allows for multi-mirroring, where traffic from one source can be mirrored across multiple interfaces, enabling the distribution of traffic to various network security tools simultaneously.

- Use Case: A security team can mirror traffic from the core switch (e.g., ens33) and send it to both a Network Access Control (NAC) device and an Intrusion Detection System (IDS) using separate network interfaces (e.g., ens34 for NAC and ens38 for IDS). This ensures that both tools receive the same traffic in real-time, improving visibility across the network without duplicating traffic manually.

2. VLAN-based Traffic Filtering for Targeted Security Monitoring
The ability to filter traffic based on VLAN ID allows precise control over which network segments' traffic is monitored or redirected to specific tools.

- Use Case: A network administrator can configure the Packet Broker to filter and forward traffic from a specific VLAN (e.g., VLAN 100) to a dedicated security appliance for further inspection. This setup is ideal for environments where different VLANs represent different security zones, ensuring that traffic from sensitive zones receives closer scrutiny.

3. Protocol-based Redirection for Optimized Traffic Management
Protocol-based filtering allows the Packet Broker to route traffic based on the type of protocol being used (e.g., TCP, UDP).

- Use Case: SOC teams can use this feature to redirect only TCP traffic to the IDS for stateful packet inspection, while UDP traffic is sent to another system for performance monitoring. This minimizes unnecessary overhead on critical security appliances by sending only relevant traffic to each tool.

4. TCP Flag Filtering for Network Defense
The Packet Broker can filter traffic based on TCP flags such as SYN, ACK, or FIN. This is particularly useful for detecting and mitigating specific types of attacks.

- Use Case: The Packet Broker can be configured to filter all SYN packets on port 80 and redirect them to an external firewall or DDoS mitigation system. This feature helps detect SYN flood attacks by identifying abnormal levels of SYN packets and allowing them to be processed separately.

5. Dynamic Rule Updates for Incident Response
One of the key features of the Packet Broker is its ability to dynamically update rules during runtime without requiring a restart. This is critical in fast-moving environments where the SOC team needs to react to live incidents.

- Use Case: During a security incident, the SOC team can quickly adjust the packet broker rules to mirror traffic from a specific source IP or redirect traffic from an interface under investigation to an isolated network for forensics, all without disrupting ongoing network traffic.

6. Excluding Specific Protocols for Efficient Bandwidth Usage
The exclusion rule feature allows certain protocols or traffic types to be ignored, ensuring that only the most relevant traffic is forwarded to security devices.

- Use Case: A SOC analyst can configure the Packet Broker to exclude SSH traffic from the mirrored data sent to a security appliance, ensuring that bandwidth is preserved for more critical traffic types like HTTP or DNS, which are more likely to require inspection for anomalies.

7. Time-based Rule Activation for Off-Hour Monitoring
With time-based rules, the Packet Broker can activate or deactivate certain rules during specified time windows, allowing administrators to adjust traffic flows based on business hours or network load.

- Use Case: A company might want to redirect traffic from a development VLAN to an IDS only during off-peak hours (e.g., from 8:00 PM to 6:00 AM) when sensitive tests are being run. The Packet Broker can automatically switch to the configured rules for this time window, providing flexibility in monitoring.

## Contributing
```
Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.
```

# TO DO
- [ ] Web UI
- [ ] Dynamic Rules Management with API
- [ ] Dynamic Monitoring
- [ ] Logging
- [ ] libcap to DPDK
