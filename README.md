# Packet Broker

Packet Broker is a software tool designed to capture and redirect network traffic based on user-defined rules. It is useful for network security, traffic analysis, and traffic mirroring between network interfaces.

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

## Contributing
Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## TO DO
- [ ] Web UI
- [ ] Dynamic Rules Management with API
- [ ] Dynamic Monitoring
- [ ] Logging
