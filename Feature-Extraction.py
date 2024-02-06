import subprocess
import time
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

# Defining a dictionary called config to hold all the different configuration settings.
# It contains a key called "exe_paths" with a list of file paths to executable files.
config = {
    "exe_paths": [
        # Paths to Malicious executables in the exe_paths list.
        r"C:\Users\vboxuser\Downloads\Malicious\CmdManager.exe",
        r"C:\Users\vboxuser\Downloads\Malicious\DarkTequila.exe",  
        r"C:\Users\vboxuser\Downloads\Malicious\GoziBankerISFB.exe",
        r"C:\Users\vboxuser\Downloads\Malicious\botcmd.exe",
        r"C:\Users\vboxuser\Downloads\Malicious\OctopusDelphi.exe",
        # Paths to legitimate executables in the exe_paths list.
        r"C:\Users\vboxuser\Downloads\Legitimate\AnyDesk.exe",
        r"C:\Users\vboxuser\Downloads\Legitimate\disk-drill-win.exe",
        r"C:\Users\vboxuser\Downloads\Legitimate\Thunderbird Setup 115.1.1.exe",  
        r"C:\Users\vboxuser\Downloads\Legitimate\setup-lightshot.exe",
        r"C:\Users\vboxuser\Downloads\Legitimate\ZoomInstallerFull.exe",
    ],
    
    # Path to the TShark executable used for packet capturing.
    "tshark_path": r"C:\\Program Files\\Wireshark\\tshark.exe",
    
    # Defining the directory where the captured packets (PCAP files) will be stored.
    "output_dir": r"C:\\Users\\vboxuser\\Downloads\\malicious_pcap",
}

# Defining a function called start_processes and pass the below mentioned parameters:
def start_processes(exe_path, tshark_path, output_pcap_path):
    
    # Defining the command for capturing packets using TShark.
    capture_cmd = [tshark_path, '-i', 'Ethernet', '-w', output_pcap_path]

    # Starting the packet capture process using subprocess.Popen and store it in capture_proc.
    capture_proc = subprocess.Popen(capture_cmd)
    
    # Starting the executable file specified in exe_path using subprocess.Popen and store it in exe_proc.
    exe_proc = subprocess.Popen(exe_path)
    
    # To allow the processes to run, pause the program for 10 seconds.
    time.sleep(10)
    
    # Terminate the packet capture process and executable process.
    capture_proc.terminate()
    exe_proc.terminate()

# Defining a function called process_packets and pass the path to the output PCAP file as a parameter.
def process_packets(output_pcap_path):
    
    # Create "statistics" and "network" keys in the data dictionary.
    data = {
        "statistics": [],
        "network": [],
    }
    
    # Defining a list of monitored protocols.
    monitored_protocols = ["HTTPS", "SMTP", "HTTP", "DNS", "ICMP", 
                           "FTP", "Telnet", "SSH", "SMB", "RDP", 
                           "SNMP", "SSDP"]
    
    # Create packet_counts for storing packet count statistics using defaultdict.
    packet_counts = defaultdict(lambda: defaultdict(int))

    # Create byte_counts for storing byte count statistics using defaultdict.
    byte_counts = defaultdict(lambda: defaultdict(int))

    # Read the PCAP file mentioned in output_pcap_path using pyshark's FileCapture.
    with pyshark.FileCapture(output_pcap_path) as cap:
        
        # Run a loop for each packet in the capture.
        for packet in cap:
            
            # Check if the packet is an IP packet.
            if 'IP' in packet:
                
                # Create keys based on the source and destination IP addresses.
                key_src_dst = (packet.ip.src, packet.ip.dst)
                key_dst_src = (packet.ip.dst, packet.ip.src)

                # Update packet counts from source to destination.
                packet_counts[key_src_dst]["from_src_to_dst"] += 1
                
                # Update byte counts from source to destination.
                byte_counts[key_src_dst]["from_src_to_dst"] += int(packet.ip.len)

                # Update packet counts from destination to source.
                packet_counts[key_dst_src]["from_dst_to_src"] += 1
                
                # Update byte counts from destination to source.
                byte_counts[key_dst_src]["from_dst_to_src"] += int(packet.ip.len)

                # Check if the packet's highest-layer protocol is among the monitored protocols.
                if packet.highest_layer in monitored_protocols:
                    
                    # Create a dictionary to hold various attributes of the network data.
                    network_data = {
                        'Source IP': packet.ip.src,
                        'Destination IP': packet.ip.dst,
                        
                        # Check the packet's TCP or UDP status after capturing the source port.
                        'Source Port': packet.tcp.srcport if 'TCP' in packet else (packet.udp.srcport if 'UDP' in packet else None),
                        
                        # Check the packet's TCP or UDP status after capturing the destination port.
                        'Destination Port': packet.tcp.dstport if 'TCP' in packet else (packet.udp.dstport if 'UDP' in packet else None),
                        
                        'Protocol': packet.highest_layer,
                        'Info': packet.highest_layer
                    }

                    # If the highest-layer protocol is HTTP, start collecting HTTP-specific information.
                    # Currently, it only includes code for HTTP. This can be extended as needed.
                    if packet.highest_layer == "HTTP":
                        
                        # Create a list to hold HTTP-specific information.
                        http_info = []
                        
                        # If the HTTP packet has a 'request_method', then append it to the http_info list.
                        if hasattr(packet.http, 'request_method'):
                            http_info.append(packet.http.request_method)
                        
                        # If the HTTP packet has a 'host', then append it to the http_info list.
                        if hasattr(packet.http, 'host'):
                            http_info.append(packet.http.host)
                        
                        # Update the 'Info' field in network_data by joining the collected HTTP info.
                        network_data["Info"] = ' '.join(http_info)
                    
                    # If the highest-layer protocol is DNS, start collecting DNS-specific information.
                    elif packet.highest_layer == "DNS":
                        
                        # Create a list to hold DNS-specific information.
                        dns_info = []
                        
                        # If the DNS packet has a 'qry_name', append it to the dns_info list.
                        if hasattr(packet.dns, 'qry_name'):
                            dns_info.append(f"Query:{packet.dns.qry_name}")
                        
                        # If the DNS packet has a 'resp_name', append it to the dns_info list.
                        if hasattr(packet.dns, 'resp_name'):
                            dns_info.append(f"Response:{packet.dns.resp_name}")
                        
                        # Update the 'Info' field in network_data by joining the collected DNS info.
                        network_data["Info"] = ' '.join(dns_info)
                    data["network"].append(network_data)
            
    # Populating statistical data from the collected packet counts.
    for (src, dst), counts in packet_counts.items():

        # Create a dictionary to hold various statistics.
        stats = {
            'Source IP': src,
            'Destination IP': dst,
            
            # Total number of packets between the source and destination is calculated below.
            'Total Packets': counts["from_src_to_dst"] + counts["from_dst_to_src"],
            
            # Storing the number of packets from source to destination.
            'Packets from Source to Destination': counts["from_src_to_dst"],
            
            # Storing the number of packets from destination to source.
            'Packets from Destination to Source': counts["from_dst_to_src"],
            
            # Storing the total bytes sent from source to destination.
            'Sent (bytes)': byte_counts[(src, dst)]["from_src_to_dst"],
            
            # Storing the total bytes received from destination to source.
            'Received (bytes)': byte_counts[(src, dst)]["from_dst_to_src"]
        }
        
        # Append the data dictionary with statistics data to the 'statistics' list.
        data["statistics"].append(stats)
    return data

# Defining a function called save_data_to_excel and pass the collected data and a file path as a parameter.
def save_data_to_excel(data, path):
    
    # Use pandas ExcelWriter to write the data to an Excel file.
    with pd.ExcelWriter(path) as writer:
        
        # Run a loop for each key-value pair in the data dictionary.
        for key, value in data.items():

            # Printing the progress of writing data to the Excel file.
            print(f"Writing data for {key}...")
            
            # If the key is not "headers", then write the data frame to a new sheet in the Excel file.
            if key != "headers":
                pd.DataFrame(value).to_excel(writer, sheet_name=key.capitalize(), index=False)
            
            # If the key is "headers", then loop for each header key-value pair and write them to a new sheet.
            else:
                for header_key, header_value in value.items():
                    pd.DataFrame(header_value).to_excel(writer, sheet_name=header_key.upper() + ' Headers', index=False)

# Defining a function called plot_data and pass the path to the executable and the Excel file as parameters.
def plot_data(exe_path, excel_path):
    
    # Reading the 'Statistics' excel sheet from the Excel file into a pandas DataFrame.
    df_stats = pd.read_excel(excel_path, sheet_name='Statistics')
    
    # If the 'Sent (bytes)' column is not present in the DataFrame df_stats.
    if 'Sent (bytes)' not in df_stats.columns:
        print(f"'Sent (bytes)' column not found in {excel_path}. Skipping plotting for this file.")
        return

    # If the 'Received (bytes)' column is not present in the DataFrame df_stats.
    if 'Received (bytes)' not in df_stats.columns:
        print(f"'Received (bytes)' column not found in {excel_path}. Skipping plotting for this file.")
        return

    # Extracting the executable name from the exe_path by splitting on '\\\\' and taking the last element.
    exe_name = exe_path.split('\\\\')[-1]

    # Extracting the 'Sent (bytes)' and 'Received (bytes)' columns from the DataFrame df_stats.
    bytes_sent = df_stats['Sent (bytes)']
    bytes_received = df_stats['Received (bytes)']

    # Creating labels for the x-axis using Source IP and Destination IP for each row in df_stats.
    labels = [f"{row['Source IP']} to {row['Destination IP']}" for _, row in df_stats.iterrows()]

    fig, ax = plt.subplots(figsize=(10, 6))

    # Creating a bar plot for 'Sent bytes', with colors 'g' (green) for cases where sent > received, else 'r' (red).
    ax.bar(labels, bytes_sent, label='Sent bytes', color=['g' if s > r else 'r' for s, r in zip(bytes_sent, bytes_received)])

    # Creating a bar plot for 'Received bytes', with colors 'r' (red) for cases where sent > received, else 'g' (green).
    # The 'bottom' parameter is used to stack 'Received bytes' on top of 'Sent bytes'.
    ax.bar(labels, bytes_received, label='Received bytes', color=['r' if s > r else 'g' for s, r in zip(bytes_sent, bytes_received)], bottom=bytes_sent)

    # Adding the title of the plot using the executable name.
    ax.set_title(f'Sent and Received Bytes ({exe_name})')

    # Adding labels for y-axis and x-axis.
    ax.set_ylabel('Bytes')
    ax.set_xlabel('Source to Destination')

    ax.legend()
    plt.xticks(rotation=45, ha='right')

    plt.tight_layout()
    plt.show()

# The main execution block starts here.
for idx, exe_path in enumerate(config["exe_paths"]):
    
    # Defining the output path for the captured packets.
    output_path = f"{config['output_dir']}/output_{idx}.pcap"
    
    # Calling the start_processes function to begin packet capturing and running the executable.
    start_processes(exe_path, config["tshark_path"], output_path)
    
    # Calling the process_packets function by passig the output path for the captured packets.
    packet_data = process_packets(output_path)
    
    # Creating a new Excel file path by replacing the ".pcap" extension with ".xlsx".
    excel_path = output_path.replace(".pcap", ".xlsx")

    # Calling the function save_data_to_excel to save the collected packet data to the Excel file.
    save_data_to_excel(packet_data, excel_path)

    # Calling the function plot_data to generate plots based on the saved Excel file and executable path.
    plot_data(exe_path, excel_path)
