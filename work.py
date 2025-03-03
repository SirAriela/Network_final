
import matplotlib.pyplot as plt
from scapy.layers.inet import IP, TCP
import pandas as pd
from scapy.all import rdpcap
from scapy.layers.tls.all import TLS
from pathlib import Path

def ip_header(path):
    data = []

    if path.exists():
        packets = rdpcap(str(path))
        print(f"Total packets found: {len(packets)}")

        # Iterate over packets to extract IP header data
        for packet in packets:
            record = {}
            if IP in packet:
                ip_layer = packet[IP]
                record["ttl"] = ip_layer.ttl
                record["length"] = ip_layer.len
                record["source"] = ip_layer.src
                record["dst"] = ip_layer.dst
            else:
                record["ttl"] = None
                record["length"] = None
                record["source"] = None
                record["dst"] = None

            if TCP in packet:
                tcp_layer = packet[TCP]
                record["tcp_src_port"] = tcp_layer.sport
                record["tcp_dst_port"] = tcp_layer.dport
                record["tcp_flags"] = tcp_layer.flags
                record["tcp_window"] = tcp_layer.window
            else:
                record["tcp_src_port"] = None
                record["tcp_dst_port"] = None
                record["tcp_flags"] = None
                record["tcp_window"] = None

            # Extract TLS header fields if available (if the TLS layer is recognized)
            if TLS and packet.haslayer(TLS):
                tls_layer = packet[TLS]
                # As an example, try to extract the TLS version (this may depend on your scapy version)
                record["tls_version"] = getattr(tls_layer, 'version', None)
            else:
                record["tls_version"] = None
            data.append(record)


        # Convert the list to a DataFrame
        df = pd.DataFrame(data)

        # Plotting the distribution of TTL values
        plt.figure()
        plt.hist(df['ttl'], bins=range(0, 256, 5), edgecolor='black')
        plt.xlabel('TTL')
        plt.ylabel('Frequency')
        plt.title('Distribution of TTL Values')
        plt.show()

        # Plotting the distribution of Packet Lengths
        plt.figure()
        plt.hist(df['length'], bins=35, edgecolor='black')
        plt.xlabel('Packet Length')
        plt.ylabel('Frequency')
        plt.title('Distribution of Packet Lengths')
        plt.show()

        source_counts = df['source'].value_counts()

        plt.figure(figsize=(10, 12))
        source_counts.plot(kind='bar')
        plt.xlabel('source ip')
        plt.ylabel('number of packets')
        plt.title('distributions of packets via source ip')
        plt.show()

        dst_counts = df['dst'].value_counts()

        plt.figure(figsize=(10, 12))
        dst_counts.plot(kind='bar')
        plt.xlabel('dest ip')
        plt.ylabel('number of packets')
        plt.title('distributions of packets via dest ip')
        plt.show()

        # Use qcut to create, for example, 10 quantile bins (adjust the number as needed)
        df['tcp_window_qbin'] = pd.qcut(df['tcp_window'], q=20, duplicates='drop')

        # Count the number of packets in each quantile bin
        tcp_window_qbin_counts = df['tcp_window_qbin'].value_counts().sort_index()

        plt.figure(figsize=(10, 10))
        tcp_window_qbin_counts.plot(kind='bar', edgecolor='black')
        plt.xlabel('TCP Window Size Range (Quantiles)')
        plt.ylabel('Number of Packets')
        plt.title('Distribution of Packets by TCP Window Size (Quantile Binning)')
        plt.xticks(rotation=45)
        plt.show()



        # Plot TLS Version Distribution as a Bar Chart (if TLS data is available)
        if df["tls_version"].notnull().sum() > 0:
            tls_counts = df['tls_version'].value_counts().sort_index()

            plt.figure(figsize=(10, 12))
            tls_counts.plot(kind='bar')
            plt.xlabel('TLS Version')
            plt.ylabel('Number of Packets')
            plt.title('Distribution of Packets by TLS Version')
            plt.show()


def main():

    # show ip header characteristics
    spotify = Path("spotify_stream_music.pcapng")
    web_browser_chrome = Path("web-surfing_chrome.pcapng")
    web_browser_firefox = Path("web-surfing_firefox.pcapng")
    youtube = Path("youtube_stream.pcapng")
    zoom = Path("zoom_call.pcapng")

    print("select which app you want to explore")
    print("1 - spotify")
    print("2 - web browser chrome")
    print("3 - web browser firefox")
    print("4 - youtube")
    print("5 - zoom")

    choice = int(input("Enter your choice: "))
    if choice == 1:
        ip_header(spotify)
    if choice == 2:
        ip_header(web_browser_chrome)
    if choice == 3:
        ip_header(web_browser_firefox)
    if choice == 4:
        ip_header(youtube)
    if choice == 5:
        ip_header(zoom)
    else: print("Invalid choice please try again, but this time choose a valid option. thank you :)")


if __name__ == "__main__":
    main()
