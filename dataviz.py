#!/usr/bin/python3

from datetime import datetime
import os
import math
import statistics

import networkx as nx
import matplotlib.pyplot as plt

def generate_graph_image(db_conn, out_dir):
    # Create digraph object, as we have directional nature in our process.
    G = nx.DiGraph()

    cursor = db_conn.cursor()
    cursor.execute('SELECT src_ip, dst_ip, COUNT(*) FROM ip_packets GROUP BY src_ip, dst_ip;')

    for row in cursor:
        src_ip = row[0]
        dst_ip = row[1]
        count = row[2]
    
        G.add_node(src_ip)
        G.add_node(dst_ip)
        G.add_edge(src_ip, dst_ip, weight=count)

    plt.figure(figsize=(20,10))

    pos = nx.planar_layout(G)

    # Draw the graph. 
    nx.draw(G, with_labels=True, node_size=300, node_color='green', width=1, arrowstyle='-|>', 
            arrowsize=30, font_size=10, pos=pos, edge_color='red')
    
    # Draw packet count labels on edges.
    labels = nx.get_edge_attributes(G,'weight')
    nx.draw_networkx_edge_labels(G,pos,edge_labels=labels)

    # Save result into file.
    plt.savefig(os.path.join(out_dir, 'network_graph.png'))
    plt.show()

def generate_packet_linechart(db_conn, out_dir):
    cursor = db_conn.cursor()

    # Establish first and last packet timestamps of PCAP we're processing.
    cursor.execute('SELECT ts FROM ip_packets ORDER BY ts LIMIT 1;')
    res = cursor.fetchone()

    if res is None:
        print("Cannot get first timestamp - bailing out.")
        return

    first_timestamp = res[0]
    # https://stackoverflow.com/questions/3682748/converting-unix-timestamp-string-to-readable-date
    first_timestamp = datetime.strptime(first_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    first_timestamp = first_timestamp.timestamp() # Converts to UNIX timestamp.

    cursor.execute('SELECT ts FROM ip_packets ORDER BY ts DESC LIMIT 1;')
    res = cursor.fetchone()

    if res is None:
        print("Cannot get last timestamp - bailing out.")
        return

    last_timestamp = res[0]
    last_timestamp = datetime.strptime(last_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    last_timestamp = last_timestamp.timestamp()

    duration = last_timestamp - first_timestamp
    slot_duration = 1.0 # 1 second, like in Wireshark by default.

    # How many slots we have for data?
    n_slots = math.ceil(float(duration) / slot_duration)
    n_slots = int(n_slots)

    slots = list()

    for _ in range(n_slots):
        slots.append(0)

    cursor.execute('SELECT ts FROM ip_packets;')
    for row in cursor:
        ts = row[0]
        ts = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f") 
        ts = ts.timestamp()

        time_since_start = ts - first_timestamp

        slot_number = int(math.floor(float(time_since_start) / slot_duration))

        if slot_number > n_slots - 1:
            slot_number = n_slots - 1

        slots[slot_number] += 1

    # Recompute packets-per-slots into packets-per-second.
    slots = list(map(lambda b: b / float(slot_duration), slots))

    # Prepare to plot a chart.
    fig, ax = plt.subplots()

    # Compute mean, standard devation and high-intensity threshold values.
    mean_intensity = statistics.mean(slots)
    std = statistics.stdev(slots)
    thr = mean_intensity + 2 * std

    # We will need an array of time values to plot intensity values against.
    # https://stackoverflow.com/questions/10712002/create-an-empty-list-in-python-with-certain-size
    t = [None] * n_slots
    for i in range(0, n_slots):
        t[i] = slot_duration * i

    ax.plot(t, slots, color="black")
    ax.grid()
    ax.set(xlabel="Time (seconds)", title="Packets per second")

    # Draw a horizontal red line to visualize high intensity cutoff.
    ax.axhline(y=thr, color='red')

    # Save and display data visualisation.
    chart_path = os.path.join(out_dir, "t.png")
    fig.savefig(chart_path)

    plt.show()
