#!/usr/bin/python3

import sys
import os
import json
import shutil

import applayer
import dataviz
import database
import kml

def print_stats_for_protocol(db_conn, protocol_no, protocol_name):
    cursor = db_conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM ip_packets WHERE protocol={};'.format(protocol_no))

    res = cursor.fetchone()

    if res is not None and len(res) > 0:
        n = res[0]

        cursor.execute('SELECT SUM(ip_len) FROM ip_packets WHERE protocol={};'.format(protocol_no))
        res = cursor.fetchone()

        total = res[0]
        mean = float(total)/n

        cursor.execute('SELECT ts FROM ip_packets WHERE protocol={} ORDER BY ts LIMIT 1;'.format(
            protocol_no))
        res = cursor.fetchone()
        ts_first = res[0]

        cursor.execute('SELECT ts FROM ip_packets WHERE protocol={} ORDER BY ts DESC LIMIT 1;'.format(protocol_no))
        res = cursor.fetchone()
        ts_last = res[0]

        print("{} {} packets; mean length {}; first at {}, last at {}".format(n, protocol_name, 
            mean, ts_first, ts_last))

def print_packet_stats(db_conn):
    print_stats_for_protocol(db_conn, 17, "UDP")
    print_stats_for_protocol(db_conn, 2, "IGMP")
    print_stats_for_protocol(db_conn, 6, "TCP")


def get_packets_by_ip_pair(db_conn):
    results = list()

    cursor = db_conn.cursor()

    cursor.execute('SELECT src_ip, dst_ip, COUNT(*) FROM ip_packets GROUP BY src_ip, dst_ip;')

    for row in cursor:
        src_ip = row[0]
        dst_ip = row[1]
        count = row[2]

        results.append({
            'from' : src_ip,
            'to' : dst_ip,
            'packet_count' : count,
        })

    results = sorted(results, key=lambda d: d.get('packet_count'))

    results = list(reversed(results))

    return results

# Perform PCAP analysis. Set up directory and run all routines that actually
# analyses network traffic.
def analyse_pcap(pcap_filepath, out_dir):
    if not os.path.exists(pcap_filepath):
        print("Error: cannot find file {}".format(pcap_filepath))
        sys.exit(1)

    print("Starting traffic analysis...")

    if os.path.exists(out_dir) and os.path.isdir(out_dir):
        for child in os.listdir(out_dir):
            if os.path.isdir(os.path.join(out_dir, child)):
                shutil.rmtree(os.path.join(out_dir, child))
            else:
                os.remove(os.path.join(out_dir, child))
    else:
        os.mkdir(out_dir)

    db_conn = database.prepare_sqlite3_db(out_dir)
    database.read_pcap_into_db(pcap_filepath, db_conn)

    print_packet_stats(db_conn)
    applayer.print_email_info(db_conn)
    applayer.print_http_image_info(db_conn)

    packets_by_ips = get_packets_by_ip_pair(db_conn)

    print("IP traffic by host:")
    for p in packets_by_ips:
        print("{} -> {}: {} packets".format(p.get('from'), p.get('to'), p.get('packet_count')))

    json_path = os.path.join(out_dir, 'ip.json')
    with open(json_path, "w+") as json_f:
        json.dump(packets_by_ips, json_f, indent=4)

    dataviz.generate_graph_image(db_conn, out_dir)
    dataviz.generate_packet_linechart(db_conn, out_dir)
    kml.generate_kml_file(db_conn, out_dir)

    db_conn.close()

def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("{} <pcap_file> <out_dir>".format(sys.argv[0]))
        sys.exit(0)

    analyse_pcap(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()

