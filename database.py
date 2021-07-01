#!/usr/bin/python3

from datetime import datetime
import os
import sqlite3
import socket

import dpkt

SQLITE3_FILENAME = "tmp.sqlite"

def read_pcap_into_db(pcap_filepath, db_conn):
    f = open(pcap_filepath, "rb")
    reader = dpkt.pcap.Reader(f)

    cursor = db_conn.cursor()

    for ts, buf in reader:
        eth = dpkt.ethernet.Ethernet(buf)

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
    
        cursor.execute('INSERT INTO ip_packets VALUES (?, ?, ?, ?, ?, ?)', 
                (datetime.utcfromtimestamp(ts).isoformat(), # https://stackoverflow.com/a/3682808
                    socket.inet_ntop(socket.AF_INET, ip.src), 
                    socket.inet_ntop(socket.AF_INET, ip.dst),
                    ip.p, ip.len, buf))

    db_conn.commit()

def prepare_sqlite3_db(out_dir):
    sqlite3_path = os.path.join(out_dir, SQLITE3_FILENAME)

    db_conn = sqlite3.connect(sqlite3_path)
    cursor = db_conn.cursor()

    db_conn.execute('CREATE TABLE IF NOT EXISTS ip_packets (ts TEXT, src_ip TEXT, dst_ip TEXT, protocol INT, ip_len INT, raw_data BLOB);')
    db_conn.execute('DELETE FROM ip_packets;')

    db_conn.commit()

    return db_conn

