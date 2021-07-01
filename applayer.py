#!/usr/bin/python3

import re

import dpkt

def print_http_image_info(db_conn):
    # Dictionaries for unique values.
    image_uris = list()
    image_filenames = list()

    cursor = db_conn.cursor()
    cursor.execute('SELECT raw_data FROM ip_packets WHERE protocol=6;')

    for row in cursor:
        eth = dpkt.ethernet.Ethernet(row[0])
        ip = eth.data
        tcp = ip.data

        if tcp.dport == 80:
            payload_str = tcp.data.decode('utf-8')
            lines = payload_str.split('\r\n')

            first_line = lines[0]

            if first_line.startswith('GET ') and first_line.endswith(' HTTP/1.1'):
                uri = first_line[len('GET '):].replace(' HTTP/1.1', '')
                uri_lowercased = uri.lower()

                if 'png' in uri_lowercased or 'jpg' in uri_lowercased or 'gif' in uri_lowercased:
                    if not uri in image_uris:
                        image_uris.append(uri)

                    if '?' in uri:
                        uri = uri.split('?')[0]

                    image_filename = uri.split('/')[-1]

                    if not image_filename in image_filenames:
                        image_filenames.append(image_filename)

    print("Requested image URIs:")
    for uri in image_uris:
        print(uri)

    print("Requested image filenames:")
    for filename in image_filenames:
        print(filename)

def print_email_info(db_conn):
    src_emails = list()
    dest_emails = list()

    cursor = db_conn.cursor()
    cursor.execute('SELECT raw_data FROM ip_packets WHERE protocol=6;')

    for row in cursor:
        eth = dpkt.ethernet.Ethernet(row[0])
        ip = eth.data
        tcp = ip.data

        if tcp.dport == 25 or tcp.dport == 587 or tcp.dport == 465:
            payload_str = tcp.data.decode('utf-8')

            match = re.search('From: (?:\".*\")? <([^@]+@[^\.]+\.\w+)>', payload_str)
            if match is not None:
                from_email = match.groups()[0]

                if not from_email in src_emails:
                    src_emails.append(from_email)

            match = re.search('To: (?:\".*\" )?<([^@]+@[^\.]+\.\w+)>', payload_str)
            if match is not None:
                to_email = match.groups()[0]

                if not to_email in dest_emails:
                    dest_emails.append(to_email)

    print("Source email addresses:")
    for e in src_emails:
        print(e)

    print("Destination email addresses:")
    for e in dest_emails:
        print(e)

