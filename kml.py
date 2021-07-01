#!/usr/bin/python3

import os
import sys

import pykml
from ip2geotools.databases.noncommercial import DbIpCity
from pykml.factory import KML_ElementMaker as KML
from lxml import etree

def generate_kml_file(db_conn, out_dir):
    # Internal function to convert IP address into KML placemark (if it has a location known by DB).
    def placemark_from_ip(ip_addr):
        print("placemark_from_ip", ip_addr)
        try:
            response = DbIpCity.get(ip_addr, api_key='free')
        except Exception as e:
            return None
       
        country = response.country
        city = response.city
        latitude = response.latitude
        longitude = response.longitude

        placemark = KML.Placemark(
            KML.name(ip_addr),
            KML.description("{}, {}".format(city, country)),
            KML.Point(
                KML.coordinates("{},{}".format(longitude, latitude))
            )
        )

        return placemark

    # Start new KML document.
    kml_doc = KML.kml(KML.Document())

    # Prepare dictionaries for placemarks and linestrings.
    # This will enable us to not repeat ourselved when generating them.
    placemarks_by_ip = dict()

    cursor = db_conn.cursor()
    cursor.execute('SELECT src_ip, dst_ip FROM ip_packets GROUP BY src_ip, dst_ip;')

    for row in cursor:
        src_ip = row[0]
        dst_ip = row[0]

        src_placemark = placemarks_by_ip.get(src_ip)
        if src_placemark is None:
            src_placemark = placemark_from_ip(src_ip)
            placemarks_by_ip[src_ip] = src_placemark

        dst_placemark = placemarks_by_ip.get(dst_ip)
        if dst_placemark is None:
            dst_placemark = placemark_from_ip(dst_ip)
            placemarks_by_ip[dst_ip] = dst_placemark

    # Put placemarks we created into KML document.
    for ip in placemarks_by_ip.keys():
        if placemarks_by_ip.get(ip) is not None:
            kml_doc.Document.append(placemarks_by_ip.get(ip))

    # Render KML string and write to file.
    kml_str = etree.tostring(kml_doc, pretty_print=True).decode('utf-8')

    kml_filepath = os.path.join(out_dir, "network.kml")

    with open(kml_filepath, "w+") as kml_f:
        kml_f.write(kml_str)

    # Attempt to do some platform-specific trickery to make Google Earth open our KML file
    # we just created.
    if sys.platform.startswith('darwin'):
        os.system("open {}".format(kml_filepath))
    elif sys.platform.startswith('nt'):
        os.startfile(kml_filepath)
    elif sys.platform.startswith('linux'):
        os.system("xdg-open {}".format(kml_filepath))

