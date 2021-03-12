#!/usr/bin/env python3

# This python script will take a .json file created by the analysis test in pfcptest
# and output .csv files containing statistics about the pfcp messages.
#
# Example usage:
#  python3 pfcp-analysis.py --file pcaps/n4_interface_capture.json --outdir out

import argparse
import json
import time
import os
import csv

ies = [
    'create_pdr', 
    'create_far', 
    'create_urr', 
    'create_qer', 
    'update_pdr',
    'update_far',
    'update_urr',
    'update_qer',
    'remove_pdr',
    'remove_far',
    'remove_urr',
    'remove_qer',
    'create_bar',
    'update_bar',
    'remove_bar']

sessions = {}
seq_num_lookup = {}

# Process all the packets in the pcap
def processPcap(pcap_file):
    global seq_num_lookup

    with open(args.file) as f:
        cap = json.load(f)

    for packet in cap['packets']:
        seq_num = packet['seq_num']
        packet_number = packet['packet_number']
        msg_name = packet['msg_name']

        if 'req' in msg_name:
            if seq_num in seq_num_lookup:
                print(f"Error: packet {packet_number} duplicate sequence number")
            else:
                seq_num_lookup[seq_num] = packet
        elif 'rsp' in msg_name:
            if not seq_num in seq_num_lookup:
                print(f"Error: packet {packet_number} missing sequence number")
            else:
                packet['req'] = seq_num_lookup[seq_num]
                seq_num_lookup[seq_num]['rsp'] = packet
                del seq_num_lookup[seq_num]

            # in cp_seid, up_seid order
            if 'est' in msg_name:
                session = (packet['req']['seid'], packet['seid'])
            else:
                session = (packet['seid'], packet['req']['seid'])

            if not session in sessions:
                sessions[session] = []

            sessions[session].append(packet)

    for packet in seq_num_lookup:
        print(f"Missing response for packet {packet['packet_number']}")

def writeSessionsDetailsCsv():
    global ies
    global sessions

    sessions_csv = os.path.join(outpath, 'sessions_details.csv')
    with open(sessions_csv, 'w', newline='') as file:
        csvwriter = csv.writer(file, dialect=csv.excel)

        headers = []
        headers.append('cp_seid')
        headers.append('up_seid')
        headers.append('message')
        headers.append('ie')
        headers.append('id')
        headers.append('packet_number')
        csvwriter.writerow(headers)

        for session, packets in sessions.items():
            for packet in packets:
                req = packet['req']

                for ie_name in ies:
                    if not ie_name in req:
                        continue

                    ie_type = ie_name.split('_')[1]

                    for ie in req[ie_name]:
                        values = []
                        values.append(f"{session[0]:#0{18}x}")
                        values.append(f"{session[1]:#0{18}x}")
                        values.append(req['msg_name'])
                        values.append(ie_name)
                        values.append(ie[f"{ie_type}_id"])
                        values.append(req['packet_number'])
                        csvwriter.writerow(values)

def writeSessionsActivityCsv():
    global ies
    global sessions

    sessions_csv = os.path.join(outpath, 'sessions_activity.csv')
    with open(sessions_csv, 'w', newline='') as file:
        csvwriter = csv.writer(file, dialect=csv.excel)

        ie_types = ['pdr', 'far', 'urr', 'qer', 'bar']

        headers = []
        headers.append('cp_seid')
        headers.append('up_seid')
        headers.append('session_est_req')
        headers.append('session_del_rsp')
        for ie_type in ie_types:
            headers.append(f"max_active_{ie_type}")
        headers.append('packet_filter')
        csvwriter.writerow(headers)

        for session, packets in sessions.items():
            session_est_req = False
            session_del_rsp = False
            packet_numbers = []
            active_sets = {}
            max_actives = {}
            for ie_type in ie_types:
                active_sets[ie_type] = {}
                max_actives[ie_type] = 0

            for packet in packets:
                req = packet['req']

                if req['msg_name'] == 'sess_est_req':
                    session_est_req = True

                if packet['msg_name'] == 'sess_del_rsp':
                    session_del_rsp = True
                
                packet_numbers.append(req['packet_number'])
                packet_numbers.append(packet['packet_number'])

                for ie_name in ies:
                    if not ie_name in req:
                        continue

                    ie_activity = ie_name.split('_')[0]
                    ie_type = ie_name.split('_')[1]

                    for ie in req[ie_name]:
                        ie_id = ie[f"{ie_type}_id"]

                        active_set = active_sets[ie_type]

                        if ie_activity == 'create':
                            active_set[ie_id] = ie_id
                        elif ie_activity == 'remove':
                            if ie_id in active_set:
                                del active_set[ie_id]

                for ie_type in ie_types:
                    if len(active_sets[ie_type]) > max_actives[ie_type]:
                        max_actives[ie_type] = len(active_sets[ie_type])
                                

            values = []
            values.append(f"{session[0]:#0{18}x}")
            values.append(f"{session[1]:#0{18}x}")
            values.append(session_est_req)
            values.append(session_del_rsp)
            for ie_type in ie_types:
                values.append(max_actives[ie_type])
            packet_filter = 'frame.number in { '
            for packet_number in packet_numbers:
                packet_filter += f"{packet_number} "
            packet_filter += '}'
            values.append(packet_filter)
            csvwriter.writerow(values)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Open a pcap file and gathers PFCP stats')
    parser.add_argument('--file', dest='file', action='store', help='A pcap file')
    parser.add_argument('--outdir', dest='outdir', action='store', help='Output directory')
    args = parser.parse_args()

    processPcap(args.file)

    # Create outpath
    outpath = os.path.join(args.outdir, os.path.splitext(args.file)[0])
    if not os.path.exists(outpath):
        os.makedirs(outpath)

    writeSessionsDetailsCsv()
    writeSessionsActivityCsv()
