"""
This module contains API functions for importing data from Infoblox.
"""

import os
import csv
import json
from infoblox_client import connector
from util import decrypt


class InfobloxAPI:
    def __init__(self, conf):
        self.range_data = {}
        print("Running InfobloxAPI...")
        self.VLAN_FILEPATH = conf['offline_path']
        self.connector_opts = {
            'host': conf['hostname'],
            'ssl_verify': True,
            'username': decrypt(conf['username']),
            'password': decrypt(conf["password"])
        }

    def process_range(self, result):
        range_data = {}
        if result:
            print("Processing API data")
        elif os.path.exists(self.VLAN_FILEPATH):
            with open(self.VLAN_FILEPATH, 'r') as vlan_file:
                csv_reader = csv.reader(vlan_file)
                vlan_csv = list(csv_reader)[1:]

                for row in vlan_csv:
                    if row[3] not in range_data.keys():
                        range_data[row[3]] = {
                            'department': row[4],
                            'subnets': {}
                        }
                    subnet_obj = {
                        'name': row[2],
                        'cidr': row[0],
                        'protection': 5,
                        'availability': 5,
                        'comment': row[1]
                    }
                    range_data[row[3]]['subnets'][row[0]] = subnet_obj
        else:
            subnet_obj = {
                'name': 'Unknown',
                'cidr': '0.0.0.0/0',
                'protection': 5,
                'availability': 5,
                'comment': 'Unknown'
            }
            range_data['NO REF'] = {
                'department': 'Unknown',
                'subnets': subnet_obj
            }
        # Api data processing

        self.range_data = range_data

    def import_data(self):
        # connect API
        return False

    def write_to_disk(self):
        with open('.tmp.range_data', 'w+') as f:
            json.dump(self.range_data, f, indent=2)

    def main(self):
        result = self.import_data()
        self.process_range(result)
        return self.range_data

