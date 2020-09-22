"""
This is the data ingestion controller which works alongside RAEngine to reliably update the database with vulnerability
and log data.
"""

import json
import os
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

from data_ingestion import qualysapi, infobloxapi, splunkapi
from util import get_newest_file
import host_impact


class DataIngestionController:
    def __init__(self):
        self.vuln_data = {}
        self.host_data = {}
        self.subnet_data = {}

        with open('conf/config.json', 'r') as f:
            self.CONF = json.load(f)

        self.DATA_DIR = self.CONF["settings"]["data_dir"]
        if not os.path.exists(self.DATA_DIR):
            os.makedirs(self.DATA_DIR)

        self.SPLUNK_OUT = self.CONF["settings"]["splunk_output_dir"]
        if not os.path.exists(self.SPLUNK_OUT):
            os.makedirs(self.SPLUNK_OUT)
        self.DATE_STR = self.CONF['settings']['datestr_format']

    def update_db(self):
        with open(self.DATA_DIR + "vuln_data.json", "w+") as vuln:
            json.dump(self.vuln_data, vuln, indent=2)

        with open(self.DATA_DIR + "host_data.json", "w+") as host:
            json.dump(self.host_data, host, indent=2)

        with open(self.DATA_DIR + "subnet_data.json", "w+") as subnet:
            json.dump(self.subnet_data, subnet, indent=2)

    def load_db(self):
        with open(self.DATA_DIR + "vuln_data.json", "r") as vuln:
            self.vuln_data = json.load(vuln)

        with open(self.DATA_DIR + "host_data.json", "r") as host:
            self.host_data = json.load(host)

        with open(self.DATA_DIR + "subnet_data.json", "r") as subnet:
            self.subnet_data = json.load(subnet)

    def get_subnet(self, host, subnet_info, subnets):
        obj = self.host_data[host]
        obj['cidr'] = "0.0.0.0"
        obj['subnet'] = 'No Match'
        for category in subnets:
            if category not in self.subnet_data:
                self.subnet_data[category] = {}

            for subnet in subnet_info[category]["subnets"].keys():
                net = ip_network(subnet)
                if ip_address(host) in net:
                    obj['cidr'] = subnet
                    obj['subnet'] = category

                    if subnet not in self.subnet_data[category]:
                        self.subnet_data[category][subnet] = []
                    self.subnet_data[category][subnet].append(host)
                    return

    def get_connections_window(self, latest, days=90):
        host_connections = {}
        files = os.listdir(self.SPLUNK_OUT)
        earliest = latest - timedelta(days=days)
        for file in files:
            if earliest <= datetime.strptime(file.split(".")[0], self.DATE_STR) <= latest:
                with open("{}/{}".format(self.SPLUNK_OUT, file)) as conns:
                    host_conns = json.load(conns)
                    for host in host_conns.keys():
                        if host not in host_connections.keys():
                            host_connections[host] = {}
                        for port in host_conns[host].keys():
                            if port not in host_connections[host]:
                                host_connections[host][port] = host_conns[host][port]
                            else:
                                host_connections[host][[port]] += host_conns[host][port]
        return host_connections

    def main(self):
        # Get Vulnerability Data
        qualys_import = qualysapi.QualysAPI(self.CONF['data_ingestion']['qualys'])
        self.vuln_data, self.host_data = qualys_import.main()

        # Get Subnet Data
        infoblox_import = infobloxapi.InfobloxAPI(self.CONF['data_ingestion']['infoblox'])
        subnet_info = infoblox_import.main()
        subnets = sorted(dict(subnet_info).keys(), reverse=True)
        infoblox_import.write_to_disk()

        # Get Log Data
        latest = datetime.now()
        earliest = latest - timedelta(days=7)
        newest_file = get_newest_file(self.SPLUNK_OUT, self.DATE_STR)
        if not newest_file or earliest >= newest_file:
            splunk_import = splunkapi.SplunkAPI(self.CONF['data_ingestion']['splunk'])
            host_connections = splunk_import.get_host_connections()

            # Save Splunk Output
            with open("{}/{}.json".format(self.SPLUNK_OUT, latest.strftime(self.DATE_STR)), 'w+') as file:
                json.dump(host_connections, file, indent=2)

        # Update Log Data
        host_connections = self.get_connections_window(latest, days=90)
        print("Updating Log Data...")
        if host_connections:
            for host in host_connections:
                self.host_data[host]['connections'] = host_connections[host]

        # Find Subnets
        print("Finding subnets...")
        for host in self.host_data.keys():
            self.get_subnet(host, subnet_info, subnets)

        # Calculate P/A Scores
        host_pa_scores = host_impact.HostImpact(self.CONF['settings'], self.host_data, subnet_info,
                                                self.CONF['service_pa_scores'], self.subnet_data)
        host_pa_scores.calculate_pa_scores()
        host_pa_scores.export_csv()

        # Write DB
        self.update_db()


if __name__ == "__main__":
    controller = DataIngestionController()
    controller.main()
