"""
This module calculates the Protection and Availability scores for each host
"""

import math
import csv


class HostImpact:
    def __init__(self, conf, host_data, range_data, service_scores, subnet_hosts):
        self.data_dir = conf['data_dir']
        self.weights = conf['weights']['impact']
        self.host_data = host_data
        self.range_data = range_data
        self.service_scores = service_scores
        self.subnet_hosts = subnet_hosts

    def get_conn_bounds(self, subnet):
        subnet_hosts = []
        for cidr in self.subnet_hosts[subnet].keys():
            subnet_hosts.extend(iter(self.subnet_hosts[subnet][cidr]))
        max_conns = 0
        min_conns = 1000000
        for host in subnet_hosts:
            total_conns = sum(self.host_data[host]['connections'].values())
            if total_conns > max_conns:
                max_conns = total_conns
            if total_conns < min_conns:
                min_conns = total_conns

        return max_conns, min_conns

    def calculate_pa_scores(self):
        for host in self.host_data.keys():
            ip = host
            host = self.host_data[host]

            # Calculate Protection Level
            if host['subnet'] == "No Match":
                subnet_protection = 5
            else:
                subnet_protection = self.range_data[host['subnet']]['subnets'][host['cidr']]['protection']
            subnet_protection *= self.weights['protection']['identity']

            if 'connections' in host:
                services = host['connections'].keys()
                service_protection = 0
                for service in services:
                    if str(service) in self.service_scores:
                        service_data = self.service_scores[str(service)]
                        if service_data['protection'] > service_protection:
                            service_protection = service_data['protection']
                if service_protection == 0:
                    service_protection = 3
            else:
                # Flat score for client
                services = {}
                service_protection = 5
            service_protection *= self.weights['protection']['role']
            host['protection'] = subnet_protection + service_protection

            # Calculate Availability Level
            service_availability = 0
            if services:
                for service in services:
                    if str(service) in self.service_scores:
                        service_data = self.service_scores[str(service)]
                        if service_data['availability'] > service_availability:
                            service_availability = service_data['availability']
            else:
                # Flat score for client
                service_availability = 5
            service_availability *= self.weights['availability']['service']

            # Network Density
            upper_bound, lower_bound = self.get_conn_bounds(host['subnet'])
            totalconns = sum(host['connections'].values())
            if totalconns == 0:
                totalconns = 1
            density = 2.2 * math.log(totalconns) + lower_bound
            if density > upper_bound:
                density = 10
            density *= self.weights['availability']['network_density']
            host['availability'] = service_availability + density

    def export_csv(self):
        with open(f"{self.data_dir}HostImpact.csv", 'w+', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "Subnet", "CIDR", "Protection", "Availability"])
            for host in self.host_data:
                ip = host
                host = self.host_data[host]
                writer.writerow([ip, host['subnet'], host['cidr'], host['protection'], host['availability']])





