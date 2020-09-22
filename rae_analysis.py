"""
This file carries out the analysis of the data
"""

import csv
import math

from util import float_range


class RAEAnalysis:

    """Initialise global variables to use throughout script"""
    def __init__(self, output_dir, config):
        self.OUTPUT_DIR = output_dir
        self.CONF = config
        self.weights = config['settings']['weights']
        self.vuln_data = {}
        self.host_data = {}

    def run_analysis(self, vuln_data, host_data):
        self.vuln_data = vuln_data
        self.host_data = host_data
        self.calculate_risk()
        self.calculate_impact()
        self.calculate_final()

    def calculate_risk(self):
        print('Calculating Risk')
        attack_table = self.CONF["attack_table"]
        for qid in self.vuln_data.keys():
            plugin = self.vuln_data[qid]

            if "analysis" not in plugin:
                plugin["analysis"] = {}

            """Keyword Match"""
            description = plugin['threat'] + plugin['impact']
            matches = {}
            for vulntype in attack_table:
                keywords = attack_table[vulntype]["keywords"]
                keywords = keywords.lower().split(',')
                for key in keywords:
                    key = key.lstrip()
                    if key in description and vulntype not in matches.keys():
                        matches[vulntype] = float(attack_table[vulntype]["score"])

            sev_score = 0.0
            types = matches.keys()
            type = ", ".join(types)
            divider = 1
            allscores = []

            """Algorithm for multiple matches"""
            if matches:
                for score in matches.values():
                    allscores.append(score)
                allscores.sort(reverse=True)
                for score in allscores:
                    temp = int((score * 9) / 10)
                    if temp is 0:
                        sev_score = float(sev_score + 0.5 / divider)
                    else:
                        sev_score = float(sev_score + float(temp / divider))
                    divider *= 10
            else:
                sev_score = 10
                type = 'No type found'

            cvss_weight = self.CONF["settings"]["weights"]["risk"]["cvss"]
            sev_weight = self.CONF["settings"]["weights"]["risk"]["sev"]
            risk_score = float((cvss_weight * float(plugin['cvss'])) + (sev_weight * sev_score))
            sev_score = round(sev_score, 3)
            risk_score = round(risk_score, 3)

            plugin['analysis']['types'] = type
            plugin['analysis']['sev_score'] = sev_score
            plugin['analysis']['risk_score'] = risk_score

    def calculate_impact(self):
        print('Calculating Impact')

        max_attack_surface = 0

        for qid in self.vuln_data.keys():
            plugin = self.vuln_data[qid]

            """Calculate Attack Surface"""
            numaffected = len(plugin['hosts'])
            num_total_connections = 0
            for host in plugin['hosts']:
                num_total_connections = sum(self.host_data[host]['connections'].values()) + 1
            try:
                attack_surface = 2.2 * (math.log(num_total_connections) + math.log(numaffected))
            except ValueError:
                attack_surface = 10

            plugin['analysis']['attack_surface'] = round(attack_surface, 3)

            if attack_surface > max_attack_surface:
                max_attack_surface = attack_surface

            """Calculate Protection and Availability"""
            total_protection = 0
            total_availability = 0
            for host in plugin['hosts']:
                hostdata = self.host_data[host]
                total_protection += hostdata['protection']
                total_availability += hostdata['availability']
            total_protection /= numaffected
            total_availability /= numaffected

            plugin['analysis']['protection'] = round(total_protection, 3)
            plugin['analysis']['availability'] = round(total_availability, 3)

        # Normalize Attack Surface Scores
        for qid in self.vuln_data.keys():
            plugin = self.vuln_data[qid]
            plugin['analysis']['attack_surface'] = round(((plugin['analysis']['attack_surface'] / max_attack_surface) * 10), 3)

            """Calculate Total Impact"""
            attack_surface_weight = self.weights["impact"]["attack_surface"]["total"]
            protection_weight = self.weights["impact"]["protection"]["total"]
            availability_weight = self.weights["impact"]["availability"]["total"]

            impact_score = (attack_surface_weight * plugin['analysis']['attack_surface']) + \
                           (protection_weight * plugin['analysis']['protection']) + \
                           (availability_weight * plugin['analysis']['availability'])
            plugin['analysis']['impact_score'] = round(impact_score, 3)


        print('Calculate Impact Complete')

    def calculate_final(self):
        print('Calculating Final')
        writer = csv.writer(open(self.OUTPUT_DIR + self.CONF["settings"]["csv_output"], 'w+', newline=''))

        header = ["Plugin ID", "Name", "# Affected", "First Seen", "CVSS Score", "sevScore", "Risk Score",
                  "Attack Surface", "Protection", "Availability", "Impact Score", "Final Score", "Class", "Out of Band",
                  "Synopsis", "Comments"]
        writer.writerow(header)

        critical_types = self.CONF["settings"]['thresholds']["critical_types"].split(",")
        outofband_types = self.CONF["settings"]['thresholds']["outofband_types"].split(",")

        for qid in self.vuln_data.keys():
            plugin = self.vuln_data[qid]
            row = [qid]
            outofband = "no"

            risk_weight = self.weights["overall"]["risk"]
            impact_weight = self.weights["overall"]["impact"]
            final_score = (risk_weight * float(plugin['analysis']['risk_score'])) + \
                          (impact_weight * float(plugin['analysis']['impact_score']))
            plugin['analysis']['final_score'] = round(final_score, 3)

            critical_threshold = self.CONF["settings"]["thresholds"]["critical"]
            high_threshold = self.CONF["settings"]["thresholds"]["high"]
            medium_threshold = self.CONF["settings"]["thresholds"]["medium"]

            if float_range(final_score, float(critical_threshold.split("-")[0]), float(critical_threshold.split("-")[1])):
                classification = "critical"
            elif float_range(final_score, float(high_threshold.split("-")[1]), float(critical_threshold.split("-")[0])):
                for vuln_type in critical_types:
                    if vuln_type in plugin['analysis']['types']:
                        classification = "critical"
                        break
                    else:
                        classification = "high"
            elif float_range(final_score, float(high_threshold.split("-")[0]), float(high_threshold.split("-")[1])):
                classification = "high"
            elif float_range(final_score, float(medium_threshold.split("-")[0]), float(medium_threshold.split("-")[1])):
                classification = "medium"
            else:
                classification = "low"

            self.vuln_data[qid]['analysis']['class'] = classification

            if classification == "critical":
                for vuln_type in outofband_types:
                    if vuln_type in plugin['analysis']['types']:
                        if plugin['exploitability'] == "Yes":
                            outofband = "yes"

            plugin['analysis']['outofband'] = outofband

            row.append(plugin['title'])
            row.append(len(plugin['hosts']))
            row.append(plugin['first_seen'])
            row.append(plugin['cvss'])
            row.append(plugin['analysis']['sev_score'])
            row.append(plugin['analysis']['risk_score'])
            row.append(plugin['analysis']['attack_surface'])
            row.append(plugin['analysis']['protection'])
            row.append(plugin['analysis']['availability'])
            row.append(plugin['analysis']['impact_score'])
            row.append(round(plugin['analysis']['final_score'], 3))
            row.append(classification)
            row.append(outofband)
            row.append(plugin['threat'] + plugin['impact'])
            writer.writerow(row)

        print('Calculate Final Complete')