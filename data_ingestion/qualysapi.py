"""
This module contains API functions for importing data from QualysGuard.
"""

import requests
import xmltodict
import sys
import json
import csv
import os
from datetime import datetime

from util import decrypt


class QualysAPI:
    def __init__(self, conf, subnet_data=None, filter_settings=None):
        print("Running QualysAPI...")
        self.HOSTNAME = conf['hostname']
        self.REPORT_CALL = conf['report_call']
        self.REPORT_NAME = conf['report_name']
        self.AUTH = (decrypt(conf['username']), decrypt(conf['password']))
        self.SAVE_PATH = conf['save_path']
        self.HEADERS = {'X-Requested-With': 'Python'}
        self.REPORT_CACHE = ".latest_report"
        self.vuln_data = {}
        self.host_data = {}

    def list_reports(self):
        report_date = None
        report_id = 0
        fetch = False
        api_err = False
        payload = {
            'action': 'list'
        }
        response = requests.post(self.REPORT_CALL, data=payload, headers=self.HEADERS, auth=self.AUTH)
        try:
            report_list = xmltodict.parse(response.text)['REPORT_LIST_OUTPUT']['RESPONSE']['REPORT_LIST']
            if 'REPORT' in report_list:
                report_date = report_list['REPORT']['LAUNCH_DATETIME']
                report_id = report_list['REPORT']['ID']
            else:
                print("API Error: No report data available")
                api_err = True
        except KeyError:
            report_id = 0
            report_date = None
            print("API Error: No report data available")
            api_err = True

        if not os.path.exists('.latest_report'):
            fetch = True
            if api_err:
                sys.exit("No report available on server or disk. Exiting...")
        else:
            print("Existing report found, loading...")
            with open(self.REPORT_CACHE, 'r') as latest_report:
                latest_date = datetime.strptime(json.load(latest_report)['DATE'], '%Y-%m-%dT%H:%M:%SZ')
                if report_id != 0:
                    fetch = datetime.strptime(report_date, '%Y-%m-%dT%H:%M:%SZ') > latest_date
                else:
                    fetch = False

        return fetch, report_id, report_date

    def fetch_report(self, report_id, report_date):
        payload = {
            'action': 'fetch',
            'id': report_id
        }
        save_path = f"{self.SAVE_PATH}Qualys Report {report_id}.csv"
        print("Fetching ID:", report_id)
        print("Saving to: ", save_path)
        response = requests.post(self.REPORT_CALL, data=payload, headers=self.HEADERS, auth=self.AUTH, stream=True)

        with open(save_path, 'wb') as csv:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    csv.write(chunk)

        with open(self.REPORT_CACHE, 'w+') as latest_report:
            json.dump({'ID': report_id, 'PATH': save_path, 'DATE': report_date}, latest_report)

        print("Deleting report from server...")
        payload = {
            'action': 'delete',
            'id': report_id
        }
        requests.post(self.REPORT_CALL, data=payload, headers=self.HEADERS, auth=self.AUTH)

        return save_path

    def load_report(self):
        vuln_list = []
        csv.field_size_limit(sys.maxsize)
        with open(self.REPORT_CACHE, 'r') as latest_report:
            report_path = json.load(latest_report)['PATH']

        with open(report_path, 'r') as report_file:
            report = list(csv.reader(report_file))
            report = report[5:]

            for row in report:
                try:
                    vuln_list.append(
                        QData(row[0], row[1], row[2], row[3], row[5], row[6], row[8], row[9], row[10], row[12], row[13],
                              row[14], row[17], row[18], row[19], row[23], row[24], row[32], row[34], row[35], row[36],
                              row[37], row[39], row[43]))
                except IndexError:
                    continue

        return vuln_list

    def process_report(self, raw_report):
        for obj in raw_report:
            # Parsing vulnerability data
            if obj.getQID() not in self.vuln_data:
                self.vuln_data[obj.getQID()] = {
                    "title": obj.getTitle(),
                    "cvss": obj.getCVSSv3(),
                    'port': f"{obj.getProtocol()}/{obj.getPort()}",
                    "exploitability": obj.getExploitability(),
                    "first_seen": obj.getFirstDetected(),
                    'category': obj.getCategory(),
                    "threat": obj.getThreat(),
                    "impact": obj.getImpact(),
                    "solution": obj.getSolution(),
                    "hosts": [],
                }
            vuln_obj = self.vuln_data[obj.getQID()]
            if obj.getIP() not in vuln_obj["hosts"]:
                vuln_obj['hosts'].append(obj.getIP())

            # Parsing host data
            if obj.getIP() not in self.host_data:
                self.host_data[obj.getIP()] = {
                    'hostname': obj.getDNS(),
                    'netbios': obj.getNetBIOS(),
                    'os': obj.getOS(),
                    'connections': {},
                    'vulns': []
                }
            host_obj = self.host_data[obj.getIP()]
            if obj.getQID() not in host_obj['vulns']:
                host_obj['vulns'].append(obj.getQID())

    def load_db(self):
        if os.path.exists(f"{self.SAVE_PATH}vuln_data.json") and os.path.exists(
            f"{self.SAVE_PATH}host_data.json"
        ):
            print("DB exists, loading...")
            with open(f"{self.SAVE_PATH}vuln_data.json", "r") as vuln:
                self.vuln_data = json.load(vuln)
            with open(f"{self.SAVE_PATH}host_data.json", "r") as host:
                self.host_data = json.load(host)
        else:
            print("DB not found, generating...")
            raw_report = self.load_report()
            self.process_report(raw_report)

    def main(self):
        fetch, report_id, report_date = self.list_reports()
        if fetch:
            self.fetch_report(report_id, report_date)
            raw_report = self.load_report()
            self.process_report(raw_report)
        else:
            self.load_db()

        return self.vuln_data, self.host_data


class QData: # Qualys Data Object
    def __init__(self, ip, dns, netbios, qghostid, trackingagent, os, qid, title, vulnstatus, severity, port, protocol,
                 firstdetected, lastdetected, timesdetected, timesreopened, cveid, cvss3, threat, impact, solution,
                 exploitability, results, category):
        self.ip = ip
        self.dns = dns
        self.netbios = netbios
        self.qghostid = qghostid
        self.trackingagent = trackingagent
        self.os = os
        self.qid = qid
        self.title = title
        self.vulnstatus = vulnstatus
        self.severity = severity
        self.port = port
        self.protocol = protocol
        self.firstdetected = firstdetected
        self.lastdetected = lastdetected
        self.timesdetected = timesdetected
        self.timesreopened = timesreopened
        self.cveid = cveid
        self.cvss3 = cvss3
        self.threat = threat
        self.impact = impact
        self.solution = solution
        self.exploitability = exploitability
        self.results = results
        self.category = category

    def getIP(self):
        return self.ip

    def getDNS(self):
        return self.dns

    def getNetBIOS(self):
        return self.netbios

    def getQGHostID(self):
        return self.qghostid

    def getTrackingAgent(self):
        return self.trackingagent

    def getOS(self):
        return self.os

    def getQID(self):
        return self.qid

    def getTitle(self):
        return self.title

    def getVulnStatus(self):
        return self.vulnstatus

    def getSeverity(self):
        return self.severity

    def getPort(self):
        return self.port

    def getProtocol(self):
        return self.protocol

    def getFirstDetected(self):
        return self.firstdetected

    def getLastDetected(self):
        return self.lastdetected

    def getTimesDetected(self):
        return self.timesdetected

    def getTimesReopened(self):
        return self.timesreopened

    def getCVEID(self):
        return self.cveid

    def getCVSSv3(self):
        try:
            return float(self.cvss3.split(" ")[0])
        except ValueError:
            if self.cvss3 == "":
                if self.getSeverity() == '5':
                    cvss = 10
                elif self.getSeverity() == '4':
                    cvss = 8
                elif self.getSeverity() == '3':
                    cvss = 5
                else:
                    cvss = 10

            return cvss

    def getThreat(self):
        return self.threat

    def getImpact(self):
        return self.impact

    def getExploitability(self):
        return 'Yes' if self.exploitability else 'No'

    def getResults(self):
        return self.results

    def getCategory(self):
        return self.category

    def getSolution(self):
        return self.solution

    def to_dict(self):
        return json.dumps(self.__dict__)
