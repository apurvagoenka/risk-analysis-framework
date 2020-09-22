"""
This is the main controller for RAEngine which imports data and runs the analysis on it, then creates the reports
"""

import json
import os
from datetime import datetime

from rae_analysis import RAEAnalysis


class RAEngineController:
    def __init__(self):
        self.vuln_data = {}
        self.host_data = {}
        self.subnet_data = {}

        with open('conf/config.json', 'r') as f:
            self.CONF = json.load(f)
        self.DATE_STR = self.CONF['settings']['datestr_format']
        self.RUN_TIME = datetime.now().strftime(self.DATE_STR)
        self.ORG = self.CONF["settings"]["org_abbr"]
        self.DATA_DIR = self.CONF["settings"]["data_dir"]
        self.OUTPUT_DIR = "{}/{}/{}/".format('output', self.ORG, self.RUN_TIME)
        if not os.path.exists(self.DATA_DIR):
            os.makedirs(self.DATA_DIR)
        if not os.path.exists(self.OUTPUT_DIR):
            os.makedirs(self.OUTPUT_DIR)

    def load_db(self):
        with open(self.DATA_DIR + "vuln_data.json", "r") as vuln:
            self.vuln_data = json.load(vuln)

        with open(self.DATA_DIR + "host_data.json", "r") as host:
            self.host_data = json.load(host)

        with open(self.DATA_DIR + "subnet_data.json", "r") as subnet:
            self.subnet_data = json.load(subnet)

    def main(self):
        # Load DB
        self.load_db()

        # Analysis
        analysis = RAEAnalysis(self.OUTPUT_DIR, self.CONF)
        analysis.run_analysis(self.vuln_data, self.host_data)


if __name__ == "__main__":
    controller = RAEngineController()
    controller.main()
