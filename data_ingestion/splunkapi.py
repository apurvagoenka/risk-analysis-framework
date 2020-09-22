"""
This module contains API functions for importing data from Splunk.
"""
import os

from util import decrypt

import splunklib.client as client
import splunklib.results as results


class SplunkAPI:
    def __init__(self, conf):
        print("Running SplunkAPI...")
        self.CONF = conf
        self.splunk_client = client.connect(
            host=conf['hostname'],
            port=conf['port'],
            username=decrypt(conf['username']),
            password=decrypt(conf['password']),
        )
        assert isinstance(self.splunk_client, client.Service)

    def get_host_connections(self):
        host_connections = {}

        # Splunk Call
        if self.splunk_client:
            qargs = self.CONF['query']
            query = """
            search index={} earliest={} latest={}
                | where dest_port < {}
                | lookup {}  dest_ip output dest_ip
                | stats count by dest_port, dest_ip
                | table dest_ip, dest_port, count
            """.format(qargs['index'], qargs['time_range_start'], qargs['time_range_end'], qargs['dest_port_filter'],
                       qargs['host_list_filename'])

            # Run the query
            print("Running Search...")
            rr = results.ResultsReader(self.splunk_client.jobs.export(query))

            # Display the search results now that the job is done
            c = 0
            for result in rr:
                if isinstance(result, results.Message):
                    # Diagnostic messages may be returned in the results
                    print('%s: %s' % (result.type, result.message))
                elif isinstance(result, dict):
                    # Normal events are returned as dicts
                    c += 1
                    if result['dest_ip'] not in host_connections.keys():
                        host_connections[result['dest_ip']] = {}
                    host_connections[result['dest_ip']][result['dest_port']] = int(result['count'])

        print("{} rows fetched".format(c))
        return host_connections
