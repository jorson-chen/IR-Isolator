import eventlet

import requests
import json

from st2reactor.sensor.base import Sensor

mock_resp = {'results': [{'host_luid': 'fZ0xCHR5', 'shell_knocker': [], 'privilege_category': None, 'ip': '172.17.17.111', 'host_artifact_set': [{'source': None, 'vendor': 'Wistron InfoComm(Kunshan)Co, Ltd', 'value': '48:2a:e3:3a:58:a6', 'siem': False, 'type': 'mac'}, {'source': None, 'type': 'dhcp', 'value': 'DESKTOP-19RPRFL', 'siem': False}], 'privilege_level': None, 'note_modified_by': None, 'is_targeting_key_asset': False, 'note_modified_timestamp': None, 'key_asset': False, 'id': 378, 'note': None, 'severity': 'low', 'has_shell_knocker_learnings': False, 'previous_ips': [], 'state': 'active', 'ldap': None, 'sensor': 'zvu9pxze', 'assigned_date': None, 'has_active_traffic': True, 'targets_key_asset': False, 'tags': [], 'host_session_luids': ['n6d-f1Jp'], 'last_source': '172.17.17.113', 'last_detection_timestamp': '2019-12-13T08:32:14Z', 'last_modified': '2019-12-13T08:39:11Z', 'campaign_summaries': [
], 'groups': [{'name': 'Workstation-IP', 'last_modified_by': 'admin', 'last_modified': '2019-12-13T08:23:01Z', 'type': 'ip', 'id': 22, 'description': ''}], 'suspicious_admin_learnings': {'managers_of_host': [], 'host_manages': []}, '_doc_modified_ts': '2019-12-13T11:41:09.914167', 'has_custom_model': False, 'sensor_name': 'v-166', 'name': 'DESKTOP-19RPRFL', 'certainty': 23, 'probable_owner': None, 'is_key_asset': False, 'detection_summaries': [{'tags': [], 'certainty': 22, 'detection_id': 7, 'detection_type': 'Port Scan', 'detection_category': 'RECONNAISSANCE', 'summary': {'num_attempts': 100, 'dst_ips': ['172.17.15.202'], 'num_successes': 0}, 'state': 'active', 'is_targeting_key_asset': False, 'threat': 31, 'assigned_to': None, 'assigned_date': None, 'is_triaged': False}], 'threat': 23, 'assigned_to': None, 'active_traffic': True, 'last_seen': '2019-12-13T11:07:54.683282Z'}]}

URL = "https://172.17.18.39/"
TOKEN = "Token a270a1c2addcf4c58d6d2857495302038cef28a7"
headers = {'Content-Type': 'application/json', 'Authorization': TOKEN}


class VectraPollHosts(Sensor):
    def __init__(self, sensor_service, config):
        super(VectraPollHosts, self).__init__(
            sensor_service=sensor_service, config=config)
        self._logger = self.sensor_service.get_logger(
            name=self.__class__.__name__)
        self._stop = False

    def setup(self):
        pass

    def get_hosts(self):

        qry = 'host.threat:>=20 and host.certainty:>=20'
        vectra_url = URL + 'api/v2/search/hosts/?query_string= %s' % qry
        response = requests.get(url=vectra_url,
                                params={}, verify=False, headers=headers)

        if (response.json()['count'] != 0):
            print('hosts received: %s' % response.json()['count'])
            return response.json()['results']

        print('no hosts received')
        return []  # mock_resp['results']

    def set_tag(self, host):

        from datetime import datetime

        # datetime object containing current date and time
        now = datetime.now()

        # dd/mm/YY H:M:S
        dt_string = now.strftime("%d_%m_%Y-%H_%M_%S")

        data_json = json.dumps(
            {'tags': ['aut_is_time:%s' % dt_string, 'auto_isolated']})
        vectra_url = URL + 'api/v2/tagging/host/%s' % host['id']
        response = requests.patch(url=vectra_url,
                                  data=data_json, verify=False, headers=headers)

    def run(self):
        while not self._stop:
            self._logger.debug('VectraPollHosts dispatching trigger...')
            hosts = self.get_hosts()

            ips = []

            for h in hosts:

                if 'auto_isolated' in h['tags']:
                    print('there is an isolated host, ignoring: %s' % h['ip'])
                    continue

                print('there is a new host: %s' % h['ip'])
                ips.append({'ip': h['ip'], 'name': h['name'],
                            'threat': h['threat'], 'certainty': h['certainty']})

                self.set_tag(h)

            payload = {'hosts': ips}

            if (len(payload['hosts']) != 0):
                self.sensor_service.dispatch(
                    trigger='secops_lab.compromised_host_detected', payload=payload)
            eventlet.sleep(10)

    def cleanup(self):
        self._stop = True

    # Methods required for programmable sensors.
    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        pass

    def remove_trigger(self, trigger):
        pass
