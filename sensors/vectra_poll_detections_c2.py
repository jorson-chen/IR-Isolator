import eventlet

import requests
import json

from st2reactor.sensor.base import Sensor

URL = "https://172.17.18.39/"
TOKEN = "Token a270a1c2addcf4c58d6d2857495302038cef28a7"
headers = {'Content-Type': 'application/json', 'Authorization': TOKEN}


class VectraPolldetectionsC2(Sensor):
    def __init__(self, sensor_service, config):
        super(VectraPolldetectionsC2, self).__init__(
            sensor_service=sensor_service, config=config)
        self._logger = self.sensor_service.get_logger(
            name=self.__class__.__name__)
        self._stop = False

    def setup(self):
        pass

    def get_detections(self):

        vectra_url = URL + 'api/v2/detections?category=command'
        response = requests.get(url=vectra_url,
                                params={}, verify=False, headers=headers)

        if (response.json()['count'] != 0):
            print('detections received: %s' % response.json()['count'])
            return response.json()['results']

        print('no detections received')
        return [] 

    def set_tag(self, detection):

        from datetime import datetime

        # datetime object containing current date and time
        now = datetime.now()

        # dd/mm/YY H:M:S
        dt_string = now.strftime("%d_%m_%Y-%H_%M_%S")

        data_json = json.dumps(
            {'tags': ['c2_aut_is_time:%s' % dt_string, 'c2_auto_isolated']})
        vectra_url = URL + 'api/v2/tagging/detection/%s' % detection['id']
        response = requests.patch(url=vectra_url,
                                  data=data_json, verify=False, headers=headers)

    def run(self):
        while not self._stop:
            self._logger.debug('VectraPollDetectionsC2 dispatching trigger...')
            detections = self.get_detections()

            c2_detection_events = []

            for detection in detections:

                if 'c2_auto_isolated' in detection['tags']:
                    print('there is an isolated host, ignoring: %s' % detection['ip'])
                    continue

                print('there is a new host: %s' % detection['src_ip'])
                c2_detection_events.append({'src_ip': detection['src_ip'], 'detection': detection['detection'],
                            'threat': detection['threat'], 'certainty': detection['certainty'],
                            'dst_ips': detection['dst_ips']})

                self.set_tag(detection)

            payload = {'c2_detection_events': c2_detection_events}

            if (len(payload['c2_detection_events']) != 0):
                self.sensor_service.dispatch(
                    trigger='secops_lab.vectra_poll_detections_c2', payload=payload)
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
