# IR-Isolator

### About

These Stackstorm workflows can be used during incident response to isolate:
- C2 host using firewall rules (FortiGate)
- internal workstation using ACL (Extreme Networks switch)

### Preparation
Install separate stackstorm-ansible environment. This stackstorm-ansible is a copy of official repo but uses different pack name `ansible29` that allows to run ansible in a different virtual environment.
```
st2 pack install git@github.com:solidex/stackstorm-ansible.git
```
Install libs. Note: when installing use `stanley` user and `ansible29` virtual environment.
```
sudo su stanley
source /opt/stackstorm/virtualenvs/ansible29/bin/activate
pip install pyfg fortiosapi textfsm jmespath
```
Install lib to use Extreme XOS API:
```
sudo apt-get install libsoap-lite-perl
```
### Stackstorm usage (reminder)
Login:
```
st2 login st2admin
```
Create (register) some actions:
```
st2 action create actions/block_host.yaml
st2 action create actions/revert_block_host.yaml
```
Run action from CLI:
```
st2 run secops_lab.block_host ip=x.x.x.x
```
Registering aliases:
```
st2ctl reload --register-aliases
st2 action-alias list
sudo service st2chatops restart
```
Sensor diagnostics
```
sudo /opt/stackstorm/st2/bin/st2sensorcontainer --config-file=/etc/st2/st2.conf --sensor-ref=secops_lab.VectraPollHosts
```
Webhook test:
```
curl -X POST -k https://x.x.x.x/api/v1/webhooks/revert/app_is_down -H "St2-Api-Key: <key>" -H "Content-Type: application/json"
```
### There is an issue with fortiosapi.py (v1.0.1)
If you are using FortiGate with self-signed (untrusted) certificates, please fix fortiosapi.py file near line 171 to have `verify=False`:
```
data='username=' + urllib.parse.quote(username) + '&secretkey=' + urllib.parse.quote(password) + "&ajax=1", timeout=self.timeout, verify=False)
```
