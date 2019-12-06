# IR-Isolator

### About

These Stackstorm workflows can be used during incident resoinse to isolate:
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
### There is an issue with fortiosapi.py (v1.0.1)
If you are using FortiGate with self-signed (untrusted) certificates, please fix fortiosapi.py file near line 171 to have `verify=False`:
```
data='username=' + urllib.parse.quote(username) + '&secretkey=' + urllib.parse.quote(password) + "&ajax=1", timeout=self.timeout, verify=False)
```
