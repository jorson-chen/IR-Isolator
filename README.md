## IR-Isolator

These Stackstorm workflows can be used during incident resoinse to isolate:
- C2 host using firewall rules (FortiGate)
- internal workstation using ACL (Extreme Networks switch)

# Preparation
Libraries that need to be installed:
```
pip install ansible pyfg fortiosapi textfsm jmespath
```
