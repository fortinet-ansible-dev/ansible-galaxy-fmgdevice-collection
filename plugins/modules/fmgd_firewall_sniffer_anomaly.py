#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgd_firewall_sniffer_anomaly
short_description: Configuration method to edit Denial of Service
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  sniffer:
    description: The parameter (sniffer) in requested url.
    type: str
    required: true
  firewall_sniffer_anomaly:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Action taken when the threshold is reached.
        choices: ['pass', 'block', 'proxy']
      log:
        type: str
        description: Enable/disable anomaly logging.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Anomaly name.
        required: true
      quarantine:
        type: str
        description: Quarantine method.
        choices: ['none', 'attacker', 'both', 'interface']
      quarantine_expiry:
        aliases: ['quarantine-expiry']
        type: str
        description: Duration of quarantine.
      quarantine_log:
        aliases: ['quarantine-log']
        type: str
        description: Enable/disable quarantine logging.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable this anomaly.
        choices: ['disable', 'enable']
      synproxy_tcp_mss:
        aliases: ['synproxy-tcp-mss']
        type: str
        description: Determine TCP maximum segment size
        choices: ['0', '256', '512', '1024', '1300', '1360', '1460', '1500']
      synproxy_tcp_sack:
        aliases: ['synproxy-tcp-sack']
        type: str
        description: Enable/disable TCP selective acknowledage
        choices: ['disable', 'enable']
      synproxy_tcp_timestamp:
        aliases: ['synproxy-tcp-timestamp']
        type: str
        description: Enable/disable TCP timestamp option for packets replied by syn proxy module.
        choices: ['disable', 'enable']
      synproxy_tcp_window:
        aliases: ['synproxy-tcp-window']
        type: str
        description: Determine TCP Window size for packets replied by syn proxy module.
        choices: ['4096', '8192', '16384', '32768']
      synproxy_tcp_windowscale:
        aliases: ['synproxy-tcp-windowscale']
        type: str
        description: Determine TCP window scale option value for packets replied by syn proxy module.
        choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14']
      synproxy_tos:
        aliases: ['synproxy-tos']
        type: str
        description: Determine TCP differentiated services code point value
        choices: ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38',
                  '40', '46', '255']
      synproxy_ttl:
        aliases: ['synproxy-ttl']
        type: str
        description: Determine Time to live
        choices: ['32', '64', '128', '255']
      threshold:
        type: int
        description: Anomaly threshold.
      threshold_default:
        aliases: ['threshold(default)']
        type: int
        description: Threshold
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configuration method to edit Denial of Service
      fortinet.fmgdevice.fmgd_firewall_sniffer_anomaly:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        sniffer: <your own value>
        state: present # <value in [present, absent]>
        firewall_sniffer_anomaly:
          name: "your value" # Required variable, string
          # action: <value in [pass, block, proxy]>
          # log: <value in [disable, enable]>
          # quarantine: <value in [none, attacker, both, ...]>
          # quarantine_expiry: <string>
          # quarantine_log: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # synproxy_tcp_mss: <value in [0, 256, 512, ...]>
          # synproxy_tcp_sack: <value in [disable, enable]>
          # synproxy_tcp_timestamp: <value in [disable, enable]>
          # synproxy_tcp_window: <value in [4096, 8192, 16384, ...]>
          # synproxy_tcp_windowscale: <value in [0, 1, 2, ...]>
          # synproxy_tos: <value in [0, 10, 12, ...]>
          # synproxy_ttl: <value in [32, 64, 128, ...]>
          # threshold: <integer>
          # threshold_default: <integer>
'''

RETURN = '''
meta:
  description: The result of the request.
  type: dict
  returned: always
  contains:
    request_url:
      description: The full url requested.
      returned: always
      type: str
      sample: /sys/login/user
    response_code:
      description: The status of api request.
      returned: always
      type: int
      sample: 0
    response_data:
      description: The api response.
      type: list
      returned: always
    response_message:
      description: The descriptive message of the api response.
      type: str
      returned: always
      sample: OK.
    system_information:
      description: The information of the target system.
      type: dict
      returned: always
rc:
  description: The status the request.
  type: int
  returned: always
  sample: 0
version_check_warning:
  description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
  type: list
  returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}/anomaly'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'sniffer': {'required': True, 'type': 'str'},
        'firewall_sniffer_anomaly': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['pass', 'block', 'proxy'], 'type': 'str'},
                'log': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'quarantine': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'attacker', 'both', 'interface'], 'type': 'str'},
                'quarantine-expiry': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'quarantine-log': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'synproxy-tcp-mss': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                    'type': 'str'
                },
                'synproxy-tcp-sack': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'synproxy-tcp-timestamp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'synproxy-tcp-window': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['4096', '8192', '16384', '32768'], 'type': 'str'},
                'synproxy-tcp-windowscale': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                    'type': 'str'
                },
                'synproxy-tos': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                    'type': 'str'
                },
                'synproxy-ttl': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['32', '64', '128', '255'], 'type': 'str'},
                'threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'threshold(default)': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sniffer_anomaly'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
