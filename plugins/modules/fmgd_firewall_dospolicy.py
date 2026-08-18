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
module: fmgd_firewall_dospolicy
short_description: Configure IPv4 DoS policies.
version_added: "1.1.0"
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
  firewall_dospolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      anomaly:
        type: list
        elements: dict
        description: Anomaly.
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
          quarantine:
            type: str
            description: Quarantine method.
            choices: ['none', 'attacker']
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
            choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13',
                      '14']
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
      comments:
        type: str
        description: Comment.
      dstaddr:
        type: list
        elements: str
        description: Destination address name from available addresses.
      interface:
        type: list
        elements: str
        description: Incoming interface name from available interfaces.
      name:
        type: str
        description: Policy name.
      policyid:
        type: int
        description: Policy ID.
        required: true
      service:
        type: list
        elements: str
        description: Service object from available options.
      srcaddr:
        type: list
        elements: str
        description: Source address name from available addresses.
      status:
        type: str
        description: Enable/disable this policy.
        choices: ['disable', 'enable']
      custom_tags:
        aliases: ['custom-tags']
        type: list
        elements: str
        description: Custom tags.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv4 DoS policies.
      fortinet.fmgdevice.fmgd_firewall_dospolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_dospolicy:
          policyid: 0 # Required variable, integer
          # anomaly:
          #   - action: <value in [pass, block, proxy]>
          #     log: <value in [disable, enable]>
          #     name: <string>
          #     quarantine: <value in [none, attacker]>
          #     quarantine_expiry: <string>
          #     quarantine_log: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          #     synproxy_tcp_mss: <value in [0, 256, 512, ...]>
          #     synproxy_tcp_sack: <value in [disable, enable]>
          #     synproxy_tcp_timestamp: <value in [disable, enable]>
          #     synproxy_tcp_window: <value in [4096, 8192, 16384, ...]>
          #     synproxy_tcp_windowscale: <value in [0, 1, 2, ...]>
          #     synproxy_tos: <value in [0, 10, 12, ...]>
          #     synproxy_ttl: <value in [32, 64, 128, ...]>
          #     threshold: <integer>
          #     threshold_default: <integer>
          # comments: <string>
          # dstaddr: <list or string>
          # interface: <list or string>
          # name: <string>
          # service: <list or string>
          # srcaddr: <list or string>
          # status: <value in [disable, enable]>
          # custom_tags: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/DoS-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_dospolicy': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'anomaly': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['pass', 'block', 'proxy'], 'type': 'str'},
                        'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'quarantine': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'attacker'], 'type': 'str'},
                        'quarantine-expiry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'quarantine-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy-tcp-mss': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['0', '256', '512', '1024', '1300', '1360', '1460', '1500'],
                            'type': 'str'
                        },
                        'synproxy-tcp-sack': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy-tcp-timestamp': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'synproxy-tcp-window': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['4096', '8192', '16384', '32768'],
                            'type': 'str'
                        },
                        'synproxy-tcp-windowscale': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'],
                            'type': 'str'
                        },
                        'synproxy-tos': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['0', '10', '12', '14', '18', '20', '22', '26', '28', '30', '34', '36', '38', '40', '46', '255'],
                            'type': 'str'
                        },
                        'synproxy-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['32', '64', '128', '255'], 'type': 'str'},
                        'threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'threshold(default)': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'policyid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'service': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_dospolicy'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'policyid', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
