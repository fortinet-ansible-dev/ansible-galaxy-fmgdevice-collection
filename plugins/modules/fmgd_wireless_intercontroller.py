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
module: fmgd_wireless_intercontroller
short_description: Configure inter wireless controller operation.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  wireless_intercontroller:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      fast_failover_max:
        aliases: ['fast-failover-max']
        type: int
        description: Maximum number of retransmissions for fast failover HA messages between peer wireless controllers
      fast_failover_wait:
        aliases: ['fast-failover-wait']
        type: int
        description: Minimum wait time before an AP transitions from secondary controller to primary controller
      inter_controller_key:
        aliases: ['inter-controller-key']
        type: list
        elements: str
        description: Secret key for inter-controller communications.
      inter_controller_mode:
        aliases: ['inter-controller-mode']
        type: str
        description: Configure inter-controller mode
        choices: ['disable', 'l2-roaming', '1+1']
      inter_controller_peer:
        aliases: ['inter-controller-peer']
        type: list
        elements: dict
        description: Inter controller peer.
        suboptions:
          id:
            type: int
            description: ID.
          peer_ip:
            aliases: ['peer-ip']
            type: str
            description: Peer wireless controllers IP address.
          peer_port:
            aliases: ['peer-port']
            type: int
            description: Port used by the wireless controllers for inter-controller communications
          peer_priority:
            aliases: ['peer-priority']
            type: str
            description: Peer wireless controllers priority
            choices: ['primary', 'secondary']
      inter_controller_pri:
        aliases: ['inter-controller-pri']
        type: str
        description: Configure inter-controllers priority
        choices: ['primary', 'secondary']
      l3_roaming:
        aliases: ['l3-roaming']
        type: str
        description: Enable/disable layer 3 roaming
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure inter wireless controller operation.
      fortinet.fmgdevice.fmgd_wireless_intercontroller:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        wireless_intercontroller:
          # fast_failover_max: <integer>
          # fast_failover_wait: <integer>
          # inter_controller_key: <list or string>
          # inter_controller_mode: <value in [disable, l2-roaming, 1+1]>
          # inter_controller_peer:
          #   - id: <integer>
          #     peer_ip: <string>
          #     peer_port: <integer>
          #     peer_priority: <value in [primary, secondary]>
          # inter_controller_pri: <value in [primary, secondary]>
          # l3_roaming: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/wireless-controller/inter-controller'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'wireless_intercontroller': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'fast-failover-max': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'fast-failover-wait': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'inter-controller-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'inter-controller-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'l2-roaming', '1+1'], 'type': 'str'},
                'inter-controller-peer': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'peer-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'peer-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'peer-priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['primary', 'secondary'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'inter-controller-pri': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['primary', 'secondary'], 'type': 'str'},
                'l3-roaming': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_intercontroller'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
