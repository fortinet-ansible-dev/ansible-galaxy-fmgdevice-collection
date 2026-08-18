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
module: fmgd_system_ptp
short_description: Configure system PTP information.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_ptp:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      delay_mechanism:
        aliases: ['delay-mechanism']
        type: str
        description: End to end delay detection or peer to peer delay detection.
        choices: ['E2E', 'P2P']
      interface:
        type: list
        elements: str
        description: PTP client will reply through this interface.
      mode:
        type: str
        description: Multicast transmission or hybrid transmission.
        choices: ['multicast', 'hybrid']
      request_interval:
        aliases: ['request-interval']
        type: int
        description: The delay request value is the logarithmic mean interval in seconds between the delay request messages sent by the slave to the ma...
      server_interface:
        aliases: ['server-interface']
        type: list
        elements: dict
        description: Server interface.
        suboptions:
          delay_mechanism:
            aliases: ['delay-mechanism']
            type: str
            description: End to end delay detection or peer to peer delay detection.
            choices: ['E2E', 'P2P']
          id:
            type: int
            description: ID.
          server_interface_name:
            aliases: ['server-interface-name']
            type: list
            elements: str
            description: Interface name.
      server_mode:
        aliases: ['server-mode']
        type: str
        description: Enable/disable FortiGate PTP server mode.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable setting the FortiGate system time by synchronizing with an PTP Server.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure system PTP information.
      fortinet.fmgdevice.fmgd_system_ptp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_ptp:
          # delay_mechanism: <value in [E2E, P2P]>
          # interface: <list or string>
          # mode: <value in [multicast, hybrid]>
          # request_interval: <integer>
          # server_interface:
          #   - delay_mechanism: <value in [E2E, P2P]>
          #     id: <integer>
          #     server_interface_name: <list or string>
          # server_mode: <value in [disable, enable]>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/ptp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ptp': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'delay-mechanism': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['E2E', 'P2P'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['multicast', 'hybrid'], 'type': 'str'},
                'request-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'server-interface': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'delay-mechanism': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['E2E', 'P2P'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'server-interface-name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ptp'),
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
