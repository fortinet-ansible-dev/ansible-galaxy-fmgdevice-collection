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
module: fmgd_router_rip_interface
short_description: RIP interface configuration.
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
  router_rip_interface:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auth_keychain:
        aliases: ['auth-keychain']
        type: list
        elements: str
        description: Authentication key-chain name.
      auth_mode:
        aliases: ['auth-mode']
        type: str
        description: Authentication mode.
        choices: ['none', 'md5', 'text']
      auth_string:
        aliases: ['auth-string']
        type: list
        elements: str
        description: Authentication string/password.
      flags:
        type: int
        description: Flags.
      name:
        type: str
        description: Interface name.
        required: true
      receive_version:
        aliases: ['receive-version']
        type: list
        elements: str
        description: Receive version.
        choices: ['1', '2']
      send_version:
        aliases: ['send-version']
        type: list
        elements: str
        description: Send version.
        choices: ['1', '2']
      send_version2_broadcast:
        aliases: ['send-version2-broadcast']
        type: str
        description: Enable/disable broadcast version 1 compatible packets.
        choices: ['disable', 'enable']
      split_horizon:
        aliases: ['split-horizon']
        type: str
        description: Enable/disable split horizon.
        choices: ['poisoned', 'regular']
      split_horizon_status:
        aliases: ['split-horizon-status']
        type: str
        description: Enable/disable split horizon.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: RIP interface configuration.
      fortinet.fmgdevice.fmgd_router_rip_interface:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_rip_interface:
          name: "your value" # Required variable, string
          # auth_keychain: <list or string>
          # auth_mode: <value in [none, md5, text]>
          # auth_string: <list or string>
          # flags: <integer>
          # receive_version: ["1", "2"]
          # send_version: ["1", "2"]
          # send_version2_broadcast: <value in [disable, enable]>
          # split_horizon: <value in [poisoned, regular]>
          # split_horizon_status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/rip/interface'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_rip_interface': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'auth-keychain': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'auth-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'md5', 'text'], 'type': 'str'},
                'auth-string': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'flags': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'receive-version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'choices': ['1', '2'], 'elements': 'str'},
                'send-version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'choices': ['1', '2'], 'elements': 'str'},
                'send-version2-broadcast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'split-horizon': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['poisoned', 'regular'], 'type': 'str'},
                'split-horizon-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_rip_interface'),
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
