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
module: fmgd_wireless_apcfgprofile
short_description: Configure AP local configuration profiles.
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
  wireless_apcfgprofile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ac_ip:
        aliases: ['ac-ip']
        type: str
        description: IP address of the validation controller that AP must be able to join after applying AP local configuration.
      ac_port:
        aliases: ['ac-port']
        type: int
        description: Port of the validation controller that AP must be able to join after applying AP local configuration
      ac_timer:
        aliases: ['ac-timer']
        type: int
        description: Maximum waiting time for the AP to join the validation controller after applying AP local configuration
      ac_type:
        aliases: ['ac-type']
        type: str
        description: Validation controller type
        choices: ['default', 'specify', 'apcfg']
      ap_family:
        aliases: ['ap-family']
        type: str
        description: FortiAP family type
        choices: ['fap', 'fap-u', 'fap-c']
      command_list:
        aliases: ['command-list']
        type: list
        elements: dict
        description: Command list.
        suboptions:
          id:
            type: int
            description: Command ID.
          name:
            type: str
            description: AP local configuration command name.
          passwd_value:
            aliases: ['passwd-value']
            type: list
            elements: str
            description: AP local configuration command password value.
          type:
            type: str
            description: The command type
            choices: ['non-password', 'password']
          value:
            type: str
            description: AP local configuration command value.
      comment:
        type: str
        description: Comment.
      name:
        type: str
        description: AP local configuration profile name.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure AP local configuration profiles.
      fortinet.fmgdevice.fmgd_wireless_apcfgprofile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_apcfgprofile:
          name: "your value" # Required variable, string
          # ac_ip: <string>
          # ac_port: <integer>
          # ac_timer: <integer>
          # ac_type: <value in [default, specify, apcfg]>
          # ap_family: <value in [fap, fap-u, fap-c]>
          # command_list:
          #   - id: <integer>
          #     name: <string>
          #     passwd_value: <list or string>
          #     type: <value in [non-password, password]>
          #     value: <string>
          # comment: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_apcfgprofile': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'ac-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ac-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ac-timer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ac-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'specify', 'apcfg'], 'type': 'str'},
                'ap-family': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['fap', 'fap-u', 'fap-c'], 'type': 'str'},
                'command-list': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'passwd-value': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['non-password', 'password'], 'type': 'str'},
                        'value': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_apcfgprofile'),
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
