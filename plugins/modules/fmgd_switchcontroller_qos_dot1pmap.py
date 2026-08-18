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
module: fmgd_switchcontroller_qos_dot1pmap
short_description: Configure FortiSwitch QoS 802.
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
  switchcontroller_qos_dot1pmap:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: Description of the 802.
      egress_pri_tagging:
        aliases: ['egress-pri-tagging']
        type: str
        description: Enable/disable egress priority-tag frame.
        choices: ['disable', 'enable']
      name:
        type: str
        description: Dot1p map name.
        required: true
      priority_0:
        aliases: ['priority-0']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_1:
        aliases: ['priority-1']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_2:
        aliases: ['priority-2']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_3:
        aliases: ['priority-3']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_4:
        aliases: ['priority-4']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_5:
        aliases: ['priority-5']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_6:
        aliases: ['priority-6']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
      priority_7:
        aliases: ['priority-7']
        type: str
        description: COS queue mapped to dot1p priority number.
        choices: ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6',
                  'queue-7']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch QoS 802.
      fortinet.fmgdevice.fmgd_switchcontroller_qos_dot1pmap:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_qos_dot1pmap:
          name: "your value" # Required variable, string
          # description: <string>
          # egress_pri_tagging: <value in [disable, enable]>
          # priority_0: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_1: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_2: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_3: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_4: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_5: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_6: <value in [queue-0, queue-1, queue-2, ...]>
          # priority_7: <value in [queue-0, queue-1, queue-2, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/dot1p-map'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_qos_dot1pmap': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'egress-pri-tagging': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'priority-0': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-1': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-2': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-3': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-4': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-5': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-6': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                },
                'priority-7': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['queue-0', 'queue-1', 'queue-2', 'queue-3', 'queue-4', 'queue-5', 'queue-6', 'queue-7'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_qos_dot1pmap'),
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
