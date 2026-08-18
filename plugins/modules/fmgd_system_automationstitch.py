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
module: fmgd_system_automationstitch
short_description: Automation stitches.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_automationstitch:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      actions:
        type: list
        elements: dict
        description: Actions.
        suboptions:
          action:
            type: list
            elements: str
            description: Action name.
          delay:
            type: int
            description: Delay before execution
          id:
            type: int
            description: Entry ID.
          required:
            type: str
            description: Required in action chain.
            choices: ['disable', 'enable']
      description:
        type: str
        description: Description.
      destination:
        type: list
        elements: str
        description: Serial number/HA group-name of destination devices.
      name:
        type: str
        description: Name.
        required: true
      status:
        type: str
        description: Enable/disable this stitch.
        choices: ['disable', 'enable']
      trigger:
        type: list
        elements: str
        description: Trigger name.
      action:
        type: list
        elements: str
        description: Action names.
      condition:
        type: list
        elements: str
        description: Automation conditions.
      condition_logic:
        aliases: ['condition-logic']
        type: str
        description: Apply AND/OR logic to the specified automation conditions.
        choices: ['or', 'and']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Automation stitches.
      fortinet.fmgdevice.fmgd_system_automationstitch:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_automationstitch:
          name: "your value" # Required variable, string
          # actions:
          #   - action: <list or string>
          #     delay: <integer>
          #     id: <integer>
          #     required: <value in [disable, enable]>
          # description: <string>
          # destination: <list or string>
          # status: <value in [disable, enable]>
          # trigger: <list or string>
          # action: <list or string>
          # condition: <list or string>
          # condition_logic: <value in [or, and]>
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
        '/pm/config/device/{device}/global/system/automation-stitch'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_automationstitch': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'actions': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'delay': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'required': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'destination': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trigger': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'condition': {'v_range': [['7.4.6', '7.4.11'], ['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'condition-logic': {'v_range': [['7.4.6', '7.4.11'], ['7.6.2', '']], 'choices': ['or', 'and'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_automationstitch'),
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
