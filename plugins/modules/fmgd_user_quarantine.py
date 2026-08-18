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
module: fmgd_user_quarantine
short_description: Configure quarantine support.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  user_quarantine:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      firewall_groups:
        aliases: ['firewall-groups']
        type: list
        elements: str
        description: Firewall address group which includes all quarantine MAC address.
      quarantine:
        type: str
        description: Enable/disable quarantine.
        choices: ['disable', 'enable']
      targets:
        type: list
        elements: dict
        description: Targets.
        suboptions:
          description:
            type: str
            description: Description for the quarantine entry.
          entry:
            type: str
            description: Quarantine entry name.
          macs:
            type: list
            elements: dict
            description: Macs.
            suboptions:
              description:
                type: str
                description: Description for the quarantine MAC.
              drop:
                type: str
                description: Enable/disable dropping of quarantined device traffic.
                choices: ['disable', 'enable']
              mac:
                type: str
                description: Quarantine MAC.
              parent:
                type: str
                description: Parent.
              entry_id:
                aliases: ['entry-id']
                type: int
                description: FSW entry id for the quarantine MAC.
      traffic_policy:
        aliases: ['traffic-policy']
        type: list
        elements: str
        description: Traffic policy for quarantined MACs.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure quarantine support.
      fortinet.fmgdevice.fmgd_user_quarantine:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        user_quarantine:
          # firewall_groups: <list or string>
          # quarantine: <value in [disable, enable]>
          # targets:
          #   - description: <string>
          #     entry: <string>
          #     macs:
          #       - description: <string>
          #         drop: <value in [disable, enable]>
          #         mac: <string>
          #         parent: <string>
          #         entry_id: <integer>
          # traffic_policy: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/quarantine'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_quarantine': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'firewall-groups': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'quarantine': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'targets': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'entry': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'macs': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'drop': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'mac': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'parent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'entry-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        }
                    },
                    'elements': 'dict'
                },
                'traffic-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_quarantine'),
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
