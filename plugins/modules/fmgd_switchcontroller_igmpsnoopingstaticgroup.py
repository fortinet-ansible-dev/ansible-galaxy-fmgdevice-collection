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
module: fmgd_switchcontroller_igmpsnoopingstaticgroup
short_description: Configure FortiSwitch IGMP snooping static group settings.
version_added: "1.2.0"
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
  switchcontroller_igmpsnoopingstaticgroup:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: IGMP snooping static group description.
      ignore_reports:
        aliases: ['ignore-reports']
        type: str
        description: Enable/disable this ignore-reports.
        choices: ['disable', 'enable']
      mcast_addr:
        aliases: ['mcast-addr']
        type: str
        description: IGMP snooping static group multicast IP.
      name:
        type: str
        description: IGMP snooping static group name.
        required: true
      ports:
        type: list
        elements: dict
        description: Ports.
        suboptions:
          id:
            type: int
            description: ID.
          ports:
            type: list
            elements: str
            description: Port members.
          switch_id:
            aliases: ['switch-id']
            type: list
            elements: str
            description: Switch ID.
      vlan:
        type: list
        elements: str
        description: VLAN name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch IGMP snooping static group settings.
      fortinet.fmgdevice.fmgd_switchcontroller_igmpsnoopingstaticgroup:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_igmpsnoopingstaticgroup:
          name: "your value" # Required variable, string
          # description: <string>
          # ignore_reports: <value in [disable, enable]>
          # mcast_addr: <string>
          # ports:
          #   - id: <integer>
          #     ports: <list or string>
          #     switch_id: <list or string>
          # vlan: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/igmp-snooping-static-group'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_igmpsnoopingstaticgroup': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'description': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ignore-reports': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mcast-addr': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'ports': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'ports': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'switch-id': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'vlan': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_igmpsnoopingstaticgroup'),
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
