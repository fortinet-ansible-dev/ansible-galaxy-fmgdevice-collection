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
module: fmgd_wireless_snmp_community
short_description: SNMP Community Configuration.
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
  wireless_snmp_community:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      hosts:
        type: list
        elements: dict
        description: Hosts.
        suboptions:
          id:
            type: int
            description: Host entry ID.
          ip:
            type: str
            description: IPv4 address of the SNMP manager
      id:
        type: int
        description: Community ID.
        required: true
      name:
        type: str
        description: Community name.
      query_v1_status:
        aliases: ['query-v1-status']
        type: str
        description: Enable/disable SNMP v1 queries.
        choices: ['disable', 'enable']
      query_v2c_status:
        aliases: ['query-v2c-status']
        type: str
        description: Enable/disable SNMP v2c queries.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable this SNMP community.
        choices: ['disable', 'enable']
      trap_v1_status:
        aliases: ['trap-v1-status']
        type: str
        description: Enable/disable SNMP v1 traps.
        choices: ['disable', 'enable']
      trap_v2c_status:
        aliases: ['trap-v2c-status']
        type: str
        description: Enable/disable SNMP v2c traps.
        choices: ['disable', 'enable']
      hosts6:
        type: list
        elements: dict
        description: Hosts6.
        suboptions:
          id:
            type: int
            description: Host6 entry ID.
          ipv6:
            type: str
            description: IPv6 address of the SNMP manager
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: SNMP Community Configuration.
      fortinet.fmgdevice.fmgd_wireless_snmp_community:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_snmp_community:
          id: 0 # Required variable, integer
          # hosts:
          #   - id: <integer>
          #     ip: <string>
          # name: <string>
          # query_v1_status: <value in [disable, enable]>
          # query_v2c_status: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # trap_v1_status: <value in [disable, enable]>
          # trap_v2c_status: <value in [disable, enable]>
          # hosts6:
          #   - id: <integer>
          #     ipv6: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_snmp_community': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'hosts': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'query-v1-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-v2c-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-v1-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-v2c-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hosts6': {
                    'v_range': [['7.6.5', '']],
                    'type': 'list',
                    'options': {'id': {'v_range': [['7.6.5', '']], 'type': 'int'}, 'ipv6': {'v_range': [['7.6.5', '']], 'type': 'str'}},
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_snmp_community'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
