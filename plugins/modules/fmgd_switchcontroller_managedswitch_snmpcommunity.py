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
module: fmgd_switchcontroller_managedswitch_snmpcommunity
short_description: Configuration method to edit Simple Network Management Protocol
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
  managed-switch:
    description: Deprecated, please use "managed_switch"
    type: str
  managed_switch:
    description: The parameter (managed-switch) in requested url.
    type: str
  switchcontroller_managedswitch_snmpcommunity:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      events:
        type: list
        elements: str
        description: SNMP notifications
        choices: ['cpu-high', 'mem-low', 'log-full', 'intf-ip', 'ent-conf-change', 'l2mac']
      hosts:
        type: list
        elements: dict
        description: Hosts.
        suboptions:
          id:
            type: int
            description: Host entry ID.
          ip:
            type: list
            elements: str
            description: IPv4 address of the SNMP manager
      id:
        type: int
        description: SNMP community ID.
        required: true
      name:
        type: str
        description: SNMP community name.
      query_v1_port:
        aliases: ['query-v1-port']
        type: int
        description: SNMP v1 query port
      query_v1_status:
        aliases: ['query-v1-status']
        type: str
        description: Enable/disable SNMP v1 queries.
        choices: ['disable', 'enable']
      query_v2c_port:
        aliases: ['query-v2c-port']
        type: int
        description: SNMP v2c query port
      query_v2c_status:
        aliases: ['query-v2c-status']
        type: str
        description: Enable/disable SNMP v2c queries.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable this SNMP community.
        choices: ['disable', 'enable']
      trap_v1_lport:
        aliases: ['trap-v1-lport']
        type: int
        description: SNMP v2c trap local port
      trap_v1_rport:
        aliases: ['trap-v1-rport']
        type: int
        description: SNMP v2c trap remote port
      trap_v1_status:
        aliases: ['trap-v1-status']
        type: str
        description: Enable/disable SNMP v1 traps.
        choices: ['disable', 'enable']
      trap_v2c_lport:
        aliases: ['trap-v2c-lport']
        type: int
        description: SNMP v2c trap local port
      trap_v2c_rport:
        aliases: ['trap-v2c-rport']
        type: int
        description: SNMP v2c trap remote port
      trap_v2c_status:
        aliases: ['trap-v2c-status']
        type: str
        description: Enable/disable SNMP v2c traps.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configuration method to edit Simple Network Management Protocol
      fortinet.fmgdevice.fmgd_switchcontroller_managedswitch_snmpcommunity:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        managed_switch: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch_snmpcommunity:
          id: 0 # Required variable, integer
          # events: ["cpu-high", "mem-low", "log-full", "intf-ip", "ent-conf-change", "l2mac"]
          # hosts:
          #   - id: <integer>
          #     ip: <list or string>
          # name: <string>
          # query_v1_port: <integer>
          # query_v1_status: <value in [disable, enable]>
          # query_v2c_port: <integer>
          # query_v2c_status: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # trap_v1_lport: <integer>
          # trap_v1_rport: <integer>
          # trap_v1_status: <value in [disable, enable]>
          # trap_v2c_lport: <integer>
          # trap_v2c_rport: <integer>
          # trap_v2c_status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'switchcontroller_managedswitch_snmpcommunity': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'events': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['cpu-high', 'mem-low', 'log-full', 'intf-ip', 'ent-conf-change', 'l2mac'],
                    'elements': 'str'
                },
                'hosts': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'query-v1-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'query-v1-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-v2c-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'query-v2c-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-v1-lport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'trap-v1-rport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'trap-v1-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trap-v2c-lport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'trap-v2c-rport': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'trap-v2c-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_snmpcommunity'),
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
