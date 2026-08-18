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
module: fmgd_system_switchinterface
short_description: Configure software switch interfaces by grouping physical and WiFi interfaces.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_switchinterface:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      intra_switch_policy:
        aliases: ['intra-switch-policy']
        type: str
        description: Allow any traffic between switch interfaces or require firewall policies to allow traffic between switch interfaces.
        choices: ['implicit', 'explicit']
      mac_ttl:
        aliases: ['mac-ttl']
        type: int
        description: Duration for which MAC addresses are held in the ARP table
      member:
        type: list
        elements: str
        description: Names of the interfaces that belong to the virtual switch.
      name:
        type: str
        description: Interface name
        required: true
      span:
        type: str
        description: Enable/disable port spanning.
        choices: ['disable', 'enable']
      span_dest_port:
        aliases: ['span-dest-port']
        type: list
        elements: str
        description: SPAN destination port name.
      span_direction:
        aliases: ['span-direction']
        type: str
        description: The direction in which the SPAN port operates, either
        choices: ['rx', 'tx', 'both']
      span_source_port:
        aliases: ['span-source-port']
        type: list
        elements: str
        description: Physical interface name.
      type:
        type: str
        description: Type of switch based on functionality
        choices: ['switch', 'hub', 'hardware-switch']
      vdom:
        type: list
        elements: str
        description: VDOM that the software switch belongs to.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure software switch interfaces by grouping physical and WiFi interfaces.
      fortinet.fmgdevice.fmgd_system_switchinterface:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_switchinterface:
          name: "your value" # Required variable, string
          # intra_switch_policy: <value in [implicit, explicit]>
          # mac_ttl: <integer>
          # member: <list or string>
          # span: <value in [disable, enable]>
          # span_dest_port: <list or string>
          # span_direction: <value in [rx, tx, both]>
          # span_source_port: <list or string>
          # type: <value in [switch, hub, hardware-switch]>
          # vdom: <list or string>
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
        '/pm/config/device/{device}/global/system/switch-interface'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_switchinterface': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'intra-switch-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['implicit', 'explicit'], 'type': 'str'},
                'mac-ttl': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'member': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'span': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'span-dest-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'span-direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                'span-source-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['switch', 'hub', 'hardware-switch'], 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_switchinterface'),
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
