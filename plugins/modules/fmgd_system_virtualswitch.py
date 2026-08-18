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
module: fmgd_system_virtualswitch
short_description: Configure virtual hardware switch interfaces.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_virtualswitch:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      name:
        type: str
        description: Name of the virtual switch.
        required: true
      physical_switch:
        aliases: ['physical-switch']
        type: list
        elements: str
        description: Physical switch parent.
      port:
        type: list
        elements: dict
        description: Port.
        suboptions:
          alias:
            type: str
            description: Alias.
          name:
            type: list
            elements: str
            description: Physical interface name.
          poe:
            type: str
            description: Enable/disable PoE status.
            choices: ['disable', 'enable']
          status:
            type: str
            description: Interface status.
            choices: ['down', 'up']
          speed:
            type: str
            description: Interface speed.
            choices: ['auto', '10full', '10half', '100full', '100half', '1000full', '1000half',
                      '10000full', '1000auto', '10000auto', '40000full', '100Gfull', '25000full']
          mediatype:
            type: str
            description: Select SFP media interface type.
            choices: ['cfp2-sr10', 'cfp2-lr4']
      span:
        type: str
        description: Enable/disable SPAN.
        choices: ['disable', 'enable']
      span_dest_port:
        aliases: ['span-dest-port']
        type: str
        description: SPAN destination port.
      span_direction:
        aliases: ['span-direction']
        type: str
        description: SPAN direction.
        choices: ['rx', 'tx', 'both']
      span_source_port:
        aliases: ['span-source-port']
        type: str
        description: SPAN source port.
      vlan:
        type: int
        description: VLAN.
      qos:
        type: str
        description: Set QOS none or 8021p
        choices: ['none', '802.1p']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure virtual hardware switch interfaces.
      fortinet.fmgdevice.fmgd_system_virtualswitch:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_virtualswitch:
          name: "your value" # Required variable, string
          # physical_switch: <list or string>
          # port:
          #   - alias: <string>
          #     name: <list or string>
          #     poe: <value in [disable, enable]>
          #     status: <value in [down, up]>
          #     speed: <value in [auto, 10full, 10half, ...]>
          #     mediatype: <value in [cfp2-sr10, cfp2-lr4]>
          # span: <value in [disable, enable]>
          # span_dest_port: <string>
          # span_direction: <value in [rx, tx, both]>
          # span_source_port: <string>
          # vlan: <integer>
          # qos: <value in [none, 802.1p]>
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
        '/pm/config/device/{device}/global/system/virtual-switch'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_virtualswitch': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'physical-switch': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'port': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'alias': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'poe': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['down', 'up'], 'type': 'str'},
                        'speed': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': [
                                'auto', '10full', '10half', '100full', '100half', '1000full', '1000half', '10000full', '1000auto', '10000auto',
                                '40000full', '100Gfull', '25000full'
                            ],
                            'type': 'str'
                        },
                        'mediatype': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['cfp2-sr10', 'cfp2-lr4'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'span': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'span-dest-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'span-direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                'span-source-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'qos': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'choices': ['none', '802.1p'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_virtualswitch'),
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
