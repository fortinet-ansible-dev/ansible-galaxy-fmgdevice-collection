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
module: fmgd_firewall_internetserviceaddition_entry
short_description: Entries added to the Internet Service addition database.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  internet-service-addition:
    description: Deprecated, please use "internet_service_addition"
    type: str
  internet_service_addition:
    description: The parameter (internet-service-addition) in requested url.
    type: str
  firewall_internetserviceaddition_entry:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      addr_mode:
        aliases: ['addr-mode']
        type: str
        description: Address mode
        choices: ['ipv4', 'ipv6']
      id:
        type: int
        description: Entry ID
        required: true
      port_range:
        aliases: ['port-range']
        type: list
        elements: dict
        description: Port range.
        suboptions:
          end_port:
            aliases: ['end-port']
            type: int
            description: Integer value for ending TCP/UDP/SCTP destination port in range
          id:
            type: int
            description: Custom entry port range ID.
          start_port:
            aliases: ['start-port']
            type: int
            description: Integer value for starting TCP/UDP/SCTP destination port in range
      protocol:
        type: int
        description: Integer value for the protocol type as defined by IANA
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Entries added to the Internet Service addition database.
      fortinet.fmgdevice.fmgd_firewall_internetserviceaddition_entry:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        internet_service_addition: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetserviceaddition_entry:
          id: 0 # Required variable, integer
          # addr_mode: <value in [ipv4, ipv6]>
          # port_range:
          #   - end_port: <integer>
          #     id: <integer>
          #     start_port: <integer>
          # protocol: <integer>
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
        '/pm/config/device/{device}/global/firewall/internet-service-addition/{internet-service-addition}/entry'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'internet-service-addition': {'type': 'str', 'api_name': 'internet_service_addition'},
        'internet_service_addition': {'type': 'str'},
        'firewall_internetserviceaddition_entry': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'addr-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'port-range': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'end-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'start-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetserviceaddition_entry'),
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
