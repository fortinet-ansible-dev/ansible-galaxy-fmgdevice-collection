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
module: fmgd_firewall_internetservicedefinition_entry_portrange
short_description: Port ranges in the definition entry.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  internet-service-definition:
    description: Deprecated, please use "internet_service_definition"
    type: str
  internet_service_definition:
    description: The parameter (internet-service-definition) in requested url.
    type: str
  entry:
    description: The parameter (entry) in requested url.
    type: str
    required: true
  firewall_internetservicedefinition_entry_portrange:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      end_port:
        aliases: ['end-port']
        type: int
        description: End port.
      id:
        type: int
        description: Custom entry port range ID.
        required: true
      start_port:
        aliases: ['start-port']
        type: int
        description: Start port.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Port ranges in the definition entry.
      fortinet.fmgdevice.fmgd_firewall_internetservicedefinition_entry_portrange:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        internet_service_definition: <your own value>
        entry: <your own value>
        state: present # <value in [present, absent]>
        firewall_internetservicedefinition_entry_portrange:
          id: 0 # Required variable, integer
          # end_port: <integer>
          # start_port: <integer>
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
        '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}/port-range'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'internet-service-definition': {'type': 'str', 'api_name': 'internet_service_definition'},
        'internet_service_definition': {'type': 'str'},
        'entry': {'required': True, 'type': 'str'},
        'firewall_internetservicedefinition_entry_portrange': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'end-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'start-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservicedefinition_entry_portrange'),
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
