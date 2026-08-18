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
module: fmgd_firewall_address6template_subnetsegment
short_description: IPv6 subnet segments.
version_added: "1.1.0"
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
  address6-template:
    description: Deprecated, please use "address6_template"
    type: str
  address6_template:
    description: The parameter (address6-template) in requested url.
    type: str
  firewall_address6template_subnetsegment:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bits:
        type: int
        description: Number of bits.
      exclusive:
        type: str
        description: Enable/disable exclusive value.
        choices: ['disable', 'enable']
      id:
        type: int
        description: Subnet segment ID.
        required: true
      name:
        type: str
        description: Subnet segment name.
      values:
        type: list
        elements: dict
        description: Values.
        suboptions:
          name:
            type: str
            description: Subnet segment value name.
          value:
            type: str
            description: Subnet segment value.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv6 subnet segments.
      fortinet.fmgdevice.fmgd_firewall_address6template_subnetsegment:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        address6_template: <your own value>
        state: present # <value in [present, absent]>
        firewall_address6template_subnetsegment:
          id: 0 # Required variable, integer
          # bits: <integer>
          # exclusive: <value in [disable, enable]>
          # name: <string>
          # values:
          #   - name: <string>
          #     value: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/address6-template/{address6-template}/subnet-segment'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'address6-template': {'type': 'str', 'api_name': 'address6_template'},
        'address6_template': {'type': 'str'},
        'firewall_address6template_subnetsegment': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'bits': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'exclusive': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'values': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'value': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address6template_subnetsegment'),
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
