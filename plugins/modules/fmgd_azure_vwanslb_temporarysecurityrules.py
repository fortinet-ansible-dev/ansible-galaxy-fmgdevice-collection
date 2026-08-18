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
module: fmgd_azure_vwanslb_temporarysecurityrules
short_description: Configure temporary security rules.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  azure_vwanslb_temporarysecurityrules:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      expiration_time:
        aliases: ['expiration-time']
        type: str
        description: Expiration time
      rules:
        type: list
        elements: dict
        description: Rules.
        suboptions:
          destination_port_ranges:
            aliases: ['destination-port-ranges']
            type: str
            description: Destination port ranges.
          name:
            type: str
            description: Name of security rule.
          protocol:
            type: str
            description: Protocol.
            choices: ['TCP', 'UDP']
          source_address_prefix:
            aliases: ['source-address-prefix']
            type: str
            description: Source address ranges.
      status:
        type: str
        description: Status of SLB inbound security rules setting
        choices: ['disable', 'enable', 'pending', 'updating']
      type:
        type: int
        description: Type of security rules
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure temporary security rules.
      fortinet.fmgdevice.fmgd_azure_vwanslb_temporarysecurityrules:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        azure_vwanslb_temporarysecurityrules:
          # expiration_time: <string>
          # rules:
          #   - destination_port_ranges: <string>
          #     name: <string>
          #     protocol: <value in [TCP, UDP]>
          #     source_address_prefix: <string>
          # status: <value in [disable, enable, pending, ...]>
          # type: <integer>
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
        '/pm/config/device/{device}/global/azure/vwan-slb/temporary-security-rules'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'azure_vwanslb_temporarysecurityrules': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'expiration-time': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'rules': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'destination-port-ranges': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'protocol': {'v_range': [['7.4.3', '']], 'choices': ['TCP', 'UDP'], 'type': 'str'},
                        'source-address-prefix': {'v_range': [['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'pending', 'updating'], 'type': 'str'},
                'type': {'v_range': [['7.4.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'azure_vwanslb_temporarysecurityrules'),
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
