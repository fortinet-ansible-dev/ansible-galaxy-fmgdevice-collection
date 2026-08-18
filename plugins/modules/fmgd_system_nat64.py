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
module: fmgd_system_nat64
short_description: Device vdom system nat64
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
  system_nat64:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      always_synthesize_aaaa_record:
        aliases: ['always-synthesize-aaaa-record']
        type: str
        description: Enable/disable AAAA record synthesis
        choices: ['disable', 'enable']
      generate_ipv6_fragment_header:
        aliases: ['generate-ipv6-fragment-header']
        type: str
        description: Enable/disable IPv6 fragment header generation.
        choices: ['disable', 'enable']
      nat46_force_ipv4_packet_forwarding:
        aliases: ['nat46-force-ipv4-packet-forwarding']
        type: str
        description: Enable/disable mandatory IPv4 packet forwarding in nat46.
        choices: ['disable', 'enable']
      nat64_prefix:
        aliases: ['nat64-prefix']
        type: str
        description: NAT64 prefix must be
      secondary_prefix:
        aliases: ['secondary-prefix']
        type: list
        elements: dict
        description: Secondary prefix.
        suboptions:
          name:
            type: str
            description: NAT64 prefix name.
          nat64_prefix:
            aliases: ['nat64-prefix']
            type: str
            description: NAT64 prefix.
      secondary_prefix_status:
        aliases: ['secondary-prefix-status']
        type: str
        description: Enable/disable secondary NAT64 prefix.
        choices: ['disable', 'enable']
      status:
        type: str
        description: Enable/disable NAT64
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device vdom system nat64
      fortinet.fmgdevice.fmgd_system_nat64:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        system_nat64:
          # always_synthesize_aaaa_record: <value in [disable, enable]>
          # generate_ipv6_fragment_header: <value in [disable, enable]>
          # nat46_force_ipv4_packet_forwarding: <value in [disable, enable]>
          # nat64_prefix: <string>
          # secondary_prefix:
          #   - name: <string>
          #     nat64_prefix: <string>
          # secondary_prefix_status: <value in [disable, enable]>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/nat64'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_nat64': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'always-synthesize-aaaa-record': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'generate-ipv6-fragment-header': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat46-force-ipv4-packet-forwarding': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64-prefix': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'secondary-prefix': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'nat64-prefix': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'secondary-prefix-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_nat64'),
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
