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
module: fmgd_system_interface_ipv6_ip6delegatedprefixlist
short_description: Advertised IPv6 delegated prefix list.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  interface:
    description: The parameter (interface) in requested url.
    type: str
    required: true
  system_interface_ipv6_ip6delegatedprefixlist:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      autonomous_flag:
        aliases: ['autonomous-flag']
        type: str
        description: Enable/disable the autonomous flag.
        choices: ['disable', 'enable']
      delegated_prefix_iaid:
        aliases: ['delegated-prefix-iaid']
        type: int
        description: IAID of obtained delegated-prefix from the upstream interface.
      onlink_flag:
        aliases: ['onlink-flag']
        type: str
        description: Enable/disable the onlink flag.
        choices: ['disable', 'enable']
      prefix_id:
        aliases: ['prefix-id']
        type: int
        description: Prefix ID.
      rdnss:
        type: list
        elements: str
        description: Recursive DNS server option.
      rdnss_service:
        aliases: ['rdnss-service']
        type: str
        description: Recursive DNS service option.
        choices: ['delegated', 'default', 'specify']
      subnet:
        type: str
        description: Add subnet ID to routing prefix.
      upstream_interface:
        aliases: ['upstream-interface']
        type: list
        elements: str
        description: Name of the interface that provides delegated information.
      dnssl_service:
        aliases: ['dnssl-service']
        type: str
        description: Enable/disable use of domain from delegated prefix for DNSSL.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Advertised IPv6 delegated prefix list.
      fortinet.fmgdevice.fmgd_system_interface_ipv6_ip6delegatedprefixlist:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        interface: <your own value>
        state: present # <value in [present, absent]>
        system_interface_ipv6_ip6delegatedprefixlist:
          # autonomous_flag: <value in [disable, enable]>
          # delegated_prefix_iaid: <integer>
          # onlink_flag: <value in [disable, enable]>
          # prefix_id: <integer>
          # rdnss: <list or string>
          # rdnss_service: <value in [delegated, default, specify]>
          # subnet: <string>
          # upstream_interface: <list or string>
          # dnssl_service: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-delegated-prefix-list'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'system_interface_ipv6_ip6delegatedprefixlist': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'autonomous-flag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'delegated-prefix-iaid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'onlink-flag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'prefix-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'rdnss': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'rdnss-service': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['delegated', 'default', 'specify'], 'type': 'str'},
                'subnet': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'upstream-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dnssl-service': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface_ipv6_ip6delegatedprefixlist'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
