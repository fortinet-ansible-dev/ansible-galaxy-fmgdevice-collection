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
module: fmgd_system_ipam
short_description: Configure IP address management services.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_ipam:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      automatic_conflict_resolution:
        aliases: ['automatic-conflict-resolution']
        type: str
        description: Enable/disable automatic conflict resolution.
        choices: ['disable', 'enable']
      manage_lan_addresses:
        aliases: ['manage-lan-addresses']
        type: str
        description: Enable/disable default management of LAN interface addresses.
        choices: ['disable', 'enable']
      manage_lan_extension_addresses:
        aliases: ['manage-lan-extension-addresses']
        type: str
        description: Enable/disable default management of FortiExtender LAN extension interface addresses.
        choices: ['disable', 'enable']
      manage_ssid_addresses:
        aliases: ['manage-ssid-addresses']
        type: str
        description: Enable/disable default management of FortiAP SSID addresses.
        choices: ['disable', 'enable']
      pools:
        type: list
        elements: dict
        description: Pools.
        suboptions:
          description:
            type: str
            description: Description.
          exclude:
            type: list
            elements: dict
            description: Exclude.
            suboptions:
              ID:
                type: int
                description: Exclude ID.
              exclude_subnet:
                aliases: ['exclude-subnet']
                type: list
                elements: str
                description: Configure subnet to exclude from the IPAM pool.
          name:
            type: str
            description: IPAM pool name.
          subnet:
            type: list
            elements: str
            description: Configure IPAM pool subnet, Class A - Class B subnet.
      require_subnet_size_match:
        aliases: ['require-subnet-size-match']
        type: str
        description: Enable/disable reassignment of subnets to make requested and actual sizes match.
        choices: ['disable', 'enable']
      rules:
        type: list
        elements: dict
        description: Rules.
        suboptions:
          description:
            type: str
            description: Description.
          device:
            type: list
            elements: str
            description: Configure serial number or wildcard of FortiGate to match.
          dhcp:
            type: str
            description: Enable/disable DHCP server for matching IPAM interfaces.
            choices: ['disable', 'enable']
          interface:
            type: list
            elements: str
            description: Configure name or wildcard of interface to match.
          name:
            type: str
            description: IPAM rule name.
          pool:
            type: list
            elements: str
            description: Configure name of IPAM pool to use.
          role:
            type: str
            description: Configure role of interface to match.
            choices: ['any', 'lan', 'wan', 'dmz', 'undefined']
          dhcp_template:
            aliases: ['dhcp-template']
            type: list
            elements: str
            description: DHCP template for assingned interface.
          item_name:
            aliases: ['item-name']
            type: list
            elements: str
            description: Configure name or wildcard of item to match.
          item_type:
            aliases: ['item-type']
            type: str
            description: Configure whether item is an interface or an address.
            choices: ['interface', 'address']
          vdom:
            type: list
            elements: str
            description: Configure which VDOMs have access to this IPAM rule.
      server_type:
        aliases: ['server-type']
        type: str
        description: Configure the type of IPAM server to use.
        choices: ['cloud', 'fabric-root']
      status:
        type: str
        description: Enable/disable IP address management services.
        choices: ['disable', 'enable']
      pool_subnet:
        aliases: ['pool-subnet']
        type: list
        elements: str
        description: Configure IPAM pool subnet, Class A - Class B subnet.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IP address management services.
      fortinet.fmgdevice.fmgd_system_ipam:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_ipam:
          # automatic_conflict_resolution: <value in [disable, enable]>
          # manage_lan_addresses: <value in [disable, enable]>
          # manage_lan_extension_addresses: <value in [disable, enable]>
          # manage_ssid_addresses: <value in [disable, enable]>
          # pools:
          #   - description: <string>
          #     exclude:
          #       - ID: <integer>
          #         exclude_subnet: <list or string>
          #     name: <string>
          #     subnet: <list or string>
          # require_subnet_size_match: <value in [disable, enable]>
          # rules:
          #   - description: <string>
          #     device: <list or string>
          #     dhcp: <value in [disable, enable]>
          #     interface: <list or string>
          #     name: <string>
          #     pool: <list or string>
          #     role: <value in [any, lan, wan, ...]>
          #     dhcp_template: <list or string>
          #     item_name: <list or string>
          #     item_type: <value in [interface, address]>
          #     vdom: <list or string>
          # server_type: <value in [cloud, fabric-root]>
          # status: <value in [disable, enable]>
          # pool_subnet: <list or string>
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
        '/pm/config/device/{device}/global/system/ipam'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ipam': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'automatic-conflict-resolution': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'manage-lan-addresses': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'manage-lan-extension-addresses': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'manage-ssid-addresses': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pools': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'exclude': {
                            'v_range': [['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'ID': {'v_range': [['7.4.3', '']], 'type': 'int'},
                                'exclude-subnet': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'subnet': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'require-subnet-size-match': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rules': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'device': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'dhcp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'pool': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'role': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'lan', 'wan', 'dmz', 'undefined'], 'type': 'str'},
                        'dhcp-template': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'item-name': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'item-type': {'v_range': [['8.0.0', '']], 'choices': ['interface', 'address'], 'type': 'str'},
                        'vdom': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['cloud', 'fabric-root'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pool-subnet': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ipam'),
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
