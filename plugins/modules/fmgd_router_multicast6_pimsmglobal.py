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
module: fmgd_router_multicast6_pimsmglobal
short_description: PIM sparse-mode global settings.
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
  router_multicast6_pimsmglobal:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      register_rate_limit:
        aliases: ['register-rate-limit']
        type: int
        description: Limit of packets/sec per source registered through this RP
      rp_address:
        aliases: ['rp-address']
        type: list
        elements: dict
        description: Rp address.
        suboptions:
          id:
            type: int
            description: ID of the entry.
          ip6_address:
            aliases: ['ip6-address']
            type: str
            description: RP router IPv6 address.
          group:
            type: list
            elements: str
            description: Groups to use this RP.
      pim_use_sdwan:
        aliases: ['pim-use-sdwan']
        type: str
        description: Enable/disable use of SDWAN when checking RPF neighbor and sending of REG packet.
        choices: ['disable', 'enable']
      bsr_allow_quick_refresh:
        aliases: ['bsr-allow-quick-refresh']
        type: str
        description: Enable/disable accept BSR quick refresh packets from neighbors.
        choices: ['disable', 'enable']
      bsr_candidate:
        aliases: ['bsr-candidate']
        type: str
        description: Enable/disable allowing this router to become a bootstrap router
        choices: ['disable', 'enable']
      bsr_hash:
        aliases: ['bsr-hash']
        type: int
        description: BSR hash length
      bsr_interface:
        aliases: ['bsr-interface']
        type: list
        elements: str
        description: Interface to advertise as candidate BSR.
      bsr_priority:
        aliases: ['bsr-priority']
        type: int
        description: BSR priority
      cisco_crp_prefix:
        aliases: ['cisco-crp-prefix']
        type: str
        description: Enable/disable making candidate RP compatible with old Cisco IOS.
        choices: ['disable', 'enable']
      cisco_ignore_rp_set_priority:
        aliases: ['cisco-ignore-rp-set-priority']
        type: str
        description: Use only hash for RP selection
        choices: ['disable', 'enable']
      spt_threshold:
        aliases: ['spt-threshold']
        type: str
        description: Enable/disable switching to source specific trees.
        choices: ['disable', 'enable']
      spt_threshold_group:
        aliases: ['spt-threshold-group']
        type: list
        elements: str
        description: Groups allowed to switch to source tree.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: PIM sparse-mode global settings.
      fortinet.fmgdevice.fmgd_router_multicast6_pimsmglobal:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        router_multicast6_pimsmglobal:
          # register_rate_limit: <integer>
          # rp_address:
          #   - id: <integer>
          #     ip6_address: <string>
          #     group: <list or string>
          # pim_use_sdwan: <value in [disable, enable]>
          # bsr_allow_quick_refresh: <value in [disable, enable]>
          # bsr_candidate: <value in [disable, enable]>
          # bsr_hash: <integer>
          # bsr_interface: <list or string>
          # bsr_priority: <integer>
          # cisco_crp_prefix: <value in [disable, enable]>
          # cisco_ignore_rp_set_priority: <value in [disable, enable]>
          # spt_threshold: <value in [disable, enable]>
          # spt_threshold_group: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/pim-sm-global'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_multicast6_pimsmglobal': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'register-rate-limit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'rp-address': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'ip6-address': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'group': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'pim-use-sdwan': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bsr-allow-quick-refresh': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bsr-candidate': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bsr-hash': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'bsr-interface': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'bsr-priority': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'cisco-crp-prefix': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cisco-ignore-rp-set-priority': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spt-threshold': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'spt-threshold-group': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast6_pimsmglobal'),
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
