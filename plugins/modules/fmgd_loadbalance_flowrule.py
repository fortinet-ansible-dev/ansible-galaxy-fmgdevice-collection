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
module: fmgd_loadbalance_flowrule
short_description: flow rule configuration
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  loadbalance_flowrule:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: list
        elements: str
        description: Flow rule action.
        choices: ['forward', 'mirror-ingress', 'stats', 'drop', 'mirror-egress']
      comment:
        type: str
        description: Comment.
      dst_addr_ipv4:
        aliases: ['dst-addr-ipv4']
        type: list
        elements: str
        description: Destination IPv4 address and mask.
      dst_addr_ipv6:
        aliases: ['dst-addr-ipv6']
        type: str
        description: Destination IPv6 address and mask.
      dst_l4port:
        aliases: ['dst-l4port']
        type: str
        description: Destination L4 port range.
      ether_type:
        aliases: ['ether-type']
        type: str
        description: Ethernet type.
        choices: ['any', 'arp', 'ip', 'ipv4', 'ipv6']
      forward_slot:
        aliases: ['forward-slot']
        type: str
        description: Forward slot.
        choices: ['master', 'all', 'load-balance', 'FPM3', 'FPM4', 'FPM5', 'FPM6', 'FPC1', 'FPC2',
                  'FPC3', 'FPC4', 'FPC5', 'FPC6', 'FPC7', 'FPC8', 'FPC9', 'FPC10', 'FPM7', 'FPM8',
                  'FPM9', 'FPM10', 'FPM11', 'FPM12']
      icmpcode:
        type: int
        description: ICMP code.
      icmptype:
        type: int
        description: ICMP type.
      icmpv6code:
        type: int
        description: ICMPv6 code.
      icmpv6type:
        type: int
        description: ICMPv6 type.
      id:
        type: int
        description: Flow rule ID.
        required: true
      mirror_interface:
        aliases: ['mirror-interface']
        type: list
        elements: str
        description: Mirror interface.
      priority:
        type: int
        description: Priority, highest priority will match first.
      protocol:
        type: str
        description: Protocol.
      src_addr_ipv4:
        aliases: ['src-addr-ipv4']
        type: list
        elements: str
        description: Source IPv4 address and mask.
      src_addr_ipv6:
        aliases: ['src-addr-ipv6']
        type: str
        description: Source IPv6 address and mask.
      src_interface:
        aliases: ['src-interface']
        type: list
        elements: str
        description: Source interface
      src_l4port:
        aliases: ['src-l4port']
        type: str
        description: Source L4 port range.
      status:
        type: str
        description: Enable/disable this flow rule.
        choices: ['disable', 'enable']
      tcp_flag:
        aliases: ['tcp-flag']
        type: str
        description: Tcp flags.
        choices: ['any', 'syn', 'fin', 'rst']
      vlan:
        type: int
        description: VLAN ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Flow rule configuration
      fortinet.fmgdevice.fmgd_loadbalance_flowrule:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        loadbalance_flowrule:
          id: 0 # Required variable, integer
          # action: ["forward", "mirror-ingress", "stats", "drop", "mirror-egress"]
          # comment: <string>
          # dst_addr_ipv4: <list or string>
          # dst_addr_ipv6: <string>
          # dst_l4port: <string>
          # ether_type: <value in [any, arp, ip, ...]>
          # forward_slot: <value in [master, all, load-balance, ...]>
          # icmpcode: <integer>
          # icmptype: <integer>
          # icmpv6code: <integer>
          # icmpv6type: <integer>
          # mirror_interface: <list or string>
          # priority: <integer>
          # protocol: <string>
          # src_addr_ipv4: <list or string>
          # src_addr_ipv6: <string>
          # src_interface: <list or string>
          # src_l4port: <string>
          # status: <value in [disable, enable]>
          # tcp_flag: <value in [any, syn, fin, ...]>
          # vlan: <integer>
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
        '/pm/config/device/{device}/global/load-balance/flow-rule'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'loadbalance_flowrule': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'action': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['forward', 'mirror-ingress', 'stats', 'drop', 'mirror-egress'],
                    'elements': 'str'
                },
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dst-addr-ipv4': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dst-addr-ipv6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dst-l4port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ether-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'arp', 'ip', 'ipv4', 'ipv6'], 'type': 'str'},
                'forward-slot': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'master', 'all', 'load-balance', 'FPM3', 'FPM4', 'FPM5', 'FPM6', 'FPC1', 'FPC2', 'FPC3', 'FPC4', 'FPC5', 'FPC6', 'FPC7', 'FPC8',
                        'FPC9', 'FPC10', 'FPM7', 'FPM8', 'FPM9', 'FPM10', 'FPM11', 'FPM12'
                    ],
                    'type': 'str'
                },
                'icmpcode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'icmptype': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'icmpv6code': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'icmpv6type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'mirror-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'src-addr-ipv4': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-addr-ipv6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'src-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-l4port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-flag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'syn', 'fin', 'rst'], 'type': 'str'},
                'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'loadbalance_flowrule'),
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
