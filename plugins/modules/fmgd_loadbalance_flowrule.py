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
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
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
                choices:
                    - 'forward'
                    - 'mirror-ingress'
                    - 'stats'
                    - 'drop'
                    - 'mirror-egress'
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
                choices:
                    - 'any'
                    - 'arp'
                    - 'ip'
                    - 'ipv4'
                    - 'ipv6'
            forward_slot:
                aliases: ['forward-slot']
                type: str
                description: Forward slot.
                choices:
                    - 'master'
                    - 'all'
                    - 'load-balance'
                    - 'FPM3'
                    - 'FPM4'
                    - 'FPM5'
                    - 'FPM6'
                    - 'FPC1'
                    - 'FPC2'
                    - 'FPC3'
                    - 'FPC4'
                    - 'FPC5'
                    - 'FPC6'
                    - 'FPC7'
                    - 'FPC8'
                    - 'FPC9'
                    - 'FPC10'
                    - 'FPM7'
                    - 'FPM8'
                    - 'FPM9'
                    - 'FPM10'
                    - 'FPM11'
                    - 'FPM12'
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
                choices:
                    - 'disable'
                    - 'enable'
            tcp_flag:
                aliases: ['tcp-flag']
                type: str
                description: Tcp flags.
                choices:
                    - 'any'
                    - 'syn'
                    - 'fin'
                    - 'rst'
            vlan:
                type: int
                description: VLAN ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Flow rule configuration
      fortinet.fmgdevice.fmgd_loadbalance_flowrule:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        loadbalance_flowrule:
          id: 0 # Required variable, integer
          # action:
          #   - "forward"
          #   - "mirror-ingress"
          #   - "stats"
          #   - "drop"
          #   - "mirror-egress"
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
    url_params = ['device']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'loadbalance_flowrule': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'action': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['forward', 'mirror-ingress', 'stats', 'drop', 'mirror-egress'],
                    'elements': 'str'
                },
                'comment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-addr-ipv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dst-addr-ipv6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-l4port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ether-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['any', 'arp', 'ip', 'ipv4', 'ipv6'], 'type': 'str'},
                'forward-slot': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'master', 'all', 'load-balance', 'FPM3', 'FPM4', 'FPM5', 'FPM6', 'FPC1', 'FPC2', 'FPC3', 'FPC4', 'FPC5', 'FPC6', 'FPC7', 'FPC8',
                        'FPC9', 'FPC10', 'FPM7', 'FPM8', 'FPM9', 'FPM10', 'FPM11', 'FPM12'
                    ],
                    'type': 'str'
                },
                'icmpcode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'icmptype': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'icmpv6code': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'icmpv6type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'mirror-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'src-addr-ipv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-addr-ipv6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'src-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-l4port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['any', 'syn', 'fin', 'rst'], 'type': 'str'},
                'vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'loadbalance_flowrule'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
