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
module: fmgd_system_dhcp6_server
short_description: Configure DHCPv6 servers.
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    system_dhcp6_server:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            delegated_prefix_iaid:
                aliases: ['delegated-prefix-iaid']
                type: int
                description: IAID of obtained delegated-prefix from the upstream interface.
            dns_search_list:
                aliases: ['dns-search-list']
                type: str
                description: DNS search list options.
                choices:
                    - 'specify'
                    - 'delegated'
            dns_server1:
                aliases: ['dns-server1']
                type: str
                description: DNS server 1.
            dns_server2:
                aliases: ['dns-server2']
                type: str
                description: DNS server 2.
            dns_server3:
                aliases: ['dns-server3']
                type: str
                description: DNS server 3.
            dns_server4:
                aliases: ['dns-server4']
                type: str
                description: DNS server 4.
            dns_service:
                aliases: ['dns-service']
                type: str
                description: Options for assigning DNS servers to DHCPv6 clients.
                choices:
                    - 'default'
                    - 'specify'
                    - 'delegated'
            domain:
                type: str
                description: Domain name suffix for the IP addresses that the DHCP server assigns to clients.
            id:
                type: int
                description: ID.
                required: true
            interface:
                type: list
                elements: str
                description: DHCP server can assign IP configurations to clients connected to this interface.
            ip_mode:
                aliases: ['ip-mode']
                type: str
                description: Method used to assign client IP.
                choices:
                    - 'range'
                    - 'delegated'
            ip_range:
                aliases: ['ip-range']
                type: list
                elements: dict
                description: Ip range.
                suboptions:
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description: End of IP range.
                    id:
                        type: int
                        description: ID.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description: Start of IP range.
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class option matching.
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: list
                        elements: str
                        description: One or more VCI strings in quotes separated by spaces.
            lease_time:
                aliases: ['lease-time']
                type: int
                description: Lease time in seconds, 0 means unlimited.
            option1:
                type: str
                description: Option 1.
            option2:
                type: str
                description: Option 2.
            option3:
                type: str
                description: Option 3.
            prefix_mode:
                aliases: ['prefix-mode']
                type: str
                description: Assigning a prefix from a DHCPv6 client or RA.
                choices:
                    - 'dhcp6'
                    - 'ra'
            prefix_range:
                aliases: ['prefix-range']
                type: list
                elements: dict
                description: Prefix range.
                suboptions:
                    end_prefix:
                        aliases: ['end-prefix']
                        type: str
                        description: End of prefix range.
                    id:
                        type: int
                        description: ID.
                    prefix_length:
                        aliases: ['prefix-length']
                        type: int
                        description: Prefix length.
                    start_prefix:
                        aliases: ['start-prefix']
                        type: str
                        description: Start of prefix range.
            rapid_commit:
                aliases: ['rapid-commit']
                type: str
                description: Enable/disable allow/disallow rapid commit.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable this DHCPv6 configuration.
                choices:
                    - 'disable'
                    - 'enable'
            subnet:
                type: str
                description: Subnet or subnet-id if the IP mode is delegated.
            upstream_interface:
                aliases: ['upstream-interface']
                type: list
                elements: str
                description: Interface name from where delegated information is provided.
            options:
                type: list
                elements: dict
                description: Options.
                suboptions:
                    code:
                        type: int
                        description: DHCPv6 option code.
                    id:
                        type: int
                        description: ID.
                    ip6:
                        type: str
                        description: DHCP option IP6s.
                    type:
                        type: str
                        description: DHCPv6 option type.
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip6'
                            - 'fqdn'
                    value:
                        type: str
                        description: DHCPv6 option value
                    vci_match:
                        aliases: ['vci-match']
                        type: str
                        description: Enable/disable vendor class option matching.
                        choices:
                            - 'disable'
                            - 'enable'
                    vci_string:
                        aliases: ['vci-string']
                        type: list
                        elements: str
                        description: One or more VCI strings in quotes separated by spaces.
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
    - name: Configure DHCPv6 servers.
      fortinet.fmgdevice.fmgd_system_dhcp6_server:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_dhcp6_server:
          id: 0 # Required variable, integer
          # delegated_prefix_iaid: <integer>
          # dns_search_list: <value in [specify, delegated]>
          # dns_server1: <string>
          # dns_server2: <string>
          # dns_server3: <string>
          # dns_server4: <string>
          # dns_service: <value in [default, specify, delegated]>
          # domain: <string>
          # interface: <list or string>
          # ip_mode: <value in [range, delegated]>
          # ip_range:
          #   - end_ip: <string>
          #     id: <integer>
          #     start_ip: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
          # lease_time: <integer>
          # option1: <string>
          # option2: <string>
          # option3: <string>
          # prefix_mode: <value in [dhcp6, ra]>
          # prefix_range:
          #   - end_prefix: <string>
          #     id: <integer>
          #     prefix_length: <integer>
          #     start_prefix: <string>
          # rapid_commit: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # subnet: <string>
          # upstream_interface: <list or string>
          # options:
          #   - code: <integer>
          #     id: <integer>
          #     ip6: <string>
          #     type: <value in [hex, string, ip6, ...]>
          #     value: <string>
          #     vci_match: <value in [disable, enable]>
          #     vci_string: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_dhcp6_server': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'delegated-prefix-iaid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dns-search-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['specify', 'delegated'], 'type': 'str'},
                'dns-server1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dns-server2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dns-server3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dns-server4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dns-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'specify', 'delegated'], 'type': 'str'},
                'domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['range', 'delegated'], 'type': 'str'},
                'ip-range': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vci-match': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'lease-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'option1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'option2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'option3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'prefix-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dhcp6', 'ra'], 'type': 'str'},
                'prefix-range': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'end-prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'start-prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'rapid-commit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'upstream-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'options': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'code': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'id': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'ip6': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'type': {'v_range': [['7.6.0', '']], 'choices': ['hex', 'string', 'ip6', 'fqdn'], 'type': 'str'},
                        'value': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'vci-match': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vci-string': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_dhcp6_server'),
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
