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
module: fmgd_firewall_ippool
short_description: Configure IPv4 IP pools.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
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
    firewall_ippool:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comments:
                type: str
                description: Comment.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    add_nat64_route:
                        aliases: ['add-nat64-route']
                        type: str
                        description: Enable/disable adding NAT64 route.
                        choices:
                            - 'disable'
                            - 'enable'
                    arp_intf:
                        aliases: ['arp-intf']
                        type: str
                        description: Select an interface from available options that will reply to ARP requests.
                    arp_reply:
                        aliases: ['arp-reply']
                        type: str
                        description: Enable/disable replying to ARP requests when an IP Pool is added to a policy
                        choices:
                            - 'disable'
                            - 'enable'
                    associated_interface:
                        aliases: ['associated-interface']
                        type: str
                        description: Associated interface name.
                    block_size:
                        aliases: ['block-size']
                        type: int
                        description: Number of addresses in a block
                    cgn_block_size:
                        aliases: ['cgn-block-size']
                        type: int
                        description: Number of ports in a block
                    cgn_client_endip:
                        aliases: ['cgn-client-endip']
                        type: str
                        description: Final client IPv4 address
                    cgn_client_ipv6shift:
                        aliases: ['cgn-client-ipv6shift']
                        type: int
                        description: IPv6 shift for fixed-allocation.
                    cgn_client_startip:
                        aliases: ['cgn-client-startip']
                        type: str
                        description: First client IPv4 address
                    cgn_fixedalloc:
                        aliases: ['cgn-fixedalloc']
                        type: str
                        description: Enable/disable fixed-allocation mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    cgn_overload:
                        aliases: ['cgn-overload']
                        type: str
                        description: Enable/disable overload mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    cgn_port_end:
                        aliases: ['cgn-port-end']
                        type: int
                        description: Ending public port can be allocated.
                    cgn_port_start:
                        aliases: ['cgn-port-start']
                        type: int
                        description: Starting public port can be allocated.
                    cgn_spa:
                        aliases: ['cgn-spa']
                        type: str
                        description: Enable/disable single port allocation mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    comments:
                        type: str
                        description: Comment.
                    endip:
                        type: str
                        description:
                            - Support meta variable
                            - Final IPv4 address
                    endport:
                        type: int
                        description: Final port number
                    exclude_ip:
                        aliases: ['exclude-ip']
                        type: list
                        elements: str
                        description: Exclude IPs x.
                    nat64:
                        type: str
                        description: Enable/disable NAT64.
                        choices:
                            - 'disable'
                            - 'enable'
                    num_blocks_per_user:
                        aliases: ['num-blocks-per-user']
                        type: int
                        description: Number of addresses blocks that can be used by a user
                    pba_interim_log:
                        aliases: ['pba-interim-log']
                        type: int
                        description: Port block allocation interim logging interval
                    pba_timeout:
                        aliases: ['pba-timeout']
                        type: int
                        description: Port block allocation timeout
                    permit_any_host:
                        aliases: ['permit-any-host']
                        type: str
                        description: Enable/disable full cone NAT.
                        choices:
                            - 'disable'
                            - 'enable'
                    port_per_user:
                        aliases: ['port-per-user']
                        type: int
                        description: Number of port for each user
                    source_endip:
                        aliases: ['source-endip']
                        type: str
                        description:
                            - Support meta variable
                            - Final IPv4 address
                    source_startip:
                        aliases: ['source-startip']
                        type: str
                        description:
                            - Support meta variable
                            - First IPv4 address
                    startip:
                        type: str
                        description:
                            - Support meta variable
                            - First IPv4 address
                    startport:
                        type: int
                        description: First port number
                    subnet_broadcast_in_ippool:
                        aliases: ['subnet-broadcast-in-ippool']
                        type: str
                        description: Enable/disable inclusion of the subnetwork address and broadcast IP address in the NAT64 IP pool.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: IP pool type
                        choices:
                            - 'overload'
                            - 'one-to-one'
                            - 'fixed-port-range'
                            - 'port-block-allocation'
                            - 'cgn-resource-allocation'
                    utilization_alarm_clear:
                        aliases: ['utilization-alarm-clear']
                        type: int
                        description: Pool utilization alarm clear threshold
                    utilization_alarm_raise:
                        aliases: ['utilization-alarm-raise']
                        type: int
                        description: Pool utilization alarm raise threshold
                    client_prefix_length:
                        aliases: ['client-prefix-length']
                        type: int
                        description: Subnet length of a single deterministic NAT64 client
                    icmp_session_quota:
                        aliases: ['icmp-session-quota']
                        type: int
                        description: Maximum number of concurrent ICMP sessions allowed per client
                    privileged_port_use_pba:
                        aliases: ['privileged-port-use-pba']
                        type: str
                        description: Enable/disable selection of the external port from the port block allocation for NATing privileged ports
                        choices:
                            - 'disable'
                            - 'enable'
                    source_prefix6:
                        aliases: ['source-prefix6']
                        type: str
                        description: Source IPv6 network to be translated
                    tcp_session_quota:
                        aliases: ['tcp-session-quota']
                        type: int
                        description: Maximum number of concurrent TCP sessions allowed per client
                    udp_session_quota:
                        aliases: ['udp-session-quota']
                        type: int
                        description: Maximum number of concurrent UDP sessions allowed per client
            endip:
                type: str
                description:
                    - Support meta variable
                    - Final IPv4 address
            name:
                type: str
                description: IP pool name.
                required: true
            startip:
                type: str
                description:
                    - Support meta variable
                    - First IPv4 address
            arp_intf:
                aliases: ['arp-intf']
                type: list
                elements: str
                description: Select an interface from available options that will reply to ARP requests.
            cgn_overload:
                aliases: ['cgn-overload']
                type: str
                description: Enable/disable overload mode.
                choices:
                    - 'disable'
                    - 'enable'
            arp_reply:
                aliases: ['arp-reply']
                type: str
                description: Enable/disable replying to ARP requests when an IP Pool is added to a policy
                choices:
                    - 'disable'
                    - 'enable'
            add_nat64_route:
                aliases: ['add-nat64-route']
                type: str
                description: Enable/disable adding NAT64 route.
                choices:
                    - 'disable'
                    - 'enable'
            source_endip:
                aliases: ['source-endip']
                type: str
                description:
                    - Support meta variable
                    - Final IPv4 address
            exclude_ip:
                aliases: ['exclude-ip']
                type: list
                elements: str
                description: Exclude IPs x.
            cgn_port_end:
                aliases: ['cgn-port-end']
                type: int
                description: Ending public port can be allocated.
            pba_timeout:
                aliases: ['pba-timeout']
                type: int
                description: Port block allocation timeout
            associated_interface:
                aliases: ['associated-interface']
                type: list
                elements: str
                description: Associated interface name.
            cgn_spa:
                aliases: ['cgn-spa']
                type: str
                description: Enable/disable single port allocation mode.
                choices:
                    - 'disable'
                    - 'enable'
            startport:
                type: int
                description: First port number
            source_startip:
                aliases: ['source-startip']
                type: str
                description:
                    - Support meta variable
                    - First IPv4 address
            cgn_client_startip:
                aliases: ['cgn-client-startip']
                type: str
                description: First client IPv4 address
            cgn_fixedalloc:
                aliases: ['cgn-fixedalloc']
                type: str
                description: Enable/disable fixed-allocation mode.
                choices:
                    - 'disable'
                    - 'enable'
            utilization_alarm_clear:
                aliases: ['utilization-alarm-clear']
                type: int
                description: Pool utilization alarm clear threshold
            block_size:
                aliases: ['block-size']
                type: int
                description: Number of addresses in a block
            cgn_block_size:
                aliases: ['cgn-block-size']
                type: int
                description: Number of ports in a block
            pba_interim_log:
                aliases: ['pba-interim-log']
                type: int
                description: Port block allocation interim logging interval
            type:
                type: str
                description: IP pool type
                choices:
                    - 'overload'
                    - 'one-to-one'
                    - 'fixed-port-range'
                    - 'port-block-allocation'
                    - 'cgn-resource-allocation'
            cgn_client_endip:
                aliases: ['cgn-client-endip']
                type: str
                description: Final client IPv4 address
            subnet_broadcast_in_ippool:
                aliases: ['subnet-broadcast-in-ippool']
                type: str
                description: Enable/disable inclusion of the subnetwork address and broadcast IP address in the NAT64 IP pool.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            utilization_alarm_raise:
                aliases: ['utilization-alarm-raise']
                type: int
                description: Pool utilization alarm raise threshold
            port_per_user:
                aliases: ['port-per-user']
                type: int
                description: Number of port for each user
            permit_any_host:
                aliases: ['permit-any-host']
                type: str
                description: Enable/disable full cone NAT.
                choices:
                    - 'disable'
                    - 'enable'
            num_blocks_per_user:
                aliases: ['num-blocks-per-user']
                type: int
                description: Number of addresses blocks that can be used by a user
            cgn_client_ipv6shift:
                aliases: ['cgn-client-ipv6shift']
                type: int
                description: IPv6 shift for fixed-allocation.
            cgn_port_start:
                aliases: ['cgn-port-start']
                type: int
                description: Starting public port can be allocated.
            endport:
                type: int
                description: Final port number
            icmp_session_quota:
                aliases: ['icmp-session-quota']
                type: int
                description: Maximum number of concurrent ICMP sessions allowed per client
            client_prefix_length:
                aliases: ['client-prefix-length']
                type: int
                description: Subnet length of a single deterministic NAT64 client
            privileged_port_use_pba:
                aliases: ['privileged-port-use-pba']
                type: str
                description: Enable/disable selection of the external port from the port block allocation for NATing privileged ports
                choices:
                    - 'disable'
                    - 'enable'
            source_prefix6:
                aliases: ['source-prefix6']
                type: str
                description: Source IPv6 network to be translated
            tcp_session_quota:
                aliases: ['tcp-session-quota']
                type: int
                description: Maximum number of concurrent TCP sessions allowed per client
            udp_session_quota:
                aliases: ['udp-session-quota']
                type: int
                description: Maximum number of concurrent UDP sessions allowed per client
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure IPv4 IP pools.
      fortinet.fmgdevice.fmgd_firewall_ippool:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_ippool:
          name: "your value" # Required variable, string
          # comments: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     add_nat64_route: <value in [disable, enable]>
          #     arp_intf: <string>
          #     arp_reply: <value in [disable, enable]>
          #     associated_interface: <string>
          #     block_size: <integer>
          #     cgn_block_size: <integer>
          #     cgn_client_endip: <string>
          #     cgn_client_ipv6shift: <integer>
          #     cgn_client_startip: <string>
          #     cgn_fixedalloc: <value in [disable, enable]>
          #     cgn_overload: <value in [disable, enable]>
          #     cgn_port_end: <integer>
          #     cgn_port_start: <integer>
          #     cgn_spa: <value in [disable, enable]>
          #     comments: <string>
          #     endip: <string>
          #     endport: <integer>
          #     exclude_ip: <list or string>
          #     nat64: <value in [disable, enable]>
          #     num_blocks_per_user: <integer>
          #     pba_interim_log: <integer>
          #     pba_timeout: <integer>
          #     permit_any_host: <value in [disable, enable]>
          #     port_per_user: <integer>
          #     source_endip: <string>
          #     source_startip: <string>
          #     startip: <string>
          #     startport: <integer>
          #     subnet_broadcast_in_ippool: <value in [disable, enable]>
          #     type: <value in [overload, one-to-one, fixed-port-range, ...]>
          #     utilization_alarm_clear: <integer>
          #     utilization_alarm_raise: <integer>
          #     client_prefix_length: <integer>
          #     icmp_session_quota: <integer>
          #     privileged_port_use_pba: <value in [disable, enable]>
          #     source_prefix6: <string>
          #     tcp_session_quota: <integer>
          #     udp_session_quota: <integer>
          # endip: <string>
          # startip: <string>
          # arp_intf: <list or string>
          # cgn_overload: <value in [disable, enable]>
          # arp_reply: <value in [disable, enable]>
          # add_nat64_route: <value in [disable, enable]>
          # source_endip: <string>
          # exclude_ip: <list or string>
          # cgn_port_end: <integer>
          # pba_timeout: <integer>
          # associated_interface: <list or string>
          # cgn_spa: <value in [disable, enable]>
          # startport: <integer>
          # source_startip: <string>
          # cgn_client_startip: <string>
          # cgn_fixedalloc: <value in [disable, enable]>
          # utilization_alarm_clear: <integer>
          # block_size: <integer>
          # cgn_block_size: <integer>
          # pba_interim_log: <integer>
          # type: <value in [overload, one-to-one, fixed-port-range, ...]>
          # cgn_client_endip: <string>
          # subnet_broadcast_in_ippool: <value in [disable, enable]>
          # nat64: <value in [disable, enable]>
          # utilization_alarm_raise: <integer>
          # port_per_user: <integer>
          # permit_any_host: <value in [disable, enable]>
          # num_blocks_per_user: <integer>
          # cgn_client_ipv6shift: <integer>
          # cgn_port_start: <integer>
          # endport: <integer>
          # icmp_session_quota: <integer>
          # client_prefix_length: <integer>
          # privileged_port_use_pba: <value in [disable, enable]>
          # source_prefix6: <string>
          # tcp_session_quota: <integer>
          # udp_session_quota: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/ippool'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_ippool': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'comments': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'add-nat64-route': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'arp-intf': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'arp-reply': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'associated-interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'block-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'cgn-block-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'cgn-client-endip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'cgn-client-ipv6shift': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'cgn-client-startip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'cgn-fixedalloc': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cgn-overload': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cgn-port-end': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'cgn-port-start': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'cgn-spa': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'comments': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'endip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'endport': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'exclude-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'nat64': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'num-blocks-per-user': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'pba-interim-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'pba-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'permit-any-host': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'port-per-user': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'source-endip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'source-startip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'startip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'startport': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'subnet-broadcast-in-ippool': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['overload', 'one-to-one', 'fixed-port-range', 'port-block-allocation', 'cgn-resource-allocation'],
                            'type': 'str'
                        },
                        'utilization-alarm-clear': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'utilization-alarm-raise': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'client-prefix-length': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'icmp-session-quota': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'privileged-port-use-pba': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-prefix6': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'tcp-session-quota': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'udp-session-quota': {'v_range': [['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'endip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'startip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'arp-intf': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cgn-overload': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'arp-reply': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'add-nat64-route': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-endip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'exclude-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cgn-port-end': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'pba-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'associated-interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cgn-spa': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'startport': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'source-startip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cgn-client-startip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cgn-fixedalloc': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utilization-alarm-clear': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'block-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'cgn-block-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'pba-interim-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'type': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['overload', 'one-to-one', 'fixed-port-range', 'port-block-allocation', 'cgn-resource-allocation'],
                    'type': 'str'
                },
                'cgn-client-endip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'subnet-broadcast-in-ippool': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utilization-alarm-raise': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'port-per-user': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'permit-any-host': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'num-blocks-per-user': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'cgn-client-ipv6shift': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'cgn-port-start': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'endport': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'icmp-session-quota': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'client-prefix-length': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'privileged-port-use-pba': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-prefix6': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'tcp-session-quota': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'udp-session-quota': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippool'),
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
