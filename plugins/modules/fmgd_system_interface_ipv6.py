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
module: fmgd_system_interface_ipv6
short_description: IPv6 of interface.
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
    interface:
        description: The parameter (interface) in requested url.
        type: str
        required: true
    system_interface_ipv6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            autoconf:
                type: str
                description: Enable/disable address auto config.
                choices:
                    - 'disable'
                    - 'enable'
            cli_conn6_status:
                aliases: ['cli-conn6-status']
                type: int
                description: Cli conn6 status.
            dhcp6_client_options:
                aliases: ['dhcp6-client-options']
                type: list
                elements: str
                description: Dhcp6 client options.
                choices:
                    - 'rapid'
                    - 'iapd'
                    - 'iana'
                    - 'dns'
                    - 'dnsname'
            dhcp6_iapd_list:
                aliases: ['dhcp6-iapd-list']
                type: list
                elements: dict
                description: Dhcp6 iapd list.
                suboptions:
                    iaid:
                        type: int
                        description: Identity association identifier.
                    prefix_hint:
                        aliases: ['prefix-hint']
                        type: str
                        description: DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
                    prefix_hint_plt:
                        aliases: ['prefix-hint-plt']
                        type: int
                        description: DHCPv6 prefix hint preferred life time
                    prefix_hint_vlt:
                        aliases: ['prefix-hint-vlt']
                        type: int
                        description: DHCPv6 prefix hint valid life time
            dhcp6_information_request:
                aliases: ['dhcp6-information-request']
                type: str
                description: Enable/disable DHCPv6 information request.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6_prefix_delegation:
                aliases: ['dhcp6-prefix-delegation']
                type: str
                description: Enable/disable DHCPv6 prefix delegation.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6_relay_interface_id:
                aliases: ['dhcp6-relay-interface-id']
                type: str
                description: DHCP6 relay interface ID.
            dhcp6_relay_ip:
                aliases: ['dhcp6-relay-ip']
                type: list
                elements: str
                description: DHCPv6 relay IP address.
            dhcp6_relay_service:
                aliases: ['dhcp6-relay-service']
                type: str
                description: Enable/disable DHCPv6 relay.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6_relay_source_interface:
                aliases: ['dhcp6-relay-source-interface']
                type: str
                description: Enable/disable use of address on this interface as the source address of the relay message.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp6_relay_source_ip:
                aliases: ['dhcp6-relay-source-ip']
                type: str
                description: IPv6 address used by the DHCP6 relay as its source IP.
            dhcp6_relay_type:
                aliases: ['dhcp6-relay-type']
                type: str
                description: DHCPv6 relay type.
                choices:
                    - 'regular'
            icmp6_send_redirect:
                aliases: ['icmp6-send-redirect']
                type: str
                description: Enable/disable sending of ICMPv6 redirects.
                choices:
                    - 'disable'
                    - 'enable'
            interface_identifier:
                aliases: ['interface-identifier']
                type: str
                description: IPv6 interface identifier.
            ip6_address:
                aliases: ['ip6-address']
                type: str
                description: Primary IPv6 address prefix.
            ip6_allowaccess:
                aliases: ['ip6-allowaccess']
                type: list
                elements: str
                description: Allow management access to the interface.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
                    - 'capwap'
                    - 'fabric'
            ip6_default_life:
                aliases: ['ip6-default-life']
                type: int
                description: Default life
            ip6_delegated_prefix_iaid:
                aliases: ['ip6-delegated-prefix-iaid']
                type: int
                description: IAID of obtained delegated-prefix from the upstream interface.
            ip6_delegated_prefix_list:
                aliases: ['ip6-delegated-prefix-list']
                type: list
                elements: dict
                description: Ip6 delegated prefix list.
                suboptions:
                    autonomous_flag:
                        aliases: ['autonomous-flag']
                        type: str
                        description: Enable/disable the autonomous flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    delegated_prefix_iaid:
                        aliases: ['delegated-prefix-iaid']
                        type: int
                        description: IAID of obtained delegated-prefix from the upstream interface.
                    onlink_flag:
                        aliases: ['onlink-flag']
                        type: str
                        description: Enable/disable the onlink flag.
                        choices:
                            - 'disable'
                            - 'enable'
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
                        choices:
                            - 'delegated'
                            - 'default'
                            - 'specify'
                    subnet:
                        type: str
                        description: Add subnet ID to routing prefix.
                    upstream_interface:
                        aliases: ['upstream-interface']
                        type: list
                        elements: str
                        description: Name of the interface that provides delegated information.
            ip6_dns_server_override:
                aliases: ['ip6-dns-server-override']
                type: str
                description: Enable/disable using the DNS server acquired by DHCP.
                choices:
                    - 'disable'
                    - 'enable'
            ip6_extra_addr:
                aliases: ['ip6-extra-addr']
                type: list
                elements: dict
                description: Ip6 extra addr.
                suboptions:
                    prefix:
                        type: str
                        description: IPv6 address prefix.
            ip6_hop_limit:
                aliases: ['ip6-hop-limit']
                type: int
                description: Hop limit
            ip6_link_mtu:
                aliases: ['ip6-link-mtu']
                type: int
                description: IPv6 link MTU.
            ip6_manage_flag:
                aliases: ['ip6-manage-flag']
                type: str
                description: Enable/disable the managed flag.
                choices:
                    - 'disable'
                    - 'enable'
            ip6_max_interval:
                aliases: ['ip6-max-interval']
                type: int
                description: IPv6 maximum interval
            ip6_min_interval:
                aliases: ['ip6-min-interval']
                type: int
                description: IPv6 minimum interval
            ip6_mode:
                aliases: ['ip6-mode']
                type: str
                description: Addressing mode
                choices:
                    - 'static'
                    - 'dhcp'
                    - 'pppoe'
                    - 'delegated'
            ip6_other_flag:
                aliases: ['ip6-other-flag']
                type: str
                description: Enable/disable the other IPv6 flag.
                choices:
                    - 'disable'
                    - 'enable'
            ip6_prefix_list:
                aliases: ['ip6-prefix-list']
                type: list
                elements: dict
                description: Ip6 prefix list.
                suboptions:
                    autonomous_flag:
                        aliases: ['autonomous-flag']
                        type: str
                        description: Enable/disable the autonomous flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    dnssl:
                        type: list
                        elements: str
                        description: DNS search list option.
                    onlink_flag:
                        aliases: ['onlink-flag']
                        type: str
                        description: Enable/disable the onlink flag.
                        choices:
                            - 'disable'
                            - 'enable'
                    preferred_life_time:
                        aliases: ['preferred-life-time']
                        type: int
                        description: Preferred life time
                    prefix:
                        type: str
                        description: IPv6 prefix.
                    rdnss:
                        type: list
                        elements: str
                        description: Recursive DNS server option.
                    valid_life_time:
                        aliases: ['valid-life-time']
                        type: int
                        description: Valid life time
            ip6_prefix_mode:
                aliases: ['ip6-prefix-mode']
                type: str
                description: Assigning a prefix from DHCP or RA.
                choices:
                    - 'dhcp6'
                    - 'ra'
            ip6_reachable_time:
                aliases: ['ip6-reachable-time']
                type: int
                description: IPv6 reachable time
            ip6_retrans_time:
                aliases: ['ip6-retrans-time']
                type: int
                description: IPv6 retransmit time
            ip6_send_adv:
                aliases: ['ip6-send-adv']
                type: str
                description: Enable/disable sending advertisements about the interface.
                choices:
                    - 'disable'
                    - 'enable'
            ip6_subnet:
                aliases: ['ip6-subnet']
                type: str
                description: Subnet to routing prefix.
            ip6_upstream_interface:
                aliases: ['ip6-upstream-interface']
                type: list
                elements: str
                description: Interface name providing delegated information.
            nd_cert:
                aliases: ['nd-cert']
                type: list
                elements: str
                description: Neighbor discovery certificate.
            nd_cga_modifier:
                aliases: ['nd-cga-modifier']
                type: str
                description: Neighbor discovery CGA modifier.
            nd_mode:
                aliases: ['nd-mode']
                type: str
                description: Neighbor discovery mode.
                choices:
                    - 'basic'
                    - 'SEND-compatible'
            nd_security_level:
                aliases: ['nd-security-level']
                type: int
                description: Neighbor discovery security level
            nd_timestamp_delta:
                aliases: ['nd-timestamp-delta']
                type: int
                description: Neighbor discovery timestamp delta value
            nd_timestamp_fuzz:
                aliases: ['nd-timestamp-fuzz']
                type: int
                description: Neighbor discovery timestamp fuzz factor
            ra_send_mtu:
                aliases: ['ra-send-mtu']
                type: str
                description: Enable/disable sending link MTU in RA packet.
                choices:
                    - 'disable'
                    - 'enable'
            unique_autoconf_addr:
                aliases: ['unique-autoconf-addr']
                type: str
                description: Enable/disable unique auto config address.
                choices:
                    - 'disable'
                    - 'enable'
            vrip6_link_local:
                type: str
                description: Link-local IPv6 address of virtual router.
            vrrp_virtual_mac6:
                aliases: ['vrrp-virtual-mac6']
                type: str
                description: Enable/disable virtual MAC for VRRP.
                choices:
                    - 'disable'
                    - 'enable'
            vrrp6:
                type: list
                elements: dict
                description: Vrrp6.
                suboptions:
                    accept_mode:
                        aliases: ['accept-mode']
                        type: str
                        description: Enable/disable accept mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    adv_interval:
                        aliases: ['adv-interval']
                        type: int
                        description: Advertisement interval
                    ignore_default_route:
                        aliases: ['ignore-default-route']
                        type: str
                        description: Enable/disable ignoring of default route when checking destination.
                        choices:
                            - 'disable'
                            - 'enable'
                    preempt:
                        type: str
                        description: Enable/disable preempt mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority:
                        type: int
                        description: Priority of the virtual router
                    start_time:
                        aliases: ['start-time']
                        type: int
                        description: Startup time
                    status:
                        type: str
                        description: Enable/disable VRRP.
                        choices:
                            - 'disable'
                            - 'enable'
                    vrdst6:
                        type: list
                        elements: str
                        description: Monitor the route to this destination.
                    vrgrp:
                        type: int
                        description: VRRP group ID
                    vrid:
                        type: int
                        description: Virtual router identifier
                    vrip6:
                        type: str
                        description: IPv6 address of the virtual router.
                    vrdst_priority:
                        aliases: ['vrdst-priority']
                        type: int
                        description: Priority of the virtual router when the virtual router destination becomes unreachable
            dhcp6_prefix_hint_vlt:
                aliases: ['dhcp6-prefix-hint-vlt']
                type: int
                description: DHCPv6 prefix hint valid life time
            dhcp6_prefix_hint:
                aliases: ['dhcp6-prefix-hint']
                type: str
                description: DHCPv6 prefix that will be used as a hint to the upstream DHCPv6 server.
            dhcp6_prefix_hint_plt:
                aliases: ['dhcp6-prefix-hint-plt']
                type: int
                description: DHCPv6 prefix hint preferred life time
            client_options:
                aliases: ['client-options']
                type: list
                elements: dict
                description: Client options.
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
            ip6_adv_rio:
                aliases: ['ip6-adv-rio']
                type: str
                description: Enable/disable sending advertisements with route information option.
                choices:
                    - 'disable'
                    - 'enable'
            ip6_dnssl_list:
                aliases: ['ip6-dnssl-list']
                type: list
                elements: dict
                description: Ip6 dnssl list.
                suboptions:
                    dnssl_life_time:
                        aliases: ['dnssl-life-time']
                        type: int
                        description: DNS search list time in seconds
                    domain:
                        type: str
                        description: Domain name.
            ip6_rdnss_list:
                aliases: ['ip6-rdnss-list']
                type: list
                elements: dict
                description: Ip6 rdnss list.
                suboptions:
                    rdnss:
                        type: str
                        description: Recursive DNS server option.
                    rdnss_life_time:
                        aliases: ['rdnss-life-time']
                        type: int
                        description: Recursive DNS server life time in seconds
            ip6_route_list:
                aliases: ['ip6-route-list']
                type: list
                elements: dict
                description: Ip6 route list.
                suboptions:
                    route:
                        type: str
                        description: IPv6 route.
                    route_life_time:
                        aliases: ['route-life-time']
                        type: int
                        description: Route life time in seconds
                    route_pref:
                        aliases: ['route-pref']
                        type: str
                        description: Set route preference to the interface
                        choices:
                            - 'medium'
                            - 'high'
                            - 'low'
            ip6_route_pref:
                aliases: ['ip6-route-pref']
                type: str
                description: Set route preference to the interface
                choices:
                    - 'medium'
                    - 'high'
                    - 'low'
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
    - name: IPv6 of interface.
      fortinet.fmgdevice.fmgd_system_interface_ipv6:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        interface: <your own value>
        system_interface_ipv6:
          # autoconf: <value in [disable, enable]>
          # cli_conn6_status: <integer>
          # dhcp6_client_options:
          #   - "rapid"
          #   - "iapd"
          #   - "iana"
          #   - "dns"
          #   - "dnsname"
          # dhcp6_iapd_list:
          #   - iaid: <integer>
          #     prefix_hint: <string>
          #     prefix_hint_plt: <integer>
          #     prefix_hint_vlt: <integer>
          # dhcp6_information_request: <value in [disable, enable]>
          # dhcp6_prefix_delegation: <value in [disable, enable]>
          # dhcp6_relay_interface_id: <string>
          # dhcp6_relay_ip: <list or string>
          # dhcp6_relay_service: <value in [disable, enable]>
          # dhcp6_relay_source_interface: <value in [disable, enable]>
          # dhcp6_relay_source_ip: <string>
          # dhcp6_relay_type: <value in [regular]>
          # icmp6_send_redirect: <value in [disable, enable]>
          # interface_identifier: <string>
          # ip6_address: <string>
          # ip6_allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "fgfm"
          #   - "capwap"
          #   - "fabric"
          # ip6_default_life: <integer>
          # ip6_delegated_prefix_iaid: <integer>
          # ip6_delegated_prefix_list:
          #   - autonomous_flag: <value in [disable, enable]>
          #     delegated_prefix_iaid: <integer>
          #     onlink_flag: <value in [disable, enable]>
          #     prefix_id: <integer>
          #     rdnss: <list or string>
          #     rdnss_service: <value in [delegated, default, specify]>
          #     subnet: <string>
          #     upstream_interface: <list or string>
          # ip6_dns_server_override: <value in [disable, enable]>
          # ip6_extra_addr:
          #   - prefix: <string>
          # ip6_hop_limit: <integer>
          # ip6_link_mtu: <integer>
          # ip6_manage_flag: <value in [disable, enable]>
          # ip6_max_interval: <integer>
          # ip6_min_interval: <integer>
          # ip6_mode: <value in [static, dhcp, pppoe, ...]>
          # ip6_other_flag: <value in [disable, enable]>
          # ip6_prefix_list:
          #   - autonomous_flag: <value in [disable, enable]>
          #     dnssl: <list or string>
          #     onlink_flag: <value in [disable, enable]>
          #     preferred_life_time: <integer>
          #     prefix: <string>
          #     rdnss: <list or string>
          #     valid_life_time: <integer>
          # ip6_prefix_mode: <value in [dhcp6, ra]>
          # ip6_reachable_time: <integer>
          # ip6_retrans_time: <integer>
          # ip6_send_adv: <value in [disable, enable]>
          # ip6_subnet: <string>
          # ip6_upstream_interface: <list or string>
          # nd_cert: <list or string>
          # nd_cga_modifier: <string>
          # nd_mode: <value in [basic, SEND-compatible]>
          # nd_security_level: <integer>
          # nd_timestamp_delta: <integer>
          # nd_timestamp_fuzz: <integer>
          # ra_send_mtu: <value in [disable, enable]>
          # unique_autoconf_addr: <value in [disable, enable]>
          # vrip6_link_local: <string>
          # vrrp_virtual_mac6: <value in [disable, enable]>
          # vrrp6:
          #   - accept_mode: <value in [disable, enable]>
          #     adv_interval: <integer>
          #     ignore_default_route: <value in [disable, enable]>
          #     preempt: <value in [disable, enable]>
          #     priority: <integer>
          #     start_time: <integer>
          #     status: <value in [disable, enable]>
          #     vrdst6: <list or string>
          #     vrgrp: <integer>
          #     vrid: <integer>
          #     vrip6: <string>
          #     vrdst_priority: <integer>
          # dhcp6_prefix_hint_vlt: <integer>
          # dhcp6_prefix_hint: <string>
          # dhcp6_prefix_hint_plt: <integer>
          # client_options:
          #   - code: <integer>
          #     id: <integer>
          #     ip6: <string>
          #     type: <value in [hex, string, ip6, ...]>
          #     value: <string>
          # ip6_adv_rio: <value in [disable, enable]>
          # ip6_dnssl_list:
          #   - dnssl_life_time: <integer>
          #     domain: <string>
          # ip6_rdnss_list:
          #   - rdnss: <string>
          #     rdnss_life_time: <integer>
          # ip6_route_list:
          #   - route: <string>
          #     route_life_time: <integer>
          #     route_pref: <value in [medium, high, low]>
          # ip6_route_pref: <value in [medium, high, low]>
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
        '/pm/config/device/{device}/global/system/interface/{interface}/ipv6'
    ]
    url_params = ['device', 'interface']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'system_interface_ipv6': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'autoconf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cli-conn6-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dhcp6-client-options': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['rapid', 'iapd', 'iana', 'dns', 'dnsname'],
                    'elements': 'str'
                },
                'dhcp6-iapd-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'iaid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix-hint': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'prefix-hint-plt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix-hint-vlt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'dhcp6-information-request': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp6-prefix-delegation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp6-relay-interface-id': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'dhcp6-relay-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dhcp6-relay-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp6-relay-source-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp6-relay-source-ip': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'dhcp6-relay-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular'], 'type': 'str'},
                'icmp6-send-redirect': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface-identifier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm', 'capwap', 'fabric'],
                    'elements': 'str'
                },
                'ip6-default-life': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-delegated-prefix-iaid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-delegated-prefix-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'autonomous-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'delegated-prefix-iaid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'onlink-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'prefix-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'rdnss': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'rdnss-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['delegated', 'default', 'specify'], 'type': 'str'},
                        'subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'upstream-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ip6-dns-server-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip6-extra-addr': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'ip6-hop-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-link-mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-manage-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip6-max-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-min-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['static', 'dhcp', 'pppoe', 'delegated'], 'type': 'str'},
                'ip6-other-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip6-prefix-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'autonomous-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dnssl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'onlink-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'preferred-life-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'rdnss': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'valid-life-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'ip6-prefix-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dhcp6', 'ra'], 'type': 'str'},
                'ip6-reachable-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-retrans-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ip6-send-adv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip6-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-upstream-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'nd-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'nd-cga-modifier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'nd-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['basic', 'SEND-compatible'], 'type': 'str'},
                'nd-security-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nd-timestamp-delta': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nd-timestamp-fuzz': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ra-send-mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unique-autoconf-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrip6_link_local': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vrrp-virtual-mac6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrrp6': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'accept-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'adv-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ignore-default-route': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'preempt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'start-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vrdst6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'vrgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vrid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vrip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vrdst-priority': {'v_range': [['7.6.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'dhcp6-prefix-hint-vlt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dhcp6-prefix-hint': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dhcp6-prefix-hint-plt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'client-options': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'code': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'id': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'ip6': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'type': {'v_range': [['7.6.0', '']], 'choices': ['hex', 'string', 'ip6', 'fqdn'], 'type': 'str'},
                        'value': {'v_range': [['7.6.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ip6-adv-rio': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip6-dnssl-list': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {'dnssl-life-time': {'v_range': [['7.6.2', '']], 'type': 'int'}, 'domain': {'v_range': [['7.6.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'ip6-rdnss-list': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {'rdnss': {'v_range': [['7.6.2', '']], 'type': 'str'}, 'rdnss-life-time': {'v_range': [['7.6.2', '']], 'type': 'int'}},
                    'elements': 'dict'
                },
                'ip6-route-list': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'route': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'route-life-time': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'route-pref': {'v_range': [['7.6.2', '']], 'choices': ['medium', 'high', 'low'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ip6-route-pref': {'v_range': [['7.6.2', '']], 'choices': ['medium', 'high', 'low'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface_ipv6'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
