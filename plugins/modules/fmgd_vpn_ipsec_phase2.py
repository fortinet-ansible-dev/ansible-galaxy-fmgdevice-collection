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
module: fmgd_vpn_ipsec_phase2
short_description: Configure VPN autokey tunnel.
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
    vpn_ipsec_phase2:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add_route:
                aliases: ['add-route']
                type: str
                description: Enable/disable automatic route addition.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'phase1'
            auto_negotiate:
                aliases: ['auto-negotiate']
                type: str
                description: Enable/disable IPsec SA auto-negotiation.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comment.
            dhcp_ipsec:
                aliases: ['dhcp-ipsec']
                type: str
                description: Enable/disable DHCP-IPsec.
                choices:
                    - 'disable'
                    - 'enable'
            dhgrp:
                type: list
                elements: str
                description: Phase2 DH group.
                choices:
                    - '1'
                    - '2'
                    - '5'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
            diffserv:
                type: str
                description: Enable/disable applying DSCP value to the IPsec tunnel outer IP header.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode:
                type: str
                description: DSCP value to be applied to the IPsec tunnel outer IP header.
            dst_addr_type:
                aliases: ['dst-addr-type']
                type: str
                description: Remote proxy ID type.
                choices:
                    - 'subnet'
                    - 'range'
                    - 'ip'
                    - 'name'
            dst_end_ip:
                aliases: ['dst-end-ip']
                type: str
                description: Remote proxy ID IPv4 end.
            dst_end_ip6:
                aliases: ['dst-end-ip6']
                type: str
                description: Remote proxy ID IPv6 end.
            dst_name:
                aliases: ['dst-name']
                type: list
                elements: str
                description: Remote proxy ID name.
            dst_name6:
                aliases: ['dst-name6']
                type: list
                elements: str
                description: Remote proxy ID name.
            dst_port:
                aliases: ['dst-port']
                type: int
                description: Quick mode destination port
            dst_start_ip:
                aliases: ['dst-start-ip']
                type: str
                description: Remote proxy ID IPv4 start.
            dst_start_ip6:
                aliases: ['dst-start-ip6']
                type: str
                description: Remote proxy ID IPv6 start.
            dst_subnet:
                aliases: ['dst-subnet']
                type: list
                elements: str
                description: Remote proxy ID IPv4 subnet.
            dst_subnet6:
                aliases: ['dst-subnet6']
                type: str
                description: Remote proxy ID IPv6 subnet.
            encapsulation:
                type: str
                description: ESP encapsulation mode.
                choices:
                    - 'tunnel-mode'
                    - 'transport-mode'
            inbound_dscp_copy:
                aliases: ['inbound-dscp-copy']
                type: str
                description: Enable/disable copying of the DSCP in the ESP header to the inner IP header.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'phase1'
            initiator_ts_narrow:
                aliases: ['initiator-ts-narrow']
                type: str
                description: Enable/disable traffic selector narrowing for IKEv2 initiator.
                choices:
                    - 'disable'
                    - 'enable'
            ipv4_df:
                aliases: ['ipv4-df']
                type: str
                description: Enable/disable setting and resetting of IPv4 Dont Fragment bit.
                choices:
                    - 'disable'
                    - 'enable'
            keepalive:
                type: str
                description: Enable/disable keep alive.
                choices:
                    - 'disable'
                    - 'enable'
            keylife_type:
                aliases: ['keylife-type']
                type: str
                description: Keylife type.
                choices:
                    - 'seconds'
                    - 'kbs'
                    - 'both'
            keylifekbs:
                type: int
                description: Phase2 key life in number of kilobytes of traffic
            keylifeseconds:
                type: int
                description: Phase2 key life in time in seconds
            l2tp:
                type: str
                description: Enable/disable L2TP over IPsec.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: IPsec tunnel name.
                required: true
            pfs:
                type: str
                description: Enable/disable PFS feature.
                choices:
                    - 'disable'
                    - 'enable'
            phase1name:
                type: list
                elements: str
                description: Phase 1 determines the options required for phase 2.
            proposal:
                type: str
                description: Phase2 proposal.
                choices:
                    - 'null-md5'
                    - 'null-sha1'
                    - 'des-null'
                    - '3des-null'
                    - 'des-md5'
                    - 'des-sha1'
                    - '3des-md5'
                    - '3des-sha1'
                    - 'aes128-md5'
                    - 'aes128-sha1'
                    - 'aes192-md5'
                    - 'aes192-sha1'
                    - 'aes256-md5'
                    - 'aes256-sha1'
                    - 'aes128-null'
                    - 'aes192-null'
                    - 'aes256-null'
                    - 'null-sha256'
                    - 'des-sha256'
                    - '3des-sha256'
                    - 'aes128-sha256'
                    - 'aes192-sha256'
                    - 'aes256-sha256'
                    - 'des-sha384'
                    - 'des-sha512'
                    - '3des-sha384'
                    - '3des-sha512'
                    - 'aes128-sha384'
                    - 'aes128-sha512'
                    - 'aes192-sha384'
                    - 'aes192-sha512'
                    - 'aes256-sha384'
                    - 'aes256-sha512'
                    - 'null-sha384'
                    - 'null-sha512'
                    - 'aria128-null'
                    - 'aria128-md5'
                    - 'aria128-sha1'
                    - 'aria128-sha256'
                    - 'aria128-sha384'
                    - 'aria128-sha512'
                    - 'aria192-null'
                    - 'aria192-md5'
                    - 'aria192-sha1'
                    - 'aria192-sha256'
                    - 'aria192-sha384'
                    - 'aria192-sha512'
                    - 'aria256-null'
                    - 'aria256-md5'
                    - 'aria256-sha1'
                    - 'aria256-sha256'
                    - 'aria256-sha384'
                    - 'aria256-sha512'
                    - 'seed-null'
                    - 'seed-md5'
                    - 'seed-sha1'
                    - 'seed-sha256'
                    - 'seed-sha384'
                    - 'seed-sha512'
                    - 'aes128gcm'
                    - 'aes256gcm'
                    - 'chacha20poly1305'
            protocol:
                type: int
                description: Quick mode protocol selector
            replay:
                type: str
                description: Enable/disable replay detection.
                choices:
                    - 'disable'
                    - 'enable'
            route_overlap:
                aliases: ['route-overlap']
                type: str
                description: Action for overlapping routes.
                choices:
                    - 'use-old'
                    - 'use-new'
                    - 'allow'
            selector_match:
                aliases: ['selector-match']
                type: str
                description: Match type to use when comparing selectors.
                choices:
                    - 'auto'
                    - 'subset'
                    - 'exact'
            single_source:
                aliases: ['single-source']
                type: str
                description: Enable/disable single source IP restriction.
                choices:
                    - 'disable'
                    - 'enable'
            src_addr_type:
                aliases: ['src-addr-type']
                type: str
                description: Local proxy ID type.
                choices:
                    - 'subnet'
                    - 'range'
                    - 'ip'
                    - 'name'
            src_end_ip:
                aliases: ['src-end-ip']
                type: str
                description: Local proxy ID end.
            src_end_ip6:
                aliases: ['src-end-ip6']
                type: str
                description: Local proxy ID IPv6 end.
            src_name:
                aliases: ['src-name']
                type: list
                elements: str
                description: Local proxy ID name.
            src_name6:
                aliases: ['src-name6']
                type: list
                elements: str
                description: Local proxy ID name.
            src_port:
                aliases: ['src-port']
                type: int
                description: Quick mode source port
            src_start_ip:
                aliases: ['src-start-ip']
                type: str
                description: Local proxy ID start.
            src_start_ip6:
                aliases: ['src-start-ip6']
                type: str
                description: Local proxy ID IPv6 start.
            src_subnet:
                aliases: ['src-subnet']
                type: list
                elements: str
                description: Local proxy ID subnet.
            src_subnet6:
                aliases: ['src-subnet6']
                type: str
                description: Local proxy ID IPv6 subnet.
            use_natip:
                aliases: ['use-natip']
                type: str
                description: Enable to use the FortiGate public IP as the source selector when outbound NAT is used.
                choices:
                    - 'disable'
                    - 'enable'
            addke1:
                type: list
                elements: str
                description: Phase2 ADDKE1 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke2:
                type: list
                elements: str
                description: Phase2 ADDKE2 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke3:
                type: list
                elements: str
                description: Phase2 ADDKE3 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke4:
                type: list
                elements: str
                description: Phase2 ADDKE4 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke5:
                type: list
                elements: str
                description: Phase2 ADDKE5 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke6:
                type: list
                elements: str
                description: Phase2 ADDKE6 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
            addke7:
                type: list
                elements: str
                description: Phase2 ADDKE7 group.
                choices:
                    - '0'
                    - '1080'
                    - '1081'
                    - '1082'
                    - '1083'
                    - '1084'
                    - '1085'
                    - '1089'
                    - '1090'
                    - '1091'
                    - '1092'
                    - '1093'
                    - '1094'
                    - '35'
                    - '36'
                    - '37'
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
    - name: Configure VPN autokey tunnel.
      fortinet.fmgdevice.fmgd_vpn_ipsec_phase2:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_ipsec_phase2:
          name: "your value" # Required variable, string
          # add_route: <value in [disable, enable, phase1]>
          # auto_negotiate: <value in [disable, enable]>
          # comments: <string>
          # dhcp_ipsec: <value in [disable, enable]>
          # dhgrp:
          #   - "1"
          #   - "2"
          #   - "5"
          #   - "14"
          #   - "15"
          #   - "16"
          #   - "17"
          #   - "18"
          #   - "19"
          #   - "20"
          #   - "21"
          #   - "27"
          #   - "28"
          #   - "29"
          #   - "30"
          #   - "31"
          #   - "32"
          # diffserv: <value in [disable, enable]>
          # diffservcode: <string>
          # dst_addr_type: <value in [subnet, range, ip, ...]>
          # dst_end_ip: <string>
          # dst_end_ip6: <string>
          # dst_name: <list or string>
          # dst_name6: <list or string>
          # dst_port: <integer>
          # dst_start_ip: <string>
          # dst_start_ip6: <string>
          # dst_subnet: <list or string>
          # dst_subnet6: <string>
          # encapsulation: <value in [tunnel-mode, transport-mode]>
          # inbound_dscp_copy: <value in [disable, enable, phase1]>
          # initiator_ts_narrow: <value in [disable, enable]>
          # ipv4_df: <value in [disable, enable]>
          # keepalive: <value in [disable, enable]>
          # keylife_type: <value in [seconds, kbs, both]>
          # keylifekbs: <integer>
          # keylifeseconds: <integer>
          # l2tp: <value in [disable, enable]>
          # pfs: <value in [disable, enable]>
          # phase1name: <list or string>
          # proposal: <value in [null-md5, null-sha1, des-null, ...]>
          # protocol: <integer>
          # replay: <value in [disable, enable]>
          # route_overlap: <value in [use-old, use-new, allow]>
          # selector_match: <value in [auto, subset, exact]>
          # single_source: <value in [disable, enable]>
          # src_addr_type: <value in [subnet, range, ip, ...]>
          # src_end_ip: <string>
          # src_end_ip6: <string>
          # src_name: <list or string>
          # src_name6: <list or string>
          # src_port: <integer>
          # src_start_ip: <string>
          # src_start_ip6: <string>
          # src_subnet: <list or string>
          # src_subnet6: <string>
          # use_natip: <value in [disable, enable]>
          # addke1:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke2:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke3:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke4:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke5:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke6:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
          # addke7:
          #   - "0"
          #   - "1080"
          #   - "1081"
          #   - "1082"
          #   - "1083"
          #   - "1084"
          #   - "1085"
          #   - "1089"
          #   - "1090"
          #   - "1091"
          #   - "1092"
          #   - "1093"
          #   - "1094"
          #   - "35"
          #   - "36"
          #   - "37"
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_ipsec_phase2': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'add-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'phase1'], 'type': 'str'},
                'auto-negotiate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dhcp-ipsec': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhgrp': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31', '32'],
                    'elements': 'str'
                },
                'diffserv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-addr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['subnet', 'range', 'ip', 'name'], 'type': 'str'},
                'dst-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-end-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dst-name6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dst-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dst-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-start-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dst-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dst-subnet6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'encapsulation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['tunnel-mode', 'transport-mode'], 'type': 'str'},
                'inbound-dscp-copy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'phase1'], 'type': 'str'},
                'initiator-ts-narrow': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv4-df': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'keepalive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'keylife-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['seconds', 'kbs', 'both'], 'type': 'str'},
                'keylifekbs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'keylifeseconds': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'l2tp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'pfs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'phase1name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'proposal': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'null-md5', 'null-sha1', 'des-null', '3des-null', 'des-md5', 'des-sha1', '3des-md5', '3des-sha1', 'aes128-md5', 'aes128-sha1',
                        'aes192-md5', 'aes192-sha1', 'aes256-md5', 'aes256-sha1', 'aes128-null', 'aes192-null', 'aes256-null', 'null-sha256',
                        'des-sha256', '3des-sha256', 'aes128-sha256', 'aes192-sha256', 'aes256-sha256', 'des-sha384', 'des-sha512', '3des-sha384',
                        '3des-sha512', 'aes128-sha384', 'aes128-sha512', 'aes192-sha384', 'aes192-sha512', 'aes256-sha384', 'aes256-sha512',
                        'null-sha384', 'null-sha512', 'aria128-null', 'aria128-md5', 'aria128-sha1', 'aria128-sha256', 'aria128-sha384',
                        'aria128-sha512', 'aria192-null', 'aria192-md5', 'aria192-sha1', 'aria192-sha256', 'aria192-sha384', 'aria192-sha512',
                        'aria256-null', 'aria256-md5', 'aria256-sha1', 'aria256-sha256', 'aria256-sha384', 'aria256-sha512', 'seed-null', 'seed-md5',
                        'seed-sha1', 'seed-sha256', 'seed-sha384', 'seed-sha512', 'aes128gcm', 'aes256gcm', 'chacha20poly1305'
                    ],
                    'type': 'str'
                },
                'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'replay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-overlap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['use-old', 'use-new', 'allow'], 'type': 'str'},
                'selector-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'subset', 'exact'], 'type': 'str'},
                'single-source': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'src-addr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['subnet', 'range', 'ip', 'name'], 'type': 'str'},
                'src-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'src-end-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'src-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-name6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'src-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'src-start-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'src-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-subnet6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'use-natip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'addke1': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke2': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke3': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke4': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke5': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke6': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                },
                'addke7': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'choices': ['0', '1080', '1081', '1082', '1083', '1084', '1085', '1089', '1090', '1091', '1092', '1093', '1094', '35', '36', '37'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ipsec_phase2'),
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
