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
module: fmgd_system_np6_fpanomaly
short_description: NP6 IPv4 anomaly protection.
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
    np6:
        description: The parameter (np6) in requested url.
        type: str
        required: true
    system_np6_fpanomaly:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            icmp_csum_err:
                aliases: ['icmp-csum-err']
                type: str
                description: Invalid IPv4 ICMP checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            icmp_frag:
                aliases: ['icmp-frag']
                type: str
                description: Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            icmp_land:
                aliases: ['icmp-land']
                type: str
                description: ICMP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_csum_err:
                aliases: ['ipv4-csum-err']
                type: str
                description: Invalid IPv4 IP checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            ipv4_land:
                aliases: ['ipv4-land']
                type: str
                description: Land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optlsrr:
                aliases: ['ipv4-optlsrr']
                type: str
                description: Loose source record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optrr:
                aliases: ['ipv4-optrr']
                type: str
                description: Record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optsecurity:
                aliases: ['ipv4-optsecurity']
                type: str
                description: Security option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optssrr:
                aliases: ['ipv4-optssrr']
                type: str
                description: Strict source record route option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_optstream:
                aliases: ['ipv4-optstream']
                type: str
                description: Stream option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_opttimestamp:
                aliases: ['ipv4-opttimestamp']
                type: str
                description: Timestamp option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_proto_err:
                aliases: ['ipv4-proto-err']
                type: str
                description: Invalid layer 4 protocol anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv4_unknopt:
                aliases: ['ipv4-unknopt']
                type: str
                description: Unknown option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_daddr_err:
                aliases: ['ipv6-daddr-err']
                type: str
                description: Destination address as unspecified or loopback address anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_land:
                aliases: ['ipv6-land']
                type: str
                description: Land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optendpid:
                aliases: ['ipv6-optendpid']
                type: str
                description: End point identification anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_opthomeaddr:
                aliases: ['ipv6-opthomeaddr']
                type: str
                description: Home address option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optinvld:
                aliases: ['ipv6-optinvld']
                type: str
                description: Invalid option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optjumbo:
                aliases: ['ipv6-optjumbo']
                type: str
                description: Jumbo options anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optnsap:
                aliases: ['ipv6-optnsap']
                type: str
                description: Network service access point address option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_optralert:
                aliases: ['ipv6-optralert']
                type: str
                description: Router alert option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_opttunnel:
                aliases: ['ipv6-opttunnel']
                type: str
                description: Tunnel encapsulation limit option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_proto_err:
                aliases: ['ipv6-proto-err']
                type: str
                description: Layer 4 invalid protocol anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_saddr_err:
                aliases: ['ipv6-saddr-err']
                type: str
                description: Source address as multicast anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            ipv6_unknopt:
                aliases: ['ipv6-unknopt']
                type: str
                description: Unknown option anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_csum_err:
                aliases: ['tcp-csum-err']
                type: str
                description: Invalid IPv4 TCP checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            tcp_fin_noack:
                aliases: ['tcp-fin-noack']
                type: str
                description: TCP SYN flood with FIN flag set without ACK setting anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_fin_only:
                aliases: ['tcp-fin-only']
                type: str
                description: TCP SYN flood with only FIN flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_land:
                aliases: ['tcp-land']
                type: str
                description: TCP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_no_flag:
                aliases: ['tcp-no-flag']
                type: str
                description: TCP SYN flood with no flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_syn_data:
                aliases: ['tcp-syn-data']
                type: str
                description: TCP SYN flood packets with data anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_syn_fin:
                aliases: ['tcp-syn-fin']
                type: str
                description: TCP SYN flood SYN/FIN flag set anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            tcp_winnuke:
                aliases: ['tcp-winnuke']
                type: str
                description: TCP WinNuke anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
            udp_csum_err:
                aliases: ['udp-csum-err']
                type: str
                description: Invalid IPv4 UDP checksum anomalies.
                choices:
                    - 'drop'
                    - 'trap-to-host'
            udp_land:
                aliases: ['udp-land']
                type: str
                description: UDP land anomalies.
                choices:
                    - 'allow'
                    - 'drop'
                    - 'trap-to-host'
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
    - name: NP6 IPv4 anomaly protection.
      fortinet.fmgdevice.fmgd_system_np6_fpanomaly:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        np6: <your own value>
        system_np6_fpanomaly:
          # icmp_csum_err: <value in [drop, trap-to-host]>
          # icmp_frag: <value in [allow, drop, trap-to-host]>
          # icmp_land: <value in [allow, drop, trap-to-host]>
          # ipv4_csum_err: <value in [drop, trap-to-host]>
          # ipv4_land: <value in [allow, drop, trap-to-host]>
          # ipv4_optlsrr: <value in [allow, drop, trap-to-host]>
          # ipv4_optrr: <value in [allow, drop, trap-to-host]>
          # ipv4_optsecurity: <value in [allow, drop, trap-to-host]>
          # ipv4_optssrr: <value in [allow, drop, trap-to-host]>
          # ipv4_optstream: <value in [allow, drop, trap-to-host]>
          # ipv4_opttimestamp: <value in [allow, drop, trap-to-host]>
          # ipv4_proto_err: <value in [allow, drop, trap-to-host]>
          # ipv4_unknopt: <value in [allow, drop, trap-to-host]>
          # ipv6_daddr_err: <value in [allow, drop, trap-to-host]>
          # ipv6_land: <value in [allow, drop, trap-to-host]>
          # ipv6_optendpid: <value in [allow, drop, trap-to-host]>
          # ipv6_opthomeaddr: <value in [allow, drop, trap-to-host]>
          # ipv6_optinvld: <value in [allow, drop, trap-to-host]>
          # ipv6_optjumbo: <value in [allow, drop, trap-to-host]>
          # ipv6_optnsap: <value in [allow, drop, trap-to-host]>
          # ipv6_optralert: <value in [allow, drop, trap-to-host]>
          # ipv6_opttunnel: <value in [allow, drop, trap-to-host]>
          # ipv6_proto_err: <value in [allow, drop, trap-to-host]>
          # ipv6_saddr_err: <value in [allow, drop, trap-to-host]>
          # ipv6_unknopt: <value in [allow, drop, trap-to-host]>
          # tcp_csum_err: <value in [drop, trap-to-host]>
          # tcp_fin_noack: <value in [allow, drop, trap-to-host]>
          # tcp_fin_only: <value in [allow, drop, trap-to-host]>
          # tcp_land: <value in [allow, drop, trap-to-host]>
          # tcp_no_flag: <value in [allow, drop, trap-to-host]>
          # tcp_syn_data: <value in [allow, drop, trap-to-host]>
          # tcp_syn_fin: <value in [allow, drop, trap-to-host]>
          # tcp_winnuke: <value in [allow, drop, trap-to-host]>
          # udp_csum_err: <value in [drop, trap-to-host]>
          # udp_land: <value in [allow, drop, trap-to-host]>
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
        '/pm/config/device/{device}/global/system/np6/{np6}/fp-anomaly'
    ]
    url_params = ['device', 'np6']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'np6': {'required': True, 'type': 'str'},
        'system_np6_fpanomaly': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'icmp-csum-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'icmp-frag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'icmp-land': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-csum-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-land': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optlsrr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optrr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optsecurity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optssrr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optstream': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-opttimestamp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-proto-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-unknopt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-daddr-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-land': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optendpid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opthomeaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optinvld': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optjumbo': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optnsap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optralert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opttunnel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-proto-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-saddr-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-unknopt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-csum-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-noack': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-only': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-land': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-no-flag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-data': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-fin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-winnuke': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'udp-csum-err': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-land': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_np6_fpanomaly'),
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
