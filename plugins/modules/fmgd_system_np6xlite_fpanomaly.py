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
module: fmgd_system_np6xlite_fpanomaly
short_description: NP6XLITE IPv4 anomaly protection.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  np6xlite:
    description: The parameter (np6xlite) in requested url.
    type: str
    required: true
  system_np6xlite_fpanomaly:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      icmp_csum_err:
        aliases: ['icmp-csum-err']
        type: str
        description: Invalid IPv4 ICMP checksum anomalies.
        choices: ['drop', 'trap-to-host']
      icmp_frag:
        aliases: ['icmp-frag']
        type: str
        description: Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      icmp_land:
        aliases: ['icmp-land']
        type: str
        description: ICMP land anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_csum_err:
        aliases: ['ipv4-csum-err']
        type: str
        description: Invalid IPv4 IP checksum anomalies.
        choices: ['drop', 'trap-to-host']
      ipv4_land:
        aliases: ['ipv4-land']
        type: str
        description: Land anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_optlsrr:
        aliases: ['ipv4-optlsrr']
        type: str
        description: Loose source record route option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_optrr:
        aliases: ['ipv4-optrr']
        type: str
        description: Record route option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_optsecurity:
        aliases: ['ipv4-optsecurity']
        type: str
        description: Security option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_optssrr:
        aliases: ['ipv4-optssrr']
        type: str
        description: Strict source record route option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_optstream:
        aliases: ['ipv4-optstream']
        type: str
        description: Stream option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_opttimestamp:
        aliases: ['ipv4-opttimestamp']
        type: str
        description: Timestamp option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_proto_err:
        aliases: ['ipv4-proto-err']
        type: str
        description: Invalid layer 4 protocol anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv4_unknopt:
        aliases: ['ipv4-unknopt']
        type: str
        description: Unknown option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_daddr_err:
        aliases: ['ipv6-daddr-err']
        type: str
        description: Destination address as unspecified or loopback address anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_land:
        aliases: ['ipv6-land']
        type: str
        description: Land anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_optendpid:
        aliases: ['ipv6-optendpid']
        type: str
        description: End point identification anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_opthomeaddr:
        aliases: ['ipv6-opthomeaddr']
        type: str
        description: Home address option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_optinvld:
        aliases: ['ipv6-optinvld']
        type: str
        description: Invalid option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_optjumbo:
        aliases: ['ipv6-optjumbo']
        type: str
        description: Jumbo options anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_optnsap:
        aliases: ['ipv6-optnsap']
        type: str
        description: Network service access point address option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_optralert:
        aliases: ['ipv6-optralert']
        type: str
        description: Router alert option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_opttunnel:
        aliases: ['ipv6-opttunnel']
        type: str
        description: Tunnel encapsulation limit option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_proto_err:
        aliases: ['ipv6-proto-err']
        type: str
        description: Layer 4 invalid protocol anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_saddr_err:
        aliases: ['ipv6-saddr-err']
        type: str
        description: Source address as multicast anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      ipv6_unknopt:
        aliases: ['ipv6-unknopt']
        type: str
        description: Unknown option anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_csum_err:
        aliases: ['tcp-csum-err']
        type: str
        description: Invalid IPv4 TCP checksum anomalies.
        choices: ['drop', 'trap-to-host']
      tcp_fin_noack:
        aliases: ['tcp-fin-noack']
        type: str
        description: TCP SYN flood with FIN flag set without ACK setting anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_fin_only:
        aliases: ['tcp-fin-only']
        type: str
        description: TCP SYN flood with only FIN flag set anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_land:
        aliases: ['tcp-land']
        type: str
        description: TCP land anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_no_flag:
        aliases: ['tcp-no-flag']
        type: str
        description: TCP SYN flood with no flag set anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_syn_data:
        aliases: ['tcp-syn-data']
        type: str
        description: TCP SYN flood packets with data anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_syn_fin:
        aliases: ['tcp-syn-fin']
        type: str
        description: TCP SYN flood SYN/FIN flag set anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      tcp_winnuke:
        aliases: ['tcp-winnuke']
        type: str
        description: TCP WinNuke anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
      udp_csum_err:
        aliases: ['udp-csum-err']
        type: str
        description: Invalid IPv4 UDP checksum anomalies.
        choices: ['drop', 'trap-to-host']
      udp_land:
        aliases: ['udp-land']
        type: str
        description: UDP land anomalies.
        choices: ['allow', 'drop', 'trap-to-host']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: NP6XLITE IPv4 anomaly protection.
      fortinet.fmgdevice.fmgd_system_np6xlite_fpanomaly:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        np6xlite: <your own value>
        system_np6xlite_fpanomaly:
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
        '/pm/config/device/{device}/global/system/np6xlite/{np6xlite}/fp-anomaly'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'np6xlite': {'required': True, 'type': 'str'},
        'system_np6xlite_fpanomaly': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'icmp-csum-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'icmp-frag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'icmp-land': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-csum-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-land': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optlsrr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optrr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optsecurity': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optssrr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-optstream': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-opttimestamp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-proto-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv4-unknopt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-daddr-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-land': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optendpid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opthomeaddr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optinvld': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optjumbo': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optnsap': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-optralert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-opttunnel': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-proto-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-saddr-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'ipv6-unknopt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-csum-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-noack': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-fin-only': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-land': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-no-flag': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-data': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-syn-fin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'tcp-winnuke': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                'udp-csum-err': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                'udp-land': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_np6xlite_fpanomaly'),
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
