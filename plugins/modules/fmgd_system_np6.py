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
module: fmgd_system_np6
short_description: Configure NP6 attributes.
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
    system_np6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fastpath:
                type: str
                description: Enable/disable NP6 offloading
                choices:
                    - 'disable'
                    - 'enable'
            fp_anomaly:
                aliases: ['fp-anomaly']
                type: dict
                description: Fp anomaly.
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
            garbage_session_collector:
                aliases: ['garbage-session-collector']
                type: str
                description: Enable/disable garbage session collector.
                choices:
                    - 'disable'
                    - 'enable'
            hpe:
                type: dict
                description: Hpe.
                suboptions:
                    arp_max:
                        aliases: ['arp-max']
                        type: int
                        description: Maximum ARP packet rate
                    enable_shaper:
                        aliases: ['enable-shaper']
                        type: str
                        description: Enable/Disable NPU Host Protection Engine
                        choices:
                            - 'disable'
                            - 'enable'
                    esp_max:
                        aliases: ['esp-max']
                        type: int
                        description: Maximum ESP packet rate
                    icmp_max:
                        aliases: ['icmp-max']
                        type: int
                        description: Maximum ICMP packet rate
                    ip_frag_max:
                        aliases: ['ip-frag-max']
                        type: int
                        description: Maximum fragmented IP packet rate
                    ip_others_max:
                        aliases: ['ip-others-max']
                        type: int
                        description: Maximum IP packet rate for other packets
                    l2_others_max:
                        aliases: ['l2-others-max']
                        type: int
                        description: Maximum L2 packet rate for L2 packets that are not ARP packets
                    pri_type_max:
                        aliases: ['pri-type-max']
                        type: int
                        description: Maximum overflow rate of priority type traffic
                    sctp_max:
                        aliases: ['sctp-max']
                        type: int
                        description: Maximum SCTP packet rate
                    tcp_max:
                        aliases: ['tcp-max']
                        type: int
                        description: Maximum TCP packet rate
                    tcpfin_rst_max:
                        aliases: ['tcpfin-rst-max']
                        type: int
                        description: Maximum TCP carries FIN or RST flags packet rate
                    tcpsyn_ack_max:
                        aliases: ['tcpsyn-ack-max']
                        type: int
                        description: Maximum TCP carries SYN and ACK flags packet rate
                    tcpsyn_max:
                        aliases: ['tcpsyn-max']
                        type: int
                        description: Maximum TCP SYN packet rate
                    udp_max:
                        aliases: ['udp-max']
                        type: int
                        description: Maximum UDP packet rate
            ipsec_ob_hash_function:
                aliases: ['ipsec-ob-hash-function']
                type: str
                description: Set hash function for IPSec outbound.
                choices:
                    - 'global-hash'
                    - 'round-robin-global'
                    - 'switch-group-hash'
                    - 'global-hash-weighted'
                    - 'round-robin-switch-group'
            ipsec_outbound_hash:
                aliases: ['ipsec-outbound-hash']
                type: str
                description: Enable/disable hash function for IPsec outbound traffic.
                choices:
                    - 'disable'
                    - 'enable'
            low_latency_mode:
                aliases: ['low-latency-mode']
                type: str
                description: Enable/disable low latency mode.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Device Name.
                required: true
            per_session_accounting:
                aliases: ['per-session-accounting']
                type: str
                description: Enable/disable per-session accounting.
                choices:
                    - 'enable'
                    - 'disable'
                    - 'enable-by-log'
                    - 'all-enable'
                    - 'traffic-log-only'
            session_collector_interval:
                aliases: ['session-collector-interval']
                type: int
                description: Set garbage session collection cleanup interval
            session_timeout_fixed:
                aliases: ['session-timeout-fixed']
                type: str
                description: No description
                choices:
                    - 'disable'
                    - 'enable'
            session_timeout_interval:
                aliases: ['session-timeout-interval']
                type: int
                description: Set the fixed timeout for refreshing NP6 sessions
            session_timeout_random_range:
                aliases: ['session-timeout-random-range']
                type: int
                description: Set the random timeout range for refreshing NP6 sessions
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
    - name: Configure NP6 attributes.
      fortinet.fmgdevice.fmgd_system_np6:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_np6:
          name: "your value" # Required variable, string
          # fastpath: <value in [disable, enable]>
          # fp_anomaly:
          #   icmp_csum_err: <value in [drop, trap-to-host]>
          #   icmp_frag: <value in [allow, drop, trap-to-host]>
          #   icmp_land: <value in [allow, drop, trap-to-host]>
          #   ipv4_csum_err: <value in [drop, trap-to-host]>
          #   ipv4_land: <value in [allow, drop, trap-to-host]>
          #   ipv4_optlsrr: <value in [allow, drop, trap-to-host]>
          #   ipv4_optrr: <value in [allow, drop, trap-to-host]>
          #   ipv4_optsecurity: <value in [allow, drop, trap-to-host]>
          #   ipv4_optssrr: <value in [allow, drop, trap-to-host]>
          #   ipv4_optstream: <value in [allow, drop, trap-to-host]>
          #   ipv4_opttimestamp: <value in [allow, drop, trap-to-host]>
          #   ipv4_proto_err: <value in [allow, drop, trap-to-host]>
          #   ipv4_unknopt: <value in [allow, drop, trap-to-host]>
          #   ipv6_daddr_err: <value in [allow, drop, trap-to-host]>
          #   ipv6_land: <value in [allow, drop, trap-to-host]>
          #   ipv6_optendpid: <value in [allow, drop, trap-to-host]>
          #   ipv6_opthomeaddr: <value in [allow, drop, trap-to-host]>
          #   ipv6_optinvld: <value in [allow, drop, trap-to-host]>
          #   ipv6_optjumbo: <value in [allow, drop, trap-to-host]>
          #   ipv6_optnsap: <value in [allow, drop, trap-to-host]>
          #   ipv6_optralert: <value in [allow, drop, trap-to-host]>
          #   ipv6_opttunnel: <value in [allow, drop, trap-to-host]>
          #   ipv6_proto_err: <value in [allow, drop, trap-to-host]>
          #   ipv6_saddr_err: <value in [allow, drop, trap-to-host]>
          #   ipv6_unknopt: <value in [allow, drop, trap-to-host]>
          #   tcp_csum_err: <value in [drop, trap-to-host]>
          #   tcp_fin_noack: <value in [allow, drop, trap-to-host]>
          #   tcp_fin_only: <value in [allow, drop, trap-to-host]>
          #   tcp_land: <value in [allow, drop, trap-to-host]>
          #   tcp_no_flag: <value in [allow, drop, trap-to-host]>
          #   tcp_syn_data: <value in [allow, drop, trap-to-host]>
          #   tcp_syn_fin: <value in [allow, drop, trap-to-host]>
          #   tcp_winnuke: <value in [allow, drop, trap-to-host]>
          #   udp_csum_err: <value in [drop, trap-to-host]>
          #   udp_land: <value in [allow, drop, trap-to-host]>
          # garbage_session_collector: <value in [disable, enable]>
          # hpe:
          #   arp_max: <integer>
          #   enable_shaper: <value in [disable, enable]>
          #   esp_max: <integer>
          #   icmp_max: <integer>
          #   ip_frag_max: <integer>
          #   ip_others_max: <integer>
          #   l2_others_max: <integer>
          #   pri_type_max: <integer>
          #   sctp_max: <integer>
          #   tcp_max: <integer>
          #   tcpfin_rst_max: <integer>
          #   tcpsyn_ack_max: <integer>
          #   tcpsyn_max: <integer>
          #   udp_max: <integer>
          # ipsec_ob_hash_function: <value in [global-hash, round-robin-global, switch-group-hash, ...]>
          # ipsec_outbound_hash: <value in [disable, enable]>
          # low_latency_mode: <value in [disable, enable]>
          # per_session_accounting: <value in [enable, disable, enable-by-log, ...]>
          # session_collector_interval: <integer>
          # session_timeout_fixed: <value in [disable, enable]>
          # session_timeout_interval: <integer>
          # session_timeout_random_range: <integer>
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
        '/pm/config/device/{device}/global/system/np6'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_np6': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'fastpath': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fp-anomaly': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
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
                },
                'garbage-session-collector': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hpe': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'arp-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'enable-shaper': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'esp-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'icmp-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip-frag-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip-others-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'l2-others-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'pri-type-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'sctp-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'tcp-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'tcpfin-rst-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'tcpsyn-ack-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'tcpsyn-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'udp-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'ipsec-ob-hash-function': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['global-hash', 'round-robin-global', 'switch-group-hash', 'global-hash-weighted', 'round-robin-switch-group'],
                    'type': 'str'
                },
                'ipsec-outbound-hash': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'low-latency-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'per-session-accounting': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['enable', 'disable', 'enable-by-log', 'all-enable', 'traffic-log-only'],
                    'type': 'str'
                },
                'session-collector-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'session-timeout-fixed': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-timeout-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'session-timeout-random-range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_np6'),
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
