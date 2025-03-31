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
module: fmgd_loadbalance_setting
short_description: load balance setting
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
    loadbalance_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            base_ctrl_interface_mode:
                aliases: ['base-ctrl-interface-mode']
                type: int
                description: Operating mode when multiple interfaces are configured
            base_ctrl_network:
                aliases: ['base-ctrl-network']
                type: list
                elements: str
                description: Subnet to use for cluster syncronization and control
            base_mgmt_allowaccess:
                aliases: ['base-mgmt-allowaccess']
                type: list
                elements: str
                description: Management protocols allowed on mgmt-external-ip
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
                    - 'fgfm'
            base_mgmt_interface_mode:
                aliases: ['base-mgmt-interface-mode']
                type: int
                description: Operating mode when multiple interfaces are configured
            base_mgmt_internal_mac:
                aliases: ['base-mgmt-internal-mac']
                type: str
                description: MAC address for internal management communication on base channel
            base_mgmt_internal_network:
                aliases: ['base-mgmt-internal-network']
                type: list
                elements: str
                description: Subnet to use for internal management communication on the base channel
            board_init_holddown:
                aliases: ['board-init-holddown']
                type: int
                description: Delay before assuming a board is ready for traffic when a board is added into the cluster
            dp_esp_session:
                aliases: ['dp-esp-session']
                type: str
                description: Enable/Disable DP ESP session setup.
                choices:
                    - 'disable'
                    - 'enable'
            dp_fragment_session:
                aliases: ['dp-fragment-session']
                type: str
                description: Enable/Disable DP fragment session setup.
                choices:
                    - 'disable'
                    - 'enable'
            dp_gre_session:
                aliases: ['dp-gre-session']
                type: str
                description: Enable/Disable DP GRE session setup.
                choices:
                    - 'disable'
                    - 'enable'
            dp_icmp_distribution_method:
                aliases: ['dp-icmp-distribution-method']
                type: str
                description: DP distribution method for ICMP
                choices:
                    - 'to-master'
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
                    - 'derived'
                    - 'to-primary'
            dp_ipsec_session:
                aliases: ['dp-ipsec-session']
                type: str
                description: Enable/Disable DP IPSec session setup.
                choices:
                    - 'disable'
                    - 'forward-to-master'
            dp_keep_assist_sessions:
                aliases: ['dp-keep-assist-sessions']
                type: str
                description: Enable/Disable DP keep assist setup sessions.
                choices:
                    - 'disable'
                    - 'enable'
            dp_load_distribution_method:
                aliases: ['dp-load-distribution-method']
                type: str
                description: DP load distribution method.
                choices:
                    - 'round-robin'
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
                    - 'src-ip-sport'
                    - 'dst-ip-dport'
                    - 'src-dst-ip-sport-dport'
                    - 'to-master'
                    - 'to-primary'
            dp_sctp_session:
                aliases: ['dp-sctp-session']
                type: str
                description: Enable/Disable DP SCTP session setup.
                choices:
                    - 'disable'
                    - 'enable'
            dp_session_helper:
                aliases: ['dp-session-helper']
                type: str
                description: Enable/Disable DP session helper setup.
                choices:
                    - 'disable'
                    - 'enable'
            dp_session_table_type:
                aliases: ['dp-session-table-type']
                type: str
                description: DP session table type
                choices:
                    - 'vdom-based'
                    - 'intf-vlan-based'
            dp_udp_ingress_session:
                aliases: ['dp-udp-ingress-session']
                type: str
                description: Enable/Disable DP UDP ingress session setup.
                choices:
                    - 'disable'
                    - 'enable'
            dp_udp_session:
                aliases: ['dp-udp-session']
                type: str
                description: Enable/Disable DP UDP session setup.
                choices:
                    - 'disable'
                    - 'enable'
            forticontroller_proxy:
                aliases: ['forticontroller-proxy']
                type: str
                description: Enable/Disable forticontroller proxy.
                choices:
                    - 'disable'
                    - 'enable'
            forticontroller_proxy_port:
                aliases: ['forticontroller-proxy-port']
                type: int
                description: Set forticontroller proxy port
            gtp_load_balance:
                aliases: ['gtp-load-balance']
                type: str
                description: Enable/Disable GTP load balance
                choices:
                    - 'disable'
                    - 'enable'
            max_miss_heartbeats:
                aliases: ['max-miss-heartbeats']
                type: int
                description: Number of missed heartbeats before a unit is considered dead
            max_miss_mgmt_heartbeats:
                aliases: ['max-miss-mgmt-heartbeats']
                type: int
                description: Number of missed management heartbeats before a unit is considered dead
            nat_source_port:
                aliases: ['nat-source-port']
                type: str
                description: The NAT source ports will be divided in those slots
                choices:
                    - 'chassis-slots'
                    - 'enabled-slots'
            pfcp_load_balance:
                aliases: ['pfcp-load-balance']
                type: str
                description: Enable/Disable PFCP load balance
                choices:
                    - 'disable'
                    - 'enable'
            slbc_mgmt_intf:
                aliases: ['slbc-mgmt-intf']
                type: str
                description: Interface for slbc management.
            sslvpn_load_balance:
                aliases: ['sslvpn-load-balance']
                type: str
                description: Enable/Disable SSL VPN load balance
                choices:
                    - 'disable'
                    - 'enable'
            standby_override:
                aliases: ['standby-override']
                type: int
                description: Allow active units to immediately replace running standby units
            status:
                type: str
                description: Enable/disable Load Balance.
                choices:
                    - 'disable'
                    - 'enable'
            sw_load_distribution_method:
                aliases: ['sw-load-distribution-method']
                type: str
                description: Switch load distribution method.
                choices:
                    - 'src-dst-ip'
                    - 'src-dst-ip-sport-dport'
            weighted_load_balance:
                aliases: ['weighted-load-balance']
                type: str
                description: Enable/Disable weighted load balance
                choices:
                    - 'disable'
                    - 'enable'
            workers:
                type: list
                elements: dict
                description: Workers.
                suboptions:
                    slot:
                        type: int
                        description: Slot number
                    status:
                        type: str
                        description: Enable/disable this worker.
                        choices:
                            - 'disable'
                            - 'enable'
                    weight:
                        type: int
                        description: Load balancing weight
            neighbor_entry_sync:
                aliases: ['neighbor-entry-sync']
                type: str
                description: Enable/Disable neighbor entry sync
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_load_balance:
                aliases: ['ipsec-load-balance']
                type: str
                description: Ipsec load balance.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Load balance setting
      fortinet.fmgdevice.fmgd_loadbalance_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        loadbalance_setting:
          # base_ctrl_interface_mode: <integer>
          # base_ctrl_network: <list or string>
          # base_mgmt_allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          #   - "fgfm"
          # base_mgmt_interface_mode: <integer>
          # base_mgmt_internal_mac: <string>
          # base_mgmt_internal_network: <list or string>
          # board_init_holddown: <integer>
          # dp_esp_session: <value in [disable, enable]>
          # dp_fragment_session: <value in [disable, enable]>
          # dp_gre_session: <value in [disable, enable]>
          # dp_icmp_distribution_method: <value in [to-master, src-ip, dst-ip, ...]>
          # dp_ipsec_session: <value in [disable, forward-to-master]>
          # dp_keep_assist_sessions: <value in [disable, enable]>
          # dp_load_distribution_method: <value in [round-robin, src-ip, dst-ip, ...]>
          # dp_sctp_session: <value in [disable, enable]>
          # dp_session_helper: <value in [disable, enable]>
          # dp_session_table_type: <value in [vdom-based, intf-vlan-based]>
          # dp_udp_ingress_session: <value in [disable, enable]>
          # dp_udp_session: <value in [disable, enable]>
          # forticontroller_proxy: <value in [disable, enable]>
          # forticontroller_proxy_port: <integer>
          # gtp_load_balance: <value in [disable, enable]>
          # max_miss_heartbeats: <integer>
          # max_miss_mgmt_heartbeats: <integer>
          # nat_source_port: <value in [chassis-slots, enabled-slots]>
          # pfcp_load_balance: <value in [disable, enable]>
          # slbc_mgmt_intf: <string>
          # sslvpn_load_balance: <value in [disable, enable]>
          # standby_override: <integer>
          # status: <value in [disable, enable]>
          # sw_load_distribution_method: <value in [src-dst-ip, src-dst-ip-sport-dport]>
          # weighted_load_balance: <value in [disable, enable]>
          # workers:
          #   - slot: <integer>
          #     status: <value in [disable, enable]>
          #     weight: <integer>
          # neighbor_entry_sync: <value in [disable, enable]>
          # ipsec_load_balance: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/load-balance/setting'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'loadbalance_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'base-ctrl-interface-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'base-ctrl-network': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'base-mgmt-allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet', 'fgfm'],
                    'elements': 'str'
                },
                'base-mgmt-interface-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'base-mgmt-internal-mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'base-mgmt-internal-network': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'board-init-holddown': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dp-esp-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-fragment-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-gre-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-icmp-distribution-method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['to-master', 'src-ip', 'dst-ip', 'src-dst-ip', 'derived', 'to-primary'],
                    'type': 'str'
                },
                'dp-ipsec-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'forward-to-master'], 'type': 'str'},
                'dp-keep-assist-sessions': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-load-distribution-method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'round-robin', 'src-ip', 'dst-ip', 'src-dst-ip', 'src-ip-sport', 'dst-ip-dport', 'src-dst-ip-sport-dport', 'to-master',
                        'to-primary'
                    ],
                    'type': 'str'
                },
                'dp-sctp-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-session-helper': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-session-table-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['vdom-based', 'intf-vlan-based'], 'type': 'str'},
                'dp-udp-ingress-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dp-udp-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticontroller-proxy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forticontroller-proxy-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'gtp-load-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-miss-heartbeats': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-miss-mgmt-heartbeats': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nat-source-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['chassis-slots', 'enabled-slots'], 'type': 'str'},
                'pfcp-load-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'slbc-mgmt-intf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sslvpn-load-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'standby-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sw-load-distribution-method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['src-dst-ip', 'src-dst-ip-sport-dport'],
                    'type': 'str'
                },
                'weighted-load-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'workers': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'slot': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'neighbor-entry-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-load-balance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'loadbalance_setting'),
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
