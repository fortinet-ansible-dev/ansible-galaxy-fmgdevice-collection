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
module: fmgd_wireless_global
short_description: Configure wireless controller global settings.
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
    wireless_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            acd_process_count:
                aliases: ['acd-process-count']
                type: int
                description: Configure the number cw_acd daemons for multi-core CPU support
            ap_log_server:
                aliases: ['ap-log-server']
                type: str
                description: Enable/disable configuring FortiGate to redirect wireless event log messages or FortiAPs to send UTM log messages to a sys...
                choices:
                    - 'disable'
                    - 'enable'
            ap_log_server_ip:
                aliases: ['ap-log-server-ip']
                type: str
                description: IP address that FortiGate or FortiAPs send log messages to.
            ap_log_server_port:
                aliases: ['ap-log-server-port']
                type: int
                description: Port that FortiGate or FortiAPs send log messages to.
            control_message_offload:
                aliases: ['control-message-offload']
                type: list
                elements: str
                description: Configure CAPWAP control message data channel offload.
                choices:
                    - 'ebp-frame'
                    - 'aeroscout-tag'
                    - 'ap-list'
                    - 'sta-list'
                    - 'sta-cap-list'
                    - 'stats'
                    - 'aeroscout-mu'
                    - 'sta-health'
                    - 'spectral-analysis'
            data_ethernet_II:
                aliases: ['data-ethernet-II']
                type: str
                description: Configure the wireless controller to use Ethernet II or 802.
                choices:
                    - 'disable'
                    - 'enable'
            dfs_lab_test:
                aliases: ['dfs-lab-test']
                type: str
                description: Enable/disable DFS certificate lab test mode.
                choices:
                    - 'disable'
                    - 'enable'
            discovery_mc_addr:
                aliases: ['discovery-mc-addr']
                type: str
                description: Multicast IP address for AP discovery
            fiapp_eth_type:
                aliases: ['fiapp-eth-type']
                type: int
                description: Ethernet type for Fortinet Inter-Access Point Protocol
            image_download:
                aliases: ['image-download']
                type: str
                description: Enable/disable WTP image download at join time.
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_base_ip:
                aliases: ['ipsec-base-ip']
                type: str
                description: Base IP address for IPsec VPN tunnels between the access points and the wireless controller
            link_aggregation:
                aliases: ['link-aggregation']
                type: str
                description: Enable/disable calculating the CAPWAP transmit hash to load balance sessions to link aggregation nodes
                choices:
                    - 'disable'
                    - 'enable'
            local_radio_vdom:
                aliases: ['local-radio-vdom']
                type: list
                elements: str
                description: Assign local radios virtual domain.
            location:
                type: str
                description: Description of the location of the wireless controller.
            max_ble_device:
                aliases: ['max-ble-device']
                type: int
                description: Maximum number of BLE devices stored on the controller
            max_clients:
                aliases: ['max-clients']
                type: int
                description: Maximum number of clients that can connect simultaneously
            max_retransmit:
                aliases: ['max-retransmit']
                type: int
                description: Maximum number of tunnel packet retransmissions
            max_rogue_ap:
                aliases: ['max-rogue-ap']
                type: int
                description: Maximum number of rogue APs stored on the controller
            max_rogue_ap_wtp:
                aliases: ['max-rogue-ap-wtp']
                type: int
                description: Maximum number of rogue APs wtp info stored on the controller
            max_rogue_sta:
                aliases: ['max-rogue-sta']
                type: int
                description: Maximum number of rogue stations stored on the controller
            max_sta_cap:
                aliases: ['max-sta-cap']
                type: int
                description: Maximum number of station cap stored on the controller
            max_sta_cap_wtp:
                aliases: ['max-sta-cap-wtp']
                type: int
                description: Maximum number of station caps wtp info stored on the controller
            mesh_eth_type:
                aliases: ['mesh-eth-type']
                type: int
                description: Mesh Ethernet identifier included in backhaul packets
            nac_interval:
                aliases: ['nac-interval']
                type: int
                description: Interval in seconds between two WiFi network access control
            name:
                type: str
                description: Name of the wireless controller.
            rogue_scan_mac_adjacency:
                aliases: ['rogue-scan-mac-adjacency']
                type: int
                description: Maximum numerical difference between an APs Ethernet and wireless MAC values to match for rogue detection
            rolling_wtp_upgrade:
                aliases: ['rolling-wtp-upgrade']
                type: str
                description: Enable/disable rolling WTP upgrade
                choices:
                    - 'disable'
                    - 'enable'
            rolling_wtp_upgrade_threshold:
                aliases: ['rolling-wtp-upgrade-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the managed WTP to be included in rolling WTP upgrade
            tunnel_mode:
                aliases: ['tunnel-mode']
                type: str
                description: Compatible/strict tunnel mode.
                choices:
                    - 'compatible'
                    - 'strict'
            wpad_process_count:
                aliases: ['wpad-process-count']
                type: int
                description: Wpad daemon process count for multi-core CPU support.
            wtp_share:
                aliases: ['wtp-share']
                type: str
                description: Enable/disable sharing of WTPs between VDOMs.
                choices:
                    - 'disable'
                    - 'enable'
            max_wids_entry:
                aliases: ['max-wids-entry']
                type: int
                description: Maximum number of wids entries stored on the controller
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
    - name: Configure wireless controller global settings.
      fortinet.fmgdevice.fmgd_wireless_global:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        wireless_global:
          # acd_process_count: <integer>
          # ap_log_server: <value in [disable, enable]>
          # ap_log_server_ip: <string>
          # ap_log_server_port: <integer>
          # control_message_offload:
          #   - "ebp-frame"
          #   - "aeroscout-tag"
          #   - "ap-list"
          #   - "sta-list"
          #   - "sta-cap-list"
          #   - "stats"
          #   - "aeroscout-mu"
          #   - "sta-health"
          #   - "spectral-analysis"
          # data_ethernet_II: <value in [disable, enable]>
          # dfs_lab_test: <value in [disable, enable]>
          # discovery_mc_addr: <string>
          # fiapp_eth_type: <integer>
          # image_download: <value in [disable, enable]>
          # ipsec_base_ip: <string>
          # link_aggregation: <value in [disable, enable]>
          # local_radio_vdom: <list or string>
          # location: <string>
          # max_ble_device: <integer>
          # max_clients: <integer>
          # max_retransmit: <integer>
          # max_rogue_ap: <integer>
          # max_rogue_ap_wtp: <integer>
          # max_rogue_sta: <integer>
          # max_sta_cap: <integer>
          # max_sta_cap_wtp: <integer>
          # mesh_eth_type: <integer>
          # nac_interval: <integer>
          # name: <string>
          # rogue_scan_mac_adjacency: <integer>
          # rolling_wtp_upgrade: <value in [disable, enable]>
          # rolling_wtp_upgrade_threshold: <string>
          # tunnel_mode: <value in [compatible, strict]>
          # wpad_process_count: <integer>
          # wtp_share: <value in [disable, enable]>
          # max_wids_entry: <integer>
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
        '/pm/config/device/{device}/global/wireless-controller/global'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'wireless_global': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'acd-process-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ap-log-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ap-log-server-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ap-log-server-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'control-message-offload': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'ebp-frame', 'aeroscout-tag', 'ap-list', 'sta-list', 'sta-cap-list', 'stats', 'aeroscout-mu', 'sta-health', 'spectral-analysis'
                    ],
                    'elements': 'str'
                },
                'data-ethernet-II': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dfs-lab-test': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'discovery-mc-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fiapp-eth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'image-download': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-base-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'link-aggregation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-radio-vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'location': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'max-ble-device': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'max-clients': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-retransmit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-rogue-ap': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'max-rogue-ap-wtp': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'max-rogue-sta': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'max-sta-cap': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'max-sta-cap-wtp': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'mesh-eth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nac-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'rogue-scan-mac-adjacency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rolling-wtp-upgrade': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rolling-wtp-upgrade-threshold': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'tunnel-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['compatible', 'strict'], 'type': 'str'},
                'wpad-process-count': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'wtp-share': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-wids-entry': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_global'),
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
