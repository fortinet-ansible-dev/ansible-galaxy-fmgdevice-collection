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
module: fmgd_wireless_wtpprofile_lbs
short_description: Set various location based service
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    wtp-profile:
        description: Deprecated, please use "wtp_profile"
        type: str
    wtp_profile:
        description: The parameter (wtp-profile) in requested url.
        type: str
    wireless_wtpprofile_lbs:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            aeroscout:
                type: str
                description: Enable/disable AeroScout Real Time Location Service
                choices:
                    - 'disable'
                    - 'enable'
            aeroscout_ap_mac:
                aliases: ['aeroscout-ap-mac']
                type: str
                description: Use BSSID or board MAC address as AP MAC address in AeroScout AP messages
                choices:
                    - 'bssid'
                    - 'board-mac'
            aeroscout_mmu_report:
                aliases: ['aeroscout-mmu-report']
                type: str
                description: Enable/disable compounded AeroScout tag and MU report
                choices:
                    - 'disable'
                    - 'enable'
            aeroscout_mu:
                aliases: ['aeroscout-mu']
                type: str
                description: Enable/disable AeroScout Mobile Unit
                choices:
                    - 'disable'
                    - 'enable'
            aeroscout_mu_factor:
                aliases: ['aeroscout-mu-factor']
                type: int
                description: AeroScout MU mode dilution factor
            aeroscout_mu_timeout:
                aliases: ['aeroscout-mu-timeout']
                type: int
                description: AeroScout MU mode timeout
            aeroscout_server_ip:
                aliases: ['aeroscout-server-ip']
                type: str
                description: IP address of AeroScout server.
            aeroscout_server_port:
                aliases: ['aeroscout-server-port']
                type: int
                description: AeroScout server UDP listening port.
            ekahau_blink_mode:
                aliases: ['ekahau-blink-mode']
                type: str
                description: Enable/disable Ekahau blink mode
                choices:
                    - 'disable'
                    - 'enable'
            ekahau_tag:
                aliases: ['ekahau-tag']
                type: str
                description: WiFi frame MAC address or WiFi Tag.
            erc_server_ip:
                aliases: ['erc-server-ip']
                type: str
                description: IP address of Ekahau RTLS Controller
            erc_server_port:
                aliases: ['erc-server-port']
                type: int
                description: Ekahau RTLS Controller
            fortipresence:
                type: str
                description: Enable/disable FortiPresence to monitor the location and activity of WiFi clients even if they dont connect to this WiFi n...
                choices:
                    - 'disable'
                    - 'enable'
                    - 'enable2'
                    - 'foreign'
                    - 'both'
            fortipresence_ble:
                aliases: ['fortipresence-ble']
                type: str
                description: Enable/disable FortiPresence finding and reporting BLE devices.
                choices:
                    - 'disable'
                    - 'enable'
            fortipresence_frequency:
                aliases: ['fortipresence-frequency']
                type: int
                description: FortiPresence report transmit frequency
            fortipresence_port:
                aliases: ['fortipresence-port']
                type: int
                description: UDP listening port of FortiPresence server
            fortipresence_project:
                aliases: ['fortipresence-project']
                type: str
                description: FortiPresence project name
            fortipresence_rogue:
                aliases: ['fortipresence-rogue']
                type: str
                description: Enable/disable FortiPresence finding and reporting rogue APs.
                choices:
                    - 'disable'
                    - 'enable'
            fortipresence_secret:
                aliases: ['fortipresence-secret']
                type: list
                elements: str
                description: FortiPresence secret password
            fortipresence_server:
                aliases: ['fortipresence-server']
                type: str
                description: IP address of FortiPresence server.
            fortipresence_server_addr_type:
                aliases: ['fortipresence-server-addr-type']
                type: str
                description: FortiPresence server address type
                choices:
                    - 'fqdn'
                    - 'ipv4'
            fortipresence_server_fqdn:
                aliases: ['fortipresence-server-fqdn']
                type: str
                description: FQDN of FortiPresence server.
            fortipresence_unassoc:
                aliases: ['fortipresence-unassoc']
                type: str
                description: Enable/disable FortiPresence finding and reporting unassociated stations.
                choices:
                    - 'disable'
                    - 'enable'
            polestar:
                type: str
                description: Enable/disable PoleStar BLE NAO Track Real Time Location Service
                choices:
                    - 'disable'
                    - 'enable'
            polestar_accumulation_interval:
                aliases: ['polestar-accumulation-interval']
                type: int
                description: Time that measurements should be accumulated in seconds
            polestar_asset_addrgrp_list:
                aliases: ['polestar-asset-addrgrp-list']
                type: list
                elements: str
                description: Tags and asset addrgrp list to be reported.
            polestar_asset_uuid_list1:
                aliases: ['polestar-asset-uuid-list1']
                type: str
                description: Tags and asset UUID list 1 to be reported
            polestar_asset_uuid_list2:
                aliases: ['polestar-asset-uuid-list2']
                type: str
                description: Tags and asset UUID list 2 to be reported
            polestar_asset_uuid_list3:
                aliases: ['polestar-asset-uuid-list3']
                type: str
                description: Tags and asset UUID list 3 to be reported
            polestar_asset_uuid_list4:
                aliases: ['polestar-asset-uuid-list4']
                type: str
                description: Tags and asset UUID list 4 to be reported
            polestar_protocol:
                aliases: ['polestar-protocol']
                type: str
                description: Select the protocol to report Measurements, Advertising Data, or Location Data to NAO Cloud.
                choices:
                    - 'WSS'
            polestar_reporting_interval:
                aliases: ['polestar-reporting-interval']
                type: int
                description: Time between reporting accumulated measurements in seconds
            polestar_server_fqdn:
                aliases: ['polestar-server-fqdn']
                type: str
                description: FQDN of PoleStar Nao Track Server
            polestar_server_path:
                aliases: ['polestar-server-path']
                type: str
                description: Path of PoleStar Nao Track Server
            polestar_server_port:
                aliases: ['polestar-server-port']
                type: int
                description: Port of PoleStar Nao Track Server
            polestar_server_token:
                aliases: ['polestar-server-token']
                type: str
                description: Access Token of PoleStar Nao Track Server.
            station_locate:
                aliases: ['station-locate']
                type: str
                description: Enable/disable client station locating services for all clients, whether associated or not
                choices:
                    - 'disable'
                    - 'enable'
            ble_rtls:
                aliases: ['ble-rtls']
                type: str
                description: Set BLE Real Time Location Service
                choices:
                    - 'none'
                    - 'polestar'
                    - 'evresys'
            ble_rtls_accumulation_interval:
                aliases: ['ble-rtls-accumulation-interval']
                type: int
                description: Time that measurements should be accumulated in seconds
            ble_rtls_asset_addrgrp_list:
                aliases: ['ble-rtls-asset-addrgrp-list']
                type: list
                elements: str
                description: Tags and asset addrgrp list to be reported.
            ble_rtls_asset_uuid_list1:
                aliases: ['ble-rtls-asset-uuid-list1']
                type: str
                description: Tags and asset UUID list 1 to be reported
            ble_rtls_asset_uuid_list2:
                aliases: ['ble-rtls-asset-uuid-list2']
                type: str
                description: Tags and asset UUID list 2 to be reported
            ble_rtls_asset_uuid_list3:
                aliases: ['ble-rtls-asset-uuid-list3']
                type: str
                description: Tags and asset UUID list 3 to be reported
            ble_rtls_asset_uuid_list4:
                aliases: ['ble-rtls-asset-uuid-list4']
                type: str
                description: Tags and asset UUID list 4 to be reported
            ble_rtls_protocol:
                aliases: ['ble-rtls-protocol']
                type: str
                description: Select the protocol to report Measurements, Advertising Data, or Location Data to Cloud Server.
                choices:
                    - 'WSS'
            ble_rtls_reporting_interval:
                aliases: ['ble-rtls-reporting-interval']
                type: int
                description: Time between reporting accumulated measurements in seconds
            ble_rtls_server_fqdn:
                aliases: ['ble-rtls-server-fqdn']
                type: str
                description: FQDN of BLE Real Time Location Service
            ble_rtls_server_path:
                aliases: ['ble-rtls-server-path']
                type: str
                description: Path of BLE Real Time Location Service
            ble_rtls_server_port:
                aliases: ['ble-rtls-server-port']
                type: int
                description: Port of BLE Real Time Location Service
            ble_rtls_server_token:
                aliases: ['ble-rtls-server-token']
                type: str
                description: Access Token of BLE Real Time Location Service
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
    - name: Set various location based service
      fortinet.fmgdevice.fmgd_wireless_wtpprofile_lbs:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        wtp_profile: <your own value>
        wireless_wtpprofile_lbs:
          # aeroscout: <value in [disable, enable]>
          # aeroscout_ap_mac: <value in [bssid, board-mac]>
          # aeroscout_mmu_report: <value in [disable, enable]>
          # aeroscout_mu: <value in [disable, enable]>
          # aeroscout_mu_factor: <integer>
          # aeroscout_mu_timeout: <integer>
          # aeroscout_server_ip: <string>
          # aeroscout_server_port: <integer>
          # ekahau_blink_mode: <value in [disable, enable]>
          # ekahau_tag: <string>
          # erc_server_ip: <string>
          # erc_server_port: <integer>
          # fortipresence: <value in [disable, enable, enable2, ...]>
          # fortipresence_ble: <value in [disable, enable]>
          # fortipresence_frequency: <integer>
          # fortipresence_port: <integer>
          # fortipresence_project: <string>
          # fortipresence_rogue: <value in [disable, enable]>
          # fortipresence_secret: <list or string>
          # fortipresence_server: <string>
          # fortipresence_server_addr_type: <value in [fqdn, ipv4]>
          # fortipresence_server_fqdn: <string>
          # fortipresence_unassoc: <value in [disable, enable]>
          # polestar: <value in [disable, enable]>
          # polestar_accumulation_interval: <integer>
          # polestar_asset_addrgrp_list: <list or string>
          # polestar_asset_uuid_list1: <string>
          # polestar_asset_uuid_list2: <string>
          # polestar_asset_uuid_list3: <string>
          # polestar_asset_uuid_list4: <string>
          # polestar_protocol: <value in [WSS]>
          # polestar_reporting_interval: <integer>
          # polestar_server_fqdn: <string>
          # polestar_server_path: <string>
          # polestar_server_port: <integer>
          # polestar_server_token: <string>
          # station_locate: <value in [disable, enable]>
          # ble_rtls: <value in [none, polestar, evresys]>
          # ble_rtls_accumulation_interval: <integer>
          # ble_rtls_asset_addrgrp_list: <list or string>
          # ble_rtls_asset_uuid_list1: <string>
          # ble_rtls_asset_uuid_list2: <string>
          # ble_rtls_asset_uuid_list3: <string>
          # ble_rtls_asset_uuid_list4: <string>
          # ble_rtls_protocol: <value in [WSS]>
          # ble_rtls_reporting_interval: <integer>
          # ble_rtls_server_fqdn: <string>
          # ble_rtls_server_path: <string>
          # ble_rtls_server_port: <integer>
          # ble_rtls_server_token: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/lbs'
    ]
    url_params = ['device', 'vdom', 'wtp-profile']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wtp-profile': {'type': 'str', 'api_name': 'wtp_profile'},
        'wtp_profile': {'type': 'str'},
        'wireless_wtpprofile_lbs': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'aeroscout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aeroscout-ap-mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['bssid', 'board-mac'], 'type': 'str'},
                'aeroscout-mmu-report': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aeroscout-mu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'aeroscout-mu-factor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'aeroscout-mu-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'aeroscout-server-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aeroscout-server-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ekahau-blink-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ekahau-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'erc-server-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'erc-server-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fortipresence': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'enable2', 'foreign', 'both'],
                    'type': 'str'
                },
                'fortipresence-ble': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortipresence-frequency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fortipresence-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fortipresence-project': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fortipresence-rogue': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortipresence-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'fortipresence-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fortipresence-server-addr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['fqdn', 'ipv4'], 'type': 'str'},
                'fortipresence-server-fqdn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fortipresence-unassoc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'polestar': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'polestar-accumulation-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'polestar-asset-addrgrp-list': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'polestar-asset-uuid-list1': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'polestar-asset-uuid-list2': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'polestar-asset-uuid-list3': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'polestar-asset-uuid-list4': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'polestar-protocol': {'v_range': [['7.4.3', '']], 'choices': ['WSS'], 'type': 'str'},
                'polestar-reporting-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'polestar-server-fqdn': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'polestar-server-path': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'polestar-server-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'polestar-server-token': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'station-locate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ble-rtls': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'choices': ['none', 'polestar', 'evresys'], 'type': 'str'},
                'ble-rtls-accumulation-interval': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'int'},
                'ble-rtls-asset-addrgrp-list': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'ble-rtls-asset-uuid-list1': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'str'},
                'ble-rtls-asset-uuid-list2': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'str'},
                'ble-rtls-asset-uuid-list3': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'str'},
                'ble-rtls-asset-uuid-list4': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'str'},
                'ble-rtls-protocol': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'choices': ['WSS'], 'type': 'str'},
                'ble-rtls-reporting-interval': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'int'},
                'ble-rtls-server-fqdn': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'str'},
                'ble-rtls-server-path': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'str'},
                'ble-rtls-server-port': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'type': 'int'},
                'ble-rtls-server-token': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'no_log': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_wtpprofile_lbs'),
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
