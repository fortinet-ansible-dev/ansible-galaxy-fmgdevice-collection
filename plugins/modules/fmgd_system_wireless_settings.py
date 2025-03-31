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
module: fmgd_system_wireless_settings
short_description: Wireless radio configuration.
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
    system_wireless_settings:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            band:
                type: str
                description: Band.
                choices:
                    - '802.11b'
                    - '802.11a'
                    - '802.11g'
                    - '802.11n'
                    - '802.11ac'
                    - '802.11n-5G'
                    - '802.11g-only'
                    - '802.11n-only'
                    - '802.11ng-only'
                    - '802.11ac-only'
                    - '802.11acn-only'
                    - '802.11n-5G-only'
            beacon_interval:
                aliases: ['beacon-interval']
                type: int
                description: Beacon level
            bgscan:
                type: str
                description: Enable/disable background rogue AP scan.
                choices:
                    - 'disable'
                    - 'enable'
            bgscan_idle:
                aliases: ['bgscan-idle']
                type: int
                description: Interval between scanning channels
            bgscan_interval:
                aliases: ['bgscan-interval']
                type: int
                description: Interval between two rounds of scanning
            channel:
                type: int
                description: Channel.
            channel_bonding:
                aliases: ['channel-bonding']
                type: str
                description: Supported channel width.
                choices:
                    - 'disable'
                    - 'enable'
            geography:
                type: str
                description: Geography.
                choices:
                    - 'World'
                    - 'Americas'
                    - 'EMEA'
                    - 'Israel'
                    - 'Japan'
            mode:
                type: str
                description: Mode.
                choices:
                    - 'AP'
                    - 'CLIENT'
                    - 'SCAN'
            power_level:
                aliases: ['power-level']
                type: int
                description: Power level
            rogue_scan:
                aliases: ['rogue-scan']
                type: str
                description: Enable/disable rogue scan.
                choices:
                    - 'disable'
                    - 'enable'
            rogue_scan_mac_adjacency:
                aliases: ['rogue-scan-mac-adjacency']
                type: int
                description: MAC adjacency
            short_guard_interval:
                aliases: ['short-guard-interval']
                type: str
                description: Enable/disable short guard interval.
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
    - name: Wireless radio configuration.
      fortinet.fmgdevice.fmgd_system_wireless_settings:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_wireless_settings:
          # band: <value in [802.11b, 802.11a, 802.11g, ...]>
          # beacon_interval: <integer>
          # bgscan: <value in [disable, enable]>
          # bgscan_idle: <integer>
          # bgscan_interval: <integer>
          # channel: <integer>
          # channel_bonding: <value in [disable, enable]>
          # geography: <value in [World, Americas, EMEA, ...]>
          # mode: <value in [AP, CLIENT, SCAN]>
          # power_level: <integer>
          # rogue_scan: <value in [disable, enable]>
          # rogue_scan_mac_adjacency: <integer>
          # short_guard_interval: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/wireless/settings'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_wireless_settings': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'band': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        '802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G', '802.11g-only', '802.11n-only', '802.11ng-only',
                        '802.11ac-only', '802.11acn-only', '802.11n-5G-only'
                    ],
                    'type': 'str'
                },
                'beacon-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bgscan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bgscan-idle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'bgscan-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'channel-bonding': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'geography': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['World', 'Americas', 'EMEA', 'Israel', 'Japan'], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['AP', 'CLIENT', 'SCAN'], 'type': 'str'},
                'power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rogue-scan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rogue-scan-mac-adjacency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'short-guard-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_wireless_settings'),
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
