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
module: fmgd_wireless_wtp_radio2
short_description: Configuration options for radio 2.
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
    wtp:
        description: The parameter (wtp) in requested url.
        type: str
        required: true
    wireless_wtp_radio2:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_power_high:
                aliases: ['auto-power-high']
                type: int
                description: The upper bound of automatic transmit power adjustment in dBm
            auto_power_level:
                aliases: ['auto-power-level']
                type: str
                description: Enable/disable automatic power-level adjustment to prevent co-channel interference
                choices:
                    - 'disable'
                    - 'enable'
            auto_power_low:
                aliases: ['auto-power-low']
                type: int
                description: The lower bound of automatic transmit power adjustment in dBm
            auto_power_target:
                aliases: ['auto-power-target']
                type: str
                description: Target of automatic transmit power adjustment in dBm
            band:
                type: list
                elements: str
                description: WiFi band that Radio 2 operates on.
                choices:
                    - '802.11a'
                    - '802.11b'
                    - '802.11g'
                    - '802.11n'
                    - '802.11n-5G'
                    - '802.11n,g-only'
                    - '802.11g-only'
                    - '802.11n-only'
                    - '802.11n-5G-only'
                    - '802.11ac'
                    - '802.11ac,n-only'
                    - '802.11ac-only'
                    - '802.11ax-5G'
                    - '802.11ax,ac-only'
                    - '802.11ax,ac,n-only'
                    - '802.11ax-5G-only'
                    - '802.11ax'
                    - '802.11ax,n-only'
                    - '802.11ax,n,g-only'
                    - '802.11ax-only'
                    - '802.11ac-2G'
                    - '802.11ax-6G'
                    - '802.11n-2G'
                    - '802.11ac-5G'
                    - '802.11ax-2G'
                    - '802.11be-2G'
                    - '802.11be-5G'
                    - '802.11be-6G'
            channel:
                type: list
                elements: str
                description: Selected list of wireless radio channels.
            drma_manual_mode:
                aliases: ['drma-manual-mode']
                type: str
                description: Radio mode to be used for DRMA manual mode
                choices:
                    - 'ap'
                    - 'monitor'
                    - 'ncf'
                    - 'ncf-peek'
            override_band:
                aliases: ['override-band']
                type: str
                description: Enable to override the WTP profile band setting.
                choices:
                    - 'disable'
                    - 'enable'
            override_channel:
                aliases: ['override-channel']
                type: str
                description: Enable to override WTP profile channel settings.
                choices:
                    - 'disable'
                    - 'enable'
            override_txpower:
                aliases: ['override-txpower']
                type: str
                description: Enable to override the WTP profile power level configuration.
                choices:
                    - 'disable'
                    - 'enable'
            override_vaps:
                aliases: ['override-vaps']
                type: str
                description: Enable to override WTP profile Virtual Access Point
                choices:
                    - 'disable'
                    - 'enable'
            power_level:
                aliases: ['power-level']
                type: int
                description: Radio EIRP power level as a percentage of the maximum EIRP power
            power_mode:
                aliases: ['power-mode']
                type: str
                description: Set radio effective isotropic radiated power
                choices:
                    - 'dBm'
                    - 'percentage'
            power_value:
                aliases: ['power-value']
                type: int
                description: Radio EIRP power in dBm
            radio_id:
                aliases: ['radio-id']
                type: int
                description: Radio id.
            vap_all:
                aliases: ['vap-all']
                type: str
                description: Configure method for assigning SSIDs to this FortiAP
                choices:
                    - 'disable'
                    - 'enable'
                    - 'tunnel'
                    - 'bridge'
                    - 'manual'
            vap1:
                type: str
                description: Virtual Access Point
            vap2:
                type: str
                description: Virtual Access Point
            vap3:
                type: str
                description: Virtual Access Point
            vap4:
                type: str
                description: Virtual Access Point
            vap5:
                type: str
                description: Virtual Access Point
            vap6:
                type: str
                description: Virtual Access Point
            vap7:
                type: str
                description: Virtual Access Point
            vap8:
                type: str
                description: Virtual Access Point
            vaps:
                type: list
                elements: str
                description: Manually selected list of Virtual Access Points
            spectrum_analysis:
                aliases: ['spectrum-analysis']
                type: str
                description: Enable/disable spectrum analysis to find interference that would negatively impact wireless performance.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'scan-only'
            override_analysis:
                aliases: ['override-analysis']
                type: str
                description: Enable to override the WTP profile spectrum analysis configuration.
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
    - name: Configuration options for radio 2.
      fortinet.fmgdevice.fmgd_wireless_wtp_radio2:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        wtp: <your own value>
        wireless_wtp_radio2:
          # auto_power_high: <integer>
          # auto_power_level: <value in [disable, enable]>
          # auto_power_low: <integer>
          # auto_power_target: <string>
          # band:
          #   - "802.11a"
          #   - "802.11b"
          #   - "802.11g"
          #   - "802.11n"
          #   - "802.11n-5G"
          #   - "802.11n,g-only"
          #   - "802.11g-only"
          #   - "802.11n-only"
          #   - "802.11n-5G-only"
          #   - "802.11ac"
          #   - "802.11ac,n-only"
          #   - "802.11ac-only"
          #   - "802.11ax-5G"
          #   - "802.11ax,ac-only"
          #   - "802.11ax,ac,n-only"
          #   - "802.11ax-5G-only"
          #   - "802.11ax"
          #   - "802.11ax,n-only"
          #   - "802.11ax,n,g-only"
          #   - "802.11ax-only"
          #   - "802.11ac-2G"
          #   - "802.11ax-6G"
          #   - "802.11n-2G"
          #   - "802.11ac-5G"
          #   - "802.11ax-2G"
          #   - "802.11be-2G"
          #   - "802.11be-5G"
          #   - "802.11be-6G"
          # channel: <list or string>
          # drma_manual_mode: <value in [ap, monitor, ncf, ...]>
          # override_band: <value in [disable, enable]>
          # override_channel: <value in [disable, enable]>
          # override_txpower: <value in [disable, enable]>
          # override_vaps: <value in [disable, enable]>
          # power_level: <integer>
          # power_mode: <value in [dBm, percentage]>
          # power_value: <integer>
          # radio_id: <integer>
          # vap_all: <value in [disable, enable, tunnel, ...]>
          # vap1: <string>
          # vap2: <string>
          # vap3: <string>
          # vap4: <string>
          # vap5: <string>
          # vap6: <string>
          # vap7: <string>
          # vap8: <string>
          # vaps: <list or string>
          # spectrum_analysis: <value in [disable, enable, scan-only]>
          # override_analysis: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/radio-2'
    ]
    url_params = ['device', 'vdom', 'wtp']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wtp': {'required': True, 'type': 'str'},
        'wireless_wtp_radio2': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'auto-power-high': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-power-low': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-power-target': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'band': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        '802.11a', '802.11b', '802.11g', '802.11n', '802.11n-5G', '802.11n,g-only', '802.11g-only', '802.11n-only', '802.11n-5G-only',
                        '802.11ac', '802.11ac,n-only', '802.11ac-only', '802.11ax-5G', '802.11ax,ac-only', '802.11ax,ac,n-only', '802.11ax-5G-only',
                        '802.11ax', '802.11ax,n-only', '802.11ax,n,g-only', '802.11ax-only', '802.11ac-2G', '802.11ax-6G', '802.11n-2G', '802.11ac-5G',
                        '802.11ax-2G', '802.11be-2G', '802.11be-5G', '802.11be-6G'
                    ],
                    'elements': 'str'
                },
                'channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'drma-manual-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ap', 'monitor', 'ncf', 'ncf-peek'], 'type': 'str'},
                'override-band': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-channel': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-txpower': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'power-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'power-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dBm', 'percentage'], 'type': 'str'},
                'power-value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'radio-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'vap-all': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'tunnel', 'bridge', 'manual'], 'type': 'str'},
                'vap1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vap8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vaps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'spectrum-analysis': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'scan-only'], 'type': 'str'},
                'override-analysis': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_wtp_radio2'),
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
