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
module: fmgd_wireless_bleprofile
short_description: Configure Bluetooth Low Energy profile.
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
    wireless_bleprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            advertising:
                type: list
                elements: str
                description: Advertising type.
                choices:
                    - 'ibeacon'
                    - 'eddystone-uid'
                    - 'eddystone-url'
            beacon_interval:
                aliases: ['beacon-interval']
                type: int
                description: Beacon interval
            ble_scanning:
                aliases: ['ble-scanning']
                type: str
                description: Enable/disable Bluetooth Low Energy
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            eddystone_instance:
                aliases: ['eddystone-instance']
                type: str
                description: Eddystone instance ID.
            eddystone_namespace:
                aliases: ['eddystone-namespace']
                type: str
                description: Eddystone namespace ID.
            eddystone_url:
                aliases: ['eddystone-url']
                type: str
                description: Eddystone URL.
            eddystone_url_encode_hex:
                aliases: ['eddystone-url-encode-hex']
                type: str
                description: Eddystone encoded URL hexadecimal string
            ibeacon_uuid:
                aliases: ['ibeacon-uuid']
                type: str
                description: Universally Unique Identifier
            major_id:
                aliases: ['major-id']
                type: int
                description: Major ID.
            minor_id:
                aliases: ['minor-id']
                type: int
                description: Minor ID.
            name:
                type: str
                description: Bluetooth Low Energy profile name.
                required: true
            scan_interval:
                aliases: ['scan-interval']
                type: int
                description: Scan Interval
            scan_period:
                aliases: ['scan-period']
                type: int
                description: Scan Period
            scan_threshold:
                aliases: ['scan-threshold']
                type: str
                description: Minimum signal level/threshold in dBm required for the AP to report detected BLE device
            scan_time:
                aliases: ['scan-time']
                type: int
                description: Scan Time
            scan_type:
                aliases: ['scan-type']
                type: str
                description: Scan Type
                choices:
                    - 'active'
                    - 'passive'
            scan_window:
                aliases: ['scan-window']
                type: int
                description: Scan Windows
            txpower:
                type: str
                description: Transmit power level
                choices:
                    - '0'
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
                    - '11'
                    - '12'
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
    - name: Configure Bluetooth Low Energy profile.
      fortinet.fmgdevice.fmgd_wireless_bleprofile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_bleprofile:
          name: "your value" # Required variable, string
          # advertising:
          #   - "ibeacon"
          #   - "eddystone-uid"
          #   - "eddystone-url"
          # beacon_interval: <integer>
          # ble_scanning: <value in [disable, enable]>
          # comment: <string>
          # eddystone_instance: <string>
          # eddystone_namespace: <string>
          # eddystone_url: <string>
          # eddystone_url_encode_hex: <string>
          # ibeacon_uuid: <string>
          # major_id: <integer>
          # minor_id: <integer>
          # scan_interval: <integer>
          # scan_period: <integer>
          # scan_threshold: <string>
          # scan_time: <integer>
          # scan_type: <value in [active, passive]>
          # scan_window: <integer>
          # txpower: <value in [0, 1, 2, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ble-profile'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_bleprofile': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'advertising': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['ibeacon', 'eddystone-uid', 'eddystone-url'],
                    'elements': 'str'
                },
                'beacon-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ble-scanning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-instance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-namespace': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-url-encode-hex': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ibeacon-uuid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'major-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'minor-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'scan-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'scan-period': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'scan-threshold': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'scan-time': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'scan-type': {'v_range': [['7.4.3', '']], 'choices': ['active', 'passive'], 'type': 'str'},
                'scan-window': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'txpower': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_bleprofile'),
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
