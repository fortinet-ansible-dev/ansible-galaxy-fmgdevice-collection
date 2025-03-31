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
module: fmgd_switchcontroller_system
short_description: Configure system-wide switch controller settings.
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
    switchcontroller_system:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            caputp_echo_interval:
                aliases: ['caputp-echo-interval']
                type: int
                description: Echo interval for the caputp echo requests from swtp.
            caputp_max_retransmit:
                aliases: ['caputp-max-retransmit']
                type: int
                description: Maximum retransmission count for the caputp tunnel packets.
            data_sync_interval:
                aliases: ['data-sync-interval']
                type: int
                description: Time interval between collection of switch data
            dynamic_periodic_interval:
                aliases: ['dynamic-periodic-interval']
                type: int
                description: Periodic time interval to run Dynamic port policy engine
            iot_holdoff:
                aliases: ['iot-holdoff']
                type: int
                description: MAC entrys creation time.
            iot_mac_idle:
                aliases: ['iot-mac-idle']
                type: int
                description: MAC entrys idle time.
            iot_scan_interval:
                aliases: ['iot-scan-interval']
                type: int
                description: IoT scan interval
            iot_weight_threshold:
                aliases: ['iot-weight-threshold']
                type: int
                description: MAC entrys confidence value.
            nac_periodic_interval:
                aliases: ['nac-periodic-interval']
                type: int
                description: Periodic time interval to run NAC engine
            parallel_process:
                aliases: ['parallel-process']
                type: int
                description: Maximum number of parallel processes.
            parallel_process_override:
                aliases: ['parallel-process-override']
                type: str
                description: Enable/disable parallel process override.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_mode:
                aliases: ['tunnel-mode']
                type: str
                description: Compatible/strict tunnel mode.
                choices:
                    - 'compatible'
                    - 'strict'
                    - 'moderate'
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
    - name: Configure system-wide switch controller settings.
      fortinet.fmgdevice.fmgd_switchcontroller_system:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        switchcontroller_system:
          # caputp_echo_interval: <integer>
          # caputp_max_retransmit: <integer>
          # data_sync_interval: <integer>
          # dynamic_periodic_interval: <integer>
          # iot_holdoff: <integer>
          # iot_mac_idle: <integer>
          # iot_scan_interval: <integer>
          # iot_weight_threshold: <integer>
          # nac_periodic_interval: <integer>
          # parallel_process: <integer>
          # parallel_process_override: <value in [disable, enable]>
          # tunnel_mode: <value in [compatible, strict, moderate]>
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
        '/pm/config/device/{device}/global/switch-controller/system'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'switchcontroller_system': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'caputp-echo-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'caputp-max-retransmit': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'data-sync-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dynamic-periodic-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'iot-holdoff': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'iot-mac-idle': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'iot-scan-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'iot-weight-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nac-periodic-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'parallel-process': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'parallel-process-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['compatible', 'strict', 'moderate'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_system'),
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
