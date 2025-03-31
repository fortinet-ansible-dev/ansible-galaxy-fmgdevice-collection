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
module: fmgd_system_speedtestschedule
short_description: Speed test schedule for each interface.
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
    system_speedtestschedule:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ctrl_port:
                aliases: ['ctrl-port']
                type: int
                description: Port of the controller to get access token.
            diffserv:
                type: str
                description: DSCP used for speed test.
            dynamic_server:
                aliases: ['dynamic-server']
                type: str
                description: Enable/disable dynamic server option.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: list
                elements: str
                description: Interface name.
            mode:
                type: str
                description: Protocol Auto
                choices:
                    - 'UDP'
                    - 'TCP'
                    - 'Auto'
            schedules:
                type: list
                elements: str
                description: Schedules for the interface.
            server_name:
                aliases: ['server-name']
                type: str
                description: Speed test server name.
            server_port:
                aliases: ['server-port']
                type: int
                description: Port of the server to run speed test.
            status:
                type: str
                description: Enable/disable scheduled speed test.
                choices:
                    - 'disable'
                    - 'enable'
            update_inbandwidth:
                aliases: ['update-inbandwidth']
                type: str
                description: Enable/disable bypassing interfaces inbound bandwidth setting.
                choices:
                    - 'disable'
                    - 'enable'
            update_inbandwidth_maximum:
                aliases: ['update-inbandwidth-maximum']
                type: int
                description: Maximum downloading bandwidth
            update_inbandwidth_minimum:
                aliases: ['update-inbandwidth-minimum']
                type: int
                description: Minimum downloading bandwidth
            update_outbandwidth:
                aliases: ['update-outbandwidth']
                type: str
                description: Enable/disable bypassing interfaces outbound bandwidth setting.
                choices:
                    - 'disable'
                    - 'enable'
            update_outbandwidth_maximum:
                aliases: ['update-outbandwidth-maximum']
                type: int
                description: Maximum uploading bandwidth
            update_outbandwidth_minimum:
                aliases: ['update-outbandwidth-minimum']
                type: int
                description: Minimum uploading bandwidth
            update_shaper:
                aliases: ['update-shaper']
                type: str
                description: Set egress shaper based on the test result.
                choices:
                    - 'disable'
                    - 'local'
                    - 'remote'
                    - 'both'
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
    - name: Speed test schedule for each interface.
      fortinet.fmgdevice.fmgd_system_speedtestschedule:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_speedtestschedule:
          # ctrl_port: <integer>
          # diffserv: <string>
          # dynamic_server: <value in [disable, enable]>
          # interface: <list or string>
          # mode: <value in [UDP, TCP, Auto]>
          # schedules: <list or string>
          # server_name: <string>
          # server_port: <integer>
          # status: <value in [disable, enable]>
          # update_inbandwidth: <value in [disable, enable]>
          # update_inbandwidth_maximum: <integer>
          # update_inbandwidth_minimum: <integer>
          # update_outbandwidth: <value in [disable, enable]>
          # update_outbandwidth_maximum: <integer>
          # update_outbandwidth_minimum: <integer>
          # update_shaper: <value in [disable, local, remote, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-schedule'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_speedtestschedule': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'ctrl-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'diffserv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dynamic-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['UDP', 'TCP', 'Auto'], 'type': 'str'},
                'schedules': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'server-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-inbandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-inbandwidth-maximum': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'update-inbandwidth-minimum': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'update-outbandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-outbandwidth-maximum': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'update-outbandwidth-minimum': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'update-shaper': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'local', 'remote', 'both'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_speedtestschedule'),
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
