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
module: fmgd_wireless_wtpgroup
short_description: Configure WTP groups.
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
    wireless_wtpgroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ble_major_id:
                aliases: ['ble-major-id']
                type: int
                description: Override BLE Major ID.
            name:
                type: str
                description: WTP group name.
                required: true
            platform_type:
                aliases: ['platform-type']
                type: str
                description: FortiAP models to define the WTP group platform type.
                choices:
                    - '220B'
                    - '210B'
                    - '222B'
                    - '112B'
                    - '320B'
                    - '11C'
                    - '14C'
                    - '223B'
                    - '28C'
                    - '320C'
                    - '221C'
                    - '25D'
                    - '222C'
                    - '224D'
                    - '214B'
                    - '21D'
                    - '24D'
                    - '112D'
                    - '223C'
                    - '321C'
                    - 'C220C'
                    - 'C225C'
                    - 'S321C'
                    - 'S323C'
                    - 'FWF'
                    - 'S311C'
                    - 'S313C'
                    - 'AP-11N'
                    - 'S322C'
                    - 'S321CR'
                    - 'S322CR'
                    - 'S323CR'
                    - 'S421E'
                    - 'S422E'
                    - 'S423E'
                    - '421E'
                    - '423E'
                    - 'C221E'
                    - 'C226E'
                    - 'C23JD'
                    - 'C24JE'
                    - 'C21D'
                    - 'U421E'
                    - 'U423E'
                    - '221E'
                    - '222E'
                    - '223E'
                    - 'S221E'
                    - 'S223E'
                    - 'U221EV'
                    - 'U223EV'
                    - 'U321EV'
                    - 'U323EV'
                    - '224E'
                    - 'U422EV'
                    - 'U24JEV'
                    - '321E'
                    - 'U431F'
                    - 'U433F'
                    - '231E'
                    - '431F'
                    - '433F'
                    - '231F'
                    - '432F'
                    - '234F'
                    - '23JF'
                    - 'U231F'
                    - '831F'
                    - 'U234F'
                    - 'U432F'
                    - '431FL'
                    - '432FR'
                    - '433FL'
                    - '231FL'
                    - '231G'
                    - '233G'
                    - '431G'
                    - '433G'
                    - 'U231G'
                    - 'U441G'
                    - '234G'
                    - '432G'
                    - '441K'
                    - '443K'
                    - '241K'
                    - '243K'
                    - '231K'
                    - '23JK'
            wtps:
                type: list
                elements: str
                description: WTP list.
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
    - name: Configure WTP groups.
      fortinet.fmgdevice.fmgd_wireless_wtpgroup:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_wtpgroup:
          name: "your value" # Required variable, string
          # ble_major_id: <integer>
          # platform_type: <value in [220B, 210B, 222B, ...]>
          # wtps: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-group'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_wtpgroup': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'ble-major-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'platform-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        '220B', '210B', '222B', '112B', '320B', '11C', '14C', '223B', '28C', '320C', '221C', '25D', '222C', '224D', '214B', '21D', '24D',
                        '112D', '223C', '321C', 'C220C', 'C225C', 'S321C', 'S323C', 'FWF', 'S311C', 'S313C', 'AP-11N', 'S322C', 'S321CR', 'S322CR',
                        'S323CR', 'S421E', 'S422E', 'S423E', '421E', '423E', 'C221E', 'C226E', 'C23JD', 'C24JE', 'C21D', 'U421E', 'U423E', '221E',
                        '222E', '223E', 'S221E', 'S223E', 'U221EV', 'U223EV', 'U321EV', 'U323EV', '224E', 'U422EV', 'U24JEV', '321E', 'U431F', 'U433F',
                        '231E', '431F', '433F', '231F', '432F', '234F', '23JF', 'U231F', '831F', 'U234F', 'U432F', '431FL', '432FR', '433FL', '231FL',
                        '231G', '233G', '431G', '433G', 'U231G', 'U441G', '234G', '432G', '441K', '443K', '241K', '243K', '231K', '23JK'
                    ],
                    'type': 'str'
                },
                'wtps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_wtpgroup'),
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
