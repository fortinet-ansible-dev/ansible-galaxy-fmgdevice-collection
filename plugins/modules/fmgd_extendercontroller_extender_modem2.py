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
module: fmgd_extendercontroller_extender_modem2
short_description: Configuration options for modem 2.
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
    extender:
        description: The parameter (extender) in requested url.
        type: str
        required: true
    extendercontroller_extender_modem2:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _ifname:
                type: list
                elements: str
                description: Support meta variable
            _sim_profile:
                type: list
                elements: str
                description: Support meta variable
            auto_switch:
                aliases: ['auto-switch']
                type: dict
                description: Auto switch.
                suboptions:
                    dataplan:
                        type: str
                        description: Automatically switch based on data usage.
                        choices:
                            - 'disable'
                            - 'enable'
                    disconnect:
                        type: str
                        description: Auto switch by disconnect.
                        choices:
                            - 'disable'
                            - 'enable'
                    disconnect_period:
                        aliases: ['disconnect-period']
                        type: int
                        description: Automatically switch based on disconnect period.
                    disconnect_threshold:
                        aliases: ['disconnect-threshold']
                        type: int
                        description: Automatically switch based on disconnect threshold.
                    signal:
                        type: str
                        description: Automatically switch based on signal strength.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_back:
                        aliases: ['switch-back']
                        type: list
                        elements: str
                        description: Auto switch with switch back multi-options.
                        choices:
                            - 'time'
                            - 'timer'
                    switch_back_time:
                        aliases: ['switch-back-time']
                        type: str
                        description: Automatically switch over to preferred SIM/carrier at a specified time in UTC
                    switch_back_timer:
                        aliases: ['switch-back-timer']
                        type: int
                        description: Automatically switch over to preferred SIM/carrier after the given time
                    status:
                        type: str
                        description: FortiExtender automatic switch status.
                        choices:
                            - 'disable'
                            - 'enable'
            conn_status:
                aliases: ['conn-status']
                type: int
                description: Support meta variable
            default_sim:
                aliases: ['default-sim']
                type: str
                description: Default SIM selection.
                choices:
                    - 'sim1'
                    - 'sim2'
                    - 'carrier'
                    - 'cost'
            gps:
                type: str
                description: FortiExtender GPS enable/disable.
                choices:
                    - 'disable'
                    - 'enable'
            ifname:
                type: list
                elements: str
                description: FortiExtender interface name.
            modem_id:
                aliases: ['modem-id']
                type: int
                description: Support meta variable
            preferred_carrier:
                aliases: ['preferred-carrier']
                type: str
                description: Preferred carrier.
            redundant_intf:
                aliases: ['redundant-intf']
                type: str
                description: Redundant interface.
            redundant_mode:
                aliases: ['redundant-mode']
                type: str
                description: FortiExtender mode.
                choices:
                    - 'disable'
                    - 'enable'
            sim1_pin:
                aliases: ['sim1-pin']
                type: str
                description: SIM #1 PIN status.
                choices:
                    - 'disable'
                    - 'enable'
            sim1_pin_code:
                aliases: ['sim1-pin-code']
                type: list
                elements: str
                description: SIM #1 PIN password.
            sim2_pin:
                aliases: ['sim2-pin']
                type: str
                description: SIM #2 PIN status.
                choices:
                    - 'disable'
                    - 'enable'
            sim2_pin_code:
                aliases: ['sim2-pin-code']
                type: list
                elements: str
                description: SIM #2 PIN password.
            status:
                type: str
                description: FortiExtender modem status.
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
    - name: Configuration options for modem 2.
      fortinet.fmgdevice.fmgd_extendercontroller_extender_modem2:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        extender: <your own value>
        extendercontroller_extender_modem2:
          # _ifname: <list or string>
          # _sim_profile: <list or string>
          # auto_switch:
          #   dataplan: <value in [disable, enable]>
          #   disconnect: <value in [disable, enable]>
          #   disconnect_period: <integer>
          #   disconnect_threshold: <integer>
          #   signal: <value in [disable, enable]>
          #   switch_back:
          #     - "time"
          #     - "timer"
          #   switch_back_time: <string>
          #   switch_back_timer: <integer>
          #   status: <value in [disable, enable]>
          # conn_status: <integer>
          # default_sim: <value in [sim1, sim2, carrier, ...]>
          # gps: <value in [disable, enable]>
          # ifname: <list or string>
          # modem_id: <integer>
          # preferred_carrier: <string>
          # redundant_intf: <string>
          # redundant_mode: <value in [disable, enable]>
          # sim1_pin: <value in [disable, enable]>
          # sim1_pin_code: <list or string>
          # sim2_pin: <value in [disable, enable]>
          # sim2_pin_code: <list or string>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}/modem2'
    ]
    url_params = ['device', 'vdom', 'extender']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'extender': {'required': True, 'type': 'str'},
        'extendercontroller_extender_modem2': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                '_ifname': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_sim_profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'auto-switch': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dataplan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'disconnect': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'disconnect-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'disconnect-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'signal': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switch-back': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['time', 'timer'], 'elements': 'str'},
                        'switch-back-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'switch-back-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'conn-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default-sim': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['sim1', 'sim2', 'carrier', 'cost'], 'type': 'str'},
                'gps': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ifname': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'modem-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'preferred-carrier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'redundant-intf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'redundant-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim1-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim1-pin-code': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim2-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim2-pin-code': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_extender_modem2'),
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
