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
module: fmgd_system_modem
short_description: Configure MODEM.
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
    system_modem:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            altmode:
                type: str
                description: Enable/disable altmode for installations using PPP in China.
                choices:
                    - 'disable'
                    - 'enable'
            authtype1:
                type: list
                elements: str
                description: Allowed authentication types for ISP 1.
                choices:
                    - 'pap'
                    - 'chap'
                    - 'mschapv2'
                    - 'mschap'
            authtype2:
                type: list
                elements: str
                description: Allowed authentication types for ISP 2.
                choices:
                    - 'pap'
                    - 'chap'
                    - 'mschapv2'
                    - 'mschap'
            authtype3:
                type: list
                elements: str
                description: Allowed authentication types for ISP 3.
                choices:
                    - 'pap'
                    - 'chap'
                    - 'mschapv2'
                    - 'mschap'
            auto_dial:
                aliases: ['auto-dial']
                type: str
                description: Enable/disable auto-dial after a reboot or disconnection.
                choices:
                    - 'disable'
                    - 'enable'
            connect_timeout:
                aliases: ['connect-timeout']
                type: int
                description: Connection completion timeout
            dial_cmd1:
                aliases: ['dial-cmd1']
                type: str
                description: Dial command
            dial_cmd2:
                aliases: ['dial-cmd2']
                type: str
                description: Dial command
            dial_cmd3:
                aliases: ['dial-cmd3']
                type: str
                description: Dial command
            dial_on_demand:
                aliases: ['dial-on-demand']
                type: str
                description: Enable/disable to dial the modem when packets are routed to the modem interface.
                choices:
                    - 'disable'
                    - 'enable'
            distance:
                type: int
                description: Distance of learned routes
            dont_send_CR1:
                aliases: ['dont-send-CR1']
                type: str
                description: Do not send CR when connected
                choices:
                    - 'disable'
                    - 'enable'
            dont_send_CR2:
                aliases: ['dont-send-CR2']
                type: str
                description: Do not send CR when connected
                choices:
                    - 'disable'
                    - 'enable'
            dont_send_CR3:
                aliases: ['dont-send-CR3']
                type: str
                description: Do not send CR when connected
                choices:
                    - 'disable'
                    - 'enable'
            extra_init1:
                aliases: ['extra-init1']
                type: str
                description: Extra initialization string to ISP 1.
            extra_init2:
                aliases: ['extra-init2']
                type: str
                description: Extra initialization string to ISP 2.
            extra_init3:
                aliases: ['extra-init3']
                type: str
                description: Extra initialization string to ISP 3.
            holddown_timer:
                aliases: ['holddown-timer']
                type: int
                description: Hold down timer in seconds
            idle_timer:
                aliases: ['idle-timer']
                type: int
                description: MODEM connection idle time
            interface:
                type: list
                elements: str
                description: Name of redundant interface.
            lockdown_lac:
                aliases: ['lockdown-lac']
                type: str
                description: Allow connection only to the specified Location Area Code
            mode:
                type: str
                description: Set MODEM operation mode to redundant or standalone.
                choices:
                    - 'standalone'
                    - 'redundant'
            network_init:
                aliases: ['network-init']
                type: str
                description: AT command to set the Network name/type
            passwd1:
                type: list
                elements: str
                description: Password to access the specified dialup account.
            passwd2:
                type: list
                elements: str
                description: Password to access the specified dialup account.
            passwd3:
                type: list
                elements: str
                description: Password to access the specified dialup account.
            peer_modem1:
                aliases: ['peer-modem1']
                type: str
                description: Specify peer MODEM type for phone1.
                choices:
                    - 'generic'
                    - 'actiontec'
                    - 'ascend_TNT'
            peer_modem2:
                aliases: ['peer-modem2']
                type: str
                description: Specify peer MODEM type for phone2.
                choices:
                    - 'generic'
                    - 'actiontec'
                    - 'ascend_TNT'
            peer_modem3:
                aliases: ['peer-modem3']
                type: str
                description: Specify peer MODEM type for phone3.
                choices:
                    - 'generic'
                    - 'actiontec'
                    - 'ascend_TNT'
            phone1:
                type: str
                description: Phone number to connect to the dialup account
            phone2:
                type: str
                description: Phone number to connect to the dialup account
            phone3:
                type: str
                description: Phone number to connect to the dialup account
            pin_init:
                aliases: ['pin-init']
                type: str
                description: AT command to set the PIN
            ppp_echo_request1:
                aliases: ['ppp-echo-request1']
                type: str
                description: Enable/disable PPP echo-request to ISP 1.
                choices:
                    - 'disable'
                    - 'enable'
            ppp_echo_request2:
                aliases: ['ppp-echo-request2']
                type: str
                description: Enable/disable PPP echo-request to ISP 2.
                choices:
                    - 'disable'
                    - 'enable'
            ppp_echo_request3:
                aliases: ['ppp-echo-request3']
                type: str
                description: Enable/disable PPP echo-request to ISP 3.
                choices:
                    - 'disable'
                    - 'enable'
            priority:
                type: int
                description: Priority of learned routes
            redial:
                type: str
                description: Redial limit
                choices:
                    - 'none'
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
            reset:
                type: int
                description: Number of dial attempts before resetting modem
            status:
                type: str
                description: Enable/disable Modem support
                choices:
                    - 'disable'
                    - 'enable'
            username1:
                type: str
                description: User name to access the specified dialup account.
            username2:
                type: str
                description: User name to access the specified dialup account.
            username3:
                type: str
                description: User name to access the specified dialup account.
            wireless_port:
                aliases: ['wireless-port']
                type: int
                description: Enter wireless port number
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
    - name: Configure MODEM.
      fortinet.fmgdevice.fmgd_system_modem:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        system_modem:
          # altmode: <value in [disable, enable]>
          # authtype1:
          #   - "pap"
          #   - "chap"
          #   - "mschapv2"
          #   - "mschap"
          # authtype2:
          #   - "pap"
          #   - "chap"
          #   - "mschapv2"
          #   - "mschap"
          # authtype3:
          #   - "pap"
          #   - "chap"
          #   - "mschapv2"
          #   - "mschap"
          # auto_dial: <value in [disable, enable]>
          # connect_timeout: <integer>
          # dial_cmd1: <string>
          # dial_cmd2: <string>
          # dial_cmd3: <string>
          # dial_on_demand: <value in [disable, enable]>
          # distance: <integer>
          # dont_send_CR1: <value in [disable, enable]>
          # dont_send_CR2: <value in [disable, enable]>
          # dont_send_CR3: <value in [disable, enable]>
          # extra_init1: <string>
          # extra_init2: <string>
          # extra_init3: <string>
          # holddown_timer: <integer>
          # idle_timer: <integer>
          # interface: <list or string>
          # lockdown_lac: <string>
          # mode: <value in [standalone, redundant]>
          # network_init: <string>
          # passwd1: <list or string>
          # passwd2: <list or string>
          # passwd3: <list or string>
          # peer_modem1: <value in [generic, actiontec, ascend_TNT]>
          # peer_modem2: <value in [generic, actiontec, ascend_TNT]>
          # peer_modem3: <value in [generic, actiontec, ascend_TNT]>
          # phone1: <string>
          # phone2: <string>
          # phone3: <string>
          # pin_init: <string>
          # ppp_echo_request1: <value in [disable, enable]>
          # ppp_echo_request2: <value in [disable, enable]>
          # ppp_echo_request3: <value in [disable, enable]>
          # priority: <integer>
          # redial: <value in [none, 1, 2, ...]>
          # reset: <integer>
          # status: <value in [disable, enable]>
          # username1: <string>
          # username2: <string>
          # username3: <string>
          # wireless_port: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/modem'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_modem': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'altmode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authtype1': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['pap', 'chap', 'mschapv2', 'mschap'],
                    'elements': 'str'
                },
                'authtype2': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['pap', 'chap', 'mschapv2', 'mschap'],
                    'elements': 'str'
                },
                'authtype3': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['pap', 'chap', 'mschapv2', 'mschap'],
                    'elements': 'str'
                },
                'auto-dial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'connect-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dial-cmd1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dial-cmd2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dial-cmd3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dial-on-demand': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'distance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dont-send-CR1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dont-send-CR2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dont-send-CR3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extra-init1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'extra-init2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'extra-init3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'holddown-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'idle-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'lockdown-lac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['standalone', 'redundant'], 'type': 'str'},
                'network-init': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'passwd1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'passwd2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'passwd3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'peer-modem1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['generic', 'actiontec', 'ascend_TNT'], 'type': 'str'},
                'peer-modem2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['generic', 'actiontec', 'ascend_TNT'], 'type': 'str'},
                'peer-modem3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['generic', 'actiontec', 'ascend_TNT'], 'type': 'str'},
                'phone1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'phone2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'phone3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'pin-init': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ppp-echo-request1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ppp-echo-request2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ppp-echo-request3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'redial': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['none', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
                    'type': 'str'
                },
                'reset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'username2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'username3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'wireless-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_modem'),
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
