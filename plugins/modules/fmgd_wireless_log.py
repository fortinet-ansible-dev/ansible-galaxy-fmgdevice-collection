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
module: fmgd_wireless_log
short_description: Configure wireless controller event log filters.
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
    wireless_log:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addrgrp_log:
                aliases: ['addrgrp-log']
                type: str
                description: Lowest severity level to log address group message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            ble_log:
                aliases: ['ble-log']
                type: str
                description: Lowest severity level to log BLE detection message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            clb_log:
                aliases: ['clb-log']
                type: str
                description: Lowest severity level to log client load balancing message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            dhcp_starv_log:
                aliases: ['dhcp-starv-log']
                type: str
                description: Lowest severity level to log DHCP starvation event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            led_sched_log:
                aliases: ['led-sched-log']
                type: str
                description: Lowest severity level to log LED schedule event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            radio_event_log:
                aliases: ['radio-event-log']
                type: str
                description: Lowest severity level to log radio event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            rogue_event_log:
                aliases: ['rogue-event-log']
                type: str
                description: Lowest severity level to log rogue AP event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            sta_event_log:
                aliases: ['sta-event-log']
                type: str
                description: Lowest severity level to log station event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            sta_locate_log:
                aliases: ['sta-locate-log']
                type: str
                description: Lowest severity level to log station locate message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            status:
                type: str
                description: Enable/disable wireless event logging.
                choices:
                    - 'disable'
                    - 'enable'
            wids_log:
                aliases: ['wids-log']
                type: str
                description: Lowest severity level to log WIDS message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            wtp_event_log:
                aliases: ['wtp-event-log']
                type: str
                description: Lowest severity level to log WTP event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            wtp_fips_event_log:
                aliases: ['wtp-fips-event-log']
                type: str
                description: Lowest severity level to log FAP fips event message.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
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
    - name: Configure wireless controller event log filters.
      fortinet.fmgdevice.fmgd_wireless_log:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        wireless_log:
          # addrgrp_log: <value in [emergency, alert, critical, ...]>
          # ble_log: <value in [emergency, alert, critical, ...]>
          # clb_log: <value in [emergency, alert, critical, ...]>
          # dhcp_starv_log: <value in [emergency, alert, critical, ...]>
          # led_sched_log: <value in [emergency, alert, critical, ...]>
          # radio_event_log: <value in [emergency, alert, critical, ...]>
          # rogue_event_log: <value in [emergency, alert, critical, ...]>
          # sta_event_log: <value in [emergency, alert, critical, ...]>
          # sta_locate_log: <value in [emergency, alert, critical, ...]>
          # status: <value in [disable, enable]>
          # wids_log: <value in [emergency, alert, critical, ...]>
          # wtp_event_log: <value in [emergency, alert, critical, ...]>
          # wtp_fips_event_log: <value in [emergency, alert, critical, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/log'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_log': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'addrgrp-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'ble-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'clb-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'dhcp-starv-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'led-sched-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'radio-event-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'rogue-event-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'sta-event-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'sta-locate-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wids-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'wtp-event-log': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'wtp-fips-event-log': {
                    'v_range': [['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_log'),
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
