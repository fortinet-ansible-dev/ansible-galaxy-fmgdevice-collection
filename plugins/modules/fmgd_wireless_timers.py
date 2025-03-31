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
module: fmgd_wireless_timers
short_description: Configure CAPWAP timers.
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
    wireless_timers:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ap_reboot_wait_interval1:
                aliases: ['ap-reboot-wait-interval1']
                type: int
                description: Time in minutes to wait before AP reboots when there is no controller detected
            ap_reboot_wait_interval2:
                aliases: ['ap-reboot-wait-interval2']
                type: int
                description: Time in minutes to wait before AP reboots when there is no controller detected and standalone SSIDs are pushed to the AP i...
            ap_reboot_wait_time:
                aliases: ['ap-reboot-wait-time']
                type: str
                description: Time to reboot the AP when there is no controller detected and standalone SSIDs are pushed to the AP in the previous sessi...
            auth_timeout:
                aliases: ['auth-timeout']
                type: int
                description: Time after which a client is considered failed in RADIUS authentication and times out
            ble_device_cleanup:
                aliases: ['ble-device-cleanup']
                type: int
                description: Time period in minutes to keep BLE device after it is gone
            ble_scan_report_intv:
                aliases: ['ble-scan-report-intv']
                type: int
                description: Time between running Bluetooth Low Energy
            client_idle_rehome_timeout:
                aliases: ['client-idle-rehome-timeout']
                type: int
                description: Time after which a client is considered idle and disconnected from the home controller
            client_idle_timeout:
                aliases: ['client-idle-timeout']
                type: int
                description: Time after which a client is considered idle and times out
            discovery_interval:
                aliases: ['discovery-interval']
                type: int
                description: Time between discovery requests
            drma_interval:
                aliases: ['drma-interval']
                type: int
                description: Dynamic radio mode assignment
            echo_interval:
                aliases: ['echo-interval']
                type: int
                description: Time between echo requests sent by the managed WTP, AP, or FortiAP
            fake_ap_log:
                aliases: ['fake-ap-log']
                type: int
                description: Time between recording logs about fake APs if periodic fake AP logging is configured
            ipsec_intf_cleanup:
                aliases: ['ipsec-intf-cleanup']
                type: int
                description: Time period to keep IPsec VPN interfaces up after WTP sessions are disconnected
            nat_session_keep_alive:
                aliases: ['nat-session-keep-alive']
                type: int
                description: Maximal time in seconds between control requests sent by the managed WTP, AP, or FortiAP
            radio_stats_interval:
                aliases: ['radio-stats-interval']
                type: int
                description: Time between running radio reports
            rogue_ap_cleanup:
                aliases: ['rogue-ap-cleanup']
                type: int
                description: Time period in minutes to keep rogue AP after it is gone
            rogue_ap_log:
                aliases: ['rogue-ap-log']
                type: int
                description: Time between logging rogue AP messages if periodic rogue AP logging is configured
            rogue_sta_cleanup:
                aliases: ['rogue-sta-cleanup']
                type: int
                description: Time period in minutes to keep rogue station after it is gone
            sta_cap_cleanup:
                aliases: ['sta-cap-cleanup']
                type: int
                description: Time period in minutes to keep station capability data after it is gone
            sta_capability_interval:
                aliases: ['sta-capability-interval']
                type: int
                description: Time between running station capability reports
            sta_locate_timer:
                aliases: ['sta-locate-timer']
                type: int
                description: Time between running client presence flushes to remove clients that are listed but no longer present
            sta_stats_interval:
                aliases: ['sta-stats-interval']
                type: int
                description: Time between running client
            vap_stats_interval:
                aliases: ['vap-stats-interval']
                type: int
                description: Time between running Virtual Access Point
            wids_entry_cleanup:
                aliases: ['wids-entry-cleanup']
                type: int
                description: Time period in minutes to keep wids entry after it is gone
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
    - name: Configure CAPWAP timers.
      fortinet.fmgdevice.fmgd_wireless_timers:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        wireless_timers:
          # ap_reboot_wait_interval1: <integer>
          # ap_reboot_wait_interval2: <integer>
          # ap_reboot_wait_time: <string>
          # auth_timeout: <integer>
          # ble_device_cleanup: <integer>
          # ble_scan_report_intv: <integer>
          # client_idle_rehome_timeout: <integer>
          # client_idle_timeout: <integer>
          # discovery_interval: <integer>
          # drma_interval: <integer>
          # echo_interval: <integer>
          # fake_ap_log: <integer>
          # ipsec_intf_cleanup: <integer>
          # nat_session_keep_alive: <integer>
          # radio_stats_interval: <integer>
          # rogue_ap_cleanup: <integer>
          # rogue_ap_log: <integer>
          # rogue_sta_cleanup: <integer>
          # sta_cap_cleanup: <integer>
          # sta_capability_interval: <integer>
          # sta_locate_timer: <integer>
          # sta_stats_interval: <integer>
          # vap_stats_interval: <integer>
          # wids_entry_cleanup: <integer>
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
        '/pm/config/device/{device}/global/wireless-controller/timers'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'wireless_timers': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'ap-reboot-wait-interval1': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'ap-reboot-wait-interval2': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'ap-reboot-wait-time': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'auth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ble-device-cleanup': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'ble-scan-report-intv': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'client-idle-rehome-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'client-idle-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'discovery-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'drma-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'echo-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fake-ap-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ipsec-intf-cleanup': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nat-session-keep-alive': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'radio-stats-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rogue-ap-cleanup': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rogue-ap-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rogue-sta-cleanup': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'sta-cap-cleanup': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'sta-capability-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sta-locate-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sta-stats-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'vap-stats-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wids-entry-cleanup': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_timers'),
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
