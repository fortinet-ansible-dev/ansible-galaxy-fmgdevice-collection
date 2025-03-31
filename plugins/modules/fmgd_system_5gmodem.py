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
module: fmgd_system_5gmodem
short_description: Configure USB 5G modems.
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
    system_5gmodem:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            data_plan:
                aliases: ['data-plan']
                type: list
                elements: dict
                description: Data plan.
                suboptions:
                    apn:
                        type: str
                        description: Login APN string for PDP-IP packet data calls.
                    auth_type:
                        aliases: ['auth-type']
                        type: str
                        description: Authentication type for PDP-IP packet data calls.
                        choices:
                            - 'none'
                            - 'pap'
                            - 'chap'
                    name:
                        type: str
                        description: Data plan name.
                    password:
                        type: list
                        elements: str
                        description: Authentication password for PDP-IP packet data calls.
                    pdp_type:
                        aliases: ['pdp-type']
                        type: str
                        description: Packet Data Protocol
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                            - 'ipv4v6'
                    username:
                        type: str
                        description: Authentication username for PDP-IP packet data calls.
            modem1:
                type: dict
                description: Modem1.
                suboptions:
                    carrier_config:
                        aliases: ['carrier-config']
                        type: str
                        description: Carrier-config selection mode.
                        choices:
                            - 'manual'
                            - 'auto-gcf'
                            - 'auto-ptcrb'
                    custom_ipv4_netmask:
                        aliases: ['custom-ipv4-netmask']
                        type: str
                        description: Netmask assigned by the DHCP server.
                    default_gateway:
                        aliases: ['default-gateway']
                        type: str
                        description: Modem interface default gateway.
                        choices:
                            - 'auto'
                            - 'none'
                    default_netmask:
                        aliases: ['default-netmask']
                        type: str
                        description: Modem interface default netmask.
                        choices:
                            - 'auto'
                            - 'custom'
                    gps_service:
                        aliases: ['gps-service']
                        type: str
                        description: Enable/disable Modem online mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    intferface:
                        type: str
                        description: Modem interface.
                    modem_id:
                        aliases: ['modem-id']
                        type: int
                        description: Modem ID.
                    network_type:
                        aliases: ['network-type']
                        type: str
                        description: Modem network type.
                        choices:
                            - 'auto'
                            - '4g|5g'
                            - '3g|4g'
                            - '3g|5g'
                            - '5g'
                            - '4g'
                            - '3g'
                    sim_data_plan:
                        aliases: ['sim-data-plan']
                        type: list
                        elements: str
                        description: Data plan for SIM.
                    sim_pin:
                        aliases: ['sim-pin']
                        type: list
                        elements: str
                        description: PIN code for SIM
                    sim_switch:
                        aliases: ['sim-switch']
                        type: dict
                        description: Sim switch.
                        suboptions:
                            active_sim_slot:
                                aliases: ['active-sim-slot']
                                type: str
                                description: Set active SIM card slot to slot-1 or slot-2.
                                choices:
                                    - 'slot-1'
                                    - 'slot-2'
                            by_connection_state:
                                aliases: ['by-connection-state']
                                type: str
                                description: Enable/disable automatic switch of SIM by MODEM connection state
                                choices:
                                    - 'disable'
                                    - 'enable'
                            by_link_monitor:
                                aliases: ['by-link-monitor']
                                type: str
                                description: Enable/disable automatic switch of SIM by link monitor
                                choices:
                                    - 'disable'
                                    - 'enable'
                            by_sim_state:
                                aliases: ['by-sim-state']
                                type: str
                                description: Enable/disable automatic switch of SIM when MODEM SIM state is empty or in error.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            link_monitor:
                                aliases: ['link-monitor']
                                type: str
                                description: Set link monitor name.
                            modem_disconnection_time:
                                aliases: ['modem-disconnection-time']
                                type: int
                                description: Configure connection-based automatic switch of SIM time interval in seconds
                            sim_switch_log_alert_interval:
                                aliases: ['sim-switch-log-alert-interval']
                                type: int
                                description: When sim-switch > X threshold within Y interval, trigger log event
                            sim_switch_log_alert_threshold:
                                aliases: ['sim-switch-log-alert-threshold']
                                type: int
                                description: When sim-switch > X threshold within Y interval, trigger log event
                    sim1_data_plan:
                        aliases: ['sim1-data-plan']
                        type: list
                        elements: str
                        description: Data plan for SIM #1.
                    sim1_pin:
                        aliases: ['sim1-pin']
                        type: list
                        elements: str
                        description: PIN code for SIM #1
                    sim2_data_plan:
                        aliases: ['sim2-data-plan']
                        type: list
                        elements: str
                        description: Data plan for SIM #2.
                    sim2_pin:
                        aliases: ['sim2-pin']
                        type: list
                        elements: str
                        description: PIN code for SIM #2
                    status:
                        type: str
                        description: Enable/disable Modem online mode.
                        choices:
                            - 'online'
                            - 'low-power'
            modem2:
                type: dict
                description: Modem2.
                suboptions:
                    carrier_config:
                        aliases: ['carrier-config']
                        type: str
                        description: Carrier-config selection mode.
                        choices:
                            - 'manual'
                            - 'auto-gcf'
                            - 'auto-ptcrb'
                    custom_ipv4_netmask:
                        aliases: ['custom-ipv4-netmask']
                        type: str
                        description: Netmask assigned by the DHCP server.
                    default_gateway:
                        aliases: ['default-gateway']
                        type: str
                        description: Modem interface default gateway.
                        choices:
                            - 'auto'
                            - 'none'
                    default_netmask:
                        aliases: ['default-netmask']
                        type: str
                        description: Modem interface default netmask.
                        choices:
                            - 'auto'
                            - 'custom'
                    gps_service:
                        aliases: ['gps-service']
                        type: str
                        description: Enable/disable Modem online mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    intferface:
                        type: str
                        description: Modem interface.
                    modem_id:
                        aliases: ['modem-id']
                        type: int
                        description: Modem ID.
                    network_type:
                        aliases: ['network-type']
                        type: str
                        description: Modem network type.
                        choices:
                            - 'auto'
                            - '4g|5g'
                            - '3g|4g'
                            - '3g|5g'
                            - '5g'
                            - '4g'
                            - '3g'
                    sim_data_plan:
                        aliases: ['sim-data-plan']
                        type: list
                        elements: str
                        description: Data plan for SIM.
                    sim_pin:
                        aliases: ['sim-pin']
                        type: list
                        elements: str
                        description: PIN code for SIM
                    status:
                        type: str
                        description: Enable/disable Modem online mode.
                        choices:
                            - 'online'
                            - 'low-power'
            status:
                type: str
                description: Enable/disable USB 5G modem daemon.
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
    - name: Configure USB 5G modems.
      fortinet.fmgdevice.fmgd_system_5gmodem:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_5gmodem:
          # data_plan:
          #   - apn: <string>
          #     auth_type: <value in [none, pap, chap]>
          #     name: <string>
          #     password: <list or string>
          #     pdp_type: <value in [ipv4, ipv6, ipv4v6]>
          #     username: <string>
          # modem1:
          #   carrier_config: <value in [manual, auto-gcf, auto-ptcrb]>
          #   custom_ipv4_netmask: <string>
          #   default_gateway: <value in [auto, none]>
          #   default_netmask: <value in [auto, custom]>
          #   gps_service: <value in [disable, enable]>
          #   intferface: <string>
          #   modem_id: <integer>
          #   network_type: <value in [auto, 4g|5g, 3g|4g, ...]>
          #   sim_data_plan: <list or string>
          #   sim_pin: <list or string>
          #   sim_switch:
          #     active_sim_slot: <value in [slot-1, slot-2]>
          #     by_connection_state: <value in [disable, enable]>
          #     by_link_monitor: <value in [disable, enable]>
          #     by_sim_state: <value in [disable, enable]>
          #     link_monitor: <string>
          #     modem_disconnection_time: <integer>
          #     sim_switch_log_alert_interval: <integer>
          #     sim_switch_log_alert_threshold: <integer>
          #   sim1_data_plan: <list or string>
          #   sim1_pin: <list or string>
          #   sim2_data_plan: <list or string>
          #   sim2_pin: <list or string>
          #   status: <value in [online, low-power]>
          # modem2:
          #   carrier_config: <value in [manual, auto-gcf, auto-ptcrb]>
          #   custom_ipv4_netmask: <string>
          #   default_gateway: <value in [auto, none]>
          #   default_netmask: <value in [auto, custom]>
          #   gps_service: <value in [disable, enable]>
          #   intferface: <string>
          #   modem_id: <integer>
          #   network_type: <value in [auto, 4g|5g, 3g|4g, ...]>
          #   sim_data_plan: <list or string>
          #   sim_pin: <list or string>
          #   status: <value in [online, low-power]>
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
        '/pm/config/device/{device}/global/system/5g-modem'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_5gmodem': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'data-plan': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'apn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'auth-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'pap', 'chap'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'pdp-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6', 'ipv4v6'], 'type': 'str'},
                        'username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'modem1': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'carrier-config': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['manual', 'auto-gcf', 'auto-ptcrb'], 'type': 'str'},
                        'custom-ipv4-netmask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'default-gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'none'], 'type': 'str'},
                        'default-netmask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'custom'], 'type': 'str'},
                        'gps-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'intferface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'modem-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'network-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['auto', '4g|5g', '3g|4g', '3g|5g', '5g', '4g', '3g'],
                            'type': 'str'
                        },
                        'sim-data-plan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sim-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sim-switch': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'dict',
                            'options': {
                                'active-sim-slot': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['slot-1', 'slot-2'], 'type': 'str'},
                                'by-connection-state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'by-link-monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'by-sim-state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'link-monitor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'modem-disconnection-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'sim-switch-log-alert-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'sim-switch-log-alert-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            }
                        },
                        'sim1-data-plan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sim1-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sim2-data-plan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sim2-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['online', 'low-power'], 'type': 'str'}
                    }
                },
                'modem2': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'carrier-config': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['manual', 'auto-gcf', 'auto-ptcrb'], 'type': 'str'},
                        'custom-ipv4-netmask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'default-gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'none'], 'type': 'str'},
                        'default-netmask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'custom'], 'type': 'str'},
                        'gps-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'intferface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'modem-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'network-type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['auto', '4g|5g', '3g|4g', '3g|5g', '5g', '4g', '3g'],
                            'type': 'str'
                        },
                        'sim-data-plan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sim-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['online', 'low-power'], 'type': 'str'}
                    }
                },
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_5gmodem'),
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
