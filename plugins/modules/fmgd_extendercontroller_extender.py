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
module: fmgd_extendercontroller_extender
short_description: Device vdom extender controller extender
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
    extendercontroller_extender:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _dataplan:
                type: list
                elements: str
                description: Dataplan.
            _template:
                type: list
                elements: str
                description: Template.
            allowaccess:
                type: list
                elements: str
                description: Control management access to the managed extender.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
            authorized:
                type: str
                description: FortiExtender Administration
                choices:
                    - 'disable'
                    - 'enable'
            bandwidth_limit:
                aliases: ['bandwidth-limit']
                type: int
                description: FortiExtender LAN extension bandwidth limit
            description:
                type: str
                description: Description.
            device_id:
                aliases: ['device-id']
                type: int
                description: Device ID.
            enforce_bandwidth:
                aliases: ['enforce-bandwidth']
                type: str
                description: Enable/disable enforcement of bandwidth on LAN extension interface.
                choices:
                    - 'disable'
                    - 'enable'
            ext_name:
                aliases: ['ext-name']
                type: str
                description: FortiExtender name.
            extension_type:
                aliases: ['extension-type']
                type: str
                description: Extension type for this FortiExtender.
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            id:
                type: str
                description: FortiExtender serial number.
                required: true
            login_password:
                aliases: ['login-password']
                type: list
                elements: str
                description: Set the managed extenders administrator password.
            login_password_change:
                aliases: ['login-password-change']
                type: str
                description: Change or reset the administrator password of a managed extender
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            name:
                type: str
                description: FortiExtender entry name.
            override_allowaccess:
                aliases: ['override-allowaccess']
                type: str
                description: Enable to override the extender profile management access configuration.
                choices:
                    - 'disable'
                    - 'enable'
            override_enforce_bandwidth:
                aliases: ['override-enforce-bandwidth']
                type: str
                description: Enable to override the extender profile enforce-bandwidth setting.
                choices:
                    - 'disable'
                    - 'enable'
            override_login_password_change:
                aliases: ['override-login-password-change']
                type: str
                description: Enable to override the extender profile login-password
                choices:
                    - 'disable'
                    - 'enable'
            profile:
                type: list
                elements: str
                description: FortiExtender profile configuration.
            vdom:
                type: int
                description: Vdom.
            wan_extension:
                aliases: ['wan-extension']
                type: dict
                description: Wan extension.
                suboptions:
                    modem1_extension:
                        aliases: ['modem1-extension']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem2_extension:
                        aliases: ['modem2-extension']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
            modem1:
                type: dict
                description: Modem1.
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
            modem2:
                type: dict
                description: Modem2.
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
            controller_report:
                aliases: ['controller-report']
                type: dict
                description: Controller report.
                suboptions:
                    interval:
                        type: int
                        description: Controller report interval.
                    signal_threshold:
                        aliases: ['signal-threshold']
                        type: int
                        description: Controller report signal threshold.
                    status:
                        type: str
                        description: FortiExtender controller report status.
                        choices:
                            - 'disable'
                            - 'enable'
            ppp_echo_request:
                aliases: ['ppp-echo-request']
                type: str
                description: Enable/disable PPP echo request.
                choices:
                    - 'disable'
                    - 'enable'
            ppp_username:
                aliases: ['ppp-username']
                type: str
                description: PPP username.
            initiated_update:
                aliases: ['initiated-update']
                type: str
                description: Allow/disallow network initiated updates to the MODEM.
                choices:
                    - 'disable'
                    - 'enable'
            cdma_aaa_spi:
                aliases: ['cdma-aaa-spi']
                type: str
                description: CDMA AAA SPI.
            redial:
                type: str
                description: Number of redials allowed based on failed attempts.
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
            ha_shared_secret:
                aliases: ['ha-shared-secret']
                type: list
                elements: str
                description: HA shared secret.
            ppp_auth_protocol:
                aliases: ['ppp-auth-protocol']
                type: str
                description: PPP authentication protocol
                choices:
                    - 'auto'
                    - 'pap'
                    - 'chap'
            secondary_ha:
                aliases: ['secondary-ha']
                type: str
                description: Secondary HA.
            ppp_password:
                aliases: ['ppp-password']
                type: list
                elements: str
                description: PPP password.
            at_dial_script:
                aliases: ['at-dial-script']
                type: str
                description: Initialization AT commands specific to the MODEM.
            ifname:
                type: list
                elements: str
                description: FortiExtender interface name.
            cdma_nai:
                aliases: ['cdma-nai']
                type: str
                description: NAI for CDMA MODEMS.
            billing_start_day:
                aliases: ['billing-start-day']
                type: int
                description: Billing start day.
            wimax_carrier:
                aliases: ['wimax-carrier']
                type: str
                description: WiMax carrier.
            aaa_shared_secret:
                aliases: ['aaa-shared-secret']
                type: list
                elements: str
                description: AAA shared secret.
            primary_ha:
                aliases: ['primary-ha']
                type: str
                description: Primary HA.
            cdma_ha_spi:
                aliases: ['cdma-ha-spi']
                type: str
                description: CDMA HA SPI.
            dial_status:
                aliases: ['dial-status']
                type: int
                description: Dial status.
            modem_passwd:
                aliases: ['modem-passwd']
                type: list
                elements: str
                description: MODEM password.
            roaming:
                type: str
                description: Enable/disable MODEM roaming.
                choices:
                    - 'disable'
                    - 'enable'
            dial_mode:
                aliases: ['dial-mode']
                type: str
                description: Dial mode
                choices:
                    - 'dial-on-demand'
                    - 'always-connect'
            multi_mode:
                aliases: ['multi-mode']
                type: str
                description: MODEM mode of operation
                choices:
                    - 'auto'
                    - 'auto-3g'
                    - 'force-lte'
                    - 'force-3g'
                    - 'force-2g'
            mode:
                type: str
                description: FortiExtender mode.
                choices:
                    - 'standalone'
                    - 'redundant'
            sim_pin:
                aliases: ['sim-pin']
                type: list
                elements: str
                description: SIM PIN.
            modem_type:
                aliases: ['modem-type']
                type: str
                description: MODEM type
                choices:
                    - 'cdma'
                    - 'gsm/lte'
                    - 'wimax'
            redundant_intf:
                aliases: ['redundant-intf']
                type: str
                description: Redundant interface.
            role:
                type: str
                description: FortiExtender work role
                choices:
                    - 'none'
                    - 'primary'
                    - 'secondary'
            access_point_name:
                aliases: ['access-point-name']
                type: str
                description: Access point name
            wimax_realm:
                aliases: ['wimax-realm']
                type: str
                description: WiMax realm.
            wimax_auth_protocol:
                aliases: ['wimax-auth-protocol']
                type: str
                description: WiMax authentication protocol
                choices:
                    - 'tls'
                    - 'ttls'
            quota_limit_mb:
                aliases: ['quota-limit-mb']
                type: int
                description: Monthly quota limit
            admin:
                type: str
                description: FortiExtender Administration
                choices:
                    - 'disable'
                    - 'enable'
                    - 'discovered'
            conn_status:
                aliases: ['conn-status']
                type: int
                description: Conn status.
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
    - name: Device vdom extender controller extender
      fortinet.fmgdevice.fmgd_extendercontroller_extender:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        extendercontroller_extender:
          id: "your value" # Required variable, string
          # _dataplan: <list or string>
          # _template: <list or string>
          # allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          # authorized: <value in [disable, enable]>
          # bandwidth_limit: <integer>
          # description: <string>
          # device_id: <integer>
          # enforce_bandwidth: <value in [disable, enable]>
          # ext_name: <string>
          # extension_type: <value in [wan-extension, lan-extension]>
          # login_password: <list or string>
          # login_password_change: <value in [no, yes, default]>
          # name: <string>
          # override_allowaccess: <value in [disable, enable]>
          # override_enforce_bandwidth: <value in [disable, enable]>
          # override_login_password_change: <value in [disable, enable]>
          # profile: <list or string>
          # vdom: <integer>
          # wan_extension:
          #   modem1_extension: <list or string>
          #   modem2_extension: <list or string>
          # modem1:
          #   _ifname: <list or string>
          #   _sim_profile: <list or string>
          #   auto_switch:
          #     dataplan: <value in [disable, enable]>
          #     disconnect: <value in [disable, enable]>
          #     disconnect_period: <integer>
          #     disconnect_threshold: <integer>
          #     signal: <value in [disable, enable]>
          #     switch_back:
          #       - "time"
          #       - "timer"
          #     switch_back_time: <string>
          #     switch_back_timer: <integer>
          #     status: <value in [disable, enable]>
          #   conn_status: <integer>
          #   default_sim: <value in [sim1, sim2, carrier, ...]>
          #   gps: <value in [disable, enable]>
          #   ifname: <list or string>
          #   modem_id: <integer>
          #   preferred_carrier: <string>
          #   redundant_intf: <string>
          #   redundant_mode: <value in [disable, enable]>
          #   sim1_pin: <value in [disable, enable]>
          #   sim1_pin_code: <list or string>
          #   sim2_pin: <value in [disable, enable]>
          #   sim2_pin_code: <list or string>
          #   status: <value in [disable, enable]>
          # modem2:
          #   _ifname: <list or string>
          #   _sim_profile: <list or string>
          #   auto_switch:
          #     dataplan: <value in [disable, enable]>
          #     disconnect: <value in [disable, enable]>
          #     disconnect_period: <integer>
          #     disconnect_threshold: <integer>
          #     signal: <value in [disable, enable]>
          #     switch_back:
          #       - "time"
          #       - "timer"
          #     switch_back_time: <string>
          #     switch_back_timer: <integer>
          #     status: <value in [disable, enable]>
          #   conn_status: <integer>
          #   default_sim: <value in [sim1, sim2, carrier, ...]>
          #   gps: <value in [disable, enable]>
          #   ifname: <list or string>
          #   modem_id: <integer>
          #   preferred_carrier: <string>
          #   redundant_intf: <string>
          #   redundant_mode: <value in [disable, enable]>
          #   sim1_pin: <value in [disable, enable]>
          #   sim1_pin_code: <list or string>
          #   sim2_pin: <value in [disable, enable]>
          #   sim2_pin_code: <list or string>
          #   status: <value in [disable, enable]>
          # controller_report:
          #   interval: <integer>
          #   signal_threshold: <integer>
          #   status: <value in [disable, enable]>
          # ppp_echo_request: <value in [disable, enable]>
          # ppp_username: <string>
          # initiated_update: <value in [disable, enable]>
          # cdma_aaa_spi: <string>
          # redial: <value in [none, 1, 2, ...]>
          # ha_shared_secret: <list or string>
          # ppp_auth_protocol: <value in [auto, pap, chap]>
          # secondary_ha: <string>
          # ppp_password: <list or string>
          # at_dial_script: <string>
          # ifname: <list or string>
          # cdma_nai: <string>
          # billing_start_day: <integer>
          # wimax_carrier: <string>
          # aaa_shared_secret: <list or string>
          # primary_ha: <string>
          # cdma_ha_spi: <string>
          # dial_status: <integer>
          # modem_passwd: <list or string>
          # roaming: <value in [disable, enable]>
          # dial_mode: <value in [dial-on-demand, always-connect]>
          # multi_mode: <value in [auto, auto-3g, force-lte, ...]>
          # mode: <value in [standalone, redundant]>
          # sim_pin: <list or string>
          # modem_type: <value in [cdma, gsm/lte, wimax]>
          # redundant_intf: <string>
          # role: <value in [none, primary, secondary]>
          # access_point_name: <string>
          # wimax_realm: <string>
          # wimax_auth_protocol: <value in [tls, ttls]>
          # quota_limit_mb: <integer>
          # admin: <value in [disable, enable, discovered]>
          # conn_status: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'extendercontroller_extender': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                '_dataplan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                '_template': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet'],
                    'elements': 'str'
                },
                'authorized': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bandwidth-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'device-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'enforce-bandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'extension-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['wan-extension', 'lan-extension'], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'login-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'login-password-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['no', 'yes', 'default'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'override-allowaccess': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-enforce-bandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-login-password-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wan-extension': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'modem1-extension': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'modem2-extension': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'modem1': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
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
                                'switch-back': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'type': 'list',
                                    'choices': ['time', 'timer'],
                                    'elements': 'str'
                                },
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
                },
                'modem2': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
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
                                'switch-back': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'type': 'list',
                                    'choices': ['time', 'timer'],
                                    'elements': 'str'
                                },
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
                },
                'controller-report': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'signal-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ppp-echo-request': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ppp-username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'initiated-update': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cdma-aaa-spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'redial': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['none', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
                    'type': 'str'
                },
                'ha-shared-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ppp-auth-protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'pap', 'chap'], 'type': 'str'},
                'secondary-ha': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ppp-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'at-dial-script': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ifname': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'cdma-nai': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'billing-start-day': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wimax-carrier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'aaa-shared-secret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'primary-ha': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cdma-ha-spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dial-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'modem-passwd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'roaming': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dial-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['dial-on-demand', 'always-connect'], 'type': 'str'},
                'multi-mode': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['auto', 'auto-3g', 'force-lte', 'force-3g', 'force-2g'],
                    'type': 'str'
                },
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['standalone', 'redundant'], 'type': 'str'},
                'sim-pin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'modem-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['cdma', 'gsm/lte', 'wimax'], 'type': 'str'},
                'redundant-intf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'primary', 'secondary'], 'type': 'str'},
                'access-point-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'wimax-realm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'wimax-auth-protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['tls', 'ttls'], 'type': 'str'},
                'quota-limit-mb': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'admin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'discovered'], 'type': 'str'},
                'conn-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extendercontroller_extender'),
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
