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
module: fmgd_system_ltemodem
short_description: Configure USB LTE/WIMAX devices.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_ltemodem:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      allow_modify_mtu_size:
        aliases: ['allow-modify-mtu-size']
        type: str
        description: Allow FortiGate to modify the wireless WAN interface MTU size.
        choices: ['disable', 'enable']
      allow_modify_wireless_profile_table:
        aliases: ['allow-modify-wireless-profile-table']
        type: str
        description: Allow FortiGate to modify the wireless profile table if the internal LTE modem is running the GENERIC modem firmware.
        choices: ['disable', 'enable']
      apn:
        type: str
        description: Login APN string for PDP-IP packet data calls.
      authtype:
        type: str
        description: Authentication type for PDP-IP packet data calls.
        choices: ['none', 'pap', 'chap', 'both']
      auto_connect:
        aliases: ['auto-connect']
        type: str
        description: Enable/disable modem auto connect.
        choices: ['disable', 'enable']
      band_restrictions:
        aliases: ['band-restrictions']
        type: str
        description: Bitmaps for the allowed 3G and LTE bands.
      data_plan:
        aliases: ['data-plan']
        type: list
        elements: dict
        description: Data plan.
        suboptions:
          billing_date:
            aliases: ['billing-date']
            type: int
            description: LTE MODEM billing date
          billing_hour:
            aliases: ['billing-hour']
            type: int
            description: LTE MODEM billing hour
          billing_period:
            aliases: ['billing-period']
            type: str
            description: No description
            choices: ['daily', 'weekly', 'monthly']
          billing_weekday:
            aliases: ['billing-weekday']
            type: str
            description: LTE MODEM billing weekday
            choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']
          data_limit:
            aliases: ['data-limit']
            type: int
            description: LTE MODEM data limit in megabytes
          data_limit_alert:
            aliases: ['data-limit-alert']
            type: int
            description: LTE MODEM data usage percentage at which to trigger log.
          delay_switch_time:
            aliases: ['delay-switch-time']
            type: str
            description: Instead of SIM switching shortly after data limit is reached, schedule a delay switch time in format hh
          iccid:
            type: str
            description: Dedicated data plan to specific ICCID.
          name:
            type: str
            description: Data plan name.
          overage:
            type: str
            description: Enable/disable allowance of data overage as configured by data-limit
            choices: ['disable', 'enable']
          target_sim_slot:
            aliases: ['target-sim-slot']
            type: str
            description: Target sim slot
            choices: ['SIM-slot-1', 'SIM-slot-2']
      data_usage_tracking:
        aliases: ['data-usage-tracking']
        type: str
        description: Enable/disable data usage tracking.
        choices: ['disable', 'enable']
      dhcp_relay:
        aliases: ['dhcp-relay']
        type: str
        description: Enable/disable DHCP relay over modem.
        choices: ['disable', 'enable']
      extra_init:
        aliases: ['extra-init']
        type: str
        description: Extra initialization string for USB LTE/WIMAX devices.
      force_wireless_profile:
        aliases: ['force-wireless-profile']
        type: int
        description: Force to use wireless profile index
      gps_port:
        aliases: ['gps-port']
        type: int
        description: Modem GPS port index
      gps_service:
        aliases: ['gps-service']
        type: str
        description: Enable/disable GPS daemon.
        choices: ['disable', 'enable']
      holddown_timer:
        aliases: ['holddown-timer']
        type: int
        description: Hold down timer
      image_preference:
        aliases: ['image-preference']
        type: str
        description: Modem Image Preference.
        choices: ['auto-sim', 'generic', 'att', 'verizon', 'telus', 'docomo', 'softbank',
                  'sprint', 'no-change']
      interface:
        type: list
        elements: str
        description: The interface that the modem is acting as a redundant interface for.
      manual_handover:
        aliases: ['manual-handover']
        type: str
        description: Enable/Disable manual handover from 3G to LTE network.
        choices: ['disable', 'enable']
      mode:
        type: str
        description: Modem operation mode.
        choices: ['standalone', 'redundant']
      modem_port:
        aliases: ['modem-port']
        type: int
        description: Modem port index
      network_type:
        aliases: ['network-type']
        type: str
        description: Wireless network type.
        choices: ['auto', 'umts-3g', 'lte', 'cdma-hrpd']
      override_gateway:
        aliases: ['override-gateway']
        type: str
        description: Enable/disable LTE gateway override
        choices: ['disable', 'enable']
      passwd:
        type: list
        elements: str
        description: Authentication password for PDP-IP packet data calls.
      pdptype:
        type: str
        description: Packet Data Protocol
        choices: ['IPv4', 'IPv6', 'IPv4v6']
      sim_switch:
        aliases: ['sim-switch']
        type: dict
        description: Sim switch.
        suboptions:
          by_connection_state:
            aliases: ['by-connection-state']
            type: str
            description: Enable/disable automatic switch of SIM by MODEM connection state
            choices: ['disable', 'enable']
          by_data_plan:
            aliases: ['by-data-plan']
            type: str
            description: Enable/disable SIM auto switch by data-plan config.
            choices: ['disable', 'enable']
          by_link_monitor:
            aliases: ['by-link-monitor']
            type: str
            description: Enable/disable automatic switch of SIM by link monitor
            choices: ['disable', 'enable']
          by_sim_state:
            aliases: ['by-sim-state']
            type: str
            description: Enable/disable automatic switch of SIM when MODEM SIM state is empty or in error.
            choices: ['disable', 'enable']
          link_monitor:
            aliases: ['link-monitor']
            type: list
            elements: str
            description: Set link monitor name.
          modem_disconnection_time:
            aliases: ['modem-disconnection-time']
            type: int
            description: Configure connection-based automatic switch of SIM time interval in seconds
          sim_slot:
            aliases: ['sim-slot']
            type: int
            description: SIM card slot
          sim_switch_log_alert_interval:
            aliases: ['sim-switch-log-alert-interval']
            type: int
            description: When sim-switch > X threshold within Y interval, trigger log event
          sim_switch_log_alert_threshold:
            aliases: ['sim-switch-log-alert-threshold']
            type: int
            description: When sim-switch > X threshold within Y interval, trigger log event
      sim1_pin:
        aliases: ['sim1-pin']
        type: list
        elements: str
        description: PIN code for SIM #1
      sim2_pin:
        aliases: ['sim2-pin']
        type: list
        elements: str
        description: PIN code for SIM #2
      status:
        type: str
        description: Enable/disable USB LTE/WIMAX device.
        choices: ['disable', 'enable']
      username:
        type: str
        description: Authentication username for PDP-IP packet data calls.
      data_limit:
        aliases: ['data-limit']
        type: int
        description: LTE Modem data limit
      sim_slot:
        aliases: ['sim-slot']
        type: int
        description: SIM card slot
      billing_date:
        aliases: ['billing-date']
        type: int
        description: LTE Modem billing date
      connection_hot_swap:
        aliases: ['connection-hot-swap']
        type: str
        description: Set connection-based SIM card hot swap time interval.
        choices: ['never', '5-minutes', '10-minutes']
      sim_hot_swap:
        aliases: ['sim-hot-swap']
        type: str
        description: Enable/disable SIM card auto detection and hot swap.
        choices: ['disable', 'enable']
      connection_auto_switch:
        aliases: ['connection-auto-switch']
        type: str
        description: Connection auto switch.
        choices: ['disable', 'enable']
      sim_auto_switch:
        aliases: ['sim-auto-switch']
        type: str
        description: Sim auto switch.
        choices: ['disable', 'enable']
      gpsd_enabled:
        aliases: ['gpsd-enabled']
        type: str
        description: Gpsd enabled.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure USB LTE/WIMAX devices.
      fortinet.fmgdevice.fmgd_system_ltemodem:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_ltemodem:
          # allow_modify_mtu_size: <value in [disable, enable]>
          # allow_modify_wireless_profile_table: <value in [disable, enable]>
          # apn: <string>
          # authtype: <value in [none, pap, chap, ...]>
          # auto_connect: <value in [disable, enable]>
          # band_restrictions: <string>
          # data_plan:
          #   - billing_date: <integer>
          #     billing_hour: <integer>
          #     billing_period: <value in [daily, weekly, monthly]>
          #     billing_weekday: <value in [sunday, monday, tuesday, ...]>
          #     data_limit: <integer>
          #     data_limit_alert: <integer>
          #     delay_switch_time: <string>
          #     iccid: <string>
          #     name: <string>
          #     overage: <value in [disable, enable]>
          #     target_sim_slot: <value in [SIM-slot-1, SIM-slot-2]>
          # data_usage_tracking: <value in [disable, enable]>
          # dhcp_relay: <value in [disable, enable]>
          # extra_init: <string>
          # force_wireless_profile: <integer>
          # gps_port: <integer>
          # gps_service: <value in [disable, enable]>
          # holddown_timer: <integer>
          # image_preference: <value in [auto-sim, generic, att, ...]>
          # interface: <list or string>
          # manual_handover: <value in [disable, enable]>
          # mode: <value in [standalone, redundant]>
          # modem_port: <integer>
          # network_type: <value in [auto, umts-3g, lte, ...]>
          # override_gateway: <value in [disable, enable]>
          # passwd: <list or string>
          # pdptype: <value in [IPv4, IPv6, IPv4v6]>
          # sim_switch:
          #   by_connection_state: <value in [disable, enable]>
          #   by_data_plan: <value in [disable, enable]>
          #   by_link_monitor: <value in [disable, enable]>
          #   by_sim_state: <value in [disable, enable]>
          #   link_monitor: <list or string>
          #   modem_disconnection_time: <integer>
          #   sim_slot: <integer>
          #   sim_switch_log_alert_interval: <integer>
          #   sim_switch_log_alert_threshold: <integer>
          # sim1_pin: <list or string>
          # sim2_pin: <list or string>
          # status: <value in [disable, enable]>
          # username: <string>
          # data_limit: <integer>
          # sim_slot: <integer>
          # billing_date: <integer>
          # connection_hot_swap: <value in [never, 5-minutes, 10-minutes]>
          # sim_hot_swap: <value in [disable, enable]>
          # connection_auto_switch: <value in [disable, enable]>
          # sim_auto_switch: <value in [disable, enable]>
          # gpsd_enabled: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/lte-modem'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_ltemodem': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'allow-modify-mtu-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allow-modify-wireless-profile-table': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'apn': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'authtype': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'pap', 'chap', 'both'], 'type': 'str'},
                'auto-connect': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'band-restrictions': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'data-plan': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'billing-date': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'billing-hour': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'billing-period': {'v_range': [['7.4.3', '']], 'choices': ['daily', 'weekly', 'monthly'], 'type': 'str'},
                        'billing-weekday': {
                            'v_range': [['7.4.3', '']],
                            'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                            'type': 'str'
                        },
                        'data-limit': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'data-limit-alert': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'delay-switch-time': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'iccid': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'overage': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'target-sim-slot': {'v_range': [['7.4.3', '']], 'choices': ['SIM-slot-1', 'SIM-slot-2'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'data-usage-tracking': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-relay': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extra-init': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'force-wireless-profile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'gps-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'gps-service': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'holddown-timer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'image-preference': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['auto-sim', 'generic', 'att', 'verizon', 'telus', 'docomo', 'softbank', 'sprint', 'no-change'],
                    'type': 'str'
                },
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'manual-handover': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['standalone', 'redundant'], 'type': 'str'},
                'modem-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'network-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'umts-3g', 'lte', 'cdma-hrpd'], 'type': 'str'},
                'override-gateway': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'passwd': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'pdptype': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['IPv4', 'IPv6', 'IPv4v6'], 'type': 'str'},
                'sim-switch': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'by-connection-state': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'by-data-plan': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'by-link-monitor': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'by-sim-state': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'link-monitor': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'modem-disconnection-time': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'sim-slot': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'sim-switch-log-alert-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'sim-switch-log-alert-threshold': {'v_range': [['7.4.3', '']], 'type': 'int'}
                    }
                },
                'sim1-pin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim2-pin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'data-limit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'sim-slot': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'billing-date': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'connection-hot-swap': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['never', '5-minutes', '10-minutes'], 'type': 'str'},
                'sim-hot-swap': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'connection-auto-switch': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sim-auto-switch': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gpsd-enabled': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_ltemodem'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
