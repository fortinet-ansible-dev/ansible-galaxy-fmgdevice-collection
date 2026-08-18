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
module: fmgd_system_5gmodem_modem1
short_description: Configure 5G Modem1.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_5gmodem_modem1:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      carrier_config:
        aliases: ['carrier-config']
        type: str
        description: Carrier-config selection mode.
        choices: ['manual', 'auto-gcf', 'auto-ptcrb']
      custom_ipv4_netmask:
        aliases: ['custom-ipv4-netmask']
        type: str
        description: Netmask assigned by the DHCP server.
      default_gateway:
        aliases: ['default-gateway']
        type: str
        description: Modem interface default gateway.
        choices: ['auto', 'none']
      default_netmask:
        aliases: ['default-netmask']
        type: str
        description: Modem interface default netmask.
        choices: ['auto', 'custom']
      gps_service:
        aliases: ['gps-service']
        type: str
        description: Enable/disable Modem online mode.
        choices: ['disable', 'enable']
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
        choices: ['auto', '4g|5g', '3g|4g', '3g|5g', '5g', '4g', '3g']
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
            choices: ['slot-1', 'slot-2']
          by_connection_state:
            aliases: ['by-connection-state']
            type: str
            description: Enable/disable automatic switch of SIM by MODEM connection state
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
        choices: ['online', 'low-power']
      esim:
        type: str
        description: Enable/disable eSIM on SLOT-2.
        choices: ['disable', 'enable']
      gps_antenna_type:
        aliases: ['gps-antenna-type']
        type: str
        description: GPS antenna type used on the GNSS port
        choices: ['active', 'passive']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure 5G Modem1.
      fortinet.fmgdevice.fmgd_system_5gmodem_modem1:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_5gmodem_modem1:
          # carrier_config: <value in [manual, auto-gcf, auto-ptcrb]>
          # custom_ipv4_netmask: <string>
          # default_gateway: <value in [auto, none]>
          # default_netmask: <value in [auto, custom]>
          # gps_service: <value in [disable, enable]>
          # intferface: <string>
          # modem_id: <integer>
          # network_type: <value in [auto, 4g|5g, 3g|4g, ...]>
          # sim_data_plan: <list or string>
          # sim_pin: <list or string>
          # sim_switch:
          #   active_sim_slot: <value in [slot-1, slot-2]>
          #   by_connection_state: <value in [disable, enable]>
          #   by_link_monitor: <value in [disable, enable]>
          #   by_sim_state: <value in [disable, enable]>
          #   link_monitor: <string>
          #   modem_disconnection_time: <integer>
          #   sim_switch_log_alert_interval: <integer>
          #   sim_switch_log_alert_threshold: <integer>
          # sim1_data_plan: <list or string>
          # sim1_pin: <list or string>
          # sim2_data_plan: <list or string>
          # sim2_pin: <list or string>
          # status: <value in [online, low-power]>
          # esim: <value in [disable, enable]>
          # gps_antenna_type: <value in [active, passive]>
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
        '/pm/config/device/{device}/global/system/5g-modem/modem1'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_5gmodem_modem1': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'carrier-config': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['manual', 'auto-gcf', 'auto-ptcrb'], 'type': 'str'},
                'custom-ipv4-netmask': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'default-gateway': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'none'], 'type': 'str'},
                'default-netmask': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'custom'], 'type': 'str'},
                'gps-service': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intferface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'modem-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'network-type': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['auto', '4g|5g', '3g|4g', '3g|5g', '5g', '4g', '3g'],
                    'type': 'str'
                },
                'sim-data-plan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim-pin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim-switch': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'active-sim-slot': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['slot-1', 'slot-2'], 'type': 'str'},
                        'by-connection-state': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'by-link-monitor': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'by-sim-state': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'link-monitor': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'modem-disconnection-time': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'sim-switch-log-alert-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'sim-switch-log-alert-threshold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    }
                },
                'sim1-data-plan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim1-pin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim2-data-plan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sim2-pin': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['online', 'low-power'], 'type': 'str'},
                'esim': {'v_range': [['7.4.11', '7.4.11'], ['7.6.7', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gps-antenna-type': {'v_range': [['7.6.7', '7.6.7']], 'choices': ['active', 'passive'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_5gmodem_modem1'),
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
