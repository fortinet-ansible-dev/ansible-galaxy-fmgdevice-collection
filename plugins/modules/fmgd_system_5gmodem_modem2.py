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
module: fmgd_system_5gmodem_modem2
short_description: Configure 5G Modem2.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_5gmodem_modem2:
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
      status:
        type: str
        description: Enable/disable Modem online mode.
        choices: ['online', 'low-power']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure 5G Modem2.
      fortinet.fmgdevice.fmgd_system_5gmodem_modem2:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_5gmodem_modem2:
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
          # status: <value in [online, low-power]>
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
        '/pm/config/device/{device}/global/system/5g-modem/modem2'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_5gmodem_modem2': {
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
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['online', 'low-power'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_5gmodem_modem2'),
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
