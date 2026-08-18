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
module: fmgd_system_wireless_settings
short_description: Wireless radio configuration.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_wireless_settings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      band:
        type: str
        description: Band.
        choices: ['802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G',
                  '802.11g-only', '802.11n-only', '802.11ng-only', '802.11ac-only',
                  '802.11acn-only', '802.11n-5G-only']
      beacon_interval:
        aliases: ['beacon-interval']
        type: int
        description: Beacon level
      bgscan:
        type: str
        description: Enable/disable background rogue AP scan.
        choices: ['disable', 'enable']
      bgscan_idle:
        aliases: ['bgscan-idle']
        type: int
        description: Interval between scanning channels
      bgscan_interval:
        aliases: ['bgscan-interval']
        type: int
        description: Interval between two rounds of scanning
      channel:
        type: int
        description: Channel.
      channel_bonding:
        aliases: ['channel-bonding']
        type: str
        description: Supported channel width.
        choices: ['disable', 'enable']
      geography:
        type: str
        description: Geography.
        choices: ['World', 'Americas', 'EMEA', 'Israel', 'Japan']
      mode:
        type: str
        description: Mode.
        choices: ['AP', 'CLIENT', 'SCAN']
      power_level:
        aliases: ['power-level']
        type: int
        description: Power level
      rogue_scan:
        aliases: ['rogue-scan']
        type: str
        description: Enable/disable rogue scan.
        choices: ['disable', 'enable']
      rogue_scan_mac_adjacency:
        aliases: ['rogue-scan-mac-adjacency']
        type: int
        description: MAC adjacency
      short_guard_interval:
        aliases: ['short-guard-interval']
        type: str
        description: Enable/disable short guard interval.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Wireless radio configuration.
      fortinet.fmgdevice.fmgd_system_wireless_settings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_wireless_settings:
          # band: <value in [802.11b, 802.11a, 802.11g, ...]>
          # beacon_interval: <integer>
          # bgscan: <value in [disable, enable]>
          # bgscan_idle: <integer>
          # bgscan_interval: <integer>
          # channel: <integer>
          # channel_bonding: <value in [disable, enable]>
          # geography: <value in [World, Americas, EMEA, ...]>
          # mode: <value in [AP, CLIENT, SCAN]>
          # power_level: <integer>
          # rogue_scan: <value in [disable, enable]>
          # rogue_scan_mac_adjacency: <integer>
          # short_guard_interval: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/wireless/settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_wireless_settings': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'band': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        '802.11b', '802.11a', '802.11g', '802.11n', '802.11ac', '802.11n-5G', '802.11g-only', '802.11n-only', '802.11ng-only',
                        '802.11ac-only', '802.11acn-only', '802.11n-5G-only'
                    ],
                    'type': 'str'
                },
                'beacon-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'bgscan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bgscan-idle': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'bgscan-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'channel': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'channel-bonding': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'geography': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['World', 'Americas', 'EMEA', 'Israel', 'Japan'], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['AP', 'CLIENT', 'SCAN'], 'type': 'str'},
                'power-level': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'rogue-scan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rogue-scan-mac-adjacency': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'short-guard-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_wireless_settings'),
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
