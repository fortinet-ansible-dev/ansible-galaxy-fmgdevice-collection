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
module: fmgd_wireless_bleprofile
short_description: Configure Bluetooth Low Energy profile.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  wireless_bleprofile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      advertising:
        type: list
        elements: str
        description: Advertising type.
        choices: ['ibeacon', 'eddystone-uid', 'eddystone-url']
      beacon_interval:
        aliases: ['beacon-interval']
        type: int
        description: Beacon interval
      ble_scanning:
        aliases: ['ble-scanning']
        type: str
        description: Enable/disable Bluetooth Low Energy
        choices: ['disable', 'enable']
      comment:
        type: str
        description: Comment.
      eddystone_instance:
        aliases: ['eddystone-instance']
        type: str
        description: Eddystone instance ID.
      eddystone_namespace:
        aliases: ['eddystone-namespace']
        type: str
        description: Eddystone namespace ID.
      eddystone_url:
        aliases: ['eddystone-url']
        type: str
        description: Eddystone URL.
      eddystone_url_encode_hex:
        aliases: ['eddystone-url-encode-hex']
        type: str
        description: Eddystone encoded URL hexadecimal string
      ibeacon_uuid:
        aliases: ['ibeacon-uuid']
        type: str
        description: Universally Unique Identifier
      major_id:
        aliases: ['major-id']
        type: int
        description: Major ID.
      minor_id:
        aliases: ['minor-id']
        type: int
        description: Minor ID.
      name:
        type: str
        description: Bluetooth Low Energy profile name.
        required: true
      scan_interval:
        aliases: ['scan-interval']
        type: int
        description: Scan Interval
      scan_period:
        aliases: ['scan-period']
        type: int
        description: Scan Period
      scan_threshold:
        aliases: ['scan-threshold']
        type: str
        description: Minimum signal level/threshold in dBm required for the AP to report detected BLE device
      scan_time:
        aliases: ['scan-time']
        type: int
        description: Scan Time
      scan_type:
        aliases: ['scan-type']
        type: str
        description: Scan Type
        choices: ['active', 'passive']
      scan_window:
        aliases: ['scan-window']
        type: int
        description: Scan Windows
      txpower:
        type: str
        description: Transmit power level
        choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14',
                  '15', '16', '17']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure Bluetooth Low Energy profile.
      fortinet.fmgdevice.fmgd_wireless_bleprofile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_bleprofile:
          name: "your value" # Required variable, string
          # advertising: ["ibeacon", "eddystone-uid", "eddystone-url"]
          # beacon_interval: <integer>
          # ble_scanning: <value in [disable, enable]>
          # comment: <string>
          # eddystone_instance: <string>
          # eddystone_namespace: <string>
          # eddystone_url: <string>
          # eddystone_url_encode_hex: <string>
          # ibeacon_uuid: <string>
          # major_id: <integer>
          # minor_id: <integer>
          # scan_interval: <integer>
          # scan_period: <integer>
          # scan_threshold: <string>
          # scan_time: <integer>
          # scan_type: <value in [active, passive]>
          # scan_window: <integer>
          # txpower: <value in [0, 1, 2, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ble-profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_bleprofile': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'advertising': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['ibeacon', 'eddystone-uid', 'eddystone-url'],
                    'elements': 'str'
                },
                'beacon-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ble-scanning': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-instance': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-namespace': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'eddystone-url-encode-hex': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ibeacon-uuid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'major-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'minor-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'scan-interval': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'scan-period': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'scan-threshold': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'scan-time': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'scan-type': {'v_range': [['7.4.3', '']], 'choices': ['active', 'passive'], 'type': 'str'},
                'scan-window': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'txpower': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_bleprofile'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
