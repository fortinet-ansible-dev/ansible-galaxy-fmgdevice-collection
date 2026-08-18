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
module: fmgd_system_interface_wifinetworks
short_description: WiFi network table.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  interface:
    description: The parameter (interface) in requested url.
    type: str
    required: true
  system_interface_wifinetworks:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      id:
        type: int
        description: ID.
        required: true
      obsolete_security_options:
        aliases: ['obsolete-security-options']
        type: str
        description: Enable/disable obsolete security options.
        choices: ['disable', 'enable']
      wifi_ca_certificate:
        aliases: ['wifi-ca-certificate']
        type: list
        elements: str
        description: CA certificate for WPA2/WPA3-ENTERPRISE.
      wifi_client_certificate:
        aliases: ['wifi-client-certificate']
        type: list
        elements: str
        description: Client certificate for WPA2/WPA3-ENTERPRISE.
      wifi_eap_type:
        aliases: ['wifi-eap-type']
        type: str
        description: WPA2/WPA3-ENTERPRISE EAP Method.
        choices: ['tls', 'peap', 'both']
      wifi_encrypt:
        aliases: ['wifi-encrypt']
        type: str
        description: Data encryption.
        choices: ['TKIP', 'AES']
      wifi_key:
        aliases: ['wifi-key']
        type: list
        elements: str
        description: WiFi WEP Key.
      wifi_keyindex:
        aliases: ['wifi-keyindex']
        type: int
        description: WEP key index
      wifi_passphrase:
        aliases: ['wifi-passphrase']
        type: list
        elements: str
        description: WiFi pre-shared key for WPA-PSK or password for WPA3-SAE and WPA2/WPA3-ENTERPRISE.
      wifi_private_key:
        aliases: ['wifi-private-key']
        type: str
        description: Private key for WPA2/WPA3-ENTERPRISE.
      wifi_private_key_password:
        aliases: ['wifi-private-key-password']
        type: list
        elements: str
        description: Password for private key file for WPA2/WPA3-ENTERPRISE.
      wifi_security:
        aliases: ['wifi-security']
        type: str
        description: Wireless access security of SSID.
        choices: ['wep64', 'wep128', 'open', 'wpa-personal', 'wpa-enterprise',
                  'wpa-only-personal', 'wpa2-only-personal', 'owe', 'wpa3-sae']
      wifi_ssid:
        aliases: ['wifi-ssid']
        type: str
        description: IEEE 802.
      wifi_username:
        aliases: ['wifi-username']
        type: str
        description: Username for WPA2/WPA3-ENTERPRISE.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: WiFi network table.
      fortinet.fmgdevice.fmgd_system_interface_wifinetworks:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        interface: <your own value>
        state: present # <value in [present, absent]>
        system_interface_wifinetworks:
          id: 0 # Required variable, integer
          # obsolete_security_options: <value in [disable, enable]>
          # wifi_ca_certificate: <list or string>
          # wifi_client_certificate: <list or string>
          # wifi_eap_type: <value in [tls, peap, both]>
          # wifi_encrypt: <value in [TKIP, AES]>
          # wifi_key: <list or string>
          # wifi_keyindex: <integer>
          # wifi_passphrase: <list or string>
          # wifi_private_key: <string>
          # wifi_private_key_password: <list or string>
          # wifi_security: <value in [wep64, wep128, open, ...]>
          # wifi_ssid: <string>
          # wifi_username: <string>
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
        '/pm/config/device/{device}/global/system/interface/{interface}/wifi-networks'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'system_interface_wifinetworks': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'obsolete-security-options': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wifi-ca-certificate': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'wifi-client-certificate': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'wifi-eap-type': {'v_range': [['7.4.3', '']], 'choices': ['tls', 'peap', 'both'], 'type': 'str'},
                'wifi-encrypt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['TKIP', 'AES'], 'type': 'str'},
                'wifi-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'wifi-keyindex': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'wifi-passphrase': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'wifi-private-key': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'wifi-private-key-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'wifi-security': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['wep64', 'wep128', 'open', 'wpa-personal', 'wpa-enterprise', 'wpa-only-personal', 'wpa2-only-personal', 'owe', 'wpa3-sae'],
                    'type': 'str'
                },
                'wifi-ssid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'wifi-username': {'v_range': [['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface_wifinetworks'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
