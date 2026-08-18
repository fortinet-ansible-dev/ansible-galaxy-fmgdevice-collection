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
module: fmgd_wireless_mpskprofile
short_description: Configure MPSK profile.
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
  wireless_mpskprofile:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      mpsk_concurrent_clients:
        aliases: ['mpsk-concurrent-clients']
        type: int
        description: Maximum number of concurrent clients that connect using the same passphrase in multiple PSK authentication
      mpsk_external_server:
        aliases: ['mpsk-external-server']
        type: list
        elements: str
        description: RADIUS server to be used to authenticate MPSK users.
      mpsk_external_server_auth:
        aliases: ['mpsk-external-server-auth']
        type: str
        description: Enable/Disable MPSK external server authentication
        choices: ['disable', 'enable']
      mpsk_group:
        aliases: ['mpsk-group']
        type: list
        elements: dict
        description: Mpsk group.
        suboptions:
          mpsk_key:
            aliases: ['mpsk-key']
            type: list
            elements: dict
            description: Mpsk key.
            suboptions:
              comment:
                type: str
                description: Comment.
              concurrent_client_limit_type:
                aliases: ['concurrent-client-limit-type']
                type: str
                description: MPSK client limit type options.
                choices: ['default', 'unlimited', 'specified']
              concurrent_clients:
                aliases: ['concurrent-clients']
                type: int
                description: Number of clients that can connect using this pre-shared key
              key_type:
                aliases: ['key-type']
                type: str
                description: Select the type of the key.
                choices: ['wpa2-personal', 'wpa3-sae']
              mac:
                type: str
                description: MAC address.
              mpsk_schedules:
                aliases: ['mpsk-schedules']
                type: list
                elements: str
                description: Firewall schedule for MPSK passphrase.
              name:
                type: str
                description: Pre-shared key name.
              passphrase:
                type: list
                elements: str
                description: WPA Pre-shared key.
              pmk:
                type: list
                elements: str
                description: WPA PMK.
              sae_password:
                aliases: ['sae-password']
                type: list
                elements: str
                description: WPA3 SAE password.
              sae_pk:
                aliases: ['sae-pk']
                type: str
                description: Enable/disable WPA3 SAE-PK
                choices: ['disable', 'enable']
              sae_private_key:
                aliases: ['sae-private-key']
                type: str
                description: Private key used for WPA3 SAE-PK authentication.
          name:
            type: str
            description: MPSK group name.
          vlan_id:
            aliases: ['vlan-id']
            type: int
            description: Optional VLAN ID.
          vlan_type:
            aliases: ['vlan-type']
            type: str
            description: MPSK group VLAN options.
            choices: ['no-vlan', 'fixed-vlan']
      mpsk_type:
        aliases: ['mpsk-type']
        type: str
        description: Select the security type of keys for this profile.
        choices: ['wpa2-personal', 'wpa3-sae', 'wpa3-sae-transition']
      name:
        type: str
        description: MPSK profile name.
        required: true
      ssid:
        type: str
        description: SSID of the VAP in which the MPSK profile is configured.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure MPSK profile.
      fortinet.fmgdevice.fmgd_wireless_mpskprofile:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        wireless_mpskprofile:
          name: "your value" # Required variable, string
          # mpsk_concurrent_clients: <integer>
          # mpsk_external_server: <list or string>
          # mpsk_external_server_auth: <value in [disable, enable]>
          # mpsk_group:
          #   - mpsk_key:
          #       - comment: <string>
          #         concurrent_client_limit_type: <value in [default, unlimited, specified]>
          #         concurrent_clients: <integer>
          #         key_type: <value in [wpa2-personal, wpa3-sae]>
          #         mac: <string>
          #         mpsk_schedules: <list or string>
          #         name: <string>
          #         passphrase: <list or string>
          #         pmk: <list or string>
          #         sae_password: <list or string>
          #         sae_pk: <value in [disable, enable]>
          #         sae_private_key: <string>
          #     name: <string>
          #     vlan_id: <integer>
          #     vlan_type: <value in [no-vlan, fixed-vlan]>
          # mpsk_type: <value in [wpa2-personal, wpa3-sae, wpa3-sae-transition]>
          # ssid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wireless_mpskprofile': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'mpsk-concurrent-clients': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'mpsk-external-server': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mpsk-external-server-auth': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mpsk-group': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'mpsk-key': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'comment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'concurrent-client-limit-type': {
                                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                                    'choices': ['default', 'unlimited', 'specified'],
                                    'type': 'str'
                                },
                                'concurrent-clients': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                                'key-type': {'v_range': [['7.4.3', '']], 'choices': ['wpa2-personal', 'wpa3-sae'], 'type': 'str'},
                                'mac': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'mpsk-schedules': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'passphrase': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'pmk': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'sae-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'sae-pk': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'sae-private-key': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'vlan-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'vlan-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['no-vlan', 'fixed-vlan'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mpsk-type': {'v_range': [['7.4.3', '']], 'choices': ['wpa2-personal', 'wpa3-sae', 'wpa3-sae-transition'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'ssid': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_mpskprofile'),
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
