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
module: fmgd_system_acme
short_description: Configure ACME client.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_acme:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      accounts:
        type: list
        elements: dict
        description: Accounts.
        suboptions:
          ca_url:
            type: str
            description: Account ca_url.
          email:
            type: str
            description: Account email.
          id:
            type: str
            description: Account id.
          privatekey:
            type: str
            description: Account Private Key.
          status:
            type: str
            description: Account status.
          url:
            type: str
            description: Account url.
          eab_key_hmac:
            aliases: ['eab-key-hmac']
            type: list
            elements: str
            description: External Acccount Binding Key HMAC.
          eab_key_id:
            aliases: ['eab-key-id']
            type: str
            description: External Acccount Binding Key ID.
      interface:
        type: list
        elements: str
        description: Interface
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IPv4 address used to connect to the ACME server.
      source_ip6:
        aliases: ['source-ip6']
        type: str
        description: Source IPv6 address used to connect to the ACME server.
      store_passphrase:
        aliases: ['store-passphrase']
        type: list
        elements: str
        description: Mod_md store passphrase
      use_ha_direct:
        aliases: ['use-ha-direct']
        type: str
        description: Enable the use of ha-mgmt interface to connect to the ACME server when ha-direct is enabled in HA configuration
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure ACME client.
      fortinet.fmgdevice.fmgd_system_acme:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_acme:
          # accounts:
          #   - ca_url: <string>
          #     email: <string>
          #     id: <string>
          #     privatekey: <string>
          #     status: <string>
          #     url: <string>
          #     eab_key_hmac: <list or string>
          #     eab_key_id: <string>
          # interface: <list or string>
          # source_ip: <string>
          # source_ip6: <string>
          # store_passphrase: <list or string>
          # use_ha_direct: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/acme'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_acme': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'accounts': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'ca_url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'email': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'privatekey': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'eab-key-hmac': {'v_range': [['7.6.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'eab-key-id': {'v_range': [['7.6.3', '']], 'no_log': True, 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'store-passphrase': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'use-ha-direct': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_acme'),
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
