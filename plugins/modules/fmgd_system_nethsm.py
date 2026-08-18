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
module: fmgd_system_nethsm
short_description: Device system nethsm
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_nethsm:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ha:
        type: str
        description: Ha.
        choices: ['disable', 'enable']
      ha_status_pulling_interval:
        aliases: ['ha-status-pulling-interval']
        type: int
        description: Ha status pulling interval.
      hagroups:
        type: list
        elements: dict
        description: Hagroups.
        suboptions:
          member:
            type: list
            elements: str
            description: Member.
          name:
            type: str
            description: Name.
      interface:
        type: list
        elements: str
        description: Interface.
      partitions:
        type: list
        elements: dict
        description: Partitions.
        suboptions:
          name:
            type: str
            description: Name.
          pkcs11_pin:
            aliases: ['pkcs11-pin']
            type: list
            elements: str
            description: Pkcs11 pin.
          slot_id:
            aliases: ['slot-id']
            type: int
            description: Slot id.
      primus_cfg:
        aliases: ['primus-cfg']
        type: str
        description: Primus cfg.
      receivetimeout:
        type: int
        description: Receivetimeout.
      rsa_mech_remap:
        aliases: ['rsa-mech-remap']
        type: str
        description: Rsa mech remap.
        choices: ['disable', 'enable']
      secret_content:
        aliases: ['secret-content']
        type: list
        elements: str
        description: Secret content.
      servers:
        type: list
        elements: dict
        description: Servers.
        suboptions:
          htl:
            type: str
            description: Htl.
            choices: ['disable', 'enable']
          name:
            type: str
            description: Name.
          port:
            type: int
            description: Port.
          server:
            type: str
            description: Server.
          server_cert:
            aliases: ['server-cert']
            type: str
            description: Server cert.
      slots:
        type: list
        elements: dict
        description: Slots.
        suboptions:
          for_ha:
            aliases: ['for-ha']
            type: str
            description: For ha.
            choices: ['no', 'yes']
          id:
            type: int
            description: Id.
          name:
            type: str
            description: Name.
          password:
            type: list
            elements: str
            description: Password.
      status:
        type: str
        description: Status.
        choices: ['disable', 'enable']
      vendor:
        type: str
        description: Vendor.
        choices: ['SafeNet', 'safenet', 'primus']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device system nethsm
      fortinet.fmgdevice.fmgd_system_nethsm:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_nethsm:
          # ha: <value in [disable, enable]>
          # ha_status_pulling_interval: <integer>
          # hagroups:
          #   - member: <list or string>
          #     name: <string>
          # interface: <list or string>
          # partitions:
          #   - name: <string>
          #     pkcs11_pin: <list or string>
          #     slot_id: <integer>
          # primus_cfg: <string>
          # receivetimeout: <integer>
          # rsa_mech_remap: <value in [disable, enable]>
          # secret_content: <list or string>
          # servers:
          #   - htl: <value in [disable, enable]>
          #     name: <string>
          #     port: <integer>
          #     server: <string>
          #     server_cert: <string>
          # slots:
          #   - for_ha: <value in [no, yes]>
          #     id: <integer>
          #     name: <string>
          #     password: <list or string>
          # status: <value in [disable, enable]>
          # vendor: <value in [SafeNet, safenet, primus]>
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
        '/pm/config/device/{device}/global/system/nethsm'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_nethsm': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'ha': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-status-pulling-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'hagroups': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'member': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'partitions': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'pkcs11-pin': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'slot-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'primus-cfg': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'receivetimeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'rsa-mech-remap': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secret-content': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'servers': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'htl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'server-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'slots': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'for-ha': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vendor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['SafeNet', 'safenet', 'primus'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_nethsm'),
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
