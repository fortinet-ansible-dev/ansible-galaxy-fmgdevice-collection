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
module: fmgd_system_csf_trustedlist
short_description: Pre-authorized and blocked security fabric nodes.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_csf_trustedlist:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Security fabric authorization action.
        choices: ['deny', 'accept']
      authorization_type:
        aliases: ['authorization-type']
        type: str
        description: Authorization type.
        choices: ['certificate', 'serial']
      certificate:
        type: str
        description: Certificate.
      downstream_authorization:
        aliases: ['downstream-authorization']
        type: str
        description: Trust authorizations by this nodes administrator.
        choices: ['disable', 'enable']
      ha_members:
        aliases: ['ha-members']
        type: list
        elements: str
        description: HA members.
      index:
        type: int
        description: Index of the downstream in tree.
      name:
        type: str
        description: Name.
        required: true
      serial:
        type: str
        description: Serial.
      guaranteed_seats:
        aliases: ['guaranteed-seats']
        type: int
        description: Guaranteed seats.
      preferred_seats:
        aliases: ['preferred-seats']
        type: int
        description: Preferred seats.
      ca:
        type: list
        elements: str
        description: Name of a CA on the downstreams certificat chain.
      ca_fingerprint:
        aliases: ['ca-fingerprint']
        type: str
        description: SHA512 fingerprint of a CA on the downstreams certificate chain.
      cn:
        type: list
        elements: str
        description: Certificate CNs used by HA members.
      last_use_time:
        aliases: ['last-use-time']
        type: str
        description: Time when an CSF member authorized by this entry was last observed.
      role:
        type: str
        description: Device role to this member.
        choices: ['downstream', 'upstream']
      upgraded:
        type: str
        description: Updrade triggered for upstream auth.
        choices: ['no', 'yes']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Pre-authorized and blocked security fabric nodes.
      fortinet.fmgdevice.fmgd_system_csf_trustedlist:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_csf_trustedlist:
          name: "your value" # Required variable, string
          # action: <value in [deny, accept]>
          # authorization_type: <value in [certificate, serial]>
          # certificate: <string>
          # downstream_authorization: <value in [disable, enable]>
          # ha_members: <list or string>
          # index: <integer>
          # serial: <string>
          # guaranteed_seats: <integer>
          # preferred_seats: <integer>
          # ca: <list or string>
          # ca_fingerprint: <string>
          # cn: <list or string>
          # last_use_time: <string>
          # role: <value in [downstream, upstream]>
          # upgraded: <value in [no, yes]>
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
        '/pm/config/device/{device}/global/system/csf/trusted-list'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_csf_trustedlist': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'authorization-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                'certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'downstream-authorization': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ha-members': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'index': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'serial': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'guaranteed-seats': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'preferred-seats': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ca': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'ca-fingerprint': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'cn': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'last-use-time': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'role': {'v_range': [['8.0.0', '']], 'choices': ['downstream', 'upstream'], 'type': 'str'},
                'upgraded': {'v_range': [['8.0.0', '']], 'choices': ['no', 'yes'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf_trustedlist'),
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
