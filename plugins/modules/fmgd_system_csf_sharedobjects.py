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
module: fmgd_system_csf_sharedobjects
short_description: Fabric-wide objects shared by non-root nodes.
version_added: "1.2.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_csf_sharedobjects:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      name:
        type: str
        description: UID of the source device.
        required: true
      objects:
        type: list
        elements: dict
        description: Objects.
        suboptions:
          keys:
            type: list
            elements: dict
            description: Keys.
            suboptions:
              name:
                type: list
                elements: str
                description: Key.
          pathname:
            type: str
            description: CMDB path and object name.
      trusted_list_entry:
        aliases: ['trusted-list-entry']
        type: list
        elements: str
        description: Trusted list entry name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Fabric-wide objects shared by non-root nodes.
      fortinet.fmgdevice.fmgd_system_csf_sharedobjects:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_csf_sharedobjects:
          name: "your value" # Required variable, string
          # objects:
          #   - keys:
          #       - name: <list or string>
          #     pathname: <string>
          # trusted_list_entry: <list or string>
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
        '/pm/config/device/{device}/global/system/csf/shared-objects'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_csf_sharedobjects': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'objects': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'keys': {
                            'v_range': [['8.0.0', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {'name': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}},
                            'elements': 'dict'
                        },
                        'pathname': {'v_range': [['8.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'trusted-list-entry': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf_sharedobjects'),
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
