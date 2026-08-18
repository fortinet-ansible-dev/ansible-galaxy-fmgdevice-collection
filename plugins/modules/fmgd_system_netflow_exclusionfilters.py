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
module: fmgd_system_netflow_exclusionfilters
short_description: Exclusion filters
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_netflow_exclusionfilters:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      destination_ip:
        aliases: ['destination-ip']
        type: str
        description: Session destination address.
      destination_port:
        aliases: ['destination-port']
        type: str
        description: Session destination port number or range.
      id:
        type: int
        description: Filter ID.
        required: true
      protocol:
        type: int
        description: Session IP protocol
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Session source address.
      source_port:
        aliases: ['source-port']
        type: str
        description: Session source port number or range.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Exclusion filters
      fortinet.fmgdevice.fmgd_system_netflow_exclusionfilters:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        system_netflow_exclusionfilters:
          id: 0 # Required variable, integer
          # destination_ip: <string>
          # destination_port: <string>
          # protocol: <integer>
          # source_ip: <string>
          # source_port: <string>
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
        '/pm/config/device/{device}/global/system/netflow/exclusion-filters'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_netflow_exclusionfilters': {
            'type': 'dict', 'v_range': [['7.6.0', '']],
            'options': {
                'destination-ip': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'destination-port': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'id': {'v_range': [['7.6.0', '']], 'required': True, 'type': 'int'},
                'protocol': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'source-ip': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'source-port': {'v_range': [['7.6.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_netflow_exclusionfilters'),
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
