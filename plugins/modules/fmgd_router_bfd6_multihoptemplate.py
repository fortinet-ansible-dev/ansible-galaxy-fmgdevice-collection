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
module: fmgd_router_bfd6_multihoptemplate
short_description: BFD IPv6 multi-hop template table.
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
  router_bfd6_multihoptemplate:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auth_mode:
        aliases: ['auth-mode']
        type: str
        description: Authentication mode.
        choices: ['none', 'md5']
      bfd_desired_min_tx:
        aliases: ['bfd-desired-min-tx']
        type: int
        description: BFD desired minimal transmit interval
      bfd_detect_mult:
        aliases: ['bfd-detect-mult']
        type: int
        description: BFD detection multiplier.
      bfd_required_min_rx:
        aliases: ['bfd-required-min-rx']
        type: int
        description: BFD required minimal receive interval
      dst:
        type: str
        description: Destination prefix.
      id:
        type: int
        description: ID.
        required: true
      md5_key:
        aliases: ['md5-key']
        type: list
        elements: str
        description: MD5 key of key ID 1.
      src:
        type: str
        description: Source prefix.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: BFD IPv6 multi-hop template table.
      fortinet.fmgdevice.fmgd_router_bfd6_multihoptemplate:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_bfd6_multihoptemplate:
          id: 0 # Required variable, integer
          # auth_mode: <value in [none, md5]>
          # bfd_desired_min_tx: <integer>
          # bfd_detect_mult: <integer>
          # bfd_required_min_rx: <integer>
          # dst: <string>
          # md5_key: <list or string>
          # src: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/multihop-template'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_bfd6_multihoptemplate': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'auth-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'md5'], 'type': 'str'},
                'bfd-desired-min-tx': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'bfd-detect-mult': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'bfd-required-min-rx': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'dst': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'md5-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'src': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_bfd6_multihoptemplate'),
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
