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
module: fmgd_switchcontroller_acl_ingress
short_description: Configure ingress ACL policies to be applied on managed FortiSwitch ports.
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
  switchcontroller_acl_ingress:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: dict
        description: Action.
        suboptions:
          count:
            type: str
            description: Enable/disable count.
            choices: ['disable', 'enable']
          drop:
            type: str
            description: Enable/disable drop.
            choices: ['disable', 'enable']
      classifier:
        type: dict
        description: Classifier.
        suboptions:
          dst_ip_prefix:
            aliases: ['dst-ip-prefix']
            type: list
            elements: str
            description: Destination IP address to be matched.
          dst_mac:
            aliases: ['dst-mac']
            type: str
            description: Destination MAC address to be matched.
          src_ip_prefix:
            aliases: ['src-ip-prefix']
            type: list
            elements: str
            description: Source IP address to be matched.
          src_mac:
            aliases: ['src-mac']
            type: str
            description: Source MAC address to be matched.
          vlan:
            type: int
            description: VLAN ID to be matched.
      description:
        type: str
        description: Description for the ACL policy.
      id:
        type: int
        description: ACL ID.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure ingress ACL policies to be applied on managed FortiSwitch ports.
      fortinet.fmgdevice.fmgd_switchcontroller_acl_ingress:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_acl_ingress:
          id: 0 # Required variable, integer
          # action:
          #   count: <value in [disable, enable]>
          #   drop: <value in [disable, enable]>
          # classifier:
          #   dst_ip_prefix: <list or string>
          #   dst_mac: <string>
          #   src_ip_prefix: <list or string>
          #   src_mac: <string>
          #   vlan: <integer>
          # description: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_acl_ingress': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'action': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'count': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'drop': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'classifier': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'dst-ip-prefix': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'dst-mac': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'src-ip-prefix': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'src-mac': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'vlan': {'v_range': [['7.4.3', '']], 'type': 'int'}
                    }
                },
                'description': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'id': {'v_range': [['7.4.3', '']], 'required': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_acl_ingress'),
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
