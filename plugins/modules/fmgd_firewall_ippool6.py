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
module: fmgd_firewall_ippool6
short_description: Configure IPv6 IP pools.
version_added: "1.1.0"
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
  firewall_ippool6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      add_nat46_route:
        aliases: ['add-nat46-route']
        type: str
        description: Enable/disable adding NAT46 route.
        choices: ['disable', 'enable']
      comments:
        type: str
        description:
          - Support meta variable
          - Comment.
      dynamic_mapping:
        type: list
        elements: dict
        description: Dynamic mapping.
        suboptions:
          _scope:
            type: list
            elements: dict
            description: Scope.
            suboptions:
              name:
                type: str
                description: Name.
              vdom:
                type: str
                description: Vdom.
          add_nat46_route:
            aliases: ['add-nat46-route']
            type: str
            description: Enable/disable adding NAT46 route.
            choices: ['disable', 'enable']
          comments:
            type: str
            description:
              - Support meta variable
              - Comment.
          endip:
            type: str
            description:
              - Support meta variable
              - Final IPv6 address
          nat46:
            type: str
            description: Enable/disable NAT46.
            choices: ['disable', 'enable']
          startip:
            type: str
            description:
              - Support meta variable
              - First IPv6 address
          external_prefix:
            aliases: ['external-prefix']
            type: str
            description:
              - Support meta variable
              - External NPTv6 prefix length
          internal_prefix:
            aliases: ['internal-prefix']
            type: str
            description:
              - Support meta variable
              - Internal NPTv6 prefix length
          type:
            type: str
            description: Configure IPv6 pool type
            choices: ['overload', 'nptv6']
          fabric_force_sync:
            aliases: ['fabric-force-sync']
            type: str
            description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
            choices: ['disable', 'enable']
          fabric_object:
            aliases: ['fabric-object']
            type: str
            description: Security Fabric global object setting.
            choices: ['disable', 'enable']
          fabric_object_source:
            aliases: ['fabric-object-source']
            type: str
            description: Source of truth for fabric object.
            choices: ['member', 'local', 'root']
          uuid:
            type: str
            description: Universally Unique Identifier
      endip:
        type: str
        description:
          - Support meta variable
          - Final IPv6 address
      name:
        type: str
        description:
          - Support meta variable
          - IPv6 IP pool name.
        required: true
      nat46:
        type: str
        description: Enable/disable NAT46.
        choices: ['disable', 'enable']
      startip:
        type: str
        description:
          - Support meta variable
          - First IPv6 address
      internal_prefix:
        aliases: ['internal-prefix']
        type: str
        description:
          - Support meta variable
          - Internal NPTv6 prefix length
      external_prefix:
        aliases: ['external-prefix']
        type: str
        description:
          - Support meta variable
          - External NPTv6 prefix length
      type:
        type: str
        description: Configure IPv6 pool type
        choices: ['overload', 'nptv6']
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 IP pools.
      fortinet.fmgdevice.fmgd_firewall_ippool6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_ippool6:
          name: "your value" # Required variable, string
          # add_nat46_route: <value in [disable, enable]>
          # comments: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     add_nat46_route: <value in [disable, enable]>
          #     comments: <string>
          #     endip: <string>
          #     nat46: <value in [disable, enable]>
          #     startip: <string>
          #     external_prefix: <string>
          #     internal_prefix: <string>
          #     type: <value in [overload, nptv6]>
          #     fabric_force_sync: <value in [disable, enable]>
          #     fabric_object: <value in [disable, enable]>
          #     fabric_object_source: <value in [member, local, root]>
          #     uuid: <string>
          # endip: <string>
          # nat46: <value in [disable, enable]>
          # startip: <string>
          # internal_prefix: <string>
          # external_prefix: <string>
          # type: <value in [overload, nptv6]>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/ippool6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_ippool6': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'add-nat46-route': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'add-nat46-route': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'comments': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'endip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'nat46': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'startip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'external-prefix': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'internal-prefix': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'type': {'v_range': [['7.6.4', '']], 'choices': ['overload', 'nptv6'], 'type': 'str'},
                        'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                        'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'endip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'nat46': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'startip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'internal-prefix': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'external-prefix': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'type': {'v_range': [['7.6.4', '']], 'choices': ['overload', 'nptv6'], 'type': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ippool6'),
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
