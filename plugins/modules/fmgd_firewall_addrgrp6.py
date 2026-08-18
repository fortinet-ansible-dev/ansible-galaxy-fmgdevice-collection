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
module: fmgd_firewall_addrgrp6
short_description: Configure IPv6 address groups.
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
  firewall_addrgrp6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _image_base64:
        aliases: ['_image-base64']
        type: str
        description: Image base64.
      color:
        type: int
        description: Integer value to determine the color of the icon in the GUI
      comment:
        type: str
        description: Comment.
      dynamic_mapping:
        type: list
        elements: dict
        description: Dynamic mapping.
        suboptions:
          _image_base64:
            aliases: ['_image-base64']
            type: str
            description: Image base64.
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
          color:
            type: int
            description: Integer value to determine the color of the icon in the GUI
          comment:
            type: str
            description: Comment.
          exclude:
            type: str
            description: Enable/disable address6 exclusion.
            choices: ['disable', 'enable']
          exclude_member:
            aliases: ['exclude-member']
            type: list
            elements: str
            description: Address6 exclusion member.
          fabric_object:
            aliases: ['fabric-object']
            type: str
            description: Security Fabric global object setting.
            choices: ['disable', 'enable']
          global_object:
            aliases: ['global-object']
            type: int
            description: Global object.
          member:
            type: list
            elements: str
            description: Address objects contained within the group.
          tags:
            type: list
            elements: str
            description: Names of object-tags applied to address.
          uuid:
            type: str
            description: Universally Unique Identifier
          visibility:
            type: str
            description: Enable/disable address group6 visibility in the GUI.
            choices: ['disable', 'enable']
          category:
            type: str
            description: Address group category.
            choices: ['default', 'ztna-ems-tag']
          custom_tags:
            aliases: ['custom-tags']
            type: list
            elements: str
            description: Custom tags.
          display_with:
            aliases: ['display-with']
            type: str
            description: Display object with first tag, all tags, or just the icon.
            choices: ['all-tags', 'first-tag-only', 'icon-and-color']
          fabric_force_sync:
            aliases: ['fabric-force-sync']
            type: str
            description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
            choices: ['disable', 'enable']
          fabric_object_source:
            aliases: ['fabric-object-source']
            type: str
            description: Source of truth for fabric object.
            choices: ['member', 'local', 'root']
          type:
            type: str
            description: Address group type.
            choices: ['default', 'dynamic-tag']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      member:
        type: list
        elements: str
        description: Address objects contained within the group.
      name:
        type: str
        description: IPv6 address group name.
        required: true
      tagging:
        type: list
        elements: dict
        description: Tagging.
        suboptions:
          category:
            type: list
            elements: str
            description: Tag category.
          name:
            type: str
            description: Tagging entry name.
          tags:
            type: list
            elements: str
            description: Tags.
      uuid:
        type: str
        description: Universally Unique Identifier
      exclude:
        type: str
        description: Enable/disable address6 exclusion.
        choices: ['disable', 'enable']
      exclude_member:
        aliases: ['exclude-member']
        type: list
        elements: str
        description: Address6 exclusion member.
      global_object:
        aliases: ['global-object']
        type: int
        description: Global object.
      visibility:
        type: str
        description: Enable/disable address group6 visibility in the GUI.
        choices: ['disable', 'enable']
      tags:
        type: list
        elements: str
        description: Names of object-tags applied to address.
      category:
        type: str
        description: Address group category.
        choices: ['default', 'ztna-ems-tag']
      custom_tags:
        aliases: ['custom-tags']
        type: list
        elements: str
        description: Custom tags.
      display_with:
        aliases: ['display-with']
        type: str
        description: Display object with first tag, all tags, or just the icon.
        choices: ['all-tags', 'first-tag-only', 'icon-and-color']
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      type:
        type: str
        description: Address group type.
        choices: ['default', 'dynamic-tag']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 address groups.
      fortinet.fmgdevice.fmgd_firewall_addrgrp6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_addrgrp6:
          name: "your value" # Required variable, string
          # _image_base64: <string>
          # color: <integer>
          # comment: <string>
          # dynamic_mapping:
          #   - _image_base64: <string>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     color: <integer>
          #     comment: <string>
          #     exclude: <value in [disable, enable]>
          #     exclude_member: <list or string>
          #     fabric_object: <value in [disable, enable]>
          #     global_object: <integer>
          #     member: <list or string>
          #     tags: <list or string>
          #     uuid: <string>
          #     visibility: <value in [disable, enable]>
          #     category: <value in [default, ztna-ems-tag]>
          #     custom_tags: <list or string>
          #     display_with: <value in [all-tags, first-tag-only, icon-and-color]>
          #     fabric_force_sync: <value in [disable, enable]>
          #     fabric_object_source: <value in [member, local, root]>
          #     type: <value in [default, dynamic-tag]>
          # fabric_object: <value in [disable, enable]>
          # member: <list or string>
          # tagging:
          #   - category: <list or string>
          #     name: <string>
          #     tags: <list or string>
          # uuid: <string>
          # exclude: <value in [disable, enable]>
          # exclude_member: <list or string>
          # global_object: <integer>
          # visibility: <value in [disable, enable]>
          # tags: <list or string>
          # category: <value in [default, ztna-ems-tag]>
          # custom_tags: <list or string>
          # display_with: <value in [all-tags, first-tag-only, icon-and-color]>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # type: <value in [default, dynamic-tag]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/addrgrp6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_addrgrp6': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_image-base64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_image-base64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'exclude': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'exclude-member': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'fabric-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'global-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'member': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'tags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'visibility': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'category': {'v_range': [['8.0.0', '']], 'choices': ['default', 'ztna-ems-tag'], 'type': 'str'},
                        'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'display-with': {'v_range': [['8.0.0', '']], 'choices': ['all-tags', 'first-tag-only', 'icon-and-color'], 'type': 'str'},
                        'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                        'type': {'v_range': [['8.0.0', '']], 'choices': ['default', 'dynamic-tag'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'member': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'tagging': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'tags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'exclude': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'exclude-member': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'global-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'int'},
                'visibility': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'category': {'v_range': [['8.0.0', '']], 'choices': ['default', 'ztna-ems-tag'], 'type': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'display-with': {'v_range': [['8.0.0', '']], 'choices': ['all-tags', 'first-tag-only', 'icon-and-color'], 'type': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'type': {'v_range': [['8.0.0', '']], 'choices': ['default', 'dynamic-tag'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_addrgrp6'),
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
