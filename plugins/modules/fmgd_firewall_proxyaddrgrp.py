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
module: fmgd_firewall_proxyaddrgrp
short_description: Configure web proxy address group.
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
  firewall_proxyaddrgrp:
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
        description: Optional comments.
      member:
        type: list
        elements: str
        description: Members of address group.
      name:
        type: str
        description: Address group name.
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
      type:
        type: str
        description: Source or destination address group type.
        choices: ['src', 'dst']
      uuid:
        type: str
        description: Universally Unique Identifier
      visibility:
        type: str
        description: Enable/disable visibility of the object in the GUI.
        choices: ['disable', 'enable']
      tags:
        type: list
        elements: str
        description: Names of object-tags
      logic_type:
        aliases: ['logic-type']
        type: str
        description: Logic type.
        choices: ['or', 'and']
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
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure web proxy address group.
      fortinet.fmgdevice.fmgd_firewall_proxyaddrgrp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_proxyaddrgrp:
          name: "your value" # Required variable, string
          # _image_base64: <string>
          # color: <integer>
          # comment: <string>
          # member: <list or string>
          # tagging:
          #   - category: <list or string>
          #     name: <string>
          #     tags: <list or string>
          # type: <value in [src, dst]>
          # uuid: <string>
          # visibility: <value in [disable, enable]>
          # tags: <list or string>
          # logic_type: <value in [or, and]>
          # custom_tags: <list or string>
          # display_with: <value in [all-tags, first-tag-only, icon-and-color]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-addrgrp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_proxyaddrgrp': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_image-base64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
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
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['src', 'dst'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'visibility': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'logic-type': {'v_range': [['7.4.9', '7.4.11'], ['7.6.5', '']], 'choices': ['or', 'and'], 'type': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'display-with': {'v_range': [['8.0.0', '']], 'choices': ['all-tags', 'first-tag-only', 'icon-and-color'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_proxyaddrgrp'),
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
