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
module: fmgd_casb_saasapplication
short_description: Configure CASB SaaS application.
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
  casb_saasapplication:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      casb_name:
        aliases: ['casb-name']
        type: str
        description: SaaS application signature name.
      description:
        type: str
        description: SaaS application description.
      domains:
        type: list
        elements: str
        description: SaaS application domain list.
      name:
        type: str
        description: SaaS application name.
        required: true
      status:
        type: str
        description: Enable/disable setting.
        choices: ['disable', 'enable']
      type:
        type: str
        description: SaaS application type.
        choices: ['built-in', 'customized']
      uuid:
        type: str
        description: Universally Unique Identifier
      output_attributes:
        aliases: ['output-attributes']
        type: list
        elements: dict
        description: Output attributes.
        suboptions:
          attr_type:
            aliases: ['attr-type']
            type: str
            description: Attr type.
            choices: ['tenant']
          description:
            type: str
            description: CASB attribute description.
          name:
            type: str
            description: CASB attribute name.
          optional:
            type: str
            description: CASB output attribute optional.
            choices: ['disable', 'enable']
          required:
            type: str
            description: Required.
            choices: ['disable', 'enable']
          type:
            type: str
            description: CASB attribute format type.
            choices: ['string', 'string-list', 'integer', 'integer-list', 'boolean']
      input_attributes:
        aliases: ['input-attributes']
        type: list
        elements: dict
        description: Input attributes.
        suboptions:
          attr_type:
            aliases: ['attr-type']
            type: str
            description: Attr type.
            choices: ['tenant']
          default:
            type: str
            description: CASB attribute default value.
            choices: ['string', 'string-list']
          description:
            type: str
            description: CASB attribute description.
          fallback_input:
            aliases: ['fallback-input']
            type: str
            description: CASB attribute legacy input.
            choices: ['disable', 'enable']
          name:
            type: str
            description: CASB attribute name.
          required:
            type: str
            description: CASB input attribute required.
            choices: ['disable', 'enable']
          type:
            type: str
            description: CASB attribute format type.
            choices: ['string', 'string-list', 'integer', 'integer-list', 'boolean']
      category:
        type: str
        description: SaaS application signature category.
      display_name:
        aliases: ['display-name']
        type: str
        description: SaaS application signature display name.
      icon_id:
        aliases: ['icon-id']
        type: int
        description: SaaS application signature icon ID.
      popularity:
        type: int
        description: SaaS application signature popularity.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure CASB SaaS application.
      fortinet.fmgdevice.fmgd_casb_saasapplication:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        casb_saasapplication:
          name: "your value" # Required variable, string
          # casb_name: <string>
          # description: <string>
          # domains: <list or string>
          # status: <value in [disable, enable]>
          # type: <value in [built-in, customized]>
          # uuid: <string>
          # output_attributes:
          #   - attr_type: <value in [tenant]>
          #     description: <string>
          #     name: <string>
          #     optional: <value in [disable, enable]>
          #     required: <value in [disable, enable]>
          #     type: <value in [string, string-list, integer, ...]>
          # input_attributes:
          #   - attr_type: <value in [tenant]>
          #     default: <value in [string, string-list]>
          #     description: <string>
          #     fallback_input: <value in [disable, enable]>
          #     name: <string>
          #     required: <value in [disable, enable]>
          #     type: <value in [string, string-list, integer, ...]>
          # category: <string>
          # display_name: <string>
          # icon_id: <integer>
          # popularity: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/casb/saas-application'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'casb_saasapplication': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'casb-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'description': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'domains': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['built-in', 'customized'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'output-attributes': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'attr-type': {'v_range': [['7.6.4', '']], 'choices': ['tenant'], 'type': 'str'},
                        'description': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'name': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'optional': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'required': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.6.4', '']], 'choices': ['string', 'string-list', 'integer', 'integer-list', 'boolean'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'input-attributes': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'attr-type': {'v_range': [['7.6.4', '']], 'choices': ['tenant'], 'type': 'str'},
                        'default': {'v_range': [['7.6.4', '']], 'choices': ['string', 'string-list'], 'type': 'str'},
                        'description': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'fallback-input': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'required': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.6.4', '']], 'choices': ['string', 'string-list', 'integer', 'integer-list', 'boolean'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'category': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'display-name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'icon-id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'popularity': {'v_range': [['8.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'casb_saasapplication'),
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
