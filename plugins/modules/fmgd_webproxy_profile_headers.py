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
module: fmgd_webproxy_profile_headers
short_description: Configure HTTP forwarded requests headers.
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
  profile:
    description: The parameter (profile) in requested url.
    type: str
    required: true
  webproxy_profile_headers:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      action:
        type: str
        description: Configure adding, removing, or logging of the HTTP header entry in HTTP requests and responses.
        choices: ['add-to-request', 'add-to-response', 'remove-from-request',
                  'remove-from-response', 'monitor-request', 'monitor-response']
      add_option:
        aliases: ['add-option']
        type: str
        description: Configure options to append content to existing HTTP header or add new HTTP header.
        choices: ['append', 'new-on-not-found', 'new', 'replace', 'replace-when-match']
      base64_encoding:
        aliases: ['base64-encoding']
        type: str
        description: Enable/disable use of base64 encoding of HTTP content.
        choices: ['disable', 'enable']
      content:
        type: str
        description: HTTP header content.
      dstaddr:
        type: list
        elements: str
        description: Destination address and address group names.
      dstaddr6:
        type: list
        elements: str
        description: Destination address and address group names
      id:
        type: int
        description: HTTP forwarded header id.
        required: true
      name:
        type: str
        description: HTTP forwarded header name.
      protocol:
        type: list
        elements: str
        description: Configure protocol
        choices: ['https', 'http']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure HTTP forwarded requests headers.
      fortinet.fmgdevice.fmgd_webproxy_profile_headers:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        state: present # <value in [present, absent]>
        webproxy_profile_headers:
          id: 0 # Required variable, integer
          # action: <value in [add-to-request, add-to-response, remove-from-request, ...]>
          # add_option: <value in [append, new-on-not-found, new, ...]>
          # base64_encoding: <value in [disable, enable]>
          # content: <string>
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # name: <string>
          # protocol: ["https", "http"]
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
        '/pm/config/device/{device}/vdom/{vdom}/web-proxy/profile/{profile}/headers'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'webproxy_profile_headers': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'action': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['add-to-request', 'add-to-response', 'remove-from-request', 'remove-from-response', 'monitor-request', 'monitor-response'],
                    'type': 'str'
                },
                'add-option': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['append', 'new-on-not-found', 'new', 'replace', 'replace-when-match'],
                    'type': 'str'
                },
                'base64-encoding': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'content': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dstaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'choices': ['https', 'http'], 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_profile_headers'),
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
