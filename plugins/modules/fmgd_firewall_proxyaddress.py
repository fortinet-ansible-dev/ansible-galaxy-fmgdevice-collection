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
module: fmgd_firewall_proxyaddress
short_description: Configure web proxy address.
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
  firewall_proxyaddress:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _image_base64:
        aliases: ['_image-base64']
        type: str
        description: Image base64.
      application:
        type: list
        elements: str
        description: SaaS application.
      case_sensitivity:
        aliases: ['case-sensitivity']
        type: str
        description: Enable to make the pattern case sensitive.
        choices: ['disable', 'enable']
      category:
        type: list
        elements: str
        description: FortiGuard category ID.
      color:
        type: int
        description: Integer value to determine the color of the icon in the GUI
      comment:
        type: str
        description: Optional comments.
      header:
        type: str
        description: HTTP header name as a regular expression.
      header_group:
        aliases: ['header-group']
        type: list
        elements: dict
        description: Header group.
        suboptions:
          case_sensitivity:
            aliases: ['case-sensitivity']
            type: str
            description: Case sensitivity in pattern.
            choices: ['disable', 'enable']
          header:
            type: str
            description: HTTP header regular expression.
          header_name:
            aliases: ['header-name']
            type: str
            description: HTTP header.
          id:
            type: int
            description: ID.
      header_name:
        aliases: ['header-name']
        type: str
        description: Name of HTTP header.
      host:
        type: list
        elements: str
        description: Address object for the host.
      host_regex:
        aliases: ['host-regex']
        type: str
        description: Host name as a regular expression.
      method:
        type: list
        elements: str
        description: HTTP request methods to be used.
        choices: ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'connect', 'other',
                  'update', 'patch', 'query']
      name:
        type: str
        description: Address name.
        required: true
      path:
        type: str
        description: URL path as a regular expression.
      post_arg:
        aliases: ['post-arg']
        type: str
        description: Post arg.
        choices: ['disable', 'enable']
      query:
        type: str
        description: Match the query part of the URL as a regular expression.
      referrer:
        type: str
        description: Enable/disable use of referrer field in the HTTP header to match the address.
        choices: ['disable', 'enable']
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
        description: Proxy address type.
        choices: ['host-regex', 'url', 'category', 'method', 'ua', 'header', 'src-advanced',
                  'dst-advanced', 'url-list', 'saas', 'response-header', 'llm-server']
      ua:
        type: list
        elements: str
        description: Names of browsers to be used as user agent.
        choices: ['chrome', 'ms', 'firefox', 'safari', 'other', 'ie', 'edge']
      ua_max_ver:
        aliases: ['ua-max-ver']
        type: str
        description: Maximum version of the user agent specified in dotted notation.
      ua_min_ver:
        aliases: ['ua-min-ver']
        type: str
        description: Minimum version of the user agent specified in dotted notation.
      url_list:
        aliases: ['url-list']
        type: list
        elements: str
        description: Url list.
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
      llm_servers:
        aliases: ['llm-servers']
        type: list
        elements: str
        description: Llm servers.
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
    - name: Configure web proxy address.
      fortinet.fmgdevice.fmgd_firewall_proxyaddress:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_proxyaddress:
          name: "your value" # Required variable, string
          # _image_base64: <string>
          # application: <list or string>
          # case_sensitivity: <value in [disable, enable]>
          # category: <list or string>
          # color: <integer>
          # comment: <string>
          # header: <string>
          # header_group:
          #   - case_sensitivity: <value in [disable, enable]>
          #     header: <string>
          #     header_name: <string>
          #     id: <integer>
          # header_name: <string>
          # host: <list or string>
          # host_regex: <string>
          # method: ["delete", "get", "head", "options", "post", "put", "trace", "connect",
          #          "other", "update", "patch", "query"]
          # path: <string>
          # post_arg: <value in [disable, enable]>
          # query: <string>
          # referrer: <value in [disable, enable]>
          # tagging:
          #   - category: <list or string>
          #     name: <string>
          #     tags: <list or string>
          # type: <value in [host-regex, url, category, ...]>
          # ua: ["chrome", "ms", "firefox", "safari", "other", "ie", "edge"]
          # ua_max_ver: <string>
          # ua_min_ver: <string>
          # url_list: <list or string>
          # uuid: <string>
          # visibility: <value in [disable, enable]>
          # tags: <list or string>
          # llm_servers: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_proxyaddress': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_image-base64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'application': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'case-sensitivity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'header-group': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'case-sensitivity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'header-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'header-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'host-regex': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'method': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['delete', 'get', 'head', 'options', 'post', 'put', 'trace', 'connect', 'other', 'update', 'patch', 'query'],
                    'elements': 'str'
                },
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'path': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'post-arg': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'referrer': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                'type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': [
                        'host-regex', 'url', 'category', 'method', 'ua', 'header', 'src-advanced', 'dst-advanced', 'url-list', 'saas', 'response-header',
                        'llm-server'
                    ],
                    'type': 'str'
                },
                'ua': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['chrome', 'ms', 'firefox', 'safari', 'other', 'ie', 'edge'],
                    'elements': 'str'
                },
                'ua-max-ver': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ua-min-ver': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'url-list': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'visibility': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'llm-servers': {'v_range': [['7.6.5', '']], 'type': 'list', 'elements': 'str'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'display-with': {'v_range': [['8.0.0', '']], 'choices': ['all-tags', 'first-tag-only', 'icon-and-color'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_proxyaddress'),
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
