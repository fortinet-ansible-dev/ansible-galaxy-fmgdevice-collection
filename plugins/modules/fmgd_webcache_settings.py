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
module: fmgd_webcache_settings
short_description: Device vdom webcache settings
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  webcache_settings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      add_x_cache:
        aliases: ['add-x-cache']
        type: str
        description: Enable/disable appending local X-Cache
        choices: ['disable', 'enable']
      always_revalidate:
        aliases: ['always-revalidate']
        type: str
        description: Enable/disable revalidation of requested cached objects, which have content on the server, before serving it to the client.
        choices: ['disable', 'enable']
      cache_by_default:
        aliases: ['cache-by-default']
        type: str
        description: Enable/disable caching content that lacks explicit caching policies from the server.
        choices: ['disable', 'enable']
      cache_cookie:
        aliases: ['cache-cookie']
        type: str
        description: Enable/disable caching cookies.
        choices: ['disable', 'enable']
      cache_expired:
        aliases: ['cache-expired']
        type: str
        description: Enable/disable caching type-1 objects that are already expired on arrival.
        choices: ['disable', 'enable']
      crawler_user_agent:
        aliases: ['crawler-user-agent']
        type: str
        description: The user agent that the web crawler will use.
      default_ttl:
        aliases: ['default-ttl']
        type: int
        description: Default object expiry time
      external:
        type: str
        description: Enable/disable external Web caching.
        choices: ['disable', 'enable']
      fresh_factor:
        aliases: ['fresh-factor']
        type: int
        description: Frequency that the server is checked to see if any objects have expired
      host_validate:
        aliases: ['host-validate']
        type: str
        description: Enable/disable validating Host
        choices: ['disable', 'enable']
      ignore_conditional:
        aliases: ['ignore-conditional']
        type: str
        description: Enable/disable controlling the behavior of cache-control HTTP 1.
        choices: ['disable', 'enable']
      ignore_ie_reload:
        aliases: ['ignore-ie-reload']
        type: str
        description: Enable/disable ignoring the PNC-interpretation of Internet Explorers Accept
        choices: ['disable', 'enable']
      ignore_ims:
        aliases: ['ignore-ims']
        type: str
        description: Enable/disable ignoring the if-modified-since
        choices: ['disable', 'enable']
      ignore_pnc:
        aliases: ['ignore-pnc']
        type: str
        description: Enable/disable ignoring the pragma no-cache
        choices: ['disable', 'enable']
      max_object_size:
        aliases: ['max-object-size']
        type: int
        description: Maximum cacheable object size in kB
      max_ttl:
        aliases: ['max-ttl']
        type: int
        description: Maximum time an object can stay in the web cache without checking to see if it has expired on the server
      min_ttl:
        aliases: ['min-ttl']
        type: int
        description: Minimum time an object can stay in the web cache without checking to see if it has expired on the server
      neg_resp_time:
        aliases: ['neg-resp-time']
        type: int
        description: Time in minutes to cache negative responses or errors
      reval_pnc:
        aliases: ['reval-pnc']
        type: str
        description: Enable/disable revalidation of pragma-no-cache
        choices: ['disable', 'enable']
      x_cache_message:
        aliases: ['x-cache-message']
        type: str
        description: Config customized x-cache header message
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Device vdom webcache settings
      fortinet.fmgdevice.fmgd_webcache_settings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        webcache_settings:
          # add_x_cache: <value in [disable, enable]>
          # always_revalidate: <value in [disable, enable]>
          # cache_by_default: <value in [disable, enable]>
          # cache_cookie: <value in [disable, enable]>
          # cache_expired: <value in [disable, enable]>
          # crawler_user_agent: <string>
          # default_ttl: <integer>
          # external: <value in [disable, enable]>
          # fresh_factor: <integer>
          # host_validate: <value in [disable, enable]>
          # ignore_conditional: <value in [disable, enable]>
          # ignore_ie_reload: <value in [disable, enable]>
          # ignore_ims: <value in [disable, enable]>
          # ignore_pnc: <value in [disable, enable]>
          # max_object_size: <integer>
          # max_ttl: <integer>
          # min_ttl: <integer>
          # neg_resp_time: <integer>
          # reval_pnc: <value in [disable, enable]>
          # x_cache_message: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/webcache/settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'webcache_settings': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'add-x-cache': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'always-revalidate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-by-default': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-cookie': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-expired': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'crawler-user-agent': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'default-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'external': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fresh-factor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'host-validate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-conditional': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-ie-reload': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-ims': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-pnc': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-object-size': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'max-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'min-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'neg-resp-time': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'reval-pnc': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'x-cache-message': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webcache_settings'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
