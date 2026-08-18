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
module: fmgd_webfilter_fortiguard
short_description: Configure FortiGuard Web Filter service.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  webfilter_fortiguard:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      cache_mem_permille:
        aliases: ['cache-mem-permille']
        type: int
        description: Maximum permille of available memory allocated to caching
      cache_mode:
        aliases: ['cache-mode']
        type: str
        description: Cache entry expiration mode.
        choices: ['ttl', 'db-ver']
      cache_prefix_match:
        aliases: ['cache-prefix-match']
        type: str
        description: Enable/disable prefix matching in the cache.
        choices: ['disable', 'enable']
      close_ports:
        aliases: ['close-ports']
        type: str
        description: Close ports used for HTTP/HTTPS override authentication and disable user overrides.
        choices: ['disable', 'enable']
      embed_image:
        aliases: ['embed-image']
        type: str
        description: Enable/disable embedding images into replacement messages
        choices: ['disable', 'enable']
      ovrd_auth_https:
        aliases: ['ovrd-auth-https']
        type: str
        description: Enable/disable use of HTTPS for override authentication.
        choices: ['disable', 'enable']
      ovrd_auth_port_http:
        aliases: ['ovrd-auth-port-http']
        type: int
        description: Port to use for FortiGuard Web Filter HTTP override authentication.
      ovrd_auth_port_https:
        aliases: ['ovrd-auth-port-https']
        type: int
        description: Port to use for FortiGuard Web Filter HTTPS override authentication in proxy mode.
      ovrd_auth_port_https_flow:
        aliases: ['ovrd-auth-port-https-flow']
        type: int
        description: Port to use for FortiGuard Web Filter HTTPS override authentication in flow mode.
      ovrd_auth_port_warning:
        aliases: ['ovrd-auth-port-warning']
        type: int
        description: Port to use for FortiGuard Web Filter Warning override authentication.
      request_packet_size_limit:
        aliases: ['request-packet-size-limit']
        type: int
        description: Limit size of URL request packets sent to FortiGuard server
      warn_auth_https:
        aliases: ['warn-auth-https']
        type: str
        description: Enable/disable use of HTTPS for warning and authentication.
        choices: ['disable', 'enable']
      cache_mem_percent:
        aliases: ['cache-mem-percent']
        type: int
        description: Maximum percentage of available memory allocated to caching
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiGuard Web Filter service.
      fortinet.fmgdevice.fmgd_webfilter_fortiguard:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        webfilter_fortiguard:
          # cache_mem_permille: <integer>
          # cache_mode: <value in [ttl, db-ver]>
          # cache_prefix_match: <value in [disable, enable]>
          # close_ports: <value in [disable, enable]>
          # embed_image: <value in [disable, enable]>
          # ovrd_auth_https: <value in [disable, enable]>
          # ovrd_auth_port_http: <integer>
          # ovrd_auth_port_https: <integer>
          # ovrd_auth_port_https_flow: <integer>
          # ovrd_auth_port_warning: <integer>
          # request_packet_size_limit: <integer>
          # warn_auth_https: <value in [disable, enable]>
          # cache_mem_percent: <integer>
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
        '/pm/config/device/{device}/global/webfilter/fortiguard'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'webfilter_fortiguard': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'cache-mem-permille': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'cache-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['ttl', 'db-ver'], 'type': 'str'},
                'cache-prefix-match': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'close-ports': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'embed-image': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ovrd-auth-https': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ovrd-auth-port-http': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ovrd-auth-port-https': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ovrd-auth-port-https-flow': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'ovrd-auth-port-warning': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'request-packet-size-limit': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'warn-auth-https': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-mem-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_fortiguard'),
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
