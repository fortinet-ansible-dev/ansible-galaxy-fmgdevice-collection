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
module: fmgd_wanopt_webcache
short_description: Configure global Web cache settings.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    wanopt_webcache:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            always_revalidate:
                aliases: ['always-revalidate']
                type: str
                description: Enable/disable revalidation of requested cached objects, which have content on the server, before serving it to the client.
                choices:
                    - 'disable'
                    - 'enable'
            cache_by_default:
                aliases: ['cache-by-default']
                type: str
                description: Enable/disable caching content that lacks explicit caching policies from the server.
                choices:
                    - 'disable'
                    - 'enable'
            cache_cookie:
                aliases: ['cache-cookie']
                type: str
                description: Enable/disable caching cookies.
                choices:
                    - 'disable'
                    - 'enable'
            cache_expired:
                aliases: ['cache-expired']
                type: str
                description: Enable/disable caching type-1 objects that are already expired on arrival.
                choices:
                    - 'disable'
                    - 'enable'
            default_ttl:
                aliases: ['default-ttl']
                type: int
                description: Default object expiry time
            external:
                type: str
                description: Enable/disable external Web caching.
                choices:
                    - 'disable'
                    - 'enable'
            fresh_factor:
                aliases: ['fresh-factor']
                type: int
                description: Frequency that the server is checked to see if any objects have expired
            host_validate:
                aliases: ['host-validate']
                type: str
                description: Enable/disable validating Host
                choices:
                    - 'disable'
                    - 'enable'
            ignore_conditional:
                aliases: ['ignore-conditional']
                type: str
                description: Enable/disable controlling the behavior of cache-control HTTP 1.
                choices:
                    - 'disable'
                    - 'enable'
            ignore_ie_reload:
                aliases: ['ignore-ie-reload']
                type: str
                description: Enable/disable ignoring the PNC-interpretation of Internet Explorers Accept
                choices:
                    - 'disable'
                    - 'enable'
            ignore_ims:
                aliases: ['ignore-ims']
                type: str
                description: Enable/disable ignoring the if-modified-since
                choices:
                    - 'disable'
                    - 'enable'
            ignore_pnc:
                aliases: ['ignore-pnc']
                type: str
                description: Enable/disable ignoring the pragma no-cache
                choices:
                    - 'disable'
                    - 'enable'
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
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure global Web cache settings.
      fortinet.fmgdevice.fmgd_wanopt_webcache:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        wanopt_webcache:
          # always_revalidate: <value in [disable, enable]>
          # cache_by_default: <value in [disable, enable]>
          # cache_cookie: <value in [disable, enable]>
          # cache_expired: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wanopt/webcache'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'wanopt_webcache': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'always-revalidate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-by-default': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-cookie': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cache-expired': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'external': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fresh-factor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'host-validate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-conditional': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-ie-reload': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-ims': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ignore-pnc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-object-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'min-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'neg-resp-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'reval-pnc': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_webcache'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
