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
module: fmgd_system_externalresource
short_description: Configure external resource.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
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
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    system_externalresource:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            category:
                type: int
                description: User resource category.
            comments:
                type: str
                description: Comment.
            interface:
                type: list
                elements: str
                description:
                    - Support meta variable
                    - Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            name:
                type: str
                description: External resource name.
                required: true
            password:
                type: list
                elements: str
                description: HTTP basic authentication password.
            proxy:
                type: str
                description: Proxy.
            proxy_password:
                aliases: ['proxy-password']
                type: list
                elements: str
                description: Proxy password.
            proxy_port:
                aliases: ['proxy-port']
                type: int
                description: Proxy port.
            proxy_username:
                aliases: ['proxy-username']
                type: str
                description: Proxy username.
            refresh_rate:
                aliases: ['refresh-rate']
                type: int
                description: Time interval to refresh external resource
            resource:
                type: str
                description: URL of external resource.
            server_identity_check:
                aliases: ['server-identity-check']
                type: str
                description: Certificate verification option.
                choices:
                    - 'none'
                    - 'basic'
                    - 'full'
            source_ip:
                aliases: ['source-ip']
                type: str
                description:
                    - Support meta variable
                    - Source IPv4 address used to communicate with server.
            status:
                type: str
                description: Enable/disable user resource.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: User resource type.
                choices:
                    - 'category'
                    - 'address'
                    - 'domain'
                    - 'malware'
                    - 'url'
                    - 'data'
                    - 'mac-address'
                    - 'generic-address'
            update_method:
                aliases: ['update-method']
                type: str
                description: External resource update method.
                choices:
                    - 'feed'
                    - 'push'
            user_agent:
                aliases: ['user-agent']
                type: str
                description: HTTP User-Agent header
            username:
                type: str
                description: HTTP basic authentication user name.
            uuid:
                type: str
                description: Universally Unique Identifier
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
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Source ip.
            address_comment_field:
                aliases: ['address-comment-field']
                type: str
                description: JSON Path to address description in generic address entry.
            client_cert:
                aliases: ['client-cert']
                type: list
                elements: str
                description: Client certificate name.
            namespace:
                type: str
                description: Generic external connector address namespace.
            object_array_path:
                aliases: ['object-array-path']
                type: str
                description: JSON Path to array of generic addresses in resource.
            source_ip_interface:
                aliases: ['source-ip-interface']
                type: list
                elements: str
                description: IPv4 Source interface for communication with the server.
            client_cert_auth:
                aliases: ['client-cert-auth']
                type: str
                description: Enable/disable using client certificate for TLS authentication.
                choices:
                    - 'disable'
                    - 'enable'
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
            address_data_field:
                aliases: ['address-data-field']
                type: str
                description: JSON Path to address data in generic address entry.
            address_name_field:
                aliases: ['address-name-field']
                type: str
                description: JSON Path to address name in generic address entry.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure external resource.
      fortinet.fmgdevice.fmgd_system_externalresource:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_externalresource:
          name: "your value" # Required variable, string
          # category: <integer>
          # comments: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # password: <list or string>
          # proxy: <string>
          # proxy_password: <list or string>
          # proxy_port: <integer>
          # proxy_username: <string>
          # refresh_rate: <integer>
          # resource: <string>
          # server_identity_check: <value in [none, basic, full]>
          # source_ip: <string>
          # status: <value in [disable, enable]>
          # type: <value in [category, address, domain, ...]>
          # update_method: <value in [feed, push]>
          # user_agent: <string>
          # username: <string>
          # uuid: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     source_ip: <string>
          # address_comment_field: <string>
          # client_cert: <list or string>
          # namespace: <string>
          # object_array_path: <string>
          # source_ip_interface: <list or string>
          # client_cert_auth: <value in [disable, enable]>
          # vrf_select: <integer>
          # address_data_field: <string>
          # address_name_field: <string>
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
        '/pm/config/device/{device}/global/system/external-resource',
        '/pm/config/device/{device}/vdom/{vdom}/system/external-resource'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_externalresource': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'comments': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'proxy': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'proxy-password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'proxy-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'proxy-username': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'refresh-rate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'resource': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'server-identity-check': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['none', 'basic', 'full'], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['category', 'address', 'domain', 'malware', 'url', 'data', 'mac-address', 'generic-address'],
                    'type': 'str'
                },
                'update-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['feed', 'push'], 'type': 'str'},
                'user-agent': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'username': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.6.4', '']],
                            'type': 'list',
                            'options': {'name': {'v_range': [['7.6.4', '']], 'type': 'str'}, 'vdom': {'v_range': [['7.6.4', '']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'source-ip': {'v_range': [['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'address-comment-field': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'namespace': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'object-array-path': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'client-cert-auth': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'address-data-field': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'address-name-field': {'v_range': [['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_externalresource'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
