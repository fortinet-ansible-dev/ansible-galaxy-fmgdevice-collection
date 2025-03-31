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
module: fmgd_system_saml_serviceproviders
short_description: Authorized service providers.
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
    system_saml_serviceproviders:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            assertion_attributes:
                aliases: ['assertion-attributes']
                type: list
                elements: dict
                description: Assertion attributes.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    type:
                        type: str
                        description: Type.
                        choices:
                            - 'username'
                            - 'email'
                            - 'privilege'
                            - 'profile-name'
            idp_artifact_resolution_url:
                aliases: ['idp-artifact-resolution-url']
                type: str
                description: IDP artifact resolution URL.
            idp_entity_id:
                aliases: ['idp-entity-id']
                type: str
                description: Idp entity id.
            idp_single_logout_url:
                aliases: ['idp-single-logout-url']
                type: str
                description: Idp single logout url.
            idp_single_sign_on_url:
                aliases: ['idp-single-sign-on-url']
                type: str
                description: Idp single sign on url.
            name:
                type: str
                description: Name.
                required: true
            prefix:
                type: str
                description: Prefix.
            sp_artifact_resolution_url:
                aliases: ['sp-artifact-resolution-url']
                type: str
                description: SP artifact resolution URL.
            sp_binding_protocol:
                aliases: ['sp-binding-protocol']
                type: str
                description: SP binding protocol.
                choices:
                    - 'post'
                    - 'redirect'
            sp_cert:
                aliases: ['sp-cert']
                type: list
                elements: str
                description: SP certificate name.
            sp_entity_id:
                aliases: ['sp-entity-id']
                type: str
                description: SP entity ID.
            sp_portal_url:
                aliases: ['sp-portal-url']
                type: str
                description: SP portal URL.
            sp_single_logout_url:
                aliases: ['sp-single-logout-url']
                type: str
                description: SP single logout URL.
            sp_single_sign_on_url:
                aliases: ['sp-single-sign-on-url']
                type: str
                description: SP single sign-on URL.
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
    - name: Authorized service providers.
      fortinet.fmgdevice.fmgd_system_saml_serviceproviders:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_saml_serviceproviders:
          name: "your value" # Required variable, string
          # assertion_attributes:
          #   - name: <string>
          #     type: <value in [username, email, privilege, ...]>
          # idp_artifact_resolution_url: <string>
          # idp_entity_id: <string>
          # idp_single_logout_url: <string>
          # idp_single_sign_on_url: <string>
          # prefix: <string>
          # sp_artifact_resolution_url: <string>
          # sp_binding_protocol: <value in [post, redirect]>
          # sp_cert: <list or string>
          # sp_entity_id: <string>
          # sp_portal_url: <string>
          # sp_single_logout_url: <string>
          # sp_single_sign_on_url: <string>
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
        '/pm/config/device/{device}/global/system/saml/service-providers'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_saml_serviceproviders': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'assertion-attributes': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'type': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['username', 'email', 'privilege', 'profile-name'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'idp-artifact-resolution-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'idp-entity-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'idp-single-logout-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'idp-single-sign-on-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sp-artifact-resolution-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sp-binding-protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['post', 'redirect'], 'type': 'str'},
                'sp-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sp-entity-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sp-portal-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sp-single-logout-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sp-single-sign-on-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_saml_serviceproviders'),
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
