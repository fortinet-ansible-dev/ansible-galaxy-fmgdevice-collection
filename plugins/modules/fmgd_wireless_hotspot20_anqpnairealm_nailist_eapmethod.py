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
module: fmgd_wireless_hotspot20_anqpnairealm_nailist_eapmethod
short_description: EAP Methods.
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
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    anqp-nai-realm:
        description: Deprecated, please use "anqp_nai_realm"
        type: str
    anqp_nai_realm:
        description: The parameter (anqp-nai-realm) in requested url.
        type: str
    nai-list:
        description: Deprecated, please use "nai_list"
        type: str
    nai_list:
        description: The parameter (nai-list) in requested url.
        type: str
    wireless_hotspot20_anqpnairealm_nailist_eapmethod:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_param:
                aliases: ['auth-param']
                type: list
                elements: dict
                description: Auth param.
                suboptions:
                    id:
                        type: str
                        description: ID of authentication parameter.
                        choices:
                            - 'non-eap-inner-auth'
                            - 'inner-auth-eap'
                            - 'credential'
                            - 'tunneled-credential'
                    index:
                        type: int
                        description: Param index.
                    val:
                        type: str
                        description: Value of authentication parameter.
                        choices:
                            - 'eap-identity'
                            - 'eap-md5'
                            - 'eap-tls'
                            - 'eap-ttls'
                            - 'eap-peap'
                            - 'eap-sim'
                            - 'eap-aka'
                            - 'eap-aka-prime'
                            - 'non-eap-pap'
                            - 'non-eap-chap'
                            - 'non-eap-mschap'
                            - 'non-eap-mschapv2'
                            - 'cred-sim'
                            - 'cred-usim'
                            - 'cred-nfc'
                            - 'cred-hardware-token'
                            - 'cred-softoken'
                            - 'cred-certificate'
                            - 'cred-user-pwd'
                            - 'cred-none'
                            - 'cred-vendor-specific'
                            - 'tun-cred-sim'
                            - 'tun-cred-usim'
                            - 'tun-cred-nfc'
                            - 'tun-cred-hardware-token'
                            - 'tun-cred-softoken'
                            - 'tun-cred-certificate'
                            - 'tun-cred-user-pwd'
                            - 'tun-cred-anonymous'
                            - 'tun-cred-vendor-specific'
            index:
                type: int
                description: EAP method index.
                required: true
            method:
                type: str
                description: EAP method type.
                choices:
                    - 'eap-identity'
                    - 'eap-md5'
                    - 'eap-tls'
                    - 'eap-ttls'
                    - 'eap-peap'
                    - 'eap-sim'
                    - 'eap-aka'
                    - 'eap-aka-prime'
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
    - name: EAP Methods.
      fortinet.fmgdevice.fmgd_wireless_hotspot20_anqpnairealm_nailist_eapmethod:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        anqp_nai_realm: <your own value>
        nai_list: <your own value>
        state: present # <value in [present, absent]>
        wireless_hotspot20_anqpnairealm_nailist_eapmethod:
          index: 0 # Required variable, integer
          # auth_param:
          #   - id: <value in [non-eap-inner-auth, inner-auth-eap, credential, ...]>
          #     index: <integer>
          #     val: <value in [eap-identity, eap-md5, eap-tls, ...]>
          # method: <value in [eap-identity, eap-md5, eap-tls, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method'
    ]
    url_params = ['device', 'vdom', 'anqp-nai-realm', 'nai-list']
    module_primary_key = 'index'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'anqp-nai-realm': {'type': 'str', 'api_name': 'anqp_nai_realm'},
        'anqp_nai_realm': {'type': 'str'},
        'nai-list': {'type': 'str', 'api_name': 'nai_list'},
        'nai_list': {'type': 'str'},
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'auth-param': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['non-eap-inner-auth', 'inner-auth-eap', 'credential', 'tunneled-credential'],
                            'type': 'str'
                        },
                        'index': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'val': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': [
                                'eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim', 'eap-aka', 'eap-aka-prime', 'non-eap-pap',
                                'non-eap-chap', 'non-eap-mschap', 'non-eap-mschapv2', 'cred-sim', 'cred-usim', 'cred-nfc', 'cred-hardware-token',
                                'cred-softoken', 'cred-certificate', 'cred-user-pwd', 'cred-none', 'cred-vendor-specific', 'tun-cred-sim',
                                'tun-cred-usim', 'tun-cred-nfc', 'tun-cred-hardware-token', 'tun-cred-softoken', 'tun-cred-certificate',
                                'tun-cred-user-pwd', 'tun-cred-anonymous', 'tun-cred-vendor-specific'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'index': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['eap-identity', 'eap-md5', 'eap-tls', 'eap-ttls', 'eap-peap', 'eap-sim', 'eap-aka', 'eap-aka-prime'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wireless_hotspot20_anqpnairealm_nailist_eapmethod'),
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
