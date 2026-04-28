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
module: fmgd_authentication_setting
short_description: Configure authentication setting.
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
    authentication_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            active_auth_scheme:
                aliases: ['active-auth-scheme']
                type: list
                elements: str
                description: Active authentication method
            auth_https:
                aliases: ['auth-https']
                type: str
                description: Enable/disable redirecting HTTP user authentication to HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            captive_portal:
                aliases: ['captive-portal']
                type: list
                elements: str
                description: Captive portal host name.
            captive_portal_ip:
                aliases: ['captive-portal-ip']
                type: str
                description: Captive portal IP address.
            captive_portal_ip6:
                aliases: ['captive-portal-ip6']
                type: str
                description: Captive portal IPv6 address.
            captive_portal_port:
                aliases: ['captive-portal-port']
                type: int
                description: Captive portal port number
            captive_portal_ssl_port:
                aliases: ['captive-portal-ssl-port']
                type: int
                description: Captive portal SSL port number
            captive_portal_type:
                aliases: ['captive-portal-type']
                type: str
                description: Captive portal type.
                choices:
                    - 'fqdn'
                    - 'ip'
            captive_portal6:
                aliases: ['captive-portal6']
                type: list
                elements: str
                description: IPv6 captive portal host name.
            cert_auth:
                aliases: ['cert-auth']
                type: str
                description: Enable/disable redirecting certificate authentication to HTTPS portal.
                choices:
                    - 'disable'
                    - 'enable'
            cert_captive_portal:
                aliases: ['cert-captive-portal']
                type: list
                elements: str
                description: Certificate captive portal host name.
            cert_captive_portal_ip:
                aliases: ['cert-captive-portal-ip']
                type: str
                description: Certificate captive portal IP address.
            cert_captive_portal_port:
                aliases: ['cert-captive-portal-port']
                type: int
                description: Certificate captive portal port number
            cookie_max_age:
                aliases: ['cookie-max-age']
                type: int
                description: Persistent web portal cookie maximum age in minutes
            cookie_refresh_div:
                aliases: ['cookie-refresh-div']
                type: int
                description: Refresh rate divider of persistent web portal cookie
            dev_range:
                aliases: ['dev-range']
                type: list
                elements: str
                description: Address range for the IP based device query.
            ip_auth_cookie:
                aliases: ['ip-auth-cookie']
                type: str
                description: Enable/disable persistent cookie on IP based web portal authentication
                choices:
                    - 'disable'
                    - 'enable'
            log_auth_request:
                aliases: ['log-auth-request']
                type: str
                description: Log auth request.
                choices:
                    - 'disable'
                    - 'enable'
            persistent_cookie:
                aliases: ['persistent-cookie']
                type: str
                description: Enable/disable persistent cookie on web portal authentication
                choices:
                    - 'disable'
                    - 'enable'
            sso_auth_scheme:
                aliases: ['sso-auth-scheme']
                type: list
                elements: str
                description: Single-Sign-On authentication method
            update_time:
                aliases: ['update-time']
                type: str
                description: Time of the last update.
            user_cert_ca:
                aliases: ['user-cert-ca']
                type: list
                elements: str
                description: CA certificate used for client certificate verification.
            rewrite_https_port:
                aliases: ['rewrite-https-port']
                type: int
                description: Rewrite https port.
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
    - name: Configure authentication setting.
      fortinet.fmgdevice.fmgd_authentication_setting:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        authentication_setting:
          # active_auth_scheme: <list or string>
          # auth_https: <value in [disable, enable]>
          # captive_portal: <list or string>
          # captive_portal_ip: <string>
          # captive_portal_ip6: <string>
          # captive_portal_port: <integer>
          # captive_portal_ssl_port: <integer>
          # captive_portal_type: <value in [fqdn, ip]>
          # captive_portal6: <list or string>
          # cert_auth: <value in [disable, enable]>
          # cert_captive_portal: <list or string>
          # cert_captive_portal_ip: <string>
          # cert_captive_portal_port: <integer>
          # cookie_max_age: <integer>
          # cookie_refresh_div: <integer>
          # dev_range: <list or string>
          # ip_auth_cookie: <value in [disable, enable]>
          # log_auth_request: <value in [disable, enable]>
          # persistent_cookie: <value in [disable, enable]>
          # sso_auth_scheme: <list or string>
          # update_time: <string>
          # user_cert_ca: <list or string>
          # rewrite_https_port: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/authentication/setting'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'authentication_setting': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'active-auth-scheme': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'auth-https': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'captive-portal': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'captive-portal-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'captive-portal-ip6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'captive-portal-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'captive-portal-ssl-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'captive-portal-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                'captive-portal6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cert-auth': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cert-captive-portal': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cert-captive-portal-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cert-captive-portal-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'cookie-max-age': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'cookie-refresh-div': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'dev-range': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ip-auth-cookie': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-auth-request': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'persistent-cookie': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sso-auth-scheme': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'update-time': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'user-cert-ca': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'rewrite-https-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'authentication_setting'),
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
