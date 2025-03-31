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
module: fmgd_user_setting
short_description: Configure user authentication setting.
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
    user_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_blackout_time:
                aliases: ['auth-blackout-time']
                type: int
                description: Time in seconds an IP address is denied access after failing to authenticate five times within one minute.
            auth_ca_cert:
                aliases: ['auth-ca-cert']
                type: list
                elements: str
                description: HTTPS CA certificate for policy authentication.
            auth_cert:
                aliases: ['auth-cert']
                type: list
                elements: str
                description: HTTPS server certificate for policy authentication.
            auth_http_basic:
                aliases: ['auth-http-basic']
                type: str
                description: Enable/disable use of HTTP basic authentication for identity-based firewall policies.
                choices:
                    - 'disable'
                    - 'enable'
            auth_invalid_max:
                aliases: ['auth-invalid-max']
                type: int
                description: Maximum number of failed authentication attempts before the user is blocked.
            auth_lockout_duration:
                aliases: ['auth-lockout-duration']
                type: int
                description: Lockout period in seconds after too many login failures.
            auth_lockout_threshold:
                aliases: ['auth-lockout-threshold']
                type: int
                description: Maximum number of failed login attempts before login lockout is triggered.
            auth_on_demand:
                aliases: ['auth-on-demand']
                type: str
                description: Always/implicitly trigger firewall authentication on demand.
                choices:
                    - 'always'
                    - 'implicitly'
            auth_portal_timeout:
                aliases: ['auth-portal-timeout']
                type: int
                description: Time in minutes before captive portal user have to re-authenticate
            auth_ports:
                aliases: ['auth-ports']
                type: list
                elements: dict
                description: Auth ports.
                suboptions:
                    id:
                        type: int
                        description: ID.
                    port:
                        type: int
                        description: Non-standard port for firewall user authentication.
                    type:
                        type: str
                        description: Service type.
                        choices:
                            - 'http'
                            - 'https'
                            - 'ftp'
                            - 'telnet'
            auth_secure_http:
                aliases: ['auth-secure-http']
                type: str
                description: Enable/disable redirecting HTTP user authentication to more secure HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            auth_src_mac:
                aliases: ['auth-src-mac']
                type: str
                description: Enable/disable source MAC for user identity.
                choices:
                    - 'disable'
                    - 'enable'
            auth_ssl_allow_renegotiation:
                aliases: ['auth-ssl-allow-renegotiation']
                type: str
                description: Allow/forbid SSL re-negotiation for HTTPS authentication.
                choices:
                    - 'disable'
                    - 'enable'
            auth_ssl_max_proto_version:
                aliases: ['auth-ssl-max-proto-version']
                type: str
                description: Maximum supported protocol version for SSL/TLS connections
                choices:
                    - 'tlsv1-1'
                    - 'tlsv1-2'
                    - 'sslv3'
                    - 'tlsv1'
                    - 'tlsv1-3'
            auth_ssl_min_proto_version:
                aliases: ['auth-ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'default'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-3'
            auth_ssl_sigalgs:
                aliases: ['auth-ssl-sigalgs']
                type: str
                description: Set signature algorithms related to HTTPS authentication
                choices:
                    - 'no-rsa-pss'
                    - 'all'
            auth_timeout:
                aliases: ['auth-timeout']
                type: int
                description: Time in minutes before the firewall user authentication timeout requires the user to re-authenticate.
            auth_timeout_type:
                aliases: ['auth-timeout-type']
                type: str
                description: Control if authenticated users have to login again after a hard timeout, after an idle timeout, or after a session timeout.
                choices:
                    - 'idle-timeout'
                    - 'hard-timeout'
                    - 'new-session'
            auth_type:
                aliases: ['auth-type']
                type: list
                elements: str
                description: Supported firewall policy authentication protocols/methods.
                choices:
                    - 'http'
                    - 'https'
                    - 'ftp'
                    - 'telnet'
            default_user_password_policy:
                aliases: ['default-user-password-policy']
                type: list
                elements: str
                description: Default password policy to apply to all local users unless otherwise specified, as defined in config user password-policy.
            per_policy_disclaimer:
                aliases: ['per-policy-disclaimer']
                type: str
                description: Enable/disable per policy disclaimer.
                choices:
                    - 'disable'
                    - 'enable'
            radius_ses_timeout_act:
                aliases: ['radius-ses-timeout-act']
                type: str
                description: Set the RADIUS session timeout to a hard timeout or to ignore RADIUS server session timeouts.
                choices:
                    - 'hard-timeout'
                    - 'ignore-timeout'
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
    - name: Configure user authentication setting.
      fortinet.fmgdevice.fmgd_user_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        user_setting:
          # auth_blackout_time: <integer>
          # auth_ca_cert: <list or string>
          # auth_cert: <list or string>
          # auth_http_basic: <value in [disable, enable]>
          # auth_invalid_max: <integer>
          # auth_lockout_duration: <integer>
          # auth_lockout_threshold: <integer>
          # auth_on_demand: <value in [always, implicitly]>
          # auth_portal_timeout: <integer>
          # auth_ports:
          #   - id: <integer>
          #     port: <integer>
          #     type: <value in [http, https, ftp, ...]>
          # auth_secure_http: <value in [disable, enable]>
          # auth_src_mac: <value in [disable, enable]>
          # auth_ssl_allow_renegotiation: <value in [disable, enable]>
          # auth_ssl_max_proto_version: <value in [tlsv1-1, tlsv1-2, sslv3, ...]>
          # auth_ssl_min_proto_version: <value in [default, TLSv1-1, TLSv1-2, ...]>
          # auth_ssl_sigalgs: <value in [no-rsa-pss, all]>
          # auth_timeout: <integer>
          # auth_timeout_type: <value in [idle-timeout, hard-timeout, new-session]>
          # auth_type:
          #   - "http"
          #   - "https"
          #   - "ftp"
          #   - "telnet"
          # default_user_password_policy: <list or string>
          # per_policy_disclaimer: <value in [disable, enable]>
          # radius_ses_timeout_act: <value in [hard-timeout, ignore-timeout]>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/setting'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'auth-blackout-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth-ca-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'auth-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'auth-http-basic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-invalid-max': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth-lockout-duration': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth-lockout-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth-on-demand': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['always', 'implicitly'], 'type': 'str'},
                'auth-portal-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth-ports': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['http', 'https', 'ftp', 'telnet'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'auth-secure-http': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-src-mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-ssl-allow-renegotiation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-ssl-max-proto-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['tlsv1-1', 'tlsv1-2', 'sslv3', 'tlsv1', 'tlsv1-3'],
                    'type': 'str'
                },
                'auth-ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'auth-ssl-sigalgs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['no-rsa-pss', 'all'], 'type': 'str'},
                'auth-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auth-timeout-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['idle-timeout', 'hard-timeout', 'new-session'],
                    'type': 'str'
                },
                'auth-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['http', 'https', 'ftp', 'telnet'],
                    'elements': 'str'
                },
                'default-user-password-policy': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'per-policy-disclaimer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-ses-timeout-act': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['hard-timeout', 'ignore-timeout'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_setting'),
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
