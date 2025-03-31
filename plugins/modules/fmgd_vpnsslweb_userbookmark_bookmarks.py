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
module: fmgd_vpnsslweb_userbookmark_bookmarks
short_description: Bookmark table.
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
    user-bookmark:
        description: Deprecated, please use "user_bookmark"
        type: str
    user_bookmark:
        description: The parameter (user-bookmark) in requested url.
        type: str
    vpnsslweb_userbookmark_bookmarks:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            additional_params:
                aliases: ['additional-params']
                type: str
                description: Additional parameters.
            apptype:
                type: str
                description: Application type.
                choices:
                    - 'web'
                    - 'ftp'
                    - 'telnet'
                    - 'smb'
                    - 'vnc'
                    - 'rdp'
                    - 'ssh'
                    - 'citrix'
                    - 'rdpnative'
                    - 'portforward'
                    - 'sftp'
            color_depth:
                aliases: ['color-depth']
                type: str
                description: Color depth per pixel.
                choices:
                    - '8'
                    - '16'
                    - '32'
            description:
                type: str
                description: Description.
            domain:
                type: str
                description: Login domain.
            folder:
                type: str
                description: Network shared file folder parameter.
            form_data:
                aliases: ['form-data']
                type: list
                elements: dict
                description: Form data.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    value:
                        type: str
                        description: Value.
            height:
                type: int
                description: Screen height
            host:
                type: str
                description: Host name/IP parameter.
            keyboard_layout:
                aliases: ['keyboard-layout']
                type: str
                description: Keyboard layout.
                choices:
                    - 'ar'
                    - 'da'
                    - 'de'
                    - 'de-ch'
                    - 'en-gb'
                    - 'en-uk'
                    - 'en-us'
                    - 'es'
                    - 'fi'
                    - 'fr'
                    - 'fr-be'
                    - 'fr-ca'
                    - 'fr-ch'
                    - 'hr'
                    - 'hu'
                    - 'it'
                    - 'ja'
                    - 'lt'
                    - 'lv'
                    - 'mk'
                    - 'no'
                    - 'pl'
                    - 'pt'
                    - 'pt-br'
                    - 'ru'
                    - 'sl'
                    - 'sv'
                    - 'tk'
                    - 'tr'
                    - 'fr-ca-m'
                    - 'wg'
                    - 'ar-101'
                    - 'ar-102'
                    - 'ar-102-azerty'
                    - 'can-mul'
                    - 'cz'
                    - 'cz-qwerty'
                    - 'cz-pr'
                    - 'nl'
                    - 'de-ibm'
                    - 'en-uk-ext'
                    - 'en-us-dvorak'
                    - 'es-var'
                    - 'fi-sami'
                    - 'hu-101'
                    - 'it-142'
                    - 'ko'
                    - 'lt-ibm'
                    - 'lt-std'
                    - 'lav-std'
                    - 'lav-leg'
                    - 'mk-std'
                    - 'no-sami'
                    - 'pol-214'
                    - 'pol-pr'
                    - 'pt-br-abnt2'
                    - 'ru-mne'
                    - 'ru-t'
                    - 'sv-sami'
                    - 'tuk'
                    - 'tur-f'
                    - 'tur-q'
                    - 'zh-sym-sg-us'
                    - 'zh-sym-us'
                    - 'zh-tr-hk'
                    - 'zh-tr-mo'
                    - 'zh-tr-us'
                    - 'fr-apple'
                    - 'la-am'
                    - 'ja-106'
            load_balancing_info:
                aliases: ['load-balancing-info']
                type: str
                description: The load balancing information or cookie which should be provided to the connection broker.
            logon_password:
                aliases: ['logon-password']
                type: list
                elements: str
                description: Logon password.
            logon_user:
                aliases: ['logon-user']
                type: str
                description: Logon user.
            name:
                type: str
                description: Bookmark name.
                required: true
            port:
                type: int
                description: Remote port.
            preconnection_blob:
                aliases: ['preconnection-blob']
                type: str
                description: An arbitrary string which identifies the RDP source.
            preconnection_id:
                aliases: ['preconnection-id']
                type: int
                description: The numeric ID of the RDP source
            restricted_admin:
                aliases: ['restricted-admin']
                type: str
                description: Enable/disable restricted admin mode for RDP.
                choices:
                    - 'disable'
                    - 'enable'
            security:
                type: str
                description: Security mode for RDP connection
                choices:
                    - 'rdp'
                    - 'nla'
                    - 'tls'
                    - 'any'
            send_preconnection_id:
                aliases: ['send-preconnection-id']
                type: str
                description: Enable/disable sending of preconnection ID.
                choices:
                    - 'disable'
                    - 'enable'
            sso:
                type: str
                description: Single sign-on.
                choices:
                    - 'disable'
                    - 'static'
                    - 'auto'
            sso_credential:
                aliases: ['sso-credential']
                type: str
                description: Single sign-on credentials.
                choices:
                    - 'sslvpn-login'
                    - 'alternative'
            sso_credential_sent_once:
                aliases: ['sso-credential-sent-once']
                type: str
                description: Single sign-on credentials are only sent once to remote server.
                choices:
                    - 'disable'
                    - 'enable'
            sso_password:
                aliases: ['sso-password']
                type: list
                elements: str
                description: SSO password.
            sso_username:
                aliases: ['sso-username']
                type: str
                description: SSO user name.
            url:
                type: str
                description: URL parameter.
            vnc_keyboard_layout:
                aliases: ['vnc-keyboard-layout']
                type: str
                description: Keyboard layout.
                choices:
                    - 'da'
                    - 'de'
                    - 'de-ch'
                    - 'en-uk'
                    - 'es'
                    - 'fi'
                    - 'fr'
                    - 'fr-be'
                    - 'it'
                    - 'no'
                    - 'pt'
                    - 'sv'
                    - 'nl'
                    - 'en-uk-ext'
                    - 'it-142'
                    - 'pt-br-abnt2'
                    - 'default'
                    - 'fr-ca-mul'
                    - 'gd'
                    - 'us-intl'
            width:
                type: int
                description: Screen width
            remote_port:
                aliases: ['remote-port']
                type: int
                description: Remote port
            show_status_window:
                aliases: ['show-status-window']
                type: str
                description: Enable/disable showing of status window.
                choices:
                    - 'disable'
                    - 'enable'
            server_layout:
                aliases: ['server-layout']
                type: str
                description: Server side keyboard layout.
                choices:
                    - 'en-us-qwerty'
                    - 'de-de-qwertz'
                    - 'fr-fr-azerty'
                    - 'it-it-qwerty'
                    - 'sv-se-qwerty'
                    - 'failsafe'
                    - 'en-gb-qwerty'
                    - 'es-es-qwerty'
                    - 'fr-ch-qwertz'
                    - 'ja-jp-qwerty'
                    - 'pt-br-qwerty'
                    - 'tr-tr-qwerty'
                    - 'fr-ca-qwerty'
            listening_port:
                aliases: ['listening-port']
                type: int
                description: Listening port
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
    - name: Bookmark table.
      fortinet.fmgdevice.fmgd_vpnsslweb_userbookmark_bookmarks:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        user_bookmark: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_userbookmark_bookmarks:
          name: "your value" # Required variable, string
          # additional_params: <string>
          # apptype: <value in [web, ftp, telnet, ...]>
          # color_depth: <value in [8, 16, 32]>
          # description: <string>
          # domain: <string>
          # folder: <string>
          # form_data:
          #   - name: <string>
          #     value: <string>
          # height: <integer>
          # host: <string>
          # keyboard_layout: <value in [ar, da, de, ...]>
          # load_balancing_info: <string>
          # logon_password: <list or string>
          # logon_user: <string>
          # port: <integer>
          # preconnection_blob: <string>
          # preconnection_id: <integer>
          # restricted_admin: <value in [disable, enable]>
          # security: <value in [rdp, nla, tls, ...]>
          # send_preconnection_id: <value in [disable, enable]>
          # sso: <value in [disable, static, auto]>
          # sso_credential: <value in [sslvpn-login, alternative]>
          # sso_credential_sent_once: <value in [disable, enable]>
          # sso_password: <list or string>
          # sso_username: <string>
          # url: <string>
          # vnc_keyboard_layout: <value in [da, de, de-ch, ...]>
          # width: <integer>
          # remote_port: <integer>
          # show_status_window: <value in [disable, enable]>
          # server_layout: <value in [en-us-qwerty, de-de-qwertz, fr-fr-azerty, ...]>
          # listening_port: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks'
    ]
    url_params = ['device', 'vdom', 'user-bookmark']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user-bookmark': {'type': 'str', 'api_name': 'user_bookmark'},
        'user_bookmark': {'type': 'str'},
        'vpnsslweb_userbookmark_bookmarks': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'additional-params': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'apptype': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['web', 'ftp', 'telnet', 'smb', 'vnc', 'rdp', 'ssh', 'citrix', 'rdpnative', 'portforward', 'sftp'],
                    'type': 'str'
                },
                'color-depth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['8', '16', '32'], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'folder': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'form-data': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'height': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'host': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'keyboard-layout': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'ar', 'da', 'de', 'de-ch', 'en-gb', 'en-uk', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch', 'hr', 'hu', 'it', 'ja', 'lt',
                        'lv', 'mk', 'no', 'pl', 'pt', 'pt-br', 'ru', 'sl', 'sv', 'tk', 'tr', 'fr-ca-m', 'wg', 'ar-101', 'ar-102', 'ar-102-azerty',
                        'can-mul', 'cz', 'cz-qwerty', 'cz-pr', 'nl', 'de-ibm', 'en-uk-ext', 'en-us-dvorak', 'es-var', 'fi-sami', 'hu-101', 'it-142',
                        'ko', 'lt-ibm', 'lt-std', 'lav-std', 'lav-leg', 'mk-std', 'no-sami', 'pol-214', 'pol-pr', 'pt-br-abnt2', 'ru-mne', 'ru-t',
                        'sv-sami', 'tuk', 'tur-f', 'tur-q', 'zh-sym-sg-us', 'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo', 'zh-tr-us', 'fr-apple', 'la-am',
                        'ja-106'
                    ],
                    'type': 'str'
                },
                'load-balancing-info': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'logon-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'logon-user': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'preconnection-blob': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'preconnection-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'restricted-admin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'security': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['rdp', 'nla', 'tls', 'any'], 'type': 'str'},
                'send-preconnection-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sso': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                'sso-credential': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                'sso-credential-sent-once': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sso-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'sso-username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vnc-keyboard-layout': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it', 'no', 'pt', 'sv', 'nl', 'en-uk-ext', 'it-142', 'pt-br-abnt2',
                        'default', 'fr-ca-mul', 'gd', 'us-intl'
                    ],
                    'type': 'str'
                },
                'width': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'remote-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'show-status-window': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-layout': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty', 'sv-se-qwerty', 'failsafe', 'en-gb-qwerty', 'es-es-qwerty',
                        'fr-ch-qwertz', 'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty', 'fr-ca-qwerty'
                    ],
                    'type': 'str'
                },
                'listening-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_userbookmark_bookmarks'),
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
