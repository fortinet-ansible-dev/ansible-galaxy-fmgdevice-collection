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
module: fmgd_vpnsslweb_portal_bookmarkgroup
short_description: Portal bookmark group.
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
  portal:
    description: The parameter (portal) in requested url.
    type: str
    required: true
  vpnsslweb_portal_bookmarkgroup:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      bookmarks:
        type: list
        elements: dict
        description: Bookmarks.
        suboptions:
          additional_params:
            aliases: ['additional-params']
            type: str
            description: Additional parameters.
          apptype:
            type: str
            description: Application type.
            choices: ['web', 'telnet', 'ssh', 'ftp', 'smb', 'vnc', 'rdp', 'sftp', 'portforward',
                      'citrix']
          color_depth:
            aliases: ['color-depth']
            type: str
            description: Color depth per pixel.
            choices: ['8', '16', '32']
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
            choices: ['da', 'de', 'de-ch', 'en-uk', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca',
                      'fr-ch', 'hr', 'hu', 'it', 'ja', 'lt', 'mk', 'no', 'pt', 'pt-br', 'ru',
                      'sl', 'sv', 'ar-101', 'ar-102', 'ar-102-azerty', 'can-mul', 'cz',
                      'cz-qwerty', 'cz-pr', 'nl', 'de-ibm', 'en-uk-ext', 'en-us-dvorak', 'es-var',
                      'fi-sami', 'hu-101', 'it-142', 'ko', 'lt-ibm', 'lt-std', 'lav-std',
                      'lav-leg', 'mk-std', 'no-sami', 'pol-214', 'pol-pr', 'pt-br-abnt2',
                      'ru-mne', 'ru-t', 'sv-sami', 'tuk', 'tur-f', 'tur-q', 'zh-sym-sg-us',
                      'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo', 'zh-tr-us', 'fr-apple', 'la-am',
                      'ja-106']
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
            choices: ['disable', 'enable']
          security:
            type: str
            description: Security mode for RDP connection
            choices: ['rdp', 'nla', 'tls', 'any']
          send_preconnection_id:
            aliases: ['send-preconnection-id']
            type: str
            description: Enable/disable sending of preconnection ID.
            choices: ['disable', 'enable']
          sso:
            type: str
            description: Single sign-on.
            choices: ['disable', 'static', 'auto']
          sso_credential:
            aliases: ['sso-credential']
            type: str
            description: Single sign-on credentials.
            choices: ['sslvpn-login', 'alternative']
          sso_credential_sent_once:
            aliases: ['sso-credential-sent-once']
            type: str
            description: Single sign-on credentials are only sent once to remote server.
            choices: ['disable', 'enable']
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
            choices: ['da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it', 'no', 'pt',
                      'sv', 'nl', 'en-uk-ext', 'it-142', 'pt-br-abnt2', 'default', 'fr-ca-mul',
                      'gd', 'us-intl']
          width:
            type: int
            description: Screen width
          server_layout:
            aliases: ['server-layout']
            type: str
            description: Server side keyboard layout.
            choices: ['en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty',
                      'sv-se-qwerty', 'failsafe', 'en-gb-qwerty', 'es-es-qwerty', 'fr-ch-qwertz',
                      'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty', 'fr-ca-qwerty']
          remote_port:
            aliases: ['remote-port']
            type: int
            description: Remote port
          show_status_window:
            aliases: ['show-status-window']
            type: str
            description: Enable/disable showing of status window.
            choices: ['disable', 'enable']
          listening_port:
            aliases: ['listening-port']
            type: int
            description: Listening port
      name:
        type: str
        description: Bookmark group name.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Portal bookmark group.
      fortinet.fmgdevice.fmgd_vpnsslweb_portal_bookmarkgroup:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        portal: <your own value>
        state: present # <value in [present, absent]>
        vpnsslweb_portal_bookmarkgroup:
          name: "your value" # Required variable, string
          # bookmarks:
          #   - additional_params: <string>
          #     apptype: <value in [web, telnet, ssh, ...]>
          #     color_depth: <value in [8, 16, 32]>
          #     description: <string>
          #     domain: <string>
          #     folder: <string>
          #     form_data:
          #       - name: <string>
          #         value: <string>
          #     height: <integer>
          #     host: <string>
          #     keyboard_layout: <value in [da, de, de-ch, ...]>
          #     load_balancing_info: <string>
          #     logon_password: <list or string>
          #     logon_user: <string>
          #     name: <string>
          #     port: <integer>
          #     preconnection_blob: <string>
          #     preconnection_id: <integer>
          #     restricted_admin: <value in [disable, enable]>
          #     security: <value in [rdp, nla, tls, ...]>
          #     send_preconnection_id: <value in [disable, enable]>
          #     sso: <value in [disable, static, auto]>
          #     sso_credential: <value in [sslvpn-login, alternative]>
          #     sso_credential_sent_once: <value in [disable, enable]>
          #     sso_password: <list or string>
          #     sso_username: <string>
          #     url: <string>
          #     vnc_keyboard_layout: <value in [da, de, de-ch, ...]>
          #     width: <integer>
          #     server_layout: <value in [en-us-qwerty, de-de-qwertz, fr-fr-azerty, ...]>
          #     remote_port: <integer>
          #     show_status_window: <value in [disable, enable]>
          #     listening_port: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/bookmark-group'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'portal': {'required': True, 'type': 'str'},
        'vpnsslweb_portal_bookmarkgroup': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'bookmarks': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'additional-params': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'apptype': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['web', 'telnet', 'ssh', 'ftp', 'smb', 'vnc', 'rdp', 'sftp', 'portforward', 'citrix'],
                            'type': 'str'
                        },
                        'color-depth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['8', '16', '32'], 'type': 'str'},
                        'description': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'folder': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'form-data': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'value': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'height': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'keyboard-layout': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'da', 'de', 'de-ch', 'en-uk', 'en-us', 'es', 'fi', 'fr', 'fr-be', 'fr-ca', 'fr-ch', 'hr', 'hu', 'it', 'ja', 'lt', 'mk',
                                'no', 'pt', 'pt-br', 'ru', 'sl', 'sv', 'ar-101', 'ar-102', 'ar-102-azerty', 'can-mul', 'cz', 'cz-qwerty', 'cz-pr', 'nl',
                                'de-ibm', 'en-uk-ext', 'en-us-dvorak', 'es-var', 'fi-sami', 'hu-101', 'it-142', 'ko', 'lt-ibm', 'lt-std', 'lav-std',
                                'lav-leg', 'mk-std', 'no-sami', 'pol-214', 'pol-pr', 'pt-br-abnt2', 'ru-mne', 'ru-t', 'sv-sami', 'tuk', 'tur-f', 'tur-q',
                                'zh-sym-sg-us', 'zh-sym-us', 'zh-tr-hk', 'zh-tr-mo', 'zh-tr-us', 'fr-apple', 'la-am', 'ja-106'
                            ],
                            'type': 'str'
                        },
                        'load-balancing-info': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'logon-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'logon-user': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'preconnection-blob': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'preconnection-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'restricted-admin': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'security': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['rdp', 'nla', 'tls', 'any'], 'type': 'str'},
                        'send-preconnection-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sso': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'static', 'auto'], 'type': 'str'},
                        'sso-credential': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['sslvpn-login', 'alternative'], 'type': 'str'},
                        'sso-credential-sent-once': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sso-password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'sso-username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'url': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'vnc-keyboard-layout': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'da', 'de', 'de-ch', 'en-uk', 'es', 'fi', 'fr', 'fr-be', 'it', 'no', 'pt', 'sv', 'nl', 'en-uk-ext', 'it-142',
                                'pt-br-abnt2', 'default', 'fr-ca-mul', 'gd', 'us-intl'
                            ],
                            'type': 'str'
                        },
                        'width': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'server-layout': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'en-us-qwerty', 'de-de-qwertz', 'fr-fr-azerty', 'it-it-qwerty', 'sv-se-qwerty', 'failsafe', 'en-gb-qwerty',
                                'es-es-qwerty', 'fr-ch-qwertz', 'ja-jp-qwerty', 'pt-br-qwerty', 'tr-tr-qwerty', 'fr-ca-qwerty'
                            ],
                            'type': 'str'
                        },
                        'remote-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'show-status-window': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'listening-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnsslweb_portal_bookmarkgroup'),
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
