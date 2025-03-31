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
module: fmgd_system_admin
short_description: Configure admin users.
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
    system_admin:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accprofile:
                type: list
                elements: str
                description: Access profile for this administrator.
            accprofile_override:
                aliases: ['accprofile-override']
                type: str
                description: Enable to use the name of an access profile provided by the remote authentication server to control the FortiGate features...
                choices:
                    - 'disable'
                    - 'enable'
            allow_remove_admin_session:
                aliases: ['allow-remove-admin-session']
                type: str
                description: Enable/disable allow admin session to be removed by privileged admin users.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comment.
            email_to:
                aliases: ['email-to']
                type: str
                description: This administrators email address.
            force_password_change:
                aliases: ['force-password-change']
                type: str
                description: Enable/disable force password change on next login.
                choices:
                    - 'disable'
                    - 'enable'
            fortitoken:
                type: list
                elements: str
                description: This administrators FortiToken serial number.
            guest_auth:
                aliases: ['guest-auth']
                type: str
                description: Enable/disable guest authentication.
                choices:
                    - 'disable'
                    - 'enable'
            guest_lang:
                aliases: ['guest-lang']
                type: list
                elements: str
                description: Guest management portal language.
            guest_usergroups:
                aliases: ['guest-usergroups']
                type: list
                elements: str
                description: Select guest user groups.
            gui_default_dashboard_template:
                aliases: ['gui-default-dashboard-template']
                type: str
                description: The default dashboard template.
            gui_ignore_invalid_signature_version:
                aliases: ['gui-ignore-invalid-signature-version']
                type: str
                description: FortiOS image build version to ignore invalid signature warning for.
            gui_ignore_release_overview_version:
                aliases: ['gui-ignore-release-overview-version']
                type: str
                description: FortiOS version to ignore release overview prompt for.
            history0:
                type: list
                elements: str
                description: History0.
            history1:
                type: list
                elements: str
                description: History1.
            ip6_trusthost1:
                aliases: ['ip6-trusthost1']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost10:
                aliases: ['ip6-trusthost10']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost2:
                aliases: ['ip6-trusthost2']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost3:
                aliases: ['ip6-trusthost3']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost4:
                aliases: ['ip6-trusthost4']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost5:
                aliases: ['ip6-trusthost5']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost6:
                aliases: ['ip6-trusthost6']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost7:
                aliases: ['ip6-trusthost7']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost8:
                aliases: ['ip6-trusthost8']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            ip6_trusthost9:
                aliases: ['ip6-trusthost9']
                type: str
                description: Any IPv6 address from which the administrator can connect to the FortiGate unit.
            name:
                type: str
                description: User name.
                required: true
            password:
                type: list
                elements: str
                description: Admin user password.
            password_expire:
                aliases: ['password-expire']
                type: list
                elements: str
                description: Password expire time.
            peer_auth:
                aliases: ['peer-auth']
                type: str
                description: Set to enable peer certificate authentication
                choices:
                    - 'disable'
                    - 'enable'
            peer_group:
                aliases: ['peer-group']
                type: list
                elements: str
                description: Name of peer group defined under config user group which has PKI members.
            remote_auth:
                aliases: ['remote-auth']
                type: str
                description: Enable/disable authentication using a remote RADIUS, LDAP, or TACACS+ server.
                choices:
                    - 'disable'
                    - 'enable'
            remote_group:
                aliases: ['remote-group']
                type: list
                elements: str
                description: User group name used for remote auth.
            schedule:
                type: str
                description: Firewall schedule used to restrict when the administrator can log in.
            sms_custom_server:
                aliases: ['sms-custom-server']
                type: list
                elements: str
                description: Custom SMS server to send SMS messages to.
            sms_phone:
                aliases: ['sms-phone']
                type: str
                description: Phone number on which the administrator receives SMS messages.
            sms_server:
                aliases: ['sms-server']
                type: str
                description: Send SMS messages using the FortiGuard SMS server or a custom server.
                choices:
                    - 'fortiguard'
                    - 'custom'
            ssh_certificate:
                aliases: ['ssh-certificate']
                type: list
                elements: str
                description: Select the certificate to be used by the FortiGate for authentication with an SSH client.
            ssh_public_key1:
                aliases: ['ssh-public-key1']
                type: str
                description: Public key of an SSH client.
            ssh_public_key2:
                aliases: ['ssh-public-key2']
                type: str
                description: Public key of an SSH client.
            ssh_public_key3:
                aliases: ['ssh-public-key3']
                type: str
                description: Public key of an SSH client.
            trusthost1:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost10:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost2:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost3:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost4:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost5:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost6:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost7:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost8:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            trusthost9:
                type: list
                elements: str
                description: Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit.
            two_factor:
                aliases: ['two-factor']
                type: str
                description: Enable/disable two-factor authentication.
                choices:
                    - 'disable'
                    - 'fortitoken'
                    - 'email'
                    - 'sms'
                    - 'fortitoken-cloud'
            two_factor_authentication:
                aliases: ['two-factor-authentication']
                type: str
                description: Authentication method by FortiToken Cloud.
                choices:
                    - 'fortitoken'
                    - 'email'
                    - 'sms'
            two_factor_notification:
                aliases: ['two-factor-notification']
                type: str
                description: Notification method for user activation by FortiToken Cloud.
                choices:
                    - 'email'
                    - 'sms'
            vdom:
                type: list
                elements: str
                description: Virtual domain
            vdom_override:
                aliases: ['vdom-override']
                type: str
                description: Enable to use the names of VDOMs provided by the remote authentication server to control the VDOMs that this administrator...
                choices:
                    - 'disable'
                    - 'enable'
            wildcard:
                type: str
                description: Enable/disable wildcard RADIUS authentication.
                choices:
                    - 'disable'
                    - 'enable'
            radius_vdom_override:
                aliases: ['radius-vdom-override']
                type: str
                description: Enable to use the names of VDOMs provided by the remote authentication server to control the VDOMs that this administrator...
                choices:
                    - 'disable'
                    - 'enable'
            hidden:
                type: int
                description: Hidden.
            old_password:
                aliases: ['old-password']
                type: list
                elements: str
                description: Admin user old password.
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
    - name: Configure admin users.
      fortinet.fmgdevice.fmgd_system_admin:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_admin:
          name: "your value" # Required variable, string
          # accprofile: <list or string>
          # accprofile_override: <value in [disable, enable]>
          # allow_remove_admin_session: <value in [disable, enable]>
          # comments: <string>
          # email_to: <string>
          # force_password_change: <value in [disable, enable]>
          # fortitoken: <list or string>
          # guest_auth: <value in [disable, enable]>
          # guest_lang: <list or string>
          # guest_usergroups: <list or string>
          # gui_default_dashboard_template: <string>
          # gui_ignore_invalid_signature_version: <string>
          # gui_ignore_release_overview_version: <string>
          # history0: <list or string>
          # history1: <list or string>
          # ip6_trusthost1: <string>
          # ip6_trusthost10: <string>
          # ip6_trusthost2: <string>
          # ip6_trusthost3: <string>
          # ip6_trusthost4: <string>
          # ip6_trusthost5: <string>
          # ip6_trusthost6: <string>
          # ip6_trusthost7: <string>
          # ip6_trusthost8: <string>
          # ip6_trusthost9: <string>
          # password: <list or string>
          # password_expire: <list or string>
          # peer_auth: <value in [disable, enable]>
          # peer_group: <list or string>
          # remote_auth: <value in [disable, enable]>
          # remote_group: <list or string>
          # schedule: <string>
          # sms_custom_server: <list or string>
          # sms_phone: <string>
          # sms_server: <value in [fortiguard, custom]>
          # ssh_certificate: <list or string>
          # ssh_public_key1: <string>
          # ssh_public_key2: <string>
          # ssh_public_key3: <string>
          # trusthost1: <list or string>
          # trusthost10: <list or string>
          # trusthost2: <list or string>
          # trusthost3: <list or string>
          # trusthost4: <list or string>
          # trusthost5: <list or string>
          # trusthost6: <list or string>
          # trusthost7: <list or string>
          # trusthost8: <list or string>
          # trusthost9: <list or string>
          # two_factor: <value in [disable, fortitoken, email, ...]>
          # two_factor_authentication: <value in [fortitoken, email, sms]>
          # two_factor_notification: <value in [email, sms]>
          # vdom: <list or string>
          # vdom_override: <value in [disable, enable]>
          # wildcard: <value in [disable, enable]>
          # radius_vdom_override: <value in [disable, enable]>
          # hidden: <integer>
          # old_password: <list or string>
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
        '/pm/config/device/{device}/global/system/admin'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_admin': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'accprofile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'accprofile-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allow-remove-admin-session': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'email-to': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'force-password-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortitoken': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'guest-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'guest-lang': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'guest-usergroups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'gui-default-dashboard-template': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gui-ignore-invalid-signature-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'gui-ignore-release-overview-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'history0': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'history1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip6-trusthost1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost10': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip6-trusthost9': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password-expire': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'peer-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'peer-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'remote-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remote-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'schedule': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sms-custom-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sms-phone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sms-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['fortiguard', 'custom'], 'type': 'str'},
                'ssh-certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssh-public-key1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'ssh-public-key2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'ssh-public-key3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'trusthost1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost10': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost5': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost7': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost8': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'trusthost9': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'two-factor': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'fortitoken', 'email', 'sms', 'fortitoken-cloud'],
                    'type': 'str'
                },
                'two-factor-authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['fortitoken', 'email', 'sms'], 'type': 'str'},
                'two-factor-notification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['email', 'sms'], 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vdom-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wildcard': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-vdom-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hidden': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'old-password': {'v_range': [['7.6.2', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_admin'),
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
