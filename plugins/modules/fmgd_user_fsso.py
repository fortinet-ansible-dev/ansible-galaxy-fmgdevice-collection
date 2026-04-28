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
module: fmgd_user_fsso
short_description: Configure Fortinet Single Sign On
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
    user_fsso:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _gui_meta:
                type: str
                description: Gui meta.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _gui_meta:
                        type: str
                        description: Gui meta.
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
                    group_poll_interval:
                        aliases: ['group-poll-interval']
                        type: int
                        description: Interval in minutes within to fetch groups from FSSO server, or unset to disable.
                    interface:
                        type: list
                        elements: str
                        description: Specify outgoing interface to reach server.
                    interface_select_method:
                        aliases: ['interface-select-method']
                        type: str
                        description: Specify how to select outgoing interface to reach server.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    ldap_poll:
                        aliases: ['ldap-poll']
                        type: str
                        description: Enable/disable automatic fetching of groups from LDAP server.
                        choices:
                            - 'disable'
                            - 'enable'
                    ldap_poll_filter:
                        aliases: ['ldap-poll-filter']
                        type: str
                        description: Filter used to fetch groups.
                    ldap_poll_interval:
                        aliases: ['ldap-poll-interval']
                        type: int
                        description: Interval in minutes within to fetch groups from LDAP server.
                    ldap_server:
                        aliases: ['ldap-server']
                        type: list
                        elements: str
                        description: LDAP server to get group information.
                    logon_timeout:
                        aliases: ['logon-timeout']
                        type: int
                        description: Interval in minutes to keep logons after FSSO server down.
                    password:
                        type: list
                        elements: str
                        description: Password of the first FSSO collector agent.
                    password2:
                        type: list
                        elements: str
                        description: Password of the second FSSO collector agent.
                    password3:
                        type: list
                        elements: str
                        description: Password of the third FSSO collector agent.
                    password4:
                        type: list
                        elements: str
                        description: Password of the fourth FSSO collector agent.
                    password5:
                        type: list
                        elements: str
                        description: Password of the fifth FSSO collector agent.
                    port:
                        type: int
                        description: Port of the first FSSO collector agent.
                    port2:
                        type: int
                        description: Port of the second FSSO collector agent.
                    port3:
                        type: int
                        description: Port of the third FSSO collector agent.
                    port4:
                        type: int
                        description: Port of the fourth FSSO collector agent.
                    port5:
                        type: int
                        description: Port of the fifth FSSO collector agent.
                    server:
                        type: str
                        description: Domain name or IP address of the first FSSO collector agent.
                    server2:
                        type: str
                        description: Domain name or IP address of the second FSSO collector agent.
                    server3:
                        type: str
                        description: Domain name or IP address of the third FSSO collector agent.
                    server4:
                        type: str
                        description: Domain name or IP address of the fourth FSSO collector agent.
                    server5:
                        type: str
                        description: Domain name or IP address of the fifth FSSO collector agent.
                    sni:
                        type: str
                        description: Server Name Indication.
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Source IP for communications to FSSO agent.
                    source_ip6:
                        aliases: ['source-ip6']
                        type: str
                        description: IPv6 source for communications to FSSO agent.
                    ssl:
                        type: str
                        description: Enable/disable use of SSL.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_server_host_ip_check:
                        aliases: ['ssl-server-host-ip-check']
                        type: str
                        description: Enable/disable server host/IP verification.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_trusted_cert:
                        aliases: ['ssl-trusted-cert']
                        type: list
                        elements: str
                        description: Trusted server certificate or CA certificate.
                    type:
                        type: str
                        description: Server type.
                        choices:
                            - 'default'
                            - 'fortinac'
                            - 'fortiems'
                            - 'fortiems-cloud'
                    user_info_server:
                        aliases: ['user-info-server']
                        type: list
                        elements: str
                        description: LDAP server to get user information.
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            group_poll_interval:
                aliases: ['group-poll-interval']
                type: int
                description: Interval in minutes within to fetch groups from FSSO server, or unset to disable.
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            ldap_poll:
                aliases: ['ldap-poll']
                type: str
                description: Enable/disable automatic fetching of groups from LDAP server.
                choices:
                    - 'disable'
                    - 'enable'
            ldap_poll_filter:
                aliases: ['ldap-poll-filter']
                type: str
                description: Filter used to fetch groups.
            ldap_poll_interval:
                aliases: ['ldap-poll-interval']
                type: int
                description: Interval in minutes within to fetch groups from LDAP server.
            ldap_server:
                aliases: ['ldap-server']
                type: list
                elements: str
                description: LDAP server to get group information.
            logon_timeout:
                aliases: ['logon-timeout']
                type: int
                description: Interval in minutes to keep logons after FSSO server down.
            name:
                type: str
                description: Name.
                required: true
            password:
                type: list
                elements: str
                description: Password of the first FSSO collector agent.
            password2:
                type: list
                elements: str
                description: Password of the second FSSO collector agent.
            password3:
                type: list
                elements: str
                description: Password of the third FSSO collector agent.
            password4:
                type: list
                elements: str
                description: Password of the fourth FSSO collector agent.
            password5:
                type: list
                elements: str
                description: Password of the fifth FSSO collector agent.
            port:
                type: int
                description: Port of the first FSSO collector agent.
            port2:
                type: int
                description: Port of the second FSSO collector agent.
            port3:
                type: int
                description: Port of the third FSSO collector agent.
            port4:
                type: int
                description: Port of the fourth FSSO collector agent.
            port5:
                type: int
                description: Port of the fifth FSSO collector agent.
            server:
                type: str
                description: Domain name or IP address of the first FSSO collector agent.
            server2:
                type: str
                description: Domain name or IP address of the second FSSO collector agent.
            server3:
                type: str
                description: Domain name or IP address of the third FSSO collector agent.
            server4:
                type: str
                description: Domain name or IP address of the fourth FSSO collector agent.
            server5:
                type: str
                description: Domain name or IP address of the fifth FSSO collector agent.
            sni:
                type: str
                description: Server Name Indication.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP for communications to FSSO agent.
            source_ip6:
                aliases: ['source-ip6']
                type: str
                description: IPv6 source for communications to FSSO agent.
            ssl:
                type: str
                description: Enable/disable use of SSL.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_host_ip_check:
                aliases: ['ssl-server-host-ip-check']
                type: str
                description: Enable/disable server host/IP verification.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_trusted_cert:
                aliases: ['ssl-trusted-cert']
                type: list
                elements: str
                description: Trusted server certificate or CA certificate.
            type:
                type: str
                description: Server type.
                choices:
                    - 'default'
                    - 'fortinac'
                    - 'fortiems'
                    - 'fortiems-cloud'
            user_info_server:
                aliases: ['user-info-server']
                type: list
                elements: str
                description: LDAP server to get user information.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Configure Fortinet Single Sign On
      fortinet.fmgdevice.fmgd_user_fsso:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_fsso:
          name: "your value" # Required variable, string
          # _gui_meta: <string>
          # dynamic_mapping:
          #   - _gui_meta: <string>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     group_poll_interval: <integer>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, sdwan, specify]>
          #     ldap_poll: <value in [disable, enable]>
          #     ldap_poll_filter: <string>
          #     ldap_poll_interval: <integer>
          #     ldap_server: <list or string>
          #     logon_timeout: <integer>
          #     password: <list or string>
          #     password2: <list or string>
          #     password3: <list or string>
          #     password4: <list or string>
          #     password5: <list or string>
          #     port: <integer>
          #     port2: <integer>
          #     port3: <integer>
          #     port4: <integer>
          #     port5: <integer>
          #     server: <string>
          #     server2: <string>
          #     server3: <string>
          #     server4: <string>
          #     server5: <string>
          #     sni: <string>
          #     source_ip: <string>
          #     source_ip6: <string>
          #     ssl: <value in [disable, enable]>
          #     ssl_server_host_ip_check: <value in [disable, enable]>
          #     ssl_trusted_cert: <list or string>
          #     type: <value in [default, fortinac, fortiems, ...]>
          #     user_info_server: <list or string>
          #     vrf_select: <integer>
          # group_poll_interval: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ldap_poll: <value in [disable, enable]>
          # ldap_poll_filter: <string>
          # ldap_poll_interval: <integer>
          # ldap_server: <list or string>
          # logon_timeout: <integer>
          # password: <list or string>
          # password2: <list or string>
          # password3: <list or string>
          # password4: <list or string>
          # password5: <list or string>
          # port: <integer>
          # port2: <integer>
          # port3: <integer>
          # port4: <integer>
          # port5: <integer>
          # server: <string>
          # server2: <string>
          # server3: <string>
          # server4: <string>
          # server5: <string>
          # sni: <string>
          # source_ip: <string>
          # source_ip6: <string>
          # ssl: <value in [disable, enable]>
          # ssl_server_host_ip_check: <value in [disable, enable]>
          # ssl_trusted_cert: <list or string>
          # type: <value in [default, fortinac, fortiems, ...]>
          # user_info_server: <list or string>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/fsso'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_fsso': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                '_gui_meta': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_gui_meta': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'group-poll-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'ldap-poll': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ldap-poll-filter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'ldap-poll-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ldap-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'logon-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password5': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'port2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'port3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'port4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'port5': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'server2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'server3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'server4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'server5': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'sni': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'source-ip6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'ssl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-host-ip-check': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-trusted-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['default', 'fortinac', 'fortiems', 'fortiems-cloud'],
                            'type': 'str'
                        },
                        'user-info-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'group-poll-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ldap-poll': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ldap-poll-filter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ldap-poll-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'ldap-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logon-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password5': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'port2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'port3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'port4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'port5': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'server2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'server3': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'server4': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'server5': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'sni': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ssl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-host-ip-check': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-trusted-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['default', 'fortinac', 'fortiems', 'fortiems-cloud'], 'type': 'str'},
                'user-info-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_fsso'),
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
