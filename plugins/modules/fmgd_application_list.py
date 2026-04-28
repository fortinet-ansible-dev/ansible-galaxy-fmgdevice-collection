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
module: fmgd_application_list
short_description: Configure application control lists.
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
    application_list:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app_replacemsg:
                aliases: ['app-replacemsg']
                type: str
                description: Enable/disable replacement messages for blocked applications.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comments.
            control_default_network_services:
                aliases: ['control-default-network-services']
                type: str
                description: Enable/disable enforcement of protocols over selected ports.
                choices:
                    - 'disable'
                    - 'enable'
            deep_app_inspection:
                aliases: ['deep-app-inspection']
                type: str
                description: Enable/disable deep application inspection.
                choices:
                    - 'disable'
                    - 'enable'
            default_network_services:
                aliases: ['default-network-services']
                type: list
                elements: dict
                description: Default network services.
                suboptions:
                    id:
                        type: int
                        description: Entry ID.
                    port:
                        type: int
                        description: Port number.
                    services:
                        type: list
                        elements: str
                        description: Network protocols.
                        choices:
                            - 'http'
                            - 'ssh'
                            - 'telnet'
                            - 'ftp'
                            - 'dns'
                            - 'smtp'
                            - 'pop3'
                            - 'imap'
                            - 'snmp'
                            - 'nntp'
                            - 'https'
                    violation_action:
                        aliases: ['violation-action']
                        type: str
                        description: Action for protocols not in the allowlist for selected port.
                        choices:
                            - 'block'
                            - 'monitor'
                            - 'pass'
            enforce_default_app_port:
                aliases: ['enforce-default-app-port']
                type: str
                description: Enable/disable default application port enforcement for allowed applications.
                choices:
                    - 'disable'
                    - 'enable'
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Pass or block traffic, or reset connection for traffic from this application.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                    application:
                        type: list
                        elements: int
                        description: ID of allowed applications.
                    behavior:
                        type: list
                        elements: str
                        description: Application behavior filter.
                    category:
                        type: list
                        elements: str
                        description: Category ID list.
                    exclusion:
                        type: list
                        elements: int
                        description: ID of excluded applications.
                    id:
                        type: int
                        description: Entry ID.
                    log:
                        type: str
                        description: Enable/disable logging for this application list.
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        aliases: ['log-packet']
                        type: str
                        description: Enable/disable packet logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    parameters:
                        type: list
                        elements: dict
                        description: Parameters.
                        suboptions:
                            id:
                                type: int
                                description: Parameter tuple ID.
                            members:
                                type: list
                                elements: dict
                                description: Members.
                                suboptions:
                                    id:
                                        type: int
                                        description: Parameter.
                                    name:
                                        type: str
                                        description: Parameter name.
                                    value:
                                        type: str
                                        description: Parameter value.
                            value:
                                type: str
                                description: Parameter value.
                    popularity:
                        type: list
                        elements: str
                        description: Application popularity filter
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                    protocols:
                        type: list
                        elements: str
                        description: Application protocol filter.
                    quarantine:
                        type: str
                        description: Quarantine method.
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine_expiry:
                        aliases: ['quarantine-expiry']
                        type: str
                        description: Duration of quarantine.
                    quarantine_log:
                        aliases: ['quarantine-log']
                        type: str
                        description: Enable/disable quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_count:
                        aliases: ['rate-count']
                        type: int
                        description: Count of the rate.
                    rate_duration:
                        aliases: ['rate-duration']
                        type: int
                        description: Duration
                    rate_mode:
                        aliases: ['rate-mode']
                        type: str
                        description: Rate limit mode.
                        choices:
                            - 'periodical'
                            - 'continuous'
                    rate_track:
                        aliases: ['rate-track']
                        type: str
                        description: Track the packet protocol field.
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                            - 'dhcp-client-mac'
                            - 'dns-domain'
                    risk:
                        type: list
                        elements: int
                        description: Risk, or impact, of allowing traffic from this application to occur
                    session_ttl:
                        aliases: ['session-ttl']
                        type: int
                        description: Session TTL
                    shaper:
                        type: list
                        elements: str
                        description: Traffic shaper.
                    technology:
                        type: list
                        elements: str
                        description: Application technology filter.
                    vendor:
                        type: list
                        elements: str
                        description: Application vendor filter.
                    shaper_reverse:
                        aliases: ['shaper-reverse']
                        type: list
                        elements: str
                        description: Reverse traffic shaper.
                    per_ip_shaper:
                        aliases: ['per-ip-shaper']
                        type: list
                        elements: str
                        description: Per-IP traffic shaper.
                    sub_category:
                        aliases: ['sub-category']
                        type: list
                        elements: int
                        description: Application Sub-category ID list.
                    tags:
                        type: list
                        elements: str
                        description: Tag filter.
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable extended logging.
                choices:
                    - 'disable'
                    - 'enable'
            force_inclusion_ssl_di_sigs:
                aliases: ['force-inclusion-ssl-di-sigs']
                type: str
                description: Enable/disable forced inclusion of SSL deep inspection signatures.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: List name.
                required: true
            options:
                type: list
                elements: str
                description: Basic application protocol signatures allowed by default.
                choices:
                    - 'allow-dns'
                    - 'allow-icmp'
                    - 'allow-http'
                    - 'allow-ssl'
                    - 'allow-quic'
            other_application_action:
                aliases: ['other-application-action']
                type: str
                description: Action for other applications.
                choices:
                    - 'pass'
                    - 'block'
            other_application_log:
                aliases: ['other-application-log']
                type: str
                description: Enable/disable logging for other applications.
                choices:
                    - 'disable'
                    - 'enable'
            p2p_block_list:
                aliases: ['p2p-block-list']
                type: list
                elements: str
                description: P2P applications to be block listed.
                choices:
                    - 'skype'
                    - 'edonkey'
                    - 'bittorrent'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: list
                elements: str
                description: Replacement message group.
            unknown_application_action:
                aliases: ['unknown-application-action']
                type: str
                description: Pass or block traffic from unknown applications.
                choices:
                    - 'pass'
                    - 'block'
            unknown_application_log:
                aliases: ['unknown-application-log']
                type: str
                description: Enable/disable logging for unknown applications.
                choices:
                    - 'disable'
                    - 'enable'
            p2p_black_list:
                aliases: ['p2p-black-list']
                type: list
                elements: str
                description: P2P applications to be black listed.
                choices:
                    - 'skype'
                    - 'edonkey'
                    - 'bittorrent'
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
    - name: Configure application control lists.
      fortinet.fmgdevice.fmgd_application_list:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        application_list:
          name: "your value" # Required variable, string
          # app_replacemsg: <value in [disable, enable]>
          # comment: <string>
          # control_default_network_services: <value in [disable, enable]>
          # deep_app_inspection: <value in [disable, enable]>
          # default_network_services:
          #   - id: <integer>
          #     port: <integer>
          #     services:
          #       - "http"
          #       - "ssh"
          #       - "telnet"
          #       - "ftp"
          #       - "dns"
          #       - "smtp"
          #       - "pop3"
          #       - "imap"
          #       - "snmp"
          #       - "nntp"
          #       - "https"
          #     violation_action: <value in [block, monitor, pass]>
          # enforce_default_app_port: <value in [disable, enable]>
          # entries:
          #   - action: <value in [pass, block, reset]>
          #     application: <list or integer>
          #     behavior: <list or string>
          #     category: <list or string>
          #     exclusion: <list or integer>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          #     log_packet: <value in [disable, enable]>
          #     parameters:
          #       - id: <integer>
          #         members:
          #           - id: <integer>
          #             name: <string>
          #             value: <string>
          #         value: <string>
          #     popularity:
          #       - "1"
          #       - "2"
          #       - "3"
          #       - "4"
          #       - "5"
          #     protocols: <list or string>
          #     quarantine: <value in [none, attacker]>
          #     quarantine_expiry: <string>
          #     quarantine_log: <value in [disable, enable]>
          #     rate_count: <integer>
          #     rate_duration: <integer>
          #     rate_mode: <value in [periodical, continuous]>
          #     rate_track: <value in [none, src-ip, dest-ip, ...]>
          #     risk: <list or integer>
          #     session_ttl: <integer>
          #     shaper: <list or string>
          #     technology: <list or string>
          #     vendor: <list or string>
          #     shaper_reverse: <list or string>
          #     per_ip_shaper: <list or string>
          #     sub_category: <list or integer>
          #     tags: <list or string>
          # extended_log: <value in [disable, enable]>
          # force_inclusion_ssl_di_sigs: <value in [disable, enable]>
          # options:
          #   - "allow-dns"
          #   - "allow-icmp"
          #   - "allow-http"
          #   - "allow-ssl"
          #   - "allow-quic"
          # other_application_action: <value in [pass, block]>
          # other_application_log: <value in [disable, enable]>
          # p2p_block_list:
          #   - "skype"
          #   - "edonkey"
          #   - "bittorrent"
          # replacemsg_group: <list or string>
          # unknown_application_action: <value in [pass, block]>
          # unknown_application_log: <value in [disable, enable]>
          # p2p_black_list:
          #   - "skype"
          #   - "edonkey"
          #   - "bittorrent"
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
        '/pm/config/device/{device}/vdom/{vdom}/application/list'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'application_list': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'app-replacemsg': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'control-default-network-services': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'deep-app-inspection': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-network-services': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'services': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['http', 'ssh', 'telnet', 'ftp', 'dns', 'smtp', 'pop3', 'imap', 'snmp', 'nntp', 'https'],
                            'elements': 'str'
                        },
                        'violation-action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'monitor', 'pass'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'enforce-default-app-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'entries': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['pass', 'block', 'reset'], 'type': 'str'},
                        'application': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'behavior': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'exclusion': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'log-packet': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'parameters': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'members': {
                                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                                    'type': 'list',
                                    'options': {
                                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                        'value': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                                    },
                                    'elements': 'dict'
                                },
                                'value': {'v_range': [['7.4.8', '7.4.10']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'popularity': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['1', '2', '3', '4', '5'],
                            'elements': 'str'
                        },
                        'protocols': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'quarantine': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['none', 'attacker'], 'type': 'str'},
                        'quarantine-expiry': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'quarantine-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rate-count': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'rate-duration': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'rate-mode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['periodical', 'continuous'], 'type': 'str'},
                        'rate-track': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['none', 'src-ip', 'dest-ip', 'dhcp-client-mac', 'dns-domain'],
                            'type': 'str'
                        },
                        'risk': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'session-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'shaper': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'technology': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'vendor': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'shaper-reverse': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'per-ip-shaper': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'sub-category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'tags': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'extended-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'force-inclusion-ssl-di-sigs': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'options': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['allow-dns', 'allow-icmp', 'allow-http', 'allow-ssl', 'allow-quic'],
                    'elements': 'str'
                },
                'other-application-action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['pass', 'block'], 'type': 'str'},
                'other-application-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'p2p-block-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['skype', 'edonkey', 'bittorrent'],
                    'elements': 'str'
                },
                'replacemsg-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'unknown-application-action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['pass', 'block'], 'type': 'str'},
                'unknown-application-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'p2p-black-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['skype', 'edonkey', 'bittorrent'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'application_list'),
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
