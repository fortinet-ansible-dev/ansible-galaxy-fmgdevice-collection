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
module: fmgd_log_threatweight
short_description: Configure threat weight settings.
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
    log_threatweight:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            application:
                type: list
                elements: dict
                description: Application.
                suboptions:
                    category:
                        type: list
                        elements: str
                        description: Application category.
                    id:
                        type: int
                        description: Entry ID.
                    level:
                        type: str
                        description: Threat weight score for Application events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            blocked_connection:
                aliases: ['blocked-connection']
                type: str
                description: Threat weight score for blocked connections.
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            botnet_connection_detected:
                aliases: ['botnet-connection-detected']
                type: str
                description: Threat weight score for detected botnet connections.
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            failed_connection:
                aliases: ['failed-connection']
                type: str
                description: Threat weight score for failed connections.
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            geolocation:
                type: list
                elements: dict
                description: Geolocation.
                suboptions:
                    country:
                        type: list
                        elements: str
                        description: Country code.
                    id:
                        type: int
                        description: Entry ID.
                    level:
                        type: str
                        description: Threat weight score for Geolocation-based events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            ips:
                type: dict
                description: Ips.
                suboptions:
                    critical_severity:
                        aliases: ['critical-severity']
                        type: str
                        description: Threat weight score for IPS critical severity events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    high_severity:
                        aliases: ['high-severity']
                        type: str
                        description: Threat weight score for IPS high severity events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    info_severity:
                        aliases: ['info-severity']
                        type: str
                        description: Threat weight score for IPS info severity events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    low_severity:
                        aliases: ['low-severity']
                        type: str
                        description: Threat weight score for IPS low severity events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    medium_severity:
                        aliases: ['medium-severity']
                        type: str
                        description: Threat weight score for IPS medium severity events.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            level:
                type: dict
                description: Level.
                suboptions:
                    critical:
                        type: int
                        description: Critical level score value
                    high:
                        type: int
                        description: High level score value
                    low:
                        type: int
                        description: Low level score value
                    medium:
                        type: int
                        description: Medium level score value
            malware:
                type: dict
                description: Malware.
                suboptions:
                    command_blocked:
                        aliases: ['command-blocked']
                        type: str
                        description: Threat weight score for blocked command detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    content_disarm:
                        aliases: ['content-disarm']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    ems_threat_feed:
                        aliases: ['ems-threat-feed']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    file_blocked:
                        aliases: ['file-blocked']
                        type: str
                        description: Threat weight score for blocked file detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fortindr:
                        type: str
                        description: Threat weight score for FortiNDR-detected virus.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fortisandbox:
                        type: str
                        description: Threat weight score for FortiSandbox-detected virus.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fsa_high_risk:
                        aliases: ['fsa-high-risk']
                        type: str
                        description: Threat weight score for FortiSandbox high risk malware detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fsa_malicious:
                        aliases: ['fsa-malicious']
                        type: str
                        description: Threat weight score for FortiSandbox malicious malware detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fsa_medium_risk:
                        aliases: ['fsa-medium-risk']
                        type: str
                        description: Threat weight score for FortiSandbox medium risk malware detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    malware_list:
                        aliases: ['malware-list']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    mimefragmented:
                        type: str
                        description: Threat weight score for mimefragmented detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    oversized:
                        type: str
                        description: Threat weight score for oversized file detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    switch_proto:
                        aliases: ['switch-proto']
                        type: str
                        description: Threat weight score for switch proto detected.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_file_type_executable:
                        aliases: ['virus-file-type-executable']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_infected:
                        aliases: ['virus-infected']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_outbreak_prevention:
                        aliases: ['virus-outbreak-prevention']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    virus_scan_error:
                        aliases: ['virus-scan-error']
                        type: str
                        description: Threat weight score for virus
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    inline_block:
                        aliases: ['inline-block']
                        type: str
                        description: Threat weight score for malware detected by inline block.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    fortiai:
                        type: str
                        description: Threat weight score for FortiAI-detected virus.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            status:
                type: str
                description: Enable/disable the threat weight feature.
                choices:
                    - 'disable'
                    - 'enable'
            url_block_detected:
                aliases: ['url-block-detected']
                type: str
                description: Threat weight score for URL blocking.
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
            web:
                type: list
                elements: dict
                description: Web.
                suboptions:
                    category:
                        type: list
                        elements: str
                        description: Threat weight score for web category filtering matches.
                    id:
                        type: int
                        description: Entry ID.
                    level:
                        type: str
                        description: Threat weight score for web category filtering matches.
                        choices:
                            - 'disable'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
            malware_detected:
                aliases: ['malware-detected']
                type: str
                description: Threat weight score for detected malware.
                choices:
                    - 'disable'
                    - 'low'
                    - 'medium'
                    - 'high'
                    - 'critical'
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
    - name: Configure threat weight settings.
      fortinet.fmgdevice.fmgd_log_threatweight:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        log_threatweight:
          # application:
          #   - category: <list or string>
          #     id: <integer>
          #     level: <value in [disable, low, medium, ...]>
          # blocked_connection: <value in [disable, low, medium, ...]>
          # botnet_connection_detected: <value in [disable, low, medium, ...]>
          # failed_connection: <value in [disable, low, medium, ...]>
          # geolocation:
          #   - country: <list or string>
          #     id: <integer>
          #     level: <value in [disable, low, medium, ...]>
          # ips:
          #   critical_severity: <value in [disable, low, medium, ...]>
          #   high_severity: <value in [disable, low, medium, ...]>
          #   info_severity: <value in [disable, low, medium, ...]>
          #   low_severity: <value in [disable, low, medium, ...]>
          #   medium_severity: <value in [disable, low, medium, ...]>
          # level:
          #   critical: <integer>
          #   high: <integer>
          #   low: <integer>
          #   medium: <integer>
          # malware:
          #   command_blocked: <value in [disable, low, medium, ...]>
          #   content_disarm: <value in [disable, low, medium, ...]>
          #   ems_threat_feed: <value in [disable, low, medium, ...]>
          #   file_blocked: <value in [disable, low, medium, ...]>
          #   fortindr: <value in [disable, low, medium, ...]>
          #   fortisandbox: <value in [disable, low, medium, ...]>
          #   fsa_high_risk: <value in [disable, low, medium, ...]>
          #   fsa_malicious: <value in [disable, low, medium, ...]>
          #   fsa_medium_risk: <value in [disable, low, medium, ...]>
          #   malware_list: <value in [disable, low, medium, ...]>
          #   mimefragmented: <value in [disable, low, medium, ...]>
          #   oversized: <value in [disable, low, medium, ...]>
          #   switch_proto: <value in [disable, low, medium, ...]>
          #   virus_file_type_executable: <value in [disable, low, medium, ...]>
          #   virus_infected: <value in [disable, low, medium, ...]>
          #   virus_outbreak_prevention: <value in [disable, low, medium, ...]>
          #   virus_scan_error: <value in [disable, low, medium, ...]>
          #   inline_block: <value in [disable, low, medium, ...]>
          #   fortiai: <value in [disable, low, medium, ...]>
          # status: <value in [disable, enable]>
          # url_block_detected: <value in [disable, low, medium, ...]>
          # web:
          #   - category: <list or string>
          #     id: <integer>
          #     level: <value in [disable, low, medium, ...]>
          # malware_detected: <value in [disable, low, medium, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/threat-weight'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_threatweight': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'application': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'level': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'blocked-connection': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'botnet-connection-detected': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'failed-connection': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'geolocation': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'country': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'level': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ips': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'critical-severity': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'high-severity': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'info-severity': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'low-severity': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'medium-severity': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        }
                    }
                },
                'level': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'critical': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'high': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'low': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'medium': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                    }
                },
                'malware': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'command-blocked': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'content-disarm': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'ems-threat-feed': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'file-blocked': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'fortindr': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'fortisandbox': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'fsa-high-risk': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'fsa-malicious': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'fsa-medium-risk': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'malware-list': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'mimefragmented': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'oversized': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'switch-proto': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'virus-file-type-executable': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'virus-infected': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'virus-outbreak-prevention': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'virus-scan-error': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'inline-block': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'fortiai': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        }
                    }
                },
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-block-detected': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                    'type': 'str'
                },
                'web': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'level': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'malware-detected': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'low', 'medium', 'high', 'critical'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_threatweight'),
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
