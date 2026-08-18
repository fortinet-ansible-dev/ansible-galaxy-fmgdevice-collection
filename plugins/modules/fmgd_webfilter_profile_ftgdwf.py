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
module: fmgd_webfilter_profile_ftgdwf
short_description: FortiGuard Web Filter settings.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  profile:
    description: The parameter (profile) in requested url.
    type: str
    required: true
  webfilter_profile_ftgdwf:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      exempt_quota:
        aliases: ['exempt-quota']
        type: list
        elements: str
        description: Do not stop quota for these categories.
      filters:
        type: list
        elements: dict
        description: Filters.
        suboptions:
          action:
            type: str
            description: Action to take for matches.
            choices: ['block', 'monitor', 'warning', 'authenticate']
          auth_usr_grp:
            aliases: ['auth-usr-grp']
            type: list
            elements: str
            description: Groups with permission to authenticate.
          category:
            type: list
            elements: str
            description: Categories and groups the filter examines.
          id:
            type: int
            description: ID number.
          log:
            type: str
            description: Enable/disable logging.
            choices: ['disable', 'enable']
          override_replacemsg:
            aliases: ['override-replacemsg']
            type: str
            description: Override replacement message.
          warn_duration:
            aliases: ['warn-duration']
            type: str
            description: Duration of warnings.
          warning_duration_type:
            aliases: ['warning-duration-type']
            type: str
            description: Re-display warning after closing browser or after a timeout.
            choices: ['session', 'timeout']
          warning_prompt:
            aliases: ['warning-prompt']
            type: str
            description: Warning prompts in each category or each domain.
            choices: ['per-domain', 'per-category']
      max_quota_timeout:
        aliases: ['max-quota-timeout']
        type: int
        description: Maximum FortiGuard quota used by single page view in seconds
      options:
        type: list
        elements: str
        description: Options for FortiGuard Web Filter.
        choices: ['error-allow', 'rate-server-ip', 'connect-request-bypass', 'ftgd-disable',
                  'http-err-detail']
      ovrd:
        type: list
        elements: str
        description: Allow web filter profile overrides.
      quota:
        type: list
        elements: dict
        description: Quota.
        suboptions:
          category:
            type: list
            elements: str
            description: FortiGuard categories to apply quota to
          duration:
            type: str
            description: Duration of quota.
          id:
            type: int
            description: ID number.
          override_replacemsg:
            aliases: ['override-replacemsg']
            type: str
            description: Override replacement message.
          type:
            type: str
            description: Quota type.
            choices: ['time', 'traffic']
          unit:
            type: str
            description: Traffic quota unit of measurement.
            choices: ['B', 'KB', 'MB', 'GB']
          value:
            type: int
            description: Traffic quota value.
          reset_frequency:
            aliases: ['reset-frequency']
            type: str
            description: Quota reset frequency
            choices: ['daily', 'weekly', 'monthly']
      rate_crl_urls:
        aliases: ['rate-crl-urls']
        type: str
        description: Enable/disable rating CRL by URL.
        choices: ['disable', 'enable']
      rate_css_urls:
        aliases: ['rate-css-urls']
        type: str
        description: Enable/disable rating CSS by URL.
        choices: ['disable', 'enable']
      rate_javascript_urls:
        aliases: ['rate-javascript-urls']
        type: str
        description: Enable/disable rating JavaScript by URL.
        choices: ['disable', 'enable']
      risk:
        type: list
        elements: dict
        description: Risk.
        suboptions:
          action:
            type: str
            description: Action.
            choices: ['block', 'monitor']
          id:
            type: int
            description: Id.
          log:
            type: str
            description: Log.
            choices: ['disable', 'enable']
          risk_level:
            aliases: ['risk-level']
            type: list
            elements: str
            description: Risk level.
      rate_image_urls:
        aliases: ['rate-image-urls']
        type: str
        description: Enable/disable rating images by URL.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: FortiGuard Web Filter settings.
      fortinet.fmgdevice.fmgd_webfilter_profile_ftgdwf:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        webfilter_profile_ftgdwf:
          # exempt_quota: <list or string>
          # filters:
          #   - action: <value in [block, monitor, warning, ...]>
          #     auth_usr_grp: <list or string>
          #     category: <list or string>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          #     override_replacemsg: <string>
          #     warn_duration: <string>
          #     warning_duration_type: <value in [session, timeout]>
          #     warning_prompt: <value in [per-domain, per-category]>
          # max_quota_timeout: <integer>
          # options: ["error-allow", "rate-server-ip", "connect-request-bypass", "ftgd-disable",
          #           "http-err-detail"]
          # ovrd: <list or string>
          # quota:
          #   - category: <list or string>
          #     duration: <string>
          #     id: <integer>
          #     override_replacemsg: <string>
          #     type: <value in [time, traffic]>
          #     unit: <value in [B, KB, MB, ...]>
          #     value: <integer>
          #     reset_frequency: <value in [daily, weekly, monthly]>
          # rate_crl_urls: <value in [disable, enable]>
          # rate_css_urls: <value in [disable, enable]>
          # rate_javascript_urls: <value in [disable, enable]>
          # risk:
          #   - action: <value in [block, monitor]>
          #     id: <integer>
          #     log: <value in [disable, enable]>
          #     risk_level: <list or string>
          # rate_image_urls: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/ftgd-wf'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'webfilter_profile_ftgdwf': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'exempt-quota': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'filters': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['block', 'monitor', 'warning', 'authenticate'],
                            'type': 'str'
                        },
                        'auth-usr-grp': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'override-replacemsg': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'warn-duration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'warning-duration-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['session', 'timeout'], 'type': 'str'},
                        'warning-prompt': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['per-domain', 'per-category'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'max-quota-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'options': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['error-allow', 'rate-server-ip', 'connect-request-bypass', 'ftgd-disable', 'http-err-detail'],
                    'elements': 'str'
                },
                'ovrd': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'quota': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'duration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'override-replacemsg': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['time', 'traffic'], 'type': 'str'},
                        'unit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['B', 'KB', 'MB', 'GB'], 'type': 'str'},
                        'value': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'reset-frequency': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['daily', 'weekly', 'monthly'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'rate-crl-urls': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-css-urls': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rate-javascript-urls': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'risk': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['block', 'monitor'], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'risk-level': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'rate-image-urls': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_ftgdwf'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
