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
module: fmgd_webfilter_profile_web
short_description: Web content filtering settings.
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
  webfilter_profile_web:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      allowlist:
        type: list
        elements: str
        description: FortiGuard allowlist settings.
        choices: ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp',
                  'exempt-rangeblock', 'extended-log-others']
      blocklist:
        type: str
        description: Enable/disable automatic addition of URLs detected by FortiSandbox to blocklist.
        choices: ['disable', 'enable']
      bword_table:
        aliases: ['bword-table']
        type: list
        elements: str
        description: Banned word table ID.
      bword_threshold:
        aliases: ['bword-threshold']
        type: int
        description: Banned word score threshold.
      content_header_list:
        aliases: ['content-header-list']
        type: list
        elements: str
        description: Content header list.
      keyword_match:
        aliases: ['keyword-match']
        type: list
        elements: str
        description: Search keywords to log when match is found.
      log_search:
        aliases: ['log-search']
        type: str
        description: Enable/disable logging all search phrases.
        choices: ['disable', 'enable']
      qwant_restrict:
        aliases: ['qwant-restrict']
        type: str
        description: Qwant restrict.
        choices: ['strict', 'none', 'moderate']
      safe_search:
        aliases: ['safe-search']
        type: list
        elements: str
        description: Safe search type.
        choices: ['url', 'header']
      urlfilter_table:
        aliases: ['urlfilter-table']
        type: list
        elements: str
        description: URL filter table ID.
      vimeo_restrict:
        aliases: ['vimeo-restrict']
        type: str
        description: Set Vimeo-restrict
      youtube_restrict:
        aliases: ['youtube-restrict']
        type: str
        description: YouTube EDU filter level.
        choices: ['strict', 'none', 'moderate']
      whitelist:
        type: list
        elements: str
        description: FortiGuard whitelist settings.
        choices: ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp',
                  'exempt-rangeblock', 'extended-log-others']
      blacklist:
        type: str
        description: Enable/disable automatic addition of URLs detected by FortiSandbox to blacklist.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Web content filtering settings.
      fortinet.fmgdevice.fmgd_webfilter_profile_web:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        webfilter_profile_web:
          # allowlist: ["exempt-av", "exempt-webcontent", "exempt-activex-java-cookie",
          #             "exempt-dlp", "exempt-rangeblock", "extended-log-others"]
          # blocklist: <value in [disable, enable]>
          # bword_table: <list or string>
          # bword_threshold: <integer>
          # content_header_list: <list or string>
          # keyword_match: <list or string>
          # log_search: <value in [disable, enable]>
          # qwant_restrict: <value in [strict, none, moderate]>
          # safe_search: ["url", "header"]
          # urlfilter_table: <list or string>
          # vimeo_restrict: <string>
          # youtube_restrict: <value in [strict, none, moderate]>
          # whitelist: ["exempt-av", "exempt-webcontent", "exempt-activex-java-cookie",
          #             "exempt-dlp", "exempt-rangeblock", "extended-log-others"]
          # blacklist: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/web'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'webfilter_profile_web': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'allowlist': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp', 'exempt-rangeblock', 'extended-log-others'],
                    'elements': 'str'
                },
                'blocklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'bword-table': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'bword-threshold': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'content-header-list': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'keyword-match': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'log-search': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'qwant-restrict': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['strict', 'none', 'moderate'], 'type': 'str'},
                'safe-search': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'choices': ['url', 'header'], 'elements': 'str'},
                'urlfilter-table': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vimeo-restrict': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'youtube-restrict': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['strict', 'none', 'moderate'], 'type': 'str'},
                'whitelist': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']],
                    'type': 'list',
                    'choices': ['exempt-av', 'exempt-webcontent', 'exempt-activex-java-cookie', 'exempt-dlp', 'exempt-rangeblock', 'extended-log-others'],
                    'elements': 'str'
                },
                'blacklist': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_profile_web'),
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
