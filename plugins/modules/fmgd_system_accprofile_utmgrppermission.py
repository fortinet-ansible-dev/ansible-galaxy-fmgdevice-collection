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
module: fmgd_system_accprofile_utmgrppermission
short_description: Custom Security Profile permissions.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  accprofile:
    description: The parameter (accprofile) in requested url.
    type: str
    required: true
  system_accprofile_utmgrppermission:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      antivirus:
        type: str
        description: Antivirus profiles and settings.
        choices: ['none', 'read', 'read-write']
      application_control:
        aliases: ['application-control']
        type: str
        description: Application Control profiles and settings.
        choices: ['none', 'read', 'read-write']
      casb:
        type: str
        description: Inline CASB filter profile and settings
        choices: ['none', 'read', 'read-write']
      data_leak_prevention:
        aliases: ['data-leak-prevention']
        type: str
        description: DLP profiles and settings.
        choices: ['none', 'read', 'read-write']
      dlp:
        type: str
        description: DLP profiles and settings.
        choices: ['none', 'read', 'read-write']
      dnsfilter:
        type: str
        description: DNS Filter profiles and settings.
        choices: ['none', 'read', 'read-write']
      emailfilter:
        type: str
        description: Email Filter and settings.
        choices: ['none', 'read', 'read-write']
      endpoint_control:
        aliases: ['endpoint-control']
        type: str
        description: FortiClient Profiles.
        choices: ['none', 'read', 'read-write']
      file_filter:
        aliases: ['file-filter']
        type: str
        description: File-filter profiles and settings.
        choices: ['none', 'read', 'read-write']
      icap:
        type: str
        description: ICAP profiles and settings.
        choices: ['none', 'read', 'read-write']
      ips:
        type: str
        description: IPS profiles and settings.
        choices: ['none', 'read', 'read-write']
      mmsgtp:
        type: str
        description: UTM permission.
        choices: ['none', 'read', 'read-write']
      videofilter:
        type: str
        description: Video filter profiles and settings.
        choices: ['none', 'read', 'read-write']
      virtual_patch:
        aliases: ['virtual-patch']
        type: str
        description: Virtual patch profiles and settings.
        choices: ['none', 'read', 'read-write']
      voip:
        type: str
        description: VoIP profiles and settings.
        choices: ['none', 'read', 'read-write']
      waf:
        type: str
        description: Web Application Firewall profiles and settings.
        choices: ['none', 'read', 'read-write']
      webfilter:
        type: str
        description: Web Filter profiles and settings.
        choices: ['none', 'read', 'read-write']
      data_loss_prevention:
        aliases: ['data-loss-prevention']
        type: str
        description: DLP profiles and settings.
        choices: ['none', 'read', 'read-write']
      spamfilter:
        type: str
        description: AntiSpam filter and settings.
        choices: ['none', 'read', 'read-write']
      telemetry:
        type: str
        description: Telemetry profile and settings.
        choices: ['none', 'read', 'read-write']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Custom Security Profile permissions.
      fortinet.fmgdevice.fmgd_system_accprofile_utmgrppermission:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        accprofile: <your own value>
        system_accprofile_utmgrppermission:
          # antivirus: <value in [none, read, read-write]>
          # application_control: <value in [none, read, read-write]>
          # casb: <value in [none, read, read-write]>
          # data_leak_prevention: <value in [none, read, read-write]>
          # dlp: <value in [none, read, read-write]>
          # dnsfilter: <value in [none, read, read-write]>
          # emailfilter: <value in [none, read, read-write]>
          # endpoint_control: <value in [none, read, read-write]>
          # file_filter: <value in [none, read, read-write]>
          # icap: <value in [none, read, read-write]>
          # ips: <value in [none, read, read-write]>
          # mmsgtp: <value in [none, read, read-write]>
          # videofilter: <value in [none, read, read-write]>
          # virtual_patch: <value in [none, read, read-write]>
          # voip: <value in [none, read, read-write]>
          # waf: <value in [none, read, read-write]>
          # webfilter: <value in [none, read, read-write]>
          # data_loss_prevention: <value in [none, read, read-write]>
          # spamfilter: <value in [none, read, read-write]>
          # telemetry: <value in [none, read, read-write]>
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
        '/pm/config/device/{device}/global/system/accprofile/{accprofile}/utmgrp-permission'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'accprofile': {'required': True, 'type': 'str'},
        'system_accprofile_utmgrppermission': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'antivirus': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'application-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'casb': {'v_range': [['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'data-leak-prevention': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'dlp': {'v_range': [['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'dnsfilter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'emailfilter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'endpoint-control': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'file-filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'icap': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'ips': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'mmsgtp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'videofilter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'virtual-patch': {'v_range': [['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'voip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'waf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'webfilter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'data-loss-prevention': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'spamfilter': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'telemetry': {'v_range': [['7.6.4', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_accprofile_utmgrppermission'),
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
