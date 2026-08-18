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
module: fmgd_log_syslogd2_filter_freestyle
short_description: Free style filters.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  log_syslogd2_filter_freestyle:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      category:
        type: str
        description: Log category.
        choices: ['traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp',
                  'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns', 'ssh', 'ssl', 'file-filter', 'icap',
                  'ztna', 'virtual-patch', 'debug']
      filter:
        type: str
        description: Free style filter string.
      filter_type:
        aliases: ['filter-type']
        type: str
        description: Include/exclude logs that match the filter.
        choices: ['include', 'exclude']
      id:
        type: int
        description: Entry ID.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Free style filters.
      fortinet.fmgdevice.fmgd_log_syslogd2_filter_freestyle:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        state: present # <value in [present, absent]>
        log_syslogd2_filter_freestyle:
          id: 0 # Required variable, integer
          # category: <value in [traffic, event, virus, ...]>
          # filter: <string>
          # filter_type: <value in [include, exclude]>
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
        '/pm/config/device/{device}/global/log/syslogd2/filter/free-style'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'log_syslogd2_filter_freestyle': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'category': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp', 'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns', 'ssh',
                        'ssl', 'file-filter', 'icap', 'ztna', 'virtual-patch', 'debug'
                    ],
                    'type': 'str'
                },
                'filter': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'filter-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_syslogd2_filter_freestyle'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
