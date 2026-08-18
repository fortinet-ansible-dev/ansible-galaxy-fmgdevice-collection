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
module: fmgd_dlp_settings
short_description: Designate logical storage for DLP fingerprint database.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  dlp_settings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      cache_mem_percent:
        aliases: ['cache-mem-percent']
        type: int
        description: Maximum percentage of available memory allocated to caching
      chunk_size:
        aliases: ['chunk-size']
        type: int
        description: Maximum fingerprint chunk size.
      db_mode:
        aliases: ['db-mode']
        type: str
        description: Behavior when the maximum size is reached.
        choices: ['stop-adding', 'remove-modified-then-oldest', 'remove-oldest']
      size:
        type: int
        description: Maximum total size of files within the storage
      storage_device:
        aliases: ['storage-device']
        type: str
        description: Storage device name.
      config_builder_timeout:
        aliases: ['config-builder-timeout']
        type: int
        description: Maximum time allowed for building a single DLP profile
      ocr:
        type: dict
        description: Ocr.
        suboptions:
          confidence:
            type: int
            description: Minimum confidence threshold for the OCR converted content to be scanned
          filetype_ignore_list:
            aliases: ['filetype-ignore-list']
            type: list
            elements: str
            description: List of file types to be exempt from OCR scanning.
          max_file_size:
            aliases: ['max-file-size']
            type: int
            description: Maximum file size for an image to be a candidate for OCR conversion in kilobytes
          scan:
            type: str
            description: Enable/disable OCR conversion of images for DLP content scanning.
            choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Designate logical storage for DLP fingerprint database.
      fortinet.fmgdevice.fmgd_dlp_settings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        dlp_settings:
          # cache_mem_percent: <integer>
          # chunk_size: <integer>
          # db_mode: <value in [stop-adding, remove-modified-then-oldest, remove-oldest]>
          # size: <integer>
          # storage_device: <string>
          # config_builder_timeout: <integer>
          # ocr:
          #   confidence: <integer>
          #   filetype_ignore_list: <list or string>
          #   max_file_size: <integer>
          #   scan: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/dlp/settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'dlp_settings': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'cache-mem-percent': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'chunk-size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'db-mode': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['stop-adding', 'remove-modified-then-oldest', 'remove-oldest'],
                    'type': 'str'
                },
                'size': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'storage-device': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'config-builder-timeout': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'ocr': {
                    'v_range': [['8.0.0', '']],
                    'type': 'dict',
                    'options': {
                        'confidence': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'filetype-ignore-list': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'max-file-size': {'v_range': [['8.0.0', '']], 'type': 'int'},
                        'scan': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_settings'),
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
