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
module: fmgd_dlp_filepattern_entries
short_description: Configure file patterns used by DLP blocking.
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
  filepattern:
    description: The parameter (filepattern) in requested url.
    type: str
    required: true
  dlp_filepattern_entries:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      file_type:
        aliases: ['file-type']
        type: str
        description: Select a file type.
        choices: ['unknown', 'exe', 'elf', 'bat', 'javascript', 'html', 'hta', 'msoffice', 'gzip',
                  'rar', 'tar', 'lzh', 'upx', 'zip', 'cab', 'bzip2', 'bzip', 'activemime', 'mime',
                  'hlp', 'arj', 'base64', 'binhex', 'uue', 'fsg', 'aspack', 'petite', 'jpeg',
                  'gif', 'tiff', 'png', 'bmp', 'msi', 'mpeg', 'mov', 'mp3', 'wma', 'wav', 'pdf',
                  'avi', 'rm', 'torrent', 'hibun', '7z', 'xz', 'msofficex', 'mach-o', 'dmg',
                  '.net', 'xar', 'chm', 'iso', 'crx', 'flac', 'jad', 'class', 'cod', 'sis',
                  'c/cpp', 'rpm', 'hwp', 'registry', 'msc', 'ignored', 'prc', 'dll', 'jar',
                  'jnlp', 'css', 'com', 'sylk', 'pfile', 'shellscript', 'python', 'lzip', 'wasm',
                  'genscript']
      filter_type:
        aliases: ['filter-type']
        type: str
        description: Filter by file name pattern or by file type.
        choices: ['pattern', 'type']
      pattern:
        type: str
        description: Add a file name pattern.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure file patterns used by DLP blocking.
      fortinet.fmgdevice.fmgd_dlp_filepattern_entries:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        filepattern: <your own value>
        state: present # <value in [present, absent]>
        dlp_filepattern_entries:
          # file_type: <value in [unknown, exe, elf, ...]>
          # filter_type: <value in [pattern, type]>
          # pattern: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/dlp/filepattern/{filepattern}/entries'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'filepattern': {'required': True, 'type': 'str'},
        'dlp_filepattern_entries': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'file-type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': [
                        'unknown', 'exe', 'elf', 'bat', 'javascript', 'html', 'hta', 'msoffice', 'gzip', 'rar', 'tar', 'lzh', 'upx', 'zip', 'cab',
                        'bzip2', 'bzip', 'activemime', 'mime', 'hlp', 'arj', 'base64', 'binhex', 'uue', 'fsg', 'aspack', 'petite', 'jpeg', 'gif', 'tiff',
                        'png', 'bmp', 'msi', 'mpeg', 'mov', 'mp3', 'wma', 'wav', 'pdf', 'avi', 'rm', 'torrent', 'hibun', '7z', 'xz', 'msofficex',
                        'mach-o', 'dmg', '.net', 'xar', 'chm', 'iso', 'crx', 'flac', 'jad', 'class', 'cod', 'sis', 'c/cpp', 'rpm', 'hwp', 'registry',
                        'msc', 'ignored', 'prc', 'dll', 'jar', 'jnlp', 'css', 'com', 'sylk', 'pfile', 'shellscript', 'python', 'lzip', 'wasm',
                        'genscript'
                    ],
                    'type': 'str'
                },
                'filter-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['pattern', 'type'], 'type': 'str'},
                'pattern': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_filepattern_entries'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
