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
module: fmgd_dlp_sensor
short_description: Configure sensors used by DLP blocking.
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
  dlp_sensor:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      comment:
        type: str
        description: Optional comments.
      entries:
        type: list
        elements: dict
        description: Entries.
        suboptions:
          count:
            type: int
            description: Count of dictionary matches to trigger sensor entry match
          dictionary:
            type: list
            elements: str
            description: Select a DLP dictionary or exact-data-match.
          id:
            type: int
            description: ID.
          status:
            type: str
            description: Enable/disable this entry.
            choices: ['disable', 'enable']
      eval:
        type: str
        description: Expression to evaluate.
      match_type:
        aliases: ['match-type']
        type: str
        description: Logical relation between entries
        choices: ['match-all', 'match-any', 'match-eval']
      name:
        type: str
        description: Name of table containing the sensor.
        required: true
      replacemsg_group:
        aliases: ['replacemsg-group']
        type: list
        elements: str
        description: Replacement message group used by this DLP sensor.
      dlp_log:
        aliases: ['dlp-log']
        type: str
        description: Enable/disable DLP logging.
        choices: ['disable', 'enable']
      extended_log:
        aliases: ['extended-log']
        type: str
        description: Enable/disable extended logging for data leak prevention.
        choices: ['disable', 'enable']
      summary_proto:
        aliases: ['summary-proto']
        type: list
        elements: str
        description: Protocols to always log summary.
        choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mapi', 'http-get', 'http-post', 'cifs',
                  'ssh', 'mm3', 'mm7', 'mm1', 'mm4']
      filter:
        type: list
        elements: dict
        description: Filter.
        suboptions:
          action:
            type: str
            description: Action to take with content that this DLP sensor matches.
            choices: ['log-only', 'block', 'quarantine-ip', 'allow']
          archive:
            type: str
            description: Enable/disable DLP archiving.
            choices: ['disable', 'enable']
          company_identifier:
            aliases: ['company-identifier']
            type: str
            description: Enter a company identifier watermark to match.
          expiry:
            type: str
            description: Quarantine duration in days, hours, minutes
          file_size:
            aliases: ['file-size']
            type: int
            description: Match files this size or larger
          file_type:
            aliases: ['file-type']
            type: list
            elements: str
            description: Select the number of a DLP file pattern table to match.
          filter_by:
            aliases: ['filter-by']
            type: str
            description: Select the type of content to match.
            choices: ['credit-card', 'ssn', 'regexp', 'file-type', 'file-size', 'fingerprint',
                      'watermark', 'encrypted', 'file-type-and-size']
          id:
            type: int
            description: ID.
          match_percentage:
            aliases: ['match-percentage']
            type: int
            description: Percentage of fingerprints in the fingerprint databases designated with the selected sensitivity to match.
          name:
            type: str
            description: Filter name.
          proto:
            type: list
            elements: str
            description: Check messages or files over one or more of these protocols.
            choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mapi', 'http-get', 'http-post',
                      'cifs', 'ssh', 'mm3', 'mm7', 'mm1', 'mm4']
          regexp:
            type: str
            description: Enter a regular expression to match
          sensitivity:
            type: list
            elements: str
            description: Select a DLP file pattern sensitivity to match.
          severity:
            type: str
            description: Select the severity or threat level that matches this filter.
            choices: ['info', 'low', 'medium', 'high', 'critical']
          type:
            type: str
            description: Select whether to check the content of messages
            choices: ['file', 'message']
          fp_sensitivity:
            aliases: ['fp-sensitivity']
            type: list
            elements: str
            description: Select a DLP file pattern sensitivity to match.
      nac_quar_log:
        aliases: ['nac-quar-log']
        type: str
        description: Enable/disable NAC quarantine logging.
        choices: ['disable', 'enable']
      full_archive_proto:
        aliases: ['full-archive-proto']
        type: list
        elements: str
        description: Protocols to always content archive.
        choices: ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mapi', 'http-get', 'http-post', 'cifs',
                  'ssh', 'mm3', 'mm7', 'mm1', 'mm4']
      feature_set:
        aliases: ['feature-set']
        type: str
        description: Flow/proxy feature set.
        choices: ['proxy', 'flow']
      fgd_id:
        aliases: ['fgd-id']
        type: int
        description: ID of object in FortiGuard database.
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure sensors used by DLP blocking.
      fortinet.fmgdevice.fmgd_dlp_sensor:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        dlp_sensor:
          name: "your value" # Required variable, string
          # comment: <string>
          # entries:
          #   - count: <integer>
          #     dictionary: <list or string>
          #     id: <integer>
          #     status: <value in [disable, enable]>
          # eval: <string>
          # match_type: <value in [match-all, match-any, match-eval]>
          # replacemsg_group: <list or string>
          # dlp_log: <value in [disable, enable]>
          # extended_log: <value in [disable, enable]>
          # summary_proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mapi", "http-get",
          #                 "http-post", "cifs", "ssh", "mm3", "mm7", "mm1", "mm4"]
          # filter:
          #   - action: <value in [log-only, block, quarantine-ip, ...]>
          #     archive: <value in [disable, enable]>
          #     company_identifier: <string>
          #     expiry: <string>
          #     file_size: <integer>
          #     file_type: <list or string>
          #     filter_by: <value in [credit-card, ssn, regexp, ...]>
          #     id: <integer>
          #     match_percentage: <integer>
          #     name: <string>
          #     proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mapi", "http-get", "http-post",
          #             "cifs", "ssh", "mm3", "mm7", "mm1", "mm4"]
          #     regexp: <string>
          #     sensitivity: <list or string>
          #     severity: <value in [info, low, medium, ...]>
          #     type: <value in [file, message]>
          #     fp_sensitivity: <list or string>
          # nac_quar_log: <value in [disable, enable]>
          # full_archive_proto: ["imap", "smtp", "pop3", "ftp", "nntp", "mapi", "http-get",
          #                      "http-post", "cifs", "ssh", "mm3", "mm7", "mm1", "mm4"]
          # feature_set: <value in [proxy, flow]>
          # fgd_id: <integer>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/dlp/sensor'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'dlp_sensor': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'entries': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'count': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'dictionary': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'eval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'match-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['match-all', 'match-any', 'match-eval'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'replacemsg-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dlp-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extended-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'summary-proto': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mapi', 'http-get', 'http-post', 'cifs', 'ssh', 'mm3', 'mm7', 'mm1', 'mm4'],
                    'elements': 'str'
                },
                'filter': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['log-only', 'block', 'quarantine-ip', 'allow'],
                            'type': 'str'
                        },
                        'archive': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'company-identifier': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'expiry': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'file-size': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'file-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'filter-by': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'credit-card', 'ssn', 'regexp', 'file-type', 'file-size', 'fingerprint', 'watermark', 'encrypted', 'file-type-and-size'
                            ],
                            'type': 'str'
                        },
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'match-percentage': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'proto': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mapi', 'http-get', 'http-post', 'cifs', 'ssh', 'mm3', 'mm7', 'mm1', 'mm4'],
                            'elements': 'str'
                        },
                        'regexp': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'sensitivity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'severity': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['info', 'low', 'medium', 'high', 'critical'],
                            'type': 'str'
                        },
                        'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['file', 'message'], 'type': 'str'},
                        'fp-sensitivity': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'nac-quar-log': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'full-archive-proto': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'ftp', 'nntp', 'mapi', 'http-get', 'http-post', 'cifs', 'ssh', 'mm3', 'mm7', 'mm1', 'mm4'],
                    'elements': 'str'
                },
                'feature-set': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'fgd-id': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_sensor'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
