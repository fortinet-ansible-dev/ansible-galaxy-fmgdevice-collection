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
module: fmgd_system_standalonecluster_clusterpeer_sessionsyncfilter
short_description: Add one or more filters if you only want to synchronize some sessions.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  cluster-peer:
    description: Deprecated, please use "cluster_peer"
    type: str
  cluster_peer:
    description: The parameter (cluster-peer) in requested url.
    type: str
  system_standalonecluster_clusterpeer_sessionsyncfilter:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      custom_service:
        aliases: ['custom-service']
        type: list
        elements: dict
        description: Custom service.
        suboptions:
          dst_port_range:
            aliases: ['dst-port-range']
            type: str
            description: Custom service destination port range.
          id:
            type: int
            description: Custom service ID.
          src_port_range:
            aliases: ['src-port-range']
            type: str
            description: Custom service source port range.
      dstaddr:
        type: list
        elements: str
        description: Only sessions to this IPv4 address are synchronized.
      dstaddr6:
        type: str
        description: Only sessions to this IPv6 address are synchronized.
      dstintf:
        type: list
        elements: str
        description: Only sessions to this interface are synchronized.
      srcaddr:
        type: list
        elements: str
        description: Only sessions from this IPv4 address are synchronized.
      srcaddr6:
        type: str
        description: Only sessions from this IPv6 address are synchronized.
      srcintf:
        type: list
        elements: str
        description: Only sessions from this interface are synchronized.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Add one or more filters if you only want to synchronize some sessions.
      fortinet.fmgdevice.fmgd_system_standalonecluster_clusterpeer_sessionsyncfilter:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        cluster_peer: <your own value>
        system_standalonecluster_clusterpeer_sessionsyncfilter:
          # custom_service:
          #   - dst_port_range: <string>
          #     id: <integer>
          #     src_port_range: <string>
          # dstaddr: <list or string>
          # dstaddr6: <string>
          # dstintf: <list or string>
          # srcaddr: <list or string>
          # srcaddr6: <string>
          # srcintf: <list or string>
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
        '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}/session-sync-filter'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'cluster-peer': {'type': 'str', 'api_name': 'cluster_peer'},
        'cluster_peer': {'type': 'str'},
        'system_standalonecluster_clusterpeer_sessionsyncfilter': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'custom-service': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'dst-port-range': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'src-port-range': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'dstaddr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'dstintf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'srcintf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_standalonecluster_clusterpeer_sessionsyncfilter'),
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
