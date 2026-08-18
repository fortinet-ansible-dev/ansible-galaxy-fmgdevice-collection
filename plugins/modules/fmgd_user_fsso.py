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
module: fmgd_user_fsso
short_description: Configure Fortinet Single Sign On
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
  user_fsso:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _gui_meta:
        type: str
        description: Gui meta.
      dynamic_mapping:
        type: list
        elements: dict
        description: Dynamic mapping.
        suboptions:
          _gui_meta:
            type: str
            description: Gui meta.
          _scope:
            type: list
            elements: dict
            description: Scope.
            suboptions:
              name:
                type: str
                description: Name.
              vdom:
                type: str
                description: Vdom.
          group_poll_interval:
            aliases: ['group-poll-interval']
            type: int
            description: Interval in minutes within to fetch groups from FSSO server, or unset to disable.
          interface:
            type: list
            elements: str
            description: Specify outgoing interface to reach server.
          interface_select_method:
            aliases: ['interface-select-method']
            type: str
            description: Specify how to select outgoing interface to reach server.
            choices: ['auto', 'sdwan', 'specify']
          ldap_poll:
            aliases: ['ldap-poll']
            type: str
            description: Enable/disable automatic fetching of groups from LDAP server.
            choices: ['disable', 'enable']
          ldap_poll_filter:
            aliases: ['ldap-poll-filter']
            type: str
            description: Filter used to fetch groups.
          ldap_poll_interval:
            aliases: ['ldap-poll-interval']
            type: int
            description: Interval in minutes within to fetch groups from LDAP server.
          ldap_server:
            aliases: ['ldap-server']
            type: list
            elements: str
            description: LDAP server to get group information.
          logon_timeout:
            aliases: ['logon-timeout']
            type: int
            description: Interval in minutes to keep logons after FSSO server down.
          password:
            type: list
            elements: str
            description: Password of the first FSSO collector agent.
          password2:
            type: list
            elements: str
            description: Password of the second FSSO collector agent.
          password3:
            type: list
            elements: str
            description: Password of the third FSSO collector agent.
          password4:
            type: list
            elements: str
            description: Password of the fourth FSSO collector agent.
          password5:
            type: list
            elements: str
            description: Password of the fifth FSSO collector agent.
          port:
            type: int
            description: Port of the first FSSO collector agent.
          port2:
            type: int
            description: Port of the second FSSO collector agent.
          port3:
            type: int
            description: Port of the third FSSO collector agent.
          port4:
            type: int
            description: Port of the fourth FSSO collector agent.
          port5:
            type: int
            description: Port of the fifth FSSO collector agent.
          server:
            type: str
            description: Domain name or IP address of the first FSSO collector agent.
          server2:
            type: str
            description: Domain name or IP address of the second FSSO collector agent.
          server3:
            type: str
            description: Domain name or IP address of the third FSSO collector agent.
          server4:
            type: str
            description: Domain name or IP address of the fourth FSSO collector agent.
          server5:
            type: str
            description: Domain name or IP address of the fifth FSSO collector agent.
          sni:
            type: str
            description: Server Name Indication.
          source_ip:
            aliases: ['source-ip']
            type: str
            description: Source IP for communications to FSSO agent.
          source_ip6:
            aliases: ['source-ip6']
            type: str
            description: IPv6 source for communications to FSSO agent.
          ssl:
            type: str
            description: Enable/disable use of SSL.
            choices: ['disable', 'enable']
          ssl_server_host_ip_check:
            aliases: ['ssl-server-host-ip-check']
            type: str
            description: Enable/disable server host/IP verification.
            choices: ['disable', 'enable']
          ssl_trusted_cert:
            aliases: ['ssl-trusted-cert']
            type: list
            elements: str
            description: Trusted server certificate or CA certificate.
          type:
            type: str
            description: Server type.
            choices: ['default', 'fortinac', 'fortiems', 'fortiems-cloud']
          user_info_server:
            aliases: ['user-info-server']
            type: list
            elements: str
            description: LDAP server to get user information.
          vrf_select:
            aliases: ['vrf-select']
            type: int
            description: VRF ID used for connection to server.
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
      group_poll_interval:
        aliases: ['group-poll-interval']
        type: int
        description: Interval in minutes within to fetch groups from FSSO server, or unset to disable.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      ldap_poll:
        aliases: ['ldap-poll']
        type: str
        description: Enable/disable automatic fetching of groups from LDAP server.
        choices: ['disable', 'enable']
      ldap_poll_filter:
        aliases: ['ldap-poll-filter']
        type: str
        description: Filter used to fetch groups.
      ldap_poll_interval:
        aliases: ['ldap-poll-interval']
        type: int
        description: Interval in minutes within to fetch groups from LDAP server.
      ldap_server:
        aliases: ['ldap-server']
        type: list
        elements: str
        description: LDAP server to get group information.
      logon_timeout:
        aliases: ['logon-timeout']
        type: int
        description: Interval in minutes to keep logons after FSSO server down.
      name:
        type: str
        description: Name.
        required: true
      password:
        type: list
        elements: str
        description: Password of the first FSSO collector agent.
      password2:
        type: list
        elements: str
        description: Password of the second FSSO collector agent.
      password3:
        type: list
        elements: str
        description: Password of the third FSSO collector agent.
      password4:
        type: list
        elements: str
        description: Password of the fourth FSSO collector agent.
      password5:
        type: list
        elements: str
        description: Password of the fifth FSSO collector agent.
      port:
        type: int
        description: Port of the first FSSO collector agent.
      port2:
        type: int
        description: Port of the second FSSO collector agent.
      port3:
        type: int
        description: Port of the third FSSO collector agent.
      port4:
        type: int
        description: Port of the fourth FSSO collector agent.
      port5:
        type: int
        description: Port of the fifth FSSO collector agent.
      server:
        type: str
        description: Domain name or IP address of the first FSSO collector agent.
      server2:
        type: str
        description: Domain name or IP address of the second FSSO collector agent.
      server3:
        type: str
        description: Domain name or IP address of the third FSSO collector agent.
      server4:
        type: str
        description: Domain name or IP address of the fourth FSSO collector agent.
      server5:
        type: str
        description: Domain name or IP address of the fifth FSSO collector agent.
      sni:
        type: str
        description: Server Name Indication.
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP for communications to FSSO agent.
      source_ip6:
        aliases: ['source-ip6']
        type: str
        description: IPv6 source for communications to FSSO agent.
      ssl:
        type: str
        description: Enable/disable use of SSL.
        choices: ['disable', 'enable']
      ssl_server_host_ip_check:
        aliases: ['ssl-server-host-ip-check']
        type: str
        description: Enable/disable server host/IP verification.
        choices: ['disable', 'enable']
      ssl_trusted_cert:
        aliases: ['ssl-trusted-cert']
        type: list
        elements: str
        description: Trusted server certificate or CA certificate.
      type:
        type: str
        description: Server type.
        choices: ['default', 'fortinac', 'fortiems', 'fortiems-cloud']
      user_info_server:
        aliases: ['user-info-server']
        type: list
        elements: str
        description: LDAP server to get user information.
      vrf_select:
        aliases: ['vrf-select']
        type: int
        description: VRF ID used for connection to server.
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
    - name: Configure Fortinet Single Sign On
      fortinet.fmgdevice.fmgd_user_fsso:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_fsso:
          name: "your value" # Required variable, string
          # _gui_meta: <string>
          # dynamic_mapping:
          #   - _gui_meta: <string>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     group_poll_interval: <integer>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, sdwan, specify]>
          #     ldap_poll: <value in [disable, enable]>
          #     ldap_poll_filter: <string>
          #     ldap_poll_interval: <integer>
          #     ldap_server: <list or string>
          #     logon_timeout: <integer>
          #     password: <list or string>
          #     password2: <list or string>
          #     password3: <list or string>
          #     password4: <list or string>
          #     password5: <list or string>
          #     port: <integer>
          #     port2: <integer>
          #     port3: <integer>
          #     port4: <integer>
          #     port5: <integer>
          #     server: <string>
          #     server2: <string>
          #     server3: <string>
          #     server4: <string>
          #     server5: <string>
          #     sni: <string>
          #     source_ip: <string>
          #     source_ip6: <string>
          #     ssl: <value in [disable, enable]>
          #     ssl_server_host_ip_check: <value in [disable, enable]>
          #     ssl_trusted_cert: <list or string>
          #     type: <value in [default, fortinac, fortiems, ...]>
          #     user_info_server: <list or string>
          #     vrf_select: <integer>
          #     fabric_force_sync: <value in [disable, enable]>
          #     fabric_object: <value in [disable, enable]>
          #     fabric_object_source: <value in [member, local, root]>
          #     uuid: <string>
          # group_poll_interval: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ldap_poll: <value in [disable, enable]>
          # ldap_poll_filter: <string>
          # ldap_poll_interval: <integer>
          # ldap_server: <list or string>
          # logon_timeout: <integer>
          # password: <list or string>
          # password2: <list or string>
          # password3: <list or string>
          # password4: <list or string>
          # password5: <list or string>
          # port: <integer>
          # port2: <integer>
          # port3: <integer>
          # port4: <integer>
          # port5: <integer>
          # server: <string>
          # server2: <string>
          # server3: <string>
          # server4: <string>
          # server5: <string>
          # sni: <string>
          # source_ip: <string>
          # source_ip6: <string>
          # ssl: <value in [disable, enable]>
          # ssl_server_host_ip_check: <value in [disable, enable]>
          # ssl_trusted_cert: <list or string>
          # type: <value in [default, fortinac, fortiems, ...]>
          # user_info_server: <list or string>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/fsso'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_fsso': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_gui_meta': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_gui_meta': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'group-poll-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'ldap-poll': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ldap-poll-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'ldap-poll-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ldap-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'logon-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password3': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password4': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password5': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'port2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'port3': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'port4': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'port5': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'server2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'server3': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'server4': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'server5': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'sni': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'source-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'source-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'ssl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-host-ip-check': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-trusted-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['default', 'fortinac', 'fortiems', 'fortiems-cloud'],
                            'type': 'str'
                        },
                        'user-info-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                        'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'group-poll-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ldap-poll': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ldap-poll-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ldap-poll-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ldap-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'logon-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password3': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password4': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password5': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'port2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'port3': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'port4': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'port5': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'server2': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'server3': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'server4': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'server5': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'sni': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-ip6': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ssl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-host-ip-check': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-trusted-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['default', 'fortinac', 'fortiems', 'fortiems-cloud'], 'type': 'str'},
                'user-info-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'},
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_fsso'),
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
