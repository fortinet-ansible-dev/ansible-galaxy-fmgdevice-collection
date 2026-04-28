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
module: fmgd_firewall_service_custom
short_description: Configure custom services.
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
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    firewall_service_custom:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app_category:
                aliases: ['app-category']
                type: list
                elements: int
                description: Application category ID.
            app_service_type:
                aliases: ['app-service-type']
                type: str
                description: Application service type.
                choices:
                    - 'disable'
                    - 'app-id'
                    - 'app-category'
            application:
                type: list
                elements: int
                description: Application ID.
            category:
                type: list
                elements: str
                description: Service category.
            check_reset_range:
                aliases: ['check-reset-range']
                type: str
                description: Configure the type of ICMP error message verification.
                choices:
                    - 'disable'
                    - 'default'
                    - 'strict'
            color:
                type: int
                description: Color of icon on the GUI.
            comment:
                type: str
                description: Comment.
            fabric_object:
                aliases: ['fabric-object']
                type: str
                description: Security Fabric global object setting.
                choices:
                    - 'disable'
                    - 'enable'
            fqdn:
                type: str
                description: Fully qualified domain name.
            icmpcode:
                type: int
                description: ICMP code.
            icmptype:
                type: int
                description: ICMP type.
            iprange:
                type: str
                description: Start and end of the IP range associated with service.
            name:
                type: str
                description: Custom service name.
                required: true
            protocol:
                type: str
                description: Protocol type based on IANA numbers.
                choices:
                    - 'ICMP'
                    - 'IP'
                    - 'TCP/UDP/SCTP'
                    - 'ICMP6'
                    - 'HTTP'
                    - 'FTP'
                    - 'CONNECT'
                    - 'ALL'
                    - 'SOCKS-TCP'
                    - 'SOCKS-UDP'
                    - 'TCP/UDP/UDP-Lite/SCTP'
            protocol_number:
                aliases: ['protocol-number']
                type: int
                description: IP protocol number.
            proxy:
                type: str
                description: Enable/disable web proxy service.
                choices:
                    - 'disable'
                    - 'enable'
            sctp_portrange:
                aliases: ['sctp-portrange']
                type: list
                elements: str
                description: Multiple SCTP port ranges.
            session_ttl:
                aliases: ['session-ttl']
                type: str
                description: Session TTL
            tcp_halfclose_timer:
                aliases: ['tcp-halfclose-timer']
                type: int
                description: Wait time to close a TCP session waiting for an unanswered FIN packet
            tcp_halfopen_timer:
                aliases: ['tcp-halfopen-timer']
                type: int
                description: Wait time to close a TCP session waiting for an unanswered open session packet
            tcp_portrange:
                aliases: ['tcp-portrange']
                type: list
                elements: str
                description: Multiple TCP port ranges.
            tcp_rst_timer:
                aliases: ['tcp-rst-timer']
                type: int
                description: Set the length of the TCP CLOSE state in seconds
            tcp_timewait_timer:
                aliases: ['tcp-timewait-timer']
                type: int
                description: Set the length of the TCP TIME-WAIT state in seconds
            udp_idle_timer:
                aliases: ['udp-idle-timer']
                type: int
                description: Number of seconds before an idle UDP connection times out
            udp_portrange:
                aliases: ['udp-portrange']
                type: list
                elements: str
                description: Multiple UDP port ranges.
            helper:
                type: str
                description: Helper name.
                choices:
                    - 'disable'
                    - 'auto'
                    - 'ftp'
                    - 'tftp'
                    - 'ras'
                    - 'h323'
                    - 'tns'
                    - 'mms'
                    - 'sip'
                    - 'pptp'
                    - 'rtsp'
                    - 'dns-udp'
                    - 'dns-tcp'
                    - 'pmap'
                    - 'rsh'
                    - 'dcerpc'
                    - 'mgcp'
                    - 'gtp-c'
                    - 'gtp-u'
                    - 'gtp-b'
                    - 'pfcp'
            uuid:
                type: str
                description: Universally Unique Identifier
            visibility:
                type: str
                description: Enable/disable the visibility of the service on the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            global_object:
                aliases: ['global-object']
                type: int
                description: Global object.
            udplite_portrange:
                aliases: ['udplite-portrange']
                type: str
                description: Multiple UDP-Lite port ranges.
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
    - name: Configure custom services.
      fortinet.fmgdevice.fmgd_firewall_service_custom:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_service_custom:
          name: "your value" # Required variable, string
          # app_category: <list or integer>
          # app_service_type: <value in [disable, app-id, app-category]>
          # application: <list or integer>
          # category: <list or string>
          # check_reset_range: <value in [disable, default, strict]>
          # color: <integer>
          # comment: <string>
          # fabric_object: <value in [disable, enable]>
          # fqdn: <string>
          # icmpcode: <integer>
          # icmptype: <integer>
          # iprange: <string>
          # protocol: <value in [ICMP, IP, TCP/UDP/SCTP, ...]>
          # protocol_number: <integer>
          # proxy: <value in [disable, enable]>
          # sctp_portrange: <list or string>
          # session_ttl: <string>
          # tcp_halfclose_timer: <integer>
          # tcp_halfopen_timer: <integer>
          # tcp_portrange: <list or string>
          # tcp_rst_timer: <integer>
          # tcp_timewait_timer: <integer>
          # udp_idle_timer: <integer>
          # udp_portrange: <list or string>
          # helper: <value in [disable, auto, ftp, ...]>
          # uuid: <string>
          # visibility: <value in [disable, enable]>
          # global_object: <integer>
          # udplite_portrange: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/service/custom'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_service_custom': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'app-category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'app-service-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'app-id', 'app-category'], 'type': 'str'},
                'application': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                'category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'check-reset-range': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'default', 'strict'], 'type': 'str'},
                'color': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'fabric-object': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fqdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'icmpcode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'icmptype': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'iprange': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'protocol': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['ICMP', 'IP', 'TCP/UDP/SCTP', 'ICMP6', 'HTTP', 'FTP', 'CONNECT', 'ALL', 'SOCKS-TCP', 'SOCKS-UDP', 'TCP/UDP/UDP-Lite/SCTP'],
                    'type': 'str'
                },
                'protocol-number': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'proxy': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sctp-portrange': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'session-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'tcp-halfclose-timer': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'tcp-halfopen-timer': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'tcp-portrange': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'tcp-rst-timer': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'tcp-timewait-timer': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'udp-idle-timer': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'udp-portrange': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'helper': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'disable', 'auto', 'ftp', 'tftp', 'ras', 'h323', 'tns', 'mms', 'sip', 'pptp', 'rtsp', 'dns-udp', 'dns-tcp', 'pmap', 'rsh',
                        'dcerpc', 'mgcp', 'gtp-c', 'gtp-u', 'gtp-b', 'pfcp'
                    ],
                    'type': 'str'
                },
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'visibility': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'global-object': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'udplite-portrange': {'v_range': [['7.6.4', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_service_custom'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
