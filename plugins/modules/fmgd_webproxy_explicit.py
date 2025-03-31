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
module: fmgd_webproxy_explicit
short_description: Configure explicit Web proxy settings.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    webproxy_explicit:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Enable/disable to request client certificate.
                choices:
                    - 'disable'
                    - 'enable'
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Action of an empty client certificate.
                choices:
                    - 'block'
                    - 'accept'
                    - 'accept-unmanageable'
            ftp_incoming_port:
                aliases: ['ftp-incoming-port']
                type: list
                elements: str
                description: Accept incoming FTP-over-HTTP requests on one or more ports
            ftp_over_http:
                aliases: ['ftp-over-http']
                type: str
                description: Enable to proxy FTP-over-HTTP sessions sent from a web browser.
                choices:
                    - 'disable'
                    - 'enable'
            http_connection_mode:
                aliases: ['http-connection-mode']
                type: str
                description: HTTP connection mode
                choices:
                    - 'static'
                    - 'multiplex'
                    - 'serverpool'
            http_incoming_port:
                aliases: ['http-incoming-port']
                type: list
                elements: str
                description: Accept incoming HTTP requests on one or more ports
            https_incoming_port:
                aliases: ['https-incoming-port']
                type: list
                elements: str
                description: Accept incoming HTTPS requests on one or more ports
            https_replacement_message:
                aliases: ['https-replacement-message']
                type: str
                description: Enable/disable sending the client a replacement message for HTTPS requests.
                choices:
                    - 'disable'
                    - 'enable'
            incoming_ip:
                aliases: ['incoming-ip']
                type: str
                description: Restrict the explicit HTTP proxy to only accept sessions from this IP address.
            incoming_ip6:
                aliases: ['incoming-ip6']
                type: str
                description: Restrict the explicit web proxy to only accept sessions from this IPv6 address.
            ipv6_status:
                aliases: ['ipv6-status']
                type: str
                description: Enable/disable allowing an IPv6 web proxy destination in policies and all IPv6 related entries in this command.
                choices:
                    - 'disable'
                    - 'enable'
            message_upon_server_error:
                aliases: ['message-upon-server-error']
                type: str
                description: Enable/disable displaying a replacement message when a server error is detected.
                choices:
                    - 'disable'
                    - 'enable'
            outgoing_ip:
                aliases: ['outgoing-ip']
                type: list
                elements: str
                description: Outgoing HTTP requests will have this IP address as their source address.
            outgoing_ip6:
                aliases: ['outgoing-ip6']
                type: list
                elements: str
                description: Outgoing HTTP requests will leave this IPv6.
            pac_file_data:
                aliases: ['pac-file-data']
                type: str
                description: PAC file contents enclosed in quotes
            pac_file_name:
                aliases: ['pac-file-name']
                type: str
                description: Pac file name.
            pac_file_server_port:
                aliases: ['pac-file-server-port']
                type: list
                elements: str
                description: Port number that PAC traffic from client web browsers uses to connect to the explicit web proxy
            pac_file_server_status:
                aliases: ['pac-file-server-status']
                type: str
                description: Enable/disable Proxy Auto-Configuration
                choices:
                    - 'disable'
                    - 'enable'
            pac_file_through_https:
                aliases: ['pac-file-through-https']
                type: str
                description: Enable/disable to get Proxy Auto-Configuration
                choices:
                    - 'disable'
                    - 'enable'
            pac_file_url:
                aliases: ['pac-file-url']
                type: str
                description: Pac file url.
            pac_policy:
                aliases: ['pac-policy']
                type: list
                elements: dict
                description: Pac policy.
                suboptions:
                    comments:
                        type: str
                        description: Optional comments.
                    dstaddr:
                        type: list
                        elements: str
                        description: Destination address objects.
                    pac_file_data:
                        aliases: ['pac-file-data']
                        type: str
                        description: PAC file contents enclosed in quotes
                    pac_file_name:
                        aliases: ['pac-file-name']
                        type: str
                        description: Pac file name.
                    policyid:
                        type: int
                        description: Policy ID.
                    srcaddr:
                        type: list
                        elements: str
                        description: Source address objects.
                    srcaddr6:
                        type: list
                        elements: str
                        description: Source address6 objects.
                    status:
                        type: str
                        description: Enable/disable policy.
                        choices:
                            - 'disable'
                            - 'enable'
            pref_dns_result:
                aliases: ['pref-dns-result']
                type: str
                description: Prefer resolving addresses using the configured IPv4 or IPv6 DNS server
                choices:
                    - 'ipv4'
                    - 'ipv6'
                    - 'ipv4-strict'
                    - 'ipv6-strict'
            realm:
                type: str
                description: Authentication realm used to identify the explicit web proxy
            sec_default_action:
                aliases: ['sec-default-action']
                type: str
                description: Accept or deny explicit web proxy sessions when no web proxy firewall policy exists.
                choices:
                    - 'deny'
                    - 'accept'
            secure_web_proxy:
                aliases: ['secure-web-proxy']
                type: str
                description: Enable/disable/require the secure web proxy for HTTP and HTTPS session.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'secure'
            secure_web_proxy_cert:
                aliases: ['secure-web-proxy-cert']
                type: list
                elements: str
                description: Name of certificates for secure web proxy.
            socks:
                type: str
                description: Enable/disable the SOCKS proxy.
                choices:
                    - 'disable'
                    - 'enable'
            socks_incoming_port:
                aliases: ['socks-incoming-port']
                type: list
                elements: str
                description: Accept incoming SOCKS proxy requests on one or more ports
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Relative strength of encryption algorithms accepted in HTTPS deep scan
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Bit-size of Diffie-Hellman
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
            status:
                type: str
                description: Enable/disable the explicit Web proxy for HTTP and HTTPS session.
                choices:
                    - 'disable'
                    - 'enable'
            strict_guest:
                aliases: ['strict-guest']
                type: str
                description: Enable/disable strict guest user checking by the explicit web proxy.
                choices:
                    - 'disable'
                    - 'enable'
            trace_auth_no_rsp:
                aliases: ['trace-auth-no-rsp']
                type: str
                description: Enable/disable logging timed-out authentication requests.
                choices:
                    - 'disable'
                    - 'enable'
            unknown_http_version:
                aliases: ['unknown-http-version']
                type: str
                description: How to handle HTTP sessions that do not comply with HTTP 0.
                choices:
                    - 'best-effort'
                    - 'reject'
                    - 'tunnel'
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: Enable/disable to detect device type by HTTP user-agent if no client certificate provided.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'sdwan'
                    - 'specify'
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure explicit Web proxy settings.
      fortinet.fmgdevice.fmgd_webproxy_explicit:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        webproxy_explicit:
          # client_cert: <value in [disable, enable]>
          # empty_cert_action: <value in [block, accept, accept-unmanageable]>
          # ftp_incoming_port: <list or string>
          # ftp_over_http: <value in [disable, enable]>
          # http_connection_mode: <value in [static, multiplex, serverpool]>
          # http_incoming_port: <list or string>
          # https_incoming_port: <list or string>
          # https_replacement_message: <value in [disable, enable]>
          # incoming_ip: <string>
          # incoming_ip6: <string>
          # ipv6_status: <value in [disable, enable]>
          # message_upon_server_error: <value in [disable, enable]>
          # outgoing_ip: <list or string>
          # outgoing_ip6: <list or string>
          # pac_file_data: <string>
          # pac_file_name: <string>
          # pac_file_server_port: <list or string>
          # pac_file_server_status: <value in [disable, enable]>
          # pac_file_through_https: <value in [disable, enable]>
          # pac_file_url: <string>
          # pac_policy:
          #   - comments: <string>
          #     dstaddr: <list or string>
          #     pac_file_data: <string>
          #     pac_file_name: <string>
          #     policyid: <integer>
          #     srcaddr: <list or string>
          #     srcaddr6: <list or string>
          #     status: <value in [disable, enable]>
          # pref_dns_result: <value in [ipv4, ipv6, ipv4-strict, ...]>
          # realm: <string>
          # sec_default_action: <value in [deny, accept]>
          # secure_web_proxy: <value in [disable, enable, secure]>
          # secure_web_proxy_cert: <list or string>
          # socks: <value in [disable, enable]>
          # socks_incoming_port: <list or string>
          # ssl_algorithm: <value in [high, medium, low]>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # status: <value in [disable, enable]>
          # strict_guest: <value in [disable, enable]>
          # trace_auth_no_rsp: <value in [disable, enable]>
          # unknown_http_version: <value in [best-effort, reject, tunnel]>
          # user_agent_detect: <value in [disable, enable]>
          # interface: <list or string>
          # interface_select_method: <value in [sdwan, specify]>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'webproxy_explicit': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'client-cert': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.4.3', '']], 'choices': ['block', 'accept', 'accept-unmanageable'], 'type': 'str'},
                'ftp-incoming-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ftp-over-http': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-connection-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['static', 'multiplex', 'serverpool'], 'type': 'str'},
                'http-incoming-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'https-incoming-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'https-replacement-message': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'incoming-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'incoming-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ipv6-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'message-upon-server-error': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outgoing-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'outgoing-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'pac-file-data': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'pac-file-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'pac-file-server-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'pac-file-server-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pac-file-through-https': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pac-file-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'pac-policy': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'dstaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'pac-file-data': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'pac-file-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'policyid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'srcaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'srcaddr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'pref-dns-result': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['ipv4', 'ipv6', 'ipv4-strict', 'ipv6-strict'],
                    'type': 'str'
                },
                'realm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sec-default-action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'secure-web-proxy': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'secure'], 'type': 'str'},
                'secure-web-proxy-cert': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'socks': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'socks-incoming-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'ssl-dh-bits': {'v_range': [['7.4.3', '']], 'choices': ['768', '1024', '1536', '2048'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strict-guest': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trace-auth-no-rsp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-http-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['best-effort', 'reject', 'tunnel'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.6.2', '']], 'choices': ['sdwan', 'specify'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_explicit'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
