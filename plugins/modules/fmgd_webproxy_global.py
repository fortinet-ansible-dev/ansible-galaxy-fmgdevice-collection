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
module: fmgd_webproxy_global
short_description: Configure Web proxy global settings.
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
    webproxy_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            always_learn_client_ip:
                aliases: ['always-learn-client-ip']
                type: str
                description: Enable/disable learning the clients IP address from headers for every request.
                choices:
                    - 'disable'
                    - 'enable'
            fast_policy_match:
                aliases: ['fast-policy-match']
                type: str
                description: Enable/disable fast matching algorithm for explicit and transparent proxy policy.
                choices:
                    - 'disable'
                    - 'enable'
            forward_proxy_auth:
                aliases: ['forward-proxy-auth']
                type: str
                description: Enable/disable forwarding proxy authentication headers.
                choices:
                    - 'disable'
                    - 'enable'
            forward_server_affinity_timeout:
                aliases: ['forward-server-affinity-timeout']
                type: int
                description: Period of time before the source IPs traffic is no longer assigned to the forwarding server
            ldap_user_cache:
                aliases: ['ldap-user-cache']
                type: str
                description: Enable/disable LDAP user cache for explicit and transparent proxy user.
                choices:
                    - 'disable'
                    - 'enable'
            learn_client_ip:
                aliases: ['learn-client-ip']
                type: str
                description: Enable/disable learning the clients IP address from headers.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'traffic-process'
                    - 'log-only'
            learn_client_ip_from_header:
                aliases: ['learn-client-ip-from-header']
                type: list
                elements: str
                description: Learn client IP address from the specified headers.
                choices:
                    - 'true-client-ip'
                    - 'x-real-ip'
                    - 'x-forwarded-for'
            learn_client_ip_srcaddr:
                aliases: ['learn-client-ip-srcaddr']
                type: list
                elements: str
                description: Source address name
            learn_client_ip_srcaddr6:
                aliases: ['learn-client-ip-srcaddr6']
                type: list
                elements: str
                description: IPv6 Source address name
            log_app_id:
                aliases: ['log-app-id']
                type: str
                description: Enable/disable always log application type in traffic log.
                choices:
                    - 'disable'
                    - 'enable'
            log_forward_server:
                aliases: ['log-forward-server']
                type: str
                description: Enable/disable forward server name logging in forward traffic log.
                choices:
                    - 'disable'
                    - 'enable'
            log_policy_pending:
                aliases: ['log-policy-pending']
                type: str
                description: Enable/disable logging sessions that are pending on policy matching.
                choices:
                    - 'disable'
                    - 'enable'
            max_message_length:
                aliases: ['max-message-length']
                type: int
                description: Maximum length of HTTP message, not including body
            max_request_length:
                aliases: ['max-request-length']
                type: int
                description: Maximum length of HTTP request line
            max_waf_body_cache_length:
                aliases: ['max-waf-body-cache-length']
                type: int
                description: Maximum length of HTTP messages processed by Web Application Firewall
            policy_category_deep_inspect:
                aliases: ['policy-category-deep-inspect']
                type: str
                description: Enable/disable deep inspection for application level category policy matching.
                choices:
                    - 'disable'
                    - 'enable'
            proxy_fqdn:
                aliases: ['proxy-fqdn']
                type: str
                description: Fully Qualified Domain Name
            proxy_transparent_cert_inspection:
                aliases: ['proxy-transparent-cert-inspection']
                type: str
                description: Enable/disable transparent proxy certificate inspection.
                choices:
                    - 'disable'
                    - 'enable'
            src_affinity_exempt_addr:
                aliases: ['src-affinity-exempt-addr']
                type: list
                elements: str
                description: IPv4 source addresses to exempt proxy affinity.
            src_affinity_exempt_addr6:
                aliases: ['src-affinity-exempt-addr6']
                type: list
                elements: str
                description: IPv6 source addresses to exempt proxy affinity.
            ssl_ca_cert:
                aliases: ['ssl-ca-cert']
                type: list
                elements: str
                description: SSL CA certificate for SSL interception.
            ssl_cert:
                aliases: ['ssl-cert']
                type: list
                elements: str
                description: SSL certificate for SSL interception.
            strict_web_check:
                aliases: ['strict-web-check']
                type: str
                description: Enable/disable strict web checking to block web sites that send incorrect headers that dont conform to HTTP 1.
                choices:
                    - 'disable'
                    - 'enable'
            webproxy_profile:
                aliases: ['webproxy-profile']
                type: list
                elements: str
                description: Name of the web proxy profile to apply when explicit proxy traffic is allowed by default and traffic is accepted that does...
            tunnel_non_http:
                aliases: ['tunnel-non-http']
                type: str
                description: Enable/disable allowing non-HTTP traffic.
                choices:
                    - 'disable'
                    - 'enable'
            unknown_http_version:
                aliases: ['unknown-http-version']
                type: str
                description: Action to take when an unknown version of HTTP is encountered
                choices:
                    - 'best-effort'
                    - 'reject'
                    - 'tunnel'
            request_obs_fold:
                aliases: ['request-obs-fold']
                type: str
                description: Action when HTTP/1.
                choices:
                    - 'block'
                    - 'replace-with-sp'
                    - 'keep'
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
    - name: Configure Web proxy global settings.
      fortinet.fmgdevice.fmgd_webproxy_global:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        webproxy_global:
          # always_learn_client_ip: <value in [disable, enable]>
          # fast_policy_match: <value in [disable, enable]>
          # forward_proxy_auth: <value in [disable, enable]>
          # forward_server_affinity_timeout: <integer>
          # ldap_user_cache: <value in [disable, enable]>
          # learn_client_ip: <value in [disable, enable, traffic-process, ...]>
          # learn_client_ip_from_header:
          #   - "true-client-ip"
          #   - "x-real-ip"
          #   - "x-forwarded-for"
          # learn_client_ip_srcaddr: <list or string>
          # learn_client_ip_srcaddr6: <list or string>
          # log_app_id: <value in [disable, enable]>
          # log_forward_server: <value in [disable, enable]>
          # log_policy_pending: <value in [disable, enable]>
          # max_message_length: <integer>
          # max_request_length: <integer>
          # max_waf_body_cache_length: <integer>
          # policy_category_deep_inspect: <value in [disable, enable]>
          # proxy_fqdn: <string>
          # proxy_transparent_cert_inspection: <value in [disable, enable]>
          # src_affinity_exempt_addr: <list or string>
          # src_affinity_exempt_addr6: <list or string>
          # ssl_ca_cert: <list or string>
          # ssl_cert: <list or string>
          # strict_web_check: <value in [disable, enable]>
          # webproxy_profile: <list or string>
          # tunnel_non_http: <value in [disable, enable]>
          # unknown_http_version: <value in [best-effort, reject, tunnel]>
          # request_obs_fold: <value in [block, replace-with-sp, keep]>
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
        '/pm/config/device/{device}/vdom/{vdom}/web-proxy/global'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'webproxy_global': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'always-learn-client-ip': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fast-policy-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forward-proxy-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forward-server-affinity-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ldap-user-cache': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'learn-client-ip': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'traffic-process', 'log-only'],
                    'type': 'str'
                },
                'learn-client-ip-from-header': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['true-client-ip', 'x-real-ip', 'x-forwarded-for'],
                    'elements': 'str'
                },
                'learn-client-ip-srcaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'learn-client-ip-srcaddr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'log-app-id': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-forward-server': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-policy-pending': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-message-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-request-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'max-waf-body-cache-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'policy-category-deep-inspect': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'proxy-fqdn': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'proxy-transparent-cert-inspection': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'src-affinity-exempt-addr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'src-affinity-exempt-addr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-ca-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'strict-web-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webproxy-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'tunnel-non-http': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-http-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['best-effort', 'reject', 'tunnel'], 'type': 'str'},
                'request-obs-fold': {'v_range': [['7.4.4', '7.4.5'], ['7.6.2', '']], 'choices': ['block', 'replace-with-sp', 'keep'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webproxy_global'),
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
