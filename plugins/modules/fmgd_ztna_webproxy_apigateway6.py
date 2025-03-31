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
module: fmgd_ztna_webproxy_apigateway6
short_description: Set IPv6 API Gateway.
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
    web-proxy:
        description: Deprecated, please use "web_proxy"
        type: str
    web_proxy:
        description: The parameter (web-proxy) in requested url.
        type: str
    ztna_webproxy_apigateway6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            h2_support:
                aliases: ['h2-support']
                type: str
                description: HTTP2 support, default=Enable.
                choices:
                    - 'disable'
                    - 'enable'
            h3_support:
                aliases: ['h3-support']
                type: str
                description: HTTP3/QUIC support, default=Disable.
                choices:
                    - 'disable'
                    - 'enable'
            http_cookie_age:
                aliases: ['http-cookie-age']
                type: int
                description: Time in minutes that client web browsers should keep a cookie.
            http_cookie_domain:
                aliases: ['http-cookie-domain']
                type: str
                description: Domain that HTTP cookie persistence should apply to.
            http_cookie_domain_from_host:
                aliases: ['http-cookie-domain-from-host']
                type: str
                description: Enable/disable use of HTTP cookie domain from host field in HTTP.
                choices:
                    - 'disable'
                    - 'enable'
            http_cookie_generation:
                aliases: ['http-cookie-generation']
                type: int
                description: Generation of HTTP cookie to be accepted.
            http_cookie_path:
                aliases: ['http-cookie-path']
                type: str
                description: Limit HTTP cookie persistence to the specified path.
            http_cookie_share:
                aliases: ['http-cookie-share']
                type: str
                description: Control sharing of cookies across API Gateway.
                choices:
                    - 'disable'
                    - 'same-ip'
            https_cookie_secure:
                aliases: ['https-cookie-secure']
                type: str
                description: Enable/disable verification that inserted HTTPS cookies are secure.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: API Gateway ID.
                required: true
            ldb_method:
                aliases: ['ldb-method']
                type: str
                description: Method used to distribute sessions to real servers.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'first-alive'
                    - 'http-host'
            persistence:
                type: str
                description: Configure how to make sure that clients connect to the same server every time they make a request that is part of the same...
                choices:
                    - 'none'
                    - 'http-cookie'
            quic:
                type: dict
                description: Quic.
                suboptions:
                    ack_delay_exponent:
                        aliases: ['ack-delay-exponent']
                        type: int
                        description: ACK delay exponent
                    active_connection_id_limit:
                        aliases: ['active-connection-id-limit']
                        type: int
                        description: Active connection ID limit
                    active_migration:
                        aliases: ['active-migration']
                        type: str
                        description: Enable/disable active migration
                        choices:
                            - 'disable'
                            - 'enable'
                    grease_quic_bit:
                        aliases: ['grease-quic-bit']
                        type: str
                        description: Enable/disable grease QUIC bit
                        choices:
                            - 'disable'
                            - 'enable'
                    max_ack_delay:
                        aliases: ['max-ack-delay']
                        type: int
                        description: Maximum ACK delay in milliseconds
                    max_datagram_frame_size:
                        aliases: ['max-datagram-frame-size']
                        type: int
                        description: Maximum datagram frame size in bytes
                    max_idle_timeout:
                        aliases: ['max-idle-timeout']
                        type: int
                        description: Maximum idle timeout milliseconds
                    max_udp_payload_size:
                        aliases: ['max-udp-payload-size']
                        type: int
                        description: Maximum UDP payload size in bytes
            realservers:
                type: list
                elements: dict
                description: Realservers.
                suboptions:
                    addr_type:
                        aliases: ['addr-type']
                        type: str
                        description: Type of address.
                        choices:
                            - 'fqdn'
                            - 'ip'
                    address:
                        type: list
                        elements: str
                        description: Address or address group of the real server.
                    health_check:
                        aliases: ['health-check']
                        type: str
                        description: Enable to check the responsiveness of the real server before forwarding traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    health_check_proto:
                        aliases: ['health-check-proto']
                        type: str
                        description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                        choices:
                            - 'ping'
                            - 'http'
                            - 'tcp-connect'
                    holddown_interval:
                        aliases: ['holddown-interval']
                        type: str
                        description: Enable/disable holddown timer.
                        choices:
                            - 'disable'
                            - 'enable'
                    http_host:
                        aliases: ['http-host']
                        type: str
                        description: HTTP server domain name in HTTP header.
                    id:
                        type: int
                        description: Real server ID.
                    ip:
                        type: str
                        description: IPv6 address of the real server.
                    port:
                        type: int
                        description: Port for communicating with the real server.
                    status:
                        type: str
                        description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic...
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
                    translate_host:
                        aliases: ['translate-host']
                        type: str
                        description: Enable/disable translation of hostname/IP from virtual server to real server.
                        choices:
                            - 'disable'
                            - 'enable'
                    weight:
                        type: int
                        description: Weight of the real server.
            service:
                type: str
                description: Service.
                choices:
                    - 'http'
                    - 'https'
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl_cipher_suites:
                aliases: ['ssl-cipher-suites']
                type: list
                elements: dict
                description: Ssl cipher suites.
                suboptions:
                    cipher:
                        type: str
                        description: Cipher suite name.
                        choices:
                            - 'TLS-RSA-WITH-RC4-128-MD5'
                            - 'TLS-RSA-WITH-RC4-128-SHA'
                            - 'TLS-RSA-WITH-DES-CBC-SHA'
                            - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                            - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                            - 'TLS-AES-128-GCM-SHA256'
                            - 'TLS-AES-256-GCM-SHA384'
                            - 'TLS-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                    priority:
                        type: int
                        description: SSL/TLS cipher suites priority.
                    versions:
                        type: list
                        elements: str
                        description: SSL/TLS versions that the cipher suite can be used with.
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Highest SSL/TLS version acceptable from a server.
                choices:
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Lowest SSL/TLS version acceptable from a server.
                choices:
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_renegotiation:
                aliases: ['ssl-renegotiation']
                type: str
                description: Enable/disable secure renegotiation to comply with RFC 5746.
                choices:
                    - 'disable'
                    - 'enable'
            url_map:
                aliases: ['url-map']
                type: str
                description: URL pattern to match.
            url_map_type:
                aliases: ['url-map-type']
                type: str
                description: Type of url-map.
                choices:
                    - 'sub-string'
                    - 'wildcard'
                    - 'regex'
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
    - name: Set IPv6 API Gateway.
      fortinet.fmgdevice.fmgd_ztna_webproxy_apigateway6:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        web_proxy: <your own value>
        state: present # <value in [present, absent]>
        ztna_webproxy_apigateway6:
          id: 0 # Required variable, integer
          # h2_support: <value in [disable, enable]>
          # h3_support: <value in [disable, enable]>
          # http_cookie_age: <integer>
          # http_cookie_domain: <string>
          # http_cookie_domain_from_host: <value in [disable, enable]>
          # http_cookie_generation: <integer>
          # http_cookie_path: <string>
          # http_cookie_share: <value in [disable, same-ip]>
          # https_cookie_secure: <value in [disable, enable]>
          # ldb_method: <value in [static, round-robin, weighted, ...]>
          # persistence: <value in [none, http-cookie]>
          # quic:
          #   ack_delay_exponent: <integer>
          #   active_connection_id_limit: <integer>
          #   active_migration: <value in [disable, enable]>
          #   grease_quic_bit: <value in [disable, enable]>
          #   max_ack_delay: <integer>
          #   max_datagram_frame_size: <integer>
          #   max_idle_timeout: <integer>
          #   max_udp_payload_size: <integer>
          # realservers:
          #   - addr_type: <value in [fqdn, ip]>
          #     address: <list or string>
          #     health_check: <value in [disable, enable]>
          #     health_check_proto: <value in [ping, http, tcp-connect]>
          #     holddown_interval: <value in [disable, enable]>
          #     http_host: <string>
          #     id: <integer>
          #     ip: <string>
          #     port: <integer>
          #     status: <value in [active, standby, disable]>
          #     translate_host: <value in [disable, enable]>
          #     weight: <integer>
          # service: <value in [http, https]>
          # ssl_algorithm: <value in [high, medium, low]>
          # ssl_cipher_suites:
          #   - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #     priority: <integer>
          #     versions:
          #       - "tls-1.0"
          #       - "tls-1.1"
          #       - "tls-1.2"
          #       - "tls-1.3"
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # ssl_max_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          # ssl_min_version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
          # ssl_renegotiation: <value in [disable, enable]>
          # url_map: <string>
          # url_map_type: <value in [sub-string, wildcard, regex]>
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
        '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6'
    ]
    url_params = ['device', 'vdom', 'web-proxy']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'web-proxy': {'type': 'str', 'api_name': 'web_proxy'},
        'web_proxy': {'type': 'str'},
        'ztna_webproxy_apigateway6': {
            'type': 'dict',
            'v_range': [['7.6.2', '']],
            'options': {
                'h2-support': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-age': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'http-cookie-domain': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'http-cookie-domain-from-host': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-generation': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'http-cookie-path': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'http-cookie-share': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                'https-cookie-secure': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'int'},
                'ldb-method': {'v_range': [['7.6.2', '']], 'choices': ['static', 'round-robin', 'weighted', 'first-alive', 'http-host'], 'type': 'str'},
                'persistence': {'v_range': [['7.6.2', '']], 'choices': ['none', 'http-cookie'], 'type': 'str'},
                'quic': {
                    'v_range': [['7.6.2', '']],
                    'type': 'dict',
                    'options': {
                        'ack-delay-exponent': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'active-connection-id-limit': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'active-migration': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'grease-quic-bit': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-ack-delay': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'max-datagram-frame-size': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'max-idle-timeout': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'max-udp-payload-size': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    }
                },
                'realservers': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'addr-type': {'v_range': [['7.6.2', '']], 'choices': ['fqdn', 'ip'], 'type': 'str'},
                        'address': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'health-check': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'health-check-proto': {'v_range': [['7.6.2', '']], 'choices': ['ping', 'http', 'tcp-connect'], 'type': 'str'},
                        'holddown-interval': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-host': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'id': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.6.2', '']], 'type': 'str'},
                        'port': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'status': {'v_range': [['7.6.2', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'translate-host': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'weight': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'service': {'v_range': [['7.6.2', '']], 'choices': ['http', 'https'], 'type': 'str'},
                'ssl-algorithm': {'v_range': [['7.6.2', '']], 'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['7.6.2', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.6.2', '']],
                            'choices': [
                                'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA', 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA', 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                                'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            ],
                            'type': 'str'
                        },
                        'priority': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.6.2', '']],
                            'type': 'list',
                            'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-dh-bits': {'v_range': [['7.6.2', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                'ssl-max-version': {'v_range': [['7.6.2', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'v_range': [['7.6.2', '']], 'choices': ['tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-renegotiation': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-map': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'url-map-type': {'v_range': [['7.6.2', '']], 'choices': ['sub-string', 'wildcard', 'regex'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_webproxy_apigateway6'),
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
