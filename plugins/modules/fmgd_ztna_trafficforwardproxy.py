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
module: fmgd_ztna_trafficforwardproxy
short_description: Configure ZTNA traffic forward proxy.
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
    ztna_trafficforwardproxy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auth_portal:
                aliases: ['auth-portal']
                type: str
                description: Enable/disable authentication portal.
                choices:
                    - 'disable'
                    - 'enable'
            client_cert:
                aliases: ['client-cert']
                type: str
                description: Enable/disable to request client certificate.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            empty_cert_action:
                aliases: ['empty-cert-action']
                type: str
                description: Action of an empty client certificate.
                choices:
                    - 'accept'
                    - 'block'
                    - 'accept-unmanageable'
            h3_support:
                aliases: ['h3-support']
                type: str
                description: Enable/disable HTTP3/QUIC support
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: list
                elements: str
                description: Interface name
            log_blocked_traffic:
                aliases: ['log-blocked-traffic']
                type: str
                description: Enable/disable logging of blocked traffic.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Traffic forward proxy name
                required: true
            port:
                type: str
                description: Accept incoming traffic on one or more ports
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
            ssl_accept_ffdhe_groups:
                aliases: ['ssl-accept-ffdhe-groups']
                type: str
                description: Enable/disable FFDHE cipher suite for SSL key exchange.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_algorithm:
                aliases: ['ssl-algorithm']
                type: str
                description: Permitted encryption algorithms for SSL sessions according to encryption strength.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
            ssl_certificate:
                aliases: ['ssl-certificate']
                type: list
                elements: str
                description: Name of the certificate to use for SSL handshake.
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
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_client_fallback:
                aliases: ['ssl-client-fallback']
                type: str
                description: Enable/disable support for preventing Downgrade Attacks on client connections
                choices:
                    - 'disable'
                    - 'enable'
            ssl_client_rekey_count:
                aliases: ['ssl-client-rekey-count']
                type: int
                description: Maximum length of data in MB before triggering a client rekey
            ssl_client_renegotiation:
                aliases: ['ssl-client-renegotiation']
                type: str
                description: Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.
                choices:
                    - 'allow'
                    - 'deny'
                    - 'secure'
            ssl_client_session_state_max:
                aliases: ['ssl-client-session-state-max']
                type: int
                description: Maximum number of client to FortiProxy SSL session states to keep.
            ssl_client_session_state_timeout:
                aliases: ['ssl-client-session-state-timeout']
                type: int
                description: Number of minutes to keep client to FortiProxy SSL session state.
            ssl_client_session_state_type:
                aliases: ['ssl-client-session-state-type']
                type: str
                description: How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            ssl_dh_bits:
                aliases: ['ssl-dh-bits']
                type: str
                description: Bit-size of Diffie-Hellman
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl_hpkp:
                aliases: ['ssl-hpkp']
                type: str
                description: Enable/disable including HPKP header in response.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'report-only'
            ssl_hpkp_age:
                aliases: ['ssl-hpkp-age']
                type: int
                description: Number of seconds the client should honor the HPKP setting.
            ssl_hpkp_backup:
                aliases: ['ssl-hpkp-backup']
                type: list
                elements: str
                description: Certificate to generate backup HPKP pin from.
            ssl_hpkp_include_subdomains:
                aliases: ['ssl-hpkp-include-subdomains']
                type: str
                description: Indicate that HPKP header applies to all subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hpkp_primary:
                aliases: ['ssl-hpkp-primary']
                type: list
                elements: str
                description: Certificate to generate primary HPKP pin from.
            ssl_hpkp_report_uri:
                aliases: ['ssl-hpkp-report-uri']
                type: str
                description: URL to report HPKP violations to.
            ssl_hsts:
                aliases: ['ssl-hsts']
                type: str
                description: Enable/disable including HSTS header in response.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_hsts_age:
                aliases: ['ssl-hsts-age']
                type: int
                description: Number of seconds the client should honor the HSTS setting.
            ssl_hsts_include_subdomains:
                aliases: ['ssl-hsts-include-subdomains']
                type: str
                description: Indicate that HSTS header applies to all subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_http_location_conversion:
                aliases: ['ssl-http-location-conversion']
                type: str
                description: Enable to replace HTTP with HTTPS in the replys Location HTTP header field.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_http_match_host:
                aliases: ['ssl-http-match-host']
                type: str
                description: Enable/disable HTTP host matching for location conversion.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_max_version:
                aliases: ['ssl-max-version']
                type: str
                description: Highest SSL/TLS version acceptable from a client.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                aliases: ['ssl-min-version']
                type: str
                description: Lowest SSL/TLS version acceptable from a client.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_mode:
                aliases: ['ssl-mode']
                type: str
                description: Apply SSL offloading between the client and the FortiGate
                choices:
                    - 'half'
                    - 'full'
            ssl_pfs:
                aliases: ['ssl-pfs']
                type: str
                description: Select the cipher suites that can be used for SSL perfect forward secrecy
                choices:
                    - 'require'
                    - 'deny'
                    - 'allow'
            ssl_send_empty_frags:
                aliases: ['ssl-send-empty-frags']
                type: str
                description: Enable/disable sending empty fragments to avoid CBC IV attacks
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_algorithm:
                aliases: ['ssl-server-algorithm']
                type: str
                description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                choices:
                    - 'high'
                    - 'low'
                    - 'medium'
                    - 'custom'
                    - 'client'
            ssl_server_cipher_suites:
                aliases: ['ssl-server-cipher-suites']
                type: list
                elements: dict
                description: Ssl server cipher suites.
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
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl_server_max_version:
                aliases: ['ssl-server-max-version']
                type: str
                description: Highest SSL/TLS version acceptable from a server.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl_server_min_version:
                aliases: ['ssl-server-min-version']
                type: str
                description: Lowest SSL/TLS version acceptable from a server.
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'client'
                    - 'tls-1.3'
            ssl_server_renegotiation:
                aliases: ['ssl-server-renegotiation']
                type: str
                description: Enable/disable secure renegotiation to comply with RFC 5746.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server_session_state_max:
                aliases: ['ssl-server-session-state-max']
                type: int
                description: Maximum number of FortiGate to Server SSL session states to keep.
            ssl_server_session_state_timeout:
                aliases: ['ssl-server-session-state-timeout']
                type: int
                description: Number of minutes to keep FortiGate to Server SSL session state.
            ssl_server_session_state_type:
                aliases: ['ssl-server-session-state-type']
                type: str
                description: How to expire SSL sessions for the segment of the SSL connection between the server and the FortiGate.
                choices:
                    - 'disable'
                    - 'time'
                    - 'count'
                    - 'both'
            status:
                type: str
                description: Enable/disable the traffic forward proxy for ZTNA traffic.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_multiplex:
                aliases: ['svr-pool-multiplex']
                type: str
                description: Enable/disable server pool multiplexing.
                choices:
                    - 'disable'
                    - 'enable'
            svr_pool_server_max_concurrent_request:
                aliases: ['svr-pool-server-max-concurrent-request']
                type: int
                description: Maximum number of concurrent requests that servers in server pool could handle
            svr_pool_server_max_request:
                aliases: ['svr-pool-server-max-request']
                type: int
                description: Maximum number of requests that servers in server pool handle before disconnecting
            svr_pool_ttl:
                aliases: ['svr-pool-ttl']
                type: int
                description: Time-to-live in the server pool for idle connections to servers.
            user_agent_detect:
                aliases: ['user-agent-detect']
                type: str
                description: Enable/disable to detect device type by HTTP user-agent if no client certificate provided.
                choices:
                    - 'disable'
                    - 'enable'
            auth_virtual_host:
                aliases: ['auth-virtual-host']
                type: list
                elements: str
                description: Virtual host for authentication portal.
            decrypted_traffic_mirror:
                aliases: ['decrypted-traffic-mirror']
                type: list
                elements: str
                description: Decrypted traffic mirror.
            host:
                type: list
                elements: str
                description: Virtual or real host name.
            vip:
                type: list
                elements: str
                description: Virtual IP name.
            vip6:
                type: list
                elements: str
                description: Virtual IPv6 name.
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
    - name: Configure ZTNA traffic forward proxy.
      fortinet.fmgdevice.fmgd_ztna_trafficforwardproxy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        ztna_trafficforwardproxy:
          name: "your value" # Required variable, string
          # auth_portal: <value in [disable, enable]>
          # client_cert: <value in [disable, enable]>
          # comment: <string>
          # empty_cert_action: <value in [accept, block, accept-unmanageable]>
          # h3_support: <value in [disable, enable]>
          # interface: <list or string>
          # log_blocked_traffic: <value in [disable, enable]>
          # port: <string>
          # quic:
          #   ack_delay_exponent: <integer>
          #   active_connection_id_limit: <integer>
          #   active_migration: <value in [disable, enable]>
          #   grease_quic_bit: <value in [disable, enable]>
          #   max_ack_delay: <integer>
          #   max_datagram_frame_size: <integer>
          #   max_idle_timeout: <integer>
          #   max_udp_payload_size: <integer>
          # ssl_accept_ffdhe_groups: <value in [disable, enable]>
          # ssl_algorithm: <value in [high, low, medium, ...]>
          # ssl_certificate: <list or string>
          # ssl_cipher_suites:
          #   - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #     priority: <integer>
          #     versions:
          #       - "ssl-3.0"
          #       - "tls-1.0"
          #       - "tls-1.1"
          #       - "tls-1.2"
          #       - "tls-1.3"
          # ssl_client_fallback: <value in [disable, enable]>
          # ssl_client_rekey_count: <integer>
          # ssl_client_renegotiation: <value in [allow, deny, secure]>
          # ssl_client_session_state_max: <integer>
          # ssl_client_session_state_timeout: <integer>
          # ssl_client_session_state_type: <value in [disable, time, count, ...]>
          # ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          # ssl_hpkp: <value in [disable, enable, report-only]>
          # ssl_hpkp_age: <integer>
          # ssl_hpkp_backup: <list or string>
          # ssl_hpkp_include_subdomains: <value in [disable, enable]>
          # ssl_hpkp_primary: <list or string>
          # ssl_hpkp_report_uri: <string>
          # ssl_hsts: <value in [disable, enable]>
          # ssl_hsts_age: <integer>
          # ssl_hsts_include_subdomains: <value in [disable, enable]>
          # ssl_http_location_conversion: <value in [disable, enable]>
          # ssl_http_match_host: <value in [disable, enable]>
          # ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_mode: <value in [half, full]>
          # ssl_pfs: <value in [require, deny, allow]>
          # ssl_send_empty_frags: <value in [disable, enable]>
          # ssl_server_algorithm: <value in [high, low, medium, ...]>
          # ssl_server_cipher_suites:
          #   - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #     priority: <integer>
          #     versions:
          #       - "ssl-3.0"
          #       - "tls-1.0"
          #       - "tls-1.1"
          #       - "tls-1.2"
          #       - "tls-1.3"
          # ssl_server_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_server_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_server_renegotiation: <value in [disable, enable]>
          # ssl_server_session_state_max: <integer>
          # ssl_server_session_state_timeout: <integer>
          # ssl_server_session_state_type: <value in [disable, time, count, ...]>
          # status: <value in [disable, enable]>
          # svr_pool_multiplex: <value in [disable, enable]>
          # svr_pool_server_max_concurrent_request: <integer>
          # svr_pool_server_max_request: <integer>
          # svr_pool_ttl: <integer>
          # user_agent_detect: <value in [disable, enable]>
          # auth_virtual_host: <list or string>
          # decrypted_traffic_mirror: <list or string>
          # host: <list or string>
          # vip: <list or string>
          # vip6: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'ztna_trafficforwardproxy': {
            'type': 'dict',
            'v_range': [['7.6.0', '']],
            'options': {
                'auth-portal': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.0', '']], 'choices': ['accept', 'block', 'accept-unmanageable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'log-blocked-traffic': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.6.0', '']], 'required': True, 'type': 'str'},
                'port': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'quic': {
                    'v_range': [['7.6.0', '']],
                    'type': 'dict',
                    'options': {
                        'ack-delay-exponent': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'active-connection-id-limit': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'active-migration': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'grease-quic-bit': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-ack-delay': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'max-datagram-frame-size': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'max-idle-timeout': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'max-udp-payload-size': {'v_range': [['7.6.0', '']], 'type': 'int'}
                    }
                },
                'ssl-accept-ffdhe-groups': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-algorithm': {'v_range': [['7.6.0', '']], 'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.6.0', '']],
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
                        'priority': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.6.0', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-client-fallback': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-rekey-count': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'int'},
                'ssl-client-renegotiation': {'v_range': [['7.6.0', '']], 'choices': ['allow', 'deny', 'secure'], 'type': 'str'},
                'ssl-client-session-state-max': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ssl-client-session-state-timeout': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ssl-client-session-state-type': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'ssl-dh-bits': {'v_range': [['7.6.0', '']], 'choices': ['768', '1024', '1536', '2048', '3072', '4096'], 'type': 'str'},
                'ssl-hpkp': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                'ssl-hpkp-age': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ssl-hpkp-backup': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'ssl-hpkp-include-subdomains': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hpkp-primary': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'ssl-hpkp-report-uri': {'v_range': [['7.6.0', '']], 'type': 'str'},
                'ssl-hsts': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hsts-age': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ssl-hsts-include-subdomains': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-location-conversion': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-match-host': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-max-version': {'v_range': [['7.6.0', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-min-version': {'v_range': [['7.6.0', '']], 'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'], 'type': 'str'},
                'ssl-mode': {'v_range': [['7.6.0', '']], 'choices': ['half', 'full'], 'type': 'str'},
                'ssl-pfs': {'v_range': [['7.6.0', '']], 'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                'ssl-send-empty-frags': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-algorithm': {'v_range': [['7.6.0', '']], 'choices': ['high', 'low', 'medium', 'custom', 'client'], 'type': 'str'},
                'ssl-server-cipher-suites': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.6.0', '']],
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
                        'priority': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.6.0', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-server-max-version': {
                    'v_range': [['7.6.0', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-server-min-version': {
                    'v_range': [['7.6.0', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-server-renegotiation': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-session-state-max': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ssl-server-session-state-timeout': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ssl-server-session-state-type': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'time', 'count', 'both'], 'type': 'str'},
                'status': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-multiplex': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'svr-pool-server-max-concurrent-request': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'svr-pool-server-max-request': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'svr-pool-ttl': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'user-agent-detect': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-virtual-host': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'host': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'vip': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'vip6': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ztna_trafficforwardproxy'),
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
