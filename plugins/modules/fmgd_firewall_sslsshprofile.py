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
module: fmgd_firewall_sslsshprofile
short_description: Configure SSL/SSH protocol options.
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
    firewall_sslsshprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowlist:
                type: str
                description: Enable/disable exempting servers by FortiGuard allowlist.
                choices:
                    - 'disable'
                    - 'enable'
            block_blocklisted_certificates:
                aliases: ['block-blocklisted-certificates']
                type: str
                description: Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blocklist.
                choices:
                    - 'disable'
                    - 'enable'
            caname:
                type: list
                elements: str
                description: CA certificate used by SSL Inspection.
            comment:
                type: str
                description: Optional comments.
            dot:
                type: dict
                description: Dot.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    quic:
                        type: str
                        description: QUIC inspection status
                        choices:
                            - 'bypass'
                            - 'block'
                            - 'inspect'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'enable'
                            - 'strict'
                            - 'disable'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    udp_not_quic:
                        aliases: ['udp-not-quic']
                        type: str
                        description: Action to be taken when matched UDP packet is not QUIC.
                        choices:
                            - 'block'
                            - 'allow'
            ech_outer_sni:
                aliases: ['ech-outer-sni']
                type: list
                elements: dict
                description: Ech outer sni.
                suboptions:
                    name:
                        type: str
                        description: ClientHelloOuter SNI name.
                    sni:
                        type: str
                        description: ClientHelloOuter SNI to be blocked.
            ftps:
                type: dict
                description: Ftps.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Minimum SSL version to be allowed.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ports:
                        type: list
                        elements: int
                        description: Ports to use for scanning
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
            https:
                type: dict
                description: Https.
                suboptions:
                    cert_probe_failure:
                        aliases: ['cert-probe-failure']
                        type: str
                        description: Action based on certificate probe failure.
                        choices:
                            - 'block'
                            - 'allow'
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    encrypted_client_hello:
                        aliases: ['encrypted-client-hello']
                        type: str
                        description: Block/allow session based on existence of encrypted-client-hello.
                        choices:
                            - 'block'
                            - 'allow'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Minimum SSL version to be allowed.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    ports:
                        type: list
                        elements: int
                        description: Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    quic:
                        type: str
                        description: QUIC inspection status
                        choices:
                            - 'bypass'
                            - 'block'
                            - 'inspect'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
                    udp_not_quic:
                        aliases: ['udp-not-quic']
                        type: str
                        description: Action to be taken when matched UDP packet is not QUIC.
                        choices:
                            - 'block'
                            - 'allow'
            imaps:
                type: dict
                description: Imaps.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: list
                        elements: int
                        description: Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
            mapi_over_https:
                aliases: ['mapi-over-https']
                type: str
                description: Enable/disable inspection of MAPI over HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name.
                required: true
            pop3s:
                type: dict
                description: Pop3s.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: list
                        elements: int
                        description: Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
            rpc_over_https:
                aliases: ['rpc-over-https']
                type: str
                description: Enable/disable inspection of RPC over HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            server_cert:
                aliases: ['server-cert']
                type: list
                elements: str
                description: Certificate used by SSL Inspection to replace server certificate.
            server_cert_mode:
                aliases: ['server-cert-mode']
                type: str
                description: Re-sign or replace the servers certificate.
                choices:
                    - 're-sign'
                    - 'replace'
            smtps:
                type: dict
                description: Smtps.
                suboptions:
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    ports:
                        type: list
                        elements: int
                        description: Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Min allowed ssl version.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
            ssh:
                type: dict
                description: Ssh.
                suboptions:
                    ports:
                        type: list
                        elements: int
                        description: Ports to use for scanning
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    ssh_algorithm:
                        aliases: ['ssh-algorithm']
                        type: str
                        description: Relative strength of encryption algorithms accepted during negotiation.
                        choices:
                            - 'compatible'
                            - 'high-encryption'
                    ssh_tun_policy_check:
                        aliases: ['ssh-tun-policy-check']
                        type: str
                        description: Enable/disable SSH tunnel policy check.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Configure protocol inspection status.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
                    unsupported_version:
                        aliases: ['unsupported-version']
                        type: str
                        description: Action based on SSH version being unsupported.
                        choices:
                            - 'block'
                            - 'bypass'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Level of SSL inspection.
                        choices:
                            - 'disable'
                            - 'deep-inspection'
            ssl:
                type: dict
                description: Ssl.
                suboptions:
                    cert_probe_failure:
                        aliases: ['cert-probe-failure']
                        type: str
                        description: Action based on certificate probe failure.
                        choices:
                            - 'block'
                            - 'allow'
                    cert_validation_failure:
                        aliases: ['cert-validation-failure']
                        type: str
                        description: Action based on certificate validation failure.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    cert_validation_timeout:
                        aliases: ['cert-validation-timeout']
                        type: str
                        description: Action based on certificate validation timeout.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_certificate:
                        aliases: ['client-certificate']
                        type: str
                        description: Action based on received client certificate.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                            - 'bypass-on-cert-req'
                    encrypted_client_hello:
                        aliases: ['encrypted-client-hello']
                        type: str
                        description: Block/allow session based on existence of encrypted-client-hello.
                        choices:
                            - 'block'
                            - 'allow'
                    expired_server_cert:
                        aliases: ['expired-server-cert']
                        type: str
                        description: Action based on server certificate is expired.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Level of SSL inspection.
                        choices:
                            - 'disable'
                            - 'certificate-inspection'
                            - 'deep-inspection'
                    min_allowed_ssl_version:
                        aliases: ['min-allowed-ssl-version']
                        type: str
                        description: Minimum SSL version to be allowed.
                        choices:
                            - 'ssl-3.0'
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
                    revoked_server_cert:
                        aliases: ['revoked-server-cert']
                        type: str
                        description: Action based on server certificate is revoked.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    sni_server_cert_check:
                        aliases: ['sni-server-cert-check']
                        type: str
                        description: Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    unsupported_ssl_cipher:
                        aliases: ['unsupported-ssl-cipher']
                        type: str
                        description: Action based on the SSL cipher used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_negotiation:
                        aliases: ['unsupported-ssl-negotiation']
                        type: str
                        description: Action based on the SSL negotiation used being unsupported.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl_version:
                        aliases: ['unsupported-ssl-version']
                        type: str
                        description: Action based on the SSL version used being unsupported.
                        choices:
                            - 'block'
                            - 'allow'
                            - 'inspect'
                    untrusted_server_cert:
                        aliases: ['untrusted-server-cert']
                        type: str
                        description: Action based on server certificate is not issued by a trusted CA.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    client_cert_request:
                        aliases: ['client-cert-request']
                        type: str
                        description: Action based on client certificate request.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    invalid_server_cert:
                        aliases: ['invalid-server-cert']
                        type: str
                        description: Allow or block the invalid SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                    unsupported_ssl:
                        aliases: ['unsupported-ssl']
                        type: str
                        description: Action based on the SSL encryption used being unsupported.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    untrusted_cert:
                        aliases: ['untrusted-cert']
                        type: str
                        description: Allow, ignore, or block the untrusted SSL session server certificate.
                        choices:
                            - 'allow'
                            - 'block'
                            - 'ignore'
                    allow_invalid_server_cert:
                        aliases: ['allow-invalid-server-cert']
                        type: str
                        description: When enabled, allows SSL sessions whose server certificate validation failed.
                        choices:
                            - 'disable'
                            - 'enable'
            ssl_anomaly_log:
                aliases: ['ssl-anomaly-log']
                type: str
                description: Enable/disable logging of SSL anomalies.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_client_certificate:
                aliases: ['ssl-client-certificate']
                type: dict
                description: Ssl client certificate.
                suboptions:
                    caname:
                        type: list
                        elements: str
                        description: Caname.
                    cert:
                        type: list
                        elements: str
                        description: Cert.
                    keyring_list:
                        aliases: ['keyring-list']
                        type: list
                        elements: str
                        description: Keyring list.
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'do-not-offer'
                            - 'keyring-list'
                            - 'ca-sign'
                            - 'static'
            ssl_exempt:
                aliases: ['ssl-exempt']
                type: list
                elements: dict
                description: Ssl exempt.
                suboptions:
                    address:
                        type: list
                        elements: str
                        description: IPv4 address object.
                    address6:
                        type: list
                        elements: str
                        description: IPv6 address object.
                    finger_print_category:
                        aliases: ['finger-print-category']
                        type: str
                        description: Finger print platform.
                        choices:
                            - 'unknown'
                            - 'firefox'
                            - 'chrome'
                            - 'safari'
                            - 'edge'
                            - 'ie'
                            - 'android'
                            - 'ios'
                            - 'windows'
                    fortiguard_category:
                        aliases: ['fortiguard-category']
                        type: list
                        elements: str
                        description: FortiGuard category ID.
                    id:
                        type: int
                        description: ID number.
                    regex:
                        type: str
                        description: Exempt servers by regular expression.
                    type:
                        type: str
                        description: Type of address object
                        choices:
                            - 'fortiguard-category'
                            - 'address'
                            - 'address6'
                            - 'wildcard-fqdn'
                            - 'regex'
                            - 'finger-print'
                    wildcard_fqdn:
                        aliases: ['wildcard-fqdn']
                        type: list
                        elements: str
                        description: Exempt servers by wildcard FQDN.
            ssl_exemption_ip_rating:
                aliases: ['ssl-exemption-ip-rating']
                type: str
                description: Enable/disable IP based URL rating.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exemption_log:
                aliases: ['ssl-exemption-log']
                type: str
                description: Enable/disable logging of SSL exemptions.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_handshake_log:
                aliases: ['ssl-handshake-log']
                type: str
                description: Enable/disable logging of TLS handshakes.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_negotiation_log:
                aliases: ['ssl-negotiation-log']
                type: str
                description: Enable/disable logging of SSL negotiation events.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_server:
                aliases: ['ssl-server']
                type: list
                elements: dict
                description: Ssl server.
                suboptions:
                    ftps_client_certificate:
                        aliases: ['ftps-client-certificate']
                        type: str
                        description: Action based on received client certificate during the FTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https_client_certificate:
                        aliases: ['https-client-certificate']
                        type: str
                        description: Action based on received client certificate during the HTTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    id:
                        type: int
                        description: SSL server ID.
                    imaps_client_certificate:
                        aliases: ['imaps-client-certificate']
                        type: str
                        description: Action based on received client certificate during the IMAPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ip:
                        type: str
                        description: IPv4 address of the SSL server.
                    pop3s_client_certificate:
                        aliases: ['pop3s-client-certificate']
                        type: str
                        description: Action based on received client certificate during the POP3S handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps_client_certificate:
                        aliases: ['smtps-client-certificate']
                        type: str
                        description: Action based on received client certificate during the SMTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl_other_client_certificate:
                        aliases: ['ssl-other-client-certificate']
                        type: str
                        description: Action based on received client certificate during an SSL protocol handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    smtps_client_cert_request:
                        aliases: ['smtps-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the SMTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    imaps_client_cert_request:
                        aliases: ['imaps-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the IMAPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ssl_other_client_cert_request:
                        aliases: ['ssl-other-client-cert-request']
                        type: str
                        description: Action based on client certificate request during an SSL protocol handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    ftps_client_cert_request:
                        aliases: ['ftps-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the FTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    https_client_cert_request:
                        aliases: ['https-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the HTTPS handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
                    pop3s_client_cert_request:
                        aliases: ['pop3s-client-cert-request']
                        type: str
                        description: Action based on client certificate request during the POP3S handshake.
                        choices:
                            - 'bypass'
                            - 'inspect'
                            - 'block'
            ssl_server_cert_log:
                aliases: ['ssl-server-cert-log']
                type: str
                description: Enable/disable logging of server certificate information.
                choices:
                    - 'disable'
                    - 'enable'
            supported_alpn:
                aliases: ['supported-alpn']
                type: str
                description: Configure ALPN option.
                choices:
                    - 'none'
                    - 'http1-1'
                    - 'http2'
                    - 'all'
            untrusted_caname:
                aliases: ['untrusted-caname']
                type: list
                elements: str
                description: Untrusted CA certificate used by SSL Inspection.
            use_ssl_server:
                aliases: ['use-ssl-server']
                type: str
                description: Enable/disable the use of SSL server table for SSL offloading.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_exemptions_log:
                aliases: ['ssl-exemptions-log']
                type: str
                description: Enable/disable logging SSL exemptions.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_anomalies_log:
                aliases: ['ssl-anomalies-log']
                type: str
                description: Enable/disable logging SSL anomalies.
                choices:
                    - 'disable'
                    - 'enable'
            whitelist:
                type: str
                description: Enable/disable exempting servers by FortiGuard whitelist.
                choices:
                    - 'disable'
                    - 'enable'
            block_blacklisted_certificates:
                aliases: ['block-blacklisted-certificates']
                type: str
                description: Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blacklist.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure SSL/SSH protocol options.
      fortinet.fmgdevice.fmgd_firewall_sslsshprofile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_sslsshprofile:
          name: "your value" # Required variable, string
          # allowlist: <value in [disable, enable]>
          # block_blocklisted_certificates: <value in [disable, enable]>
          # caname: <list or string>
          # comment: <string>
          # dot:
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   quic: <value in [bypass, block, inspect]>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [enable, strict, disable]>
          #   status: <value in [disable, deep-inspection]>
          #   unsupported_ssl_cipher: <value in [block, allow]>
          #   unsupported_ssl_negotiation: <value in [block, allow]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   udp_not_quic: <value in [block, allow]>
          # ech_outer_sni:
          #   - name: <string>
          #     sni: <string>
          # ftps:
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   ports: <list or integer>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [disable, enable, strict]>
          #   status: <value in [disable, deep-inspection]>
          #   unsupported_ssl_cipher: <value in [allow, block]>
          #   unsupported_ssl_negotiation: <value in [allow, block]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   client_cert_request: <value in [bypass, inspect, block]>
          #   invalid_server_cert: <value in [allow, block]>
          #   unsupported_ssl: <value in [bypass, inspect, block]>
          #   untrusted_cert: <value in [allow, block, ignore]>
          #   allow_invalid_server_cert: <value in [disable, enable]>
          # https:
          #   cert_probe_failure: <value in [block, allow]>
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   encrypted_client_hello: <value in [block, allow]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   ports: <list or integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   quic: <value in [bypass, block, inspect]>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [disable, enable, strict]>
          #   status: <value in [disable, certificate-inspection, deep-inspection]>
          #   unsupported_ssl_cipher: <value in [allow, block]>
          #   unsupported_ssl_negotiation: <value in [allow, block]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   client_cert_request: <value in [bypass, inspect, block]>
          #   invalid_server_cert: <value in [allow, block]>
          #   unsupported_ssl: <value in [bypass, inspect, block]>
          #   untrusted_cert: <value in [allow, block, ignore]>
          #   allow_invalid_server_cert: <value in [disable, enable]>
          #   udp_not_quic: <value in [block, allow]>
          # imaps:
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   ports: <list or integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [disable, enable, strict]>
          #   status: <value in [disable, deep-inspection]>
          #   unsupported_ssl_cipher: <value in [allow, block]>
          #   unsupported_ssl_negotiation: <value in [allow, block]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   client_cert_request: <value in [bypass, inspect, block]>
          #   invalid_server_cert: <value in [allow, block]>
          #   unsupported_ssl: <value in [bypass, inspect, block]>
          #   untrusted_cert: <value in [allow, block, ignore]>
          #   allow_invalid_server_cert: <value in [disable, enable]>
          # mapi_over_https: <value in [disable, enable]>
          # pop3s:
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   ports: <list or integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [disable, enable, strict]>
          #   status: <value in [disable, deep-inspection]>
          #   unsupported_ssl_cipher: <value in [allow, block]>
          #   unsupported_ssl_negotiation: <value in [allow, block]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   client_cert_request: <value in [bypass, inspect, block]>
          #   invalid_server_cert: <value in [allow, block]>
          #   unsupported_ssl: <value in [bypass, inspect, block]>
          #   untrusted_cert: <value in [allow, block, ignore]>
          #   allow_invalid_server_cert: <value in [disable, enable]>
          # rpc_over_https: <value in [disable, enable]>
          # server_cert: <list or string>
          # server_cert_mode: <value in [re-sign, replace]>
          # smtps:
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   ports: <list or integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [disable, enable, strict]>
          #   status: <value in [disable, deep-inspection]>
          #   unsupported_ssl_cipher: <value in [allow, block]>
          #   unsupported_ssl_negotiation: <value in [allow, block]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   client_cert_request: <value in [bypass, inspect, block]>
          #   invalid_server_cert: <value in [allow, block]>
          #   unsupported_ssl: <value in [bypass, inspect, block]>
          #   untrusted_cert: <value in [allow, block, ignore]>
          #   allow_invalid_server_cert: <value in [disable, enable]>
          # ssh:
          #   ports: <list or integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   ssh_algorithm: <value in [compatible, high-encryption]>
          #   ssh_tun_policy_check: <value in [disable, enable]>
          #   status: <value in [disable, deep-inspection]>
          #   unsupported_version: <value in [block, bypass]>
          #   inspect_all: <value in [disable, deep-inspection]>
          # ssl:
          #   cert_probe_failure: <value in [block, allow]>
          #   cert_validation_failure: <value in [allow, block, ignore]>
          #   cert_validation_timeout: <value in [allow, block, ignore]>
          #   client_certificate: <value in [bypass, inspect, block, ...]>
          #   encrypted_client_hello: <value in [block, allow]>
          #   expired_server_cert: <value in [allow, block, ignore]>
          #   inspect_all: <value in [disable, certificate-inspection, deep-inspection]>
          #   min_allowed_ssl_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #   revoked_server_cert: <value in [allow, block, ignore]>
          #   sni_server_cert_check: <value in [disable, enable, strict]>
          #   unsupported_ssl_cipher: <value in [allow, block]>
          #   unsupported_ssl_negotiation: <value in [allow, block]>
          #   unsupported_ssl_version: <value in [block, allow, inspect]>
          #   untrusted_server_cert: <value in [allow, block, ignore]>
          #   client_cert_request: <value in [bypass, inspect, block]>
          #   invalid_server_cert: <value in [allow, block]>
          #   unsupported_ssl: <value in [bypass, inspect, block]>
          #   untrusted_cert: <value in [allow, block, ignore]>
          #   allow_invalid_server_cert: <value in [disable, enable]>
          # ssl_anomaly_log: <value in [disable, enable]>
          # ssl_client_certificate:
          #   caname: <list or string>
          #   cert: <list or string>
          #   keyring_list: <list or string>
          #   status: <value in [do-not-offer, keyring-list, ca-sign, ...]>
          # ssl_exempt:
          #   - address: <list or string>
          #     address6: <list or string>
          #     finger_print_category: <value in [unknown, firefox, chrome, ...]>
          #     fortiguard_category: <list or string>
          #     id: <integer>
          #     regex: <string>
          #     type: <value in [fortiguard-category, address, address6, ...]>
          #     wildcard_fqdn: <list or string>
          # ssl_exemption_ip_rating: <value in [disable, enable]>
          # ssl_exemption_log: <value in [disable, enable]>
          # ssl_handshake_log: <value in [disable, enable]>
          # ssl_negotiation_log: <value in [disable, enable]>
          # ssl_server:
          #   - ftps_client_certificate: <value in [bypass, inspect, block]>
          #     https_client_certificate: <value in [bypass, inspect, block]>
          #     id: <integer>
          #     imaps_client_certificate: <value in [bypass, inspect, block]>
          #     ip: <string>
          #     pop3s_client_certificate: <value in [bypass, inspect, block]>
          #     smtps_client_certificate: <value in [bypass, inspect, block]>
          #     ssl_other_client_certificate: <value in [bypass, inspect, block]>
          #     smtps_client_cert_request: <value in [bypass, inspect, block]>
          #     imaps_client_cert_request: <value in [bypass, inspect, block]>
          #     ssl_other_client_cert_request: <value in [bypass, inspect, block]>
          #     ftps_client_cert_request: <value in [bypass, inspect, block]>
          #     https_client_cert_request: <value in [bypass, inspect, block]>
          #     pop3s_client_cert_request: <value in [bypass, inspect, block]>
          # ssl_server_cert_log: <value in [disable, enable]>
          # supported_alpn: <value in [none, http1-1, http2, ...]>
          # untrusted_caname: <list or string>
          # use_ssl_server: <value in [disable, enable]>
          # ssl_exemptions_log: <value in [disable, enable]>
          # ssl_anomalies_log: <value in [disable, enable]>
          # whitelist: <value in [disable, enable]>
          # block_blacklisted_certificates: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-ssh-profile'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_sslsshprofile': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'allowlist': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'block-blocklisted-certificates': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'caname': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dot': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quic': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'block', 'inspect'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['enable', 'strict', 'disable'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'udp-not-quic': {'v_range': [['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'}
                    }
                },
                'ech-outer-sni': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'sni': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ftps': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'untrusted-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'allow-invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'https': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-probe-failure': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'encrypted-client-hello': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'quic': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'block', 'inspect'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'certificate-inspection', 'deep-inspection'],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'untrusted-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'allow-invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'udp-not-quic': {'v_range': [['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'}
                    }
                },
                'imaps': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'untrusted-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'allow-invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'mapi-over-https': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'pop3s': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'untrusted-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'allow-invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'rpc-over-https': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'server-cert-mode': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['re-sign', 'replace'], 'type': 'str'},
                'smtps': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'untrusted-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'allow-invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ssh': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssh-algorithm': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['compatible', 'high-encryption'], 'type': 'str'},
                        'ssh-tun-policy-check': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'},
                        'unsupported-version': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'bypass'], 'type': 'str'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'deep-inspection'], 'type': 'str'}
                    }
                },
                'ssl': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'cert-probe-failure': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'cert-validation-failure': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'cert-validation-timeout': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['allow', 'block', 'ignore'],
                            'type': 'str'
                        },
                        'client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block', 'bypass-on-cert-req'],
                            'type': 'str'
                        },
                        'encrypted-client-hello': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'},
                        'expired-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'inspect-all': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'certificate-inspection', 'deep-inspection'],
                            'type': 'str'
                        },
                        'min-allowed-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'revoked-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'sni-server-cert-check': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'unsupported-ssl-cipher': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-negotiation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'allow', 'inspect'],
                            'type': 'str'
                        },
                        'untrusted-server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block'], 'type': 'str'},
                        'unsupported-ssl': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'untrusted-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['allow', 'block', 'ignore'], 'type': 'str'},
                        'allow-invalid-server-cert': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ssl-anomaly-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-certificate': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'caname': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'keyring-list': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'status': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['do-not-offer', 'keyring-list', 'ca-sign', 'static'],
                            'type': 'str'
                        }
                    }
                },
                'ssl-exempt': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'address': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'address6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'finger-print-category': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['unknown', 'firefox', 'chrome', 'safari', 'edge', 'ie', 'android', 'ios', 'windows'],
                            'type': 'str'
                        },
                        'fortiguard-category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'regex': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['fortiguard-category', 'address', 'address6', 'wildcard-fqdn', 'regex', 'finger-print'],
                            'type': 'str'
                        },
                        'wildcard-fqdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'ssl-exemption-ip-rating': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-exemption-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-handshake-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-negotiation-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'ftps-client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'https-client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'imaps-client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'pop3s-client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'smtps-client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'ssl-other-client-certificate': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['bypass', 'inspect', 'block'],
                            'type': 'str'
                        },
                        'smtps-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'imaps-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'ssl-other-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'ftps-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'https-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'},
                        'pop3s-client-cert-request': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['bypass', 'inspect', 'block'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ssl-server-cert-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'supported-alpn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['none', 'http1-1', 'http2', 'all'], 'type': 'str'},
                'untrusted-caname': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'use-ssl-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-exemptions-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-anomalies-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'whitelist': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'block-blacklisted-certificates': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_sslsshprofile'),
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
