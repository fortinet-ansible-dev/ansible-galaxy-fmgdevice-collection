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
module: fmgd_firewall_profileprotocoloptions
short_description: Configure protocol options.
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
    firewall_profileprotocoloptions:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cifs:
                type: dict
                description: Cifs.
                suboptions:
                    domain_controller:
                        aliases: ['domain-controller']
                        type: list
                        elements: str
                        description: Domain for which to decrypt CIFS traffic.
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    server_credential_type:
                        aliases: ['server-credential-type']
                        type: str
                        description: CIFS server credential type.
                        choices:
                            - 'none'
                            - 'credential-replication'
                            - 'credential-keytab'
                    server_keytab:
                        aliases: ['server-keytab']
                        type: list
                        elements: dict
                        description: Server keytab.
                        suboptions:
                            keytab:
                                type: str
                                description: Base64 encoded keytab file containing credential of the server.
                            password:
                                type: list
                                elements: str
                                description: Password for keytab.
                            principal:
                                type: str
                                description: Service principal.
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_window_maximum:
                        aliases: ['tcp-window-maximum']
                        type: int
                        description: Maximum dynamic TCP window size.
                    tcp_window_minimum:
                        aliases: ['tcp-window-minimum']
                        type: int
                        description: Minimum dynamic TCP window size.
                    tcp_window_size:
                        aliases: ['tcp-window-size']
                        type: int
                        description: Set TCP static window size.
                    tcp_window_type:
                        aliases: ['tcp-window-type']
                        type: str
                        description: TCP window type to use for this protocol.
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    file_filter:
                        aliases: ['file-filter']
                        type: dict
                        description: File filter.
                        suboptions:
                            entries:
                                type: list
                                elements: dict
                                description: Entries.
                                suboptions:
                                    action:
                                        type: str
                                        description: Action.
                                        choices:
                                            - 'log'
                                            - 'block'
                                    comment:
                                        type: str
                                        description: Comment.
                                    direction:
                                        type: str
                                        description: Direction.
                                        choices:
                                            - 'any'
                                            - 'incoming'
                                            - 'outgoing'
                                    file_type:
                                        aliases: ['file-type']
                                        type: list
                                        elements: str
                                        description: File type.
                                    filter:
                                        type: str
                                        description: Filter.
                                    protocol:
                                        type: list
                                        elements: str
                                        description: Protocol.
                                        choices:
                                            - 'cifs'
                            log:
                                type: str
                                description: Log.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            status:
                                type: str
                                description: Status.
                                choices:
                                    - 'disable'
                                    - 'enable'
            comment:
                type: str
                description: Optional comments.
            dns:
                type: dict
                description: Dns.
                suboptions:
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            ftp:
                type: dict
                description: Ftp.
                suboptions:
                    comfort_amount:
                        aliases: ['comfort-amount']
                        type: int
                        description: Number of bytes to send in each transmission for client comforting
                    comfort_interval:
                        aliases: ['comfort-interval']
                        type: int
                        description: Interval between successive transmissions of data for client comforting
                    explicit_ftp_tls:
                        aliases: ['explicit-ftp-tls']
                        type: str
                        description: Enable/disable FTP redirection for explicit FTPS.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'clientcomfort'
                            - 'oversize'
                            - 'splice'
                            - 'bypass-rest-command'
                            - 'bypass-mode-command'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_offloaded:
                        aliases: ['ssl-offloaded']
                        type: str
                        description: SSL decryption and encryption performed by an external device.
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    stream_based_uncompressed_limit:
                        aliases: ['stream-based-uncompressed-limit']
                        type: int
                        description: Maximum stream-based uncompressed data size that will be scanned in megabytes.
                    tcp_window_maximum:
                        aliases: ['tcp-window-maximum']
                        type: int
                        description: Maximum dynamic TCP window size.
                    tcp_window_minimum:
                        aliases: ['tcp-window-minimum']
                        type: int
                        description: Minimum dynamic TCP window size.
                    tcp_window_size:
                        aliases: ['tcp-window-size']
                        type: int
                        description: Set TCP static window size.
                    tcp_window_type:
                        aliases: ['tcp-window-type']
                        type: str
                        description: TCP window type to use for this protocol.
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Enable/disable the inspection of all ports for the protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            http:
                type: dict
                description: Http.
                suboptions:
                    address_ip_rating:
                        aliases: ['address-ip-rating']
                        type: str
                        description: Enable/disable IP based URL rating.
                        choices:
                            - 'disable'
                            - 'enable'
                    block_page_status_code:
                        aliases: ['block-page-status-code']
                        type: int
                        description: Code number returned for blocked HTTP pages
                    comfort_amount:
                        aliases: ['comfort-amount']
                        type: int
                        description: Number of bytes to send in each transmission for client comforting
                    comfort_interval:
                        aliases: ['comfort-interval']
                        type: int
                        description: Interval between successive transmissions of data for client comforting
                    dns_protection:
                        aliases: ['dns-protection']
                        type: str
                        description: Enable/disable DNS protection for HTTP/HTTPS traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    domain_fronting:
                        aliases: ['domain-fronting']
                        type: str
                        description: Domain fronting.
                        choices:
                            - 'monitor'
                            - 'block'
                            - 'allow'
                            - 'disable'
                            - 'enable'
                            - 'strict'
                    encrypted_file:
                        aliases: ['encrypted-file']
                        type: str
                        description: Encrypted file.
                        choices:
                            - 'block'
                            - 'pass'
                            - 'inspect'
                    encrypted_file_log:
                        aliases: ['encrypted-file-log']
                        type: str
                        description: Encrypted file log.
                        choices:
                            - 'disable'
                            - 'enable'
                    h2c:
                        type: str
                        description: Enable/disable h2c HTTP connection upgrade.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                            - 'chunkedbypass'
                            - 'clientcomfort'
                            - 'servercomfort'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    post_lang:
                        aliases: ['post-lang']
                        type: list
                        elements: str
                        description: ID codes for character sets to be used to convert to UTF-8 for banned words and DLP on HTTP posts
                        choices:
                            - 'jisx0201'
                            - 'jisx0208'
                            - 'jisx0212'
                            - 'gb2312'
                            - 'ksc5601-ex'
                            - 'euc-jp'
                            - 'sjis'
                            - 'iso2022-jp'
                            - 'iso2022-jp-1'
                            - 'iso2022-jp-2'
                            - 'euc-cn'
                            - 'ces-gbk'
                            - 'hz'
                            - 'ces-big5'
                            - 'euc-kr'
                            - 'iso2022-jp-3'
                            - 'iso8859-1'
                            - 'tis620'
                            - 'cp874'
                            - 'cp1252'
                            - 'cp1251'
                    range_block:
                        aliases: ['range-block']
                        type: str
                        description: Enable/disable blocking of partial downloads.
                        choices:
                            - 'disable'
                            - 'enable'
                    retry_count:
                        aliases: ['retry-count']
                        type: int
                        description: Number of attempts to retry HTTP connection
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_offloaded:
                        aliases: ['ssl-offloaded']
                        type: str
                        description: SSL decryption and encryption performed by an external device.
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    stream_based_uncompressed_limit:
                        aliases: ['stream-based-uncompressed-limit']
                        type: int
                        description: Maximum stream-based uncompressed data size that will be scanned in megabytes.
                    streaming_content_bypass:
                        aliases: ['streaming-content-bypass']
                        type: str
                        description: Enable/disable bypassing of streaming content from buffering.
                        choices:
                            - 'disable'
                            - 'enable'
                    strip_x_forwarded_for:
                        aliases: ['strip-x-forwarded-for']
                        type: str
                        description: Enable/disable stripping of HTTP X-Forwarded-For header.
                        choices:
                            - 'disable'
                            - 'enable'
                    switching_protocols:
                        aliases: ['switching-protocols']
                        type: str
                        description: Bypass from scanning, or block a connection that attempts to switch protocol.
                        choices:
                            - 'bypass'
                            - 'block'
                    tcp_window_maximum:
                        aliases: ['tcp-window-maximum']
                        type: int
                        description: Maximum dynamic TCP window size.
                    tcp_window_minimum:
                        aliases: ['tcp-window-minimum']
                        type: int
                        description: Minimum dynamic TCP window size.
                    tcp_window_size:
                        aliases: ['tcp-window-size']
                        type: int
                        description: Set TCP static window size.
                    tcp_window_type:
                        aliases: ['tcp-window-type']
                        type: str
                        description: TCP window type to use for this protocol.
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
                    tunnel_non_http:
                        aliases: ['tunnel-non-http']
                        type: str
                        description: Configure how to process non-HTTP traffic when a profile configured for HTTP traffic accepts a non-HTTP session.
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    unknown_content_encoding:
                        aliases: ['unknown-content-encoding']
                        type: str
                        description: Configure the action the FortiGate unit will take on unknown content-encoding.
                        choices:
                            - 'block'
                            - 'inspect'
                            - 'bypass'
                    unknown_http_version:
                        aliases: ['unknown-http-version']
                        type: str
                        description: How to handle HTTP sessions that do not comply with HTTP 0.
                        choices:
                            - 'best-effort'
                            - 'reject'
                            - 'tunnel'
                    verify_dns_for_policy_matching:
                        aliases: ['verify-dns-for-policy-matching']
                        type: str
                        description: Enable/disable verification of DNS for policy matching.
                        choices:
                            - 'disable'
                            - 'enable'
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Enable/disable the inspection of all ports for the protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortinet_bar:
                        aliases: ['fortinet-bar']
                        type: str
                        description: Enable/disable Fortinet bar on HTML content.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortinet_bar_port:
                        aliases: ['fortinet-bar-port']
                        type: int
                        description: Port for use by Fortinet Bar
                    http_0_9:
                        aliases: ['http-0.9']
                        type: str
                        description: Configure action to take upon receipt of HTTP 0.
                        choices:
                            - 'block'
                            - 'allow'
            imap:
                type: dict
                description: Imap.
                suboptions:
                    address_ip_rating:
                        aliases: ['address-ip-rating']
                        type: str
                        description: Address ip rating.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                            - 'fragmail'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_offloaded:
                        aliases: ['ssl-offloaded']
                        type: str
                        description: SSL decryption and encryption performed by an external device.
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Enable/disable the inspection of all ports for the protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            mail_signature:
                aliases: ['mail-signature']
                type: dict
                description: Mail signature.
                suboptions:
                    signature:
                        type: str
                        description: Email signature to be added to outgoing email
                    status:
                        type: str
                        description: Enable/disable adding an email signature to SMTP email messages as they pass through the FortiGate.
                        choices:
                            - 'disable'
                            - 'enable'
            mapi:
                type: dict
                description: Mapi.
                suboptions:
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'fragmail'
                            - 'oversize'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
            name:
                type: str
                description: Name.
                required: true
            nntp:
                type: dict
                description: Nntp.
                suboptions:
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                            - 'splice'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Enable/disable the inspection of all ports for the protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            oversize_log:
                aliases: ['oversize-log']
                type: str
                description: Enable/disable logging for antivirus oversize file blocking.
                choices:
                    - 'disable'
                    - 'enable'
            pop3:
                type: dict
                description: Pop3.
                suboptions:
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                            - 'fragmail'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_offloaded:
                        aliases: ['ssl-offloaded']
                        type: str
                        description: SSL decryption and encryption performed by an external device.
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Enable/disable the inspection of all ports for the protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            proxy_redirect:
                aliases: ['proxy-redirect']
                type: dict
                description: Proxy redirect.
                suboptions:
                    ports:
                        type: list
                        elements: int
                        description: Ports.
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: list
                elements: str
                description: Name of the replacement message group to be used.
            rpc_over_http:
                aliases: ['rpc-over-http']
                type: str
                description: Enable/disable inspection of RPC over HTTP.
                choices:
                    - 'disable'
                    - 'enable'
            smtp:
                type: dict
                description: Smtp.
                suboptions:
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                            - 'fragmail'
                            - 'splice'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    server_busy:
                        aliases: ['server-busy']
                        type: str
                        description: Enable/disable SMTP server busy when server not available.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_offloaded:
                        aliases: ['ssl-offloaded']
                        type: str
                        description: SSL decryption and encryption performed by an external device.
                        choices:
                            - 'no'
                            - 'yes'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    proxy_after_tcp_handshake:
                        aliases: ['proxy-after-tcp-handshake']
                        type: str
                        description: Proxy traffic after the TCP 3-way handshake has been established
                        choices:
                            - 'disable'
                            - 'enable'
                    inspect_all:
                        aliases: ['inspect-all']
                        type: str
                        description: Enable/disable the inspection of all ports for the protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            ssh:
                type: dict
                description: Ssh.
                suboptions:
                    comfort_amount:
                        aliases: ['comfort-amount']
                        type: int
                        description: Number of bytes to send in each transmission for client comforting
                    comfort_interval:
                        aliases: ['comfort-interval']
                        type: int
                        description: Interval between successive transmissions of data for client comforting
                    options:
                        type: list
                        elements: str
                        description: One or more options that can be applied to the session.
                        choices:
                            - 'oversize'
                            - 'clientcomfort'
                            - 'servercomfort'
                    oversize_limit:
                        aliases: ['oversize-limit']
                        type: int
                        description: Maximum in-memory file size that can be scanned
                    scan_bzip2:
                        aliases: ['scan-bzip2']
                        type: str
                        description: Enable/disable scanning of BZip2 compressed files.
                        choices:
                            - 'disable'
                            - 'enable'
                    ssl_offloaded:
                        aliases: ['ssl-offloaded']
                        type: str
                        description: SSL decryption and encryption performed by an external device.
                        choices:
                            - 'no'
                            - 'yes'
                    stream_based_uncompressed_limit:
                        aliases: ['stream-based-uncompressed-limit']
                        type: int
                        description: Maximum stream-based uncompressed data size that will be scanned in megabytes.
                    tcp_window_maximum:
                        aliases: ['tcp-window-maximum']
                        type: int
                        description: Maximum dynamic TCP window size.
                    tcp_window_minimum:
                        aliases: ['tcp-window-minimum']
                        type: int
                        description: Minimum dynamic TCP window size.
                    tcp_window_size:
                        aliases: ['tcp-window-size']
                        type: int
                        description: Set TCP static window size.
                    tcp_window_type:
                        aliases: ['tcp-window-type']
                        type: str
                        description: TCP window type to use for this protocol.
                        choices:
                            - 'system'
                            - 'static'
                            - 'dynamic'
                            - 'auto-tuning'
                    uncompressed_nest_limit:
                        aliases: ['uncompressed-nest-limit']
                        type: int
                        description: Maximum nested levels of compression that can be uncompressed and scanned
                    uncompressed_oversize_limit:
                        aliases: ['uncompressed-oversize-limit']
                        type: int
                        description: Maximum in-memory uncompressed file size that can be scanned
                    explicit_ftp_tls:
                        aliases: ['explicit-ftp-tls']
                        type: str
                        description: Explicit ftp tls.
                        choices:
                            - 'disable'
                            - 'enable'
            switching_protocols_log:
                aliases: ['switching-protocols-log']
                type: str
                description: Enable/disable logging for HTTP/HTTPS switching protocols.
                choices:
                    - 'disable'
                    - 'enable'
            feature_set:
                aliases: ['feature-set']
                type: str
                description: Feature set.
                choices:
                    - 'proxy'
                    - 'flow'
            rtmp:
                type: dict
                description: Rtmp.
                suboptions:
                    http_tunnel:
                        aliases: ['http-tunnel']
                        type: str
                        description: Enable/disable RTMP http tunnel.
                        choices:
                            - 'disable'
                            - 'enable'
                    ports:
                        type: list
                        elements: int
                        description: Ports to scan for content
                    rtmpt:
                        type: str
                        description: Enable/disable RTMPT.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable the active status of scanning for this protocol.
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
    - name: Configure protocol options.
      fortinet.fmgdevice.fmgd_firewall_profileprotocoloptions:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_profileprotocoloptions:
          name: "your value" # Required variable, string
          # cifs:
          #   domain_controller: <list or string>
          #   options:
          #     - "oversize"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   server_credential_type: <value in [none, credential-replication, credential-keytab]>
          #   server_keytab:
          #     - keytab: <string>
          #       password: <list or string>
          #       principal: <string>
          #   status: <value in [disable, enable]>
          #   tcp_window_maximum: <integer>
          #   tcp_window_minimum: <integer>
          #   tcp_window_size: <integer>
          #   tcp_window_type: <value in [system, static, dynamic, ...]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   file_filter:
          #     entries:
          #       - action: <value in [log, block]>
          #         comment: <string>
          #         direction: <value in [any, incoming, outgoing]>
          #         file_type: <list or string>
          #         filter: <string>
          #         protocol:
          #           - "cifs"
          #     log: <value in [disable, enable]>
          #     status: <value in [disable, enable]>
          # comment: <string>
          # dns:
          #   ports: <list or integer>
          #   status: <value in [disable, enable]>
          # ftp:
          #   comfort_amount: <integer>
          #   comfort_interval: <integer>
          #   explicit_ftp_tls: <value in [disable, enable]>
          #   options:
          #     - "clientcomfort"
          #     - "oversize"
          #     - "splice"
          #     - "bypass-rest-command"
          #     - "bypass-mode-command"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   ssl_offloaded: <value in [no, yes]>
          #   status: <value in [disable, enable]>
          #   stream_based_uncompressed_limit: <integer>
          #   tcp_window_maximum: <integer>
          #   tcp_window_minimum: <integer>
          #   tcp_window_size: <integer>
          #   tcp_window_type: <value in [system, static, dynamic, ...]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   inspect_all: <value in [disable, enable]>
          # http:
          #   address_ip_rating: <value in [disable, enable]>
          #   block_page_status_code: <integer>
          #   comfort_amount: <integer>
          #   comfort_interval: <integer>
          #   dns_protection: <value in [disable, enable]>
          #   domain_fronting: <value in [monitor, block, allow, ...]>
          #   encrypted_file: <value in [block, pass, inspect]>
          #   encrypted_file_log: <value in [disable, enable]>
          #   h2c: <value in [disable, enable]>
          #   options:
          #     - "oversize"
          #     - "chunkedbypass"
          #     - "clientcomfort"
          #     - "servercomfort"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   post_lang:
          #     - "jisx0201"
          #     - "jisx0208"
          #     - "jisx0212"
          #     - "gb2312"
          #     - "ksc5601-ex"
          #     - "euc-jp"
          #     - "sjis"
          #     - "iso2022-jp"
          #     - "iso2022-jp-1"
          #     - "iso2022-jp-2"
          #     - "euc-cn"
          #     - "ces-gbk"
          #     - "hz"
          #     - "ces-big5"
          #     - "euc-kr"
          #     - "iso2022-jp-3"
          #     - "iso8859-1"
          #     - "tis620"
          #     - "cp874"
          #     - "cp1252"
          #     - "cp1251"
          #   range_block: <value in [disable, enable]>
          #   retry_count: <integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   ssl_offloaded: <value in [no, yes]>
          #   status: <value in [disable, enable]>
          #   stream_based_uncompressed_limit: <integer>
          #   streaming_content_bypass: <value in [disable, enable]>
          #   strip_x_forwarded_for: <value in [disable, enable]>
          #   switching_protocols: <value in [bypass, block]>
          #   tcp_window_maximum: <integer>
          #   tcp_window_minimum: <integer>
          #   tcp_window_size: <integer>
          #   tcp_window_type: <value in [system, static, dynamic, ...]>
          #   tunnel_non_http: <value in [disable, enable]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   unknown_content_encoding: <value in [block, inspect, bypass]>
          #   unknown_http_version: <value in [best-effort, reject, tunnel]>
          #   verify_dns_for_policy_matching: <value in [disable, enable]>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   inspect_all: <value in [disable, enable]>
          #   fortinet_bar: <value in [disable, enable]>
          #   fortinet_bar_port: <integer>
          #   http_0_9: <value in [block, allow]>
          # imap:
          #   address_ip_rating: <value in [disable, enable]>
          #   options:
          #     - "oversize"
          #     - "fragmail"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   ssl_offloaded: <value in [no, yes]>
          #   status: <value in [disable, enable]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   inspect_all: <value in [disable, enable]>
          # mail_signature:
          #   signature: <string>
          #   status: <value in [disable, enable]>
          # mapi:
          #   options:
          #     - "fragmail"
          #     - "oversize"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          # nntp:
          #   options:
          #     - "oversize"
          #     - "splice"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   inspect_all: <value in [disable, enable]>
          # oversize_log: <value in [disable, enable]>
          # pop3:
          #   options:
          #     - "oversize"
          #     - "fragmail"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   ssl_offloaded: <value in [no, yes]>
          #   status: <value in [disable, enable]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   inspect_all: <value in [disable, enable]>
          # proxy_redirect:
          #   ports: <list or integer>
          #   status: <value in [disable, enable]>
          # replacemsg_group: <list or string>
          # rpc_over_http: <value in [disable, enable]>
          # smtp:
          #   options:
          #     - "oversize"
          #     - "fragmail"
          #     - "splice"
          #   oversize_limit: <integer>
          #   ports: <list or integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   server_busy: <value in [disable, enable]>
          #   ssl_offloaded: <value in [no, yes]>
          #   status: <value in [disable, enable]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   proxy_after_tcp_handshake: <value in [disable, enable]>
          #   inspect_all: <value in [disable, enable]>
          # ssh:
          #   comfort_amount: <integer>
          #   comfort_interval: <integer>
          #   options:
          #     - "oversize"
          #     - "clientcomfort"
          #     - "servercomfort"
          #   oversize_limit: <integer>
          #   scan_bzip2: <value in [disable, enable]>
          #   ssl_offloaded: <value in [no, yes]>
          #   stream_based_uncompressed_limit: <integer>
          #   tcp_window_maximum: <integer>
          #   tcp_window_minimum: <integer>
          #   tcp_window_size: <integer>
          #   tcp_window_type: <value in [system, static, dynamic, ...]>
          #   uncompressed_nest_limit: <integer>
          #   uncompressed_oversize_limit: <integer>
          #   explicit_ftp_tls: <value in [disable, enable]>
          # switching_protocols_log: <value in [disable, enable]>
          # feature_set: <value in [proxy, flow]>
          # rtmp:
          #   http_tunnel: <value in [disable, enable]>
          #   ports: <list or integer>
          #   rtmpt: <value in [disable, enable]>
          #   status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/profile-protocol-options'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_profileprotocoloptions': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'cifs': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'domain-controller': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'options': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'choices': ['oversize'], 'elements': 'str'},
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'server-credential-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['none', 'credential-replication', 'credential-keytab'],
                            'type': 'str'
                        },
                        'server-keytab': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'keytab': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                                'password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'principal': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-window-maximum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-minimum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['system', 'static', 'dynamic', 'auto-tuning'],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'file-filter': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'dict',
                            'options': {
                                'entries': {
                                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                                    'type': 'list',
                                    'options': {
                                        'action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['log', 'block'], 'type': 'str'},
                                        'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                        'direction': {
                                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                                            'choices': ['any', 'incoming', 'outgoing'],
                                            'type': 'str'
                                        },
                                        'file-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                                        'filter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                        'protocol': {
                                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                                            'type': 'list',
                                            'choices': ['cifs'],
                                            'elements': 'str'
                                        }
                                    },
                                    'elements': 'dict'
                                },
                                'log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            }
                        }
                    }
                },
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'dns': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ftp': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'comfort-amount': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'comfort-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'explicit-ftp-tls': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['clientcomfort', 'oversize', 'splice', 'bypass-rest-command', 'bypass-mode-command'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-offloaded': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stream-based-uncompressed-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-maximum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-minimum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['system', 'static', 'dynamic', 'auto-tuning'],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'http': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'address-ip-rating': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'block-page-status-code': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'comfort-amount': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'comfort-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'dns-protection': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'domain-fronting': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['monitor', 'block', 'allow', 'disable', 'enable', 'strict'],
                            'type': 'str'
                        },
                        'encrypted-file': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'pass', 'inspect'], 'type': 'str'},
                        'encrypted-file-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h2c': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['oversize', 'chunkedbypass', 'clientcomfort', 'servercomfort'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'post-lang': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'jisx0201', 'jisx0208', 'jisx0212', 'gb2312', 'ksc5601-ex', 'euc-jp', 'sjis', 'iso2022-jp', 'iso2022-jp-1',
                                'iso2022-jp-2', 'euc-cn', 'ces-gbk', 'hz', 'ces-big5', 'euc-kr', 'iso2022-jp-3', 'iso8859-1', 'tis620', 'cp874',
                                'cp1252', 'cp1251'
                            ],
                            'elements': 'str'
                        },
                        'range-block': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'retry-count': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-offloaded': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stream-based-uncompressed-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'streaming-content-bypass': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'strip-x-forwarded-for': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'switching-protocols': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['bypass', 'block'], 'type': 'str'},
                        'tcp-window-maximum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-minimum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['system', 'static', 'dynamic', 'auto-tuning'],
                            'type': 'str'
                        },
                        'tunnel-non-http': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'unknown-content-encoding': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['block', 'inspect', 'bypass'],
                            'type': 'str'
                        },
                        'unknown-http-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['best-effort', 'reject', 'tunnel'],
                            'type': 'str'
                        },
                        'verify-dns-for-policy-matching': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortinet-bar': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortinet-bar-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'http-0.9': {'v_range': [['7.6.4', '']], 'choices': ['block', 'allow'], 'type': 'str'}
                    }
                },
                'imap': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'address-ip-rating': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['oversize', 'fragmail'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-offloaded': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'mail-signature': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'signature': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'mapi': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['fragmail', 'oversize'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'}
                    }
                },
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'nntp': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'options': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'choices': ['oversize', 'splice'], 'elements': 'str'},
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'oversize-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pop3': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['oversize', 'fragmail'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-offloaded': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'proxy-redirect': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'replacemsg-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'rpc-over-http': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'smtp': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['oversize', 'fragmail', 'splice'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ports': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'server-busy': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-offloaded': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'proxy-after-tcp-handshake': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'inspect-all': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ssh': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'comfort-amount': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'comfort-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'options': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['oversize', 'clientcomfort', 'servercomfort'],
                            'elements': 'str'
                        },
                        'oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'scan-bzip2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-offloaded': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                        'stream-based-uncompressed-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-maximum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-minimum': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-size': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tcp-window-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['system', 'static', 'dynamic', 'auto-tuning'],
                            'type': 'str'
                        },
                        'uncompressed-nest-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'uncompressed-oversize-limit': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'explicit-ftp-tls': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'switching-protocols-log': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'feature-set': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'rtmp': {
                    'v_range': [['7.4.8', '7.4.10']],
                    'type': 'dict',
                    'options': {
                        'http-tunnel': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ports': {'v_range': [['7.4.8', '7.4.10']], 'type': 'list', 'elements': 'int'},
                        'rtmpt': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profileprotocoloptions'),
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
