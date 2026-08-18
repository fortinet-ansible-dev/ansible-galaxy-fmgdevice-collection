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
module: fmgd_firewall_vip6
short_description: Configure virtual IP for IPv6.
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
  firewall_vip6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      add_nat64_route:
        aliases: ['add-nat64-route']
        type: str
        description: Enable/disable adding NAT64 route.
        choices: ['disable', 'enable']
      color:
        type: int
        description: Color of icon on the GUI.
      comment:
        type: str
        description: Comment.
      dynamic_mapping:
        type: list
        elements: dict
        description: Dynamic mapping.
        suboptions:
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
          add_nat64_route:
            aliases: ['add-nat64-route']
            type: str
            description: Enable/disable adding NAT64 route.
            choices: ['disable', 'enable']
          arp_reply:
            aliases: ['arp-reply']
            type: str
            description: Enable to respond to ARP requests for this virtual IP address.
            choices: ['disable', 'enable']
          color:
            type: int
            description: Color of icon on the GUI.
          comment:
            type: str
            description: Comment.
          embedded_ipv4_address:
            aliases: ['embedded-ipv4-address']
            type: str
            description: Enable/disable use of the lower 32 bits of the external IPv6 address as mapped IPv4 address.
            choices: ['disable', 'enable']
          extip:
            type: list
            elements: str
            description:
              - Support meta variable
              - IPv6 address or address range on the external interface that you want to map to an address or address range on the destination network.
          extport:
            type: str
            description:
              - Support meta variable
              - Incoming port number range that you want to map to a port number range on the destination network.
          h2_support:
            aliases: ['h2-support']
            type: str
            description: Enable/disable HTTP2 support
            choices: ['disable', 'enable']
          h3_support:
            aliases: ['h3-support']
            type: str
            description: Enable/disable HTTP3/QUIC support
            choices: ['disable', 'enable']
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
            choices: ['disable', 'enable']
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
            description: Control sharing of cookies across virtual servers.
            choices: ['disable', 'same-ip']
          http_ip_header:
            aliases: ['http-ip-header']
            type: str
            description: For HTTP multiplexing, enable to add the original client IP address in the XForwarded-For HTTP header.
            choices: ['disable', 'enable']
          http_ip_header_name:
            aliases: ['http-ip-header-name']
            type: str
            description:
              - Support meta variable
              - For HTTP multiplexing, enter a custom HTTPS header name.
          http_multiplex:
            aliases: ['http-multiplex']
            type: str
            description: Enable/disable HTTP multiplexing.
            choices: ['disable', 'enable']
          http_redirect:
            aliases: ['http-redirect']
            type: str
            description: Enable/disable redirection of HTTP to HTTPS.
            choices: ['disable', 'enable']
          https_cookie_secure:
            aliases: ['https-cookie-secure']
            type: str
            description: Enable/disable verification that inserted HTTPS cookies are secure.
            choices: ['disable', 'enable']
          id:
            type: int
            description: Custom defined ID.
          ipv4_mappedip:
            aliases: ['ipv4-mappedip']
            type: str
            description:
              - Support meta variable
              - Range of mapped IP addresses.
          ipv4_mappedport:
            aliases: ['ipv4-mappedport']
            type: str
            description:
              - Support meta variable
              - IPv4 port number range on the destination network to which the external port number range is mapped.
          ldb_method:
            aliases: ['ldb-method']
            type: str
            description: Method used to distribute sessions to real servers.
            choices: ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt',
                      'first-alive', 'http-host']
          mappedip:
            type: list
            elements: str
            description:
              - Support meta variable
              - Mapped IPv6 address range in the format startIP-endIP.
          mappedport:
            type: str
            description:
              - Support meta variable
              - Port number range on the destination network to which the external port number range is mapped.
          max_embryonic_connections:
            aliases: ['max-embryonic-connections']
            type: int
            description: Maximum number of incomplete connections.
          monitor:
            type: list
            elements: str
            description: Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
          nat_source_vip:
            aliases: ['nat-source-vip']
            type: str
            description: Enable to perform SNAT on traffic from mappedip to the extip for all egress interfaces.
            choices: ['disable', 'enable']
          nat64:
            type: str
            description: Enable/disable DNAT64.
            choices: ['disable', 'enable']
          nat66:
            type: str
            description: Enable/disable DNAT66.
            choices: ['disable', 'enable']
          ndp_reply:
            aliases: ['ndp-reply']
            type: str
            description: Enable/disable this FortiGate units ability to respond to NDP requests for this virtual IP address
            choices: ['disable', 'enable']
          outlook_web_access:
            aliases: ['outlook-web-access']
            type: str
            description: Enable to add the Front-End-Https header for Microsoft Outlook Web Access.
            choices: ['disable', 'enable']
          persistence:
            type: str
            description: Configure how to make sure that clients connect to the same server every time they make a request that is part of the same ses...
            choices: ['none', 'http-cookie', 'ssl-session-id']
          portforward:
            type: str
            description: Enable port forwarding.
            choices: ['disable', 'enable']
          protocol:
            type: str
            description: Protocol to use when forwarding packets.
            choices: ['tcp', 'udp', 'sctp']
          realservers:
            type: list
            elements: dict
            description: Realservers.
            suboptions:
              client_ip:
                aliases: ['client-ip']
                type: str
                description: Only clients in this IP range can connect to this real server.
              healthcheck:
                type: str
                description: Enable to check the responsiveness of the real server before forwarding traffic.
                choices: ['disable', 'enable', 'vip']
              holddown_interval:
                aliases: ['holddown-interval']
                type: int
                description: Time in seconds that the system waits before re-activating a previously down active server in the active-standby mode.
              http_host:
                aliases: ['http-host']
                type: str
                description: HTTP server domain name in HTTP header.
              id:
                type: int
                description: Real server ID.
              ip:
                type: str
                description: IP address of the real server.
              max_connections:
                aliases: ['max-connections']
                type: int
                description: Max number of active connections that can directed to the real server.
              monitor:
                type: list
                elements: str
                description: Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
              port:
                type: int
                description: Port for communicating with the real server.
              status:
                type: str
                description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
                choices: ['active', 'standby', 'disable']
              translate_host:
                aliases: ['translate-host']
                type: str
                description: Enable/disable translation of hostname/IP from virtual server to real server.
                choices: ['disable', 'enable']
              weight:
                type: int
                description: Weight of the real server.
              verify_cert:
                aliases: ['verify-cert']
                type: str
                description: Enable/disable certificate verification of the real server.
                choices: ['disable', 'enable']
          server_type:
            aliases: ['server-type']
            type: str
            description: Protocol to be load balanced by the virtual server
            choices: ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps']
          src_filter:
            aliases: ['src-filter']
            type: list
            elements: str
            description:
              - Support meta variable
              - Source IP6 filter
          src_vip_filter:
            aliases: ['src-vip-filter']
            type: str
            description: Enable/disable use of src-filter to match destinations for the reverse SNAT rule.
            choices: ['disable', 'enable']
          ssl_accept_ffdhe_groups:
            aliases: ['ssl-accept-ffdhe-groups']
            type: str
            description: Enable/disable FFDHE cipher suite for SSL key exchange.
            choices: ['disable', 'enable']
          ssl_algorithm:
            aliases: ['ssl-algorithm']
            type: str
            description: Permitted encryption algorithms for SSL sessions according to encryption strength.
            choices: ['high', 'low', 'medium', 'custom']
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
                choices: ['TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA',
                          'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                          'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                          'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256',
                          'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                          'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                          'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                          'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                          'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                          'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                          'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                          'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                          'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                          'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                          'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                          'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                          'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                          'TLS-DHE-RSA-WITH-SEED-CBC-SHA', 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                          'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                          'TLS-ECDHE-RSA-WITH-RC4-128-SHA', 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                          'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                          'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                          'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                          'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                          'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                          'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                          'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                          'TLS-DHE-DSS-WITH-AES-128-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                          'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                          'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                          'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                          'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                          'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                          'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                          'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                          'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                          'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                          'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                          'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                          'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                          'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                          'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                          'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                          'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                          'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                          'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                          'TLS-DHE-DSS-WITH-SEED-CBC-SHA', 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                          'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                          'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                          'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                          'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                          'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                          'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                          'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384',
                          'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA']
              priority:
                type: int
                description: SSL/TLS cipher suites priority.
              versions:
                type: list
                elements: str
                description: SSL/TLS versions that the cipher suite can be used with.
                choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
          ssl_client_fallback:
            aliases: ['ssl-client-fallback']
            type: str
            description: Enable/disable support for preventing Downgrade Attacks on client connections
            choices: ['disable', 'enable']
          ssl_client_rekey_count:
            aliases: ['ssl-client-rekey-count']
            type: int
            description: Maximum length of data in MB before triggering a client rekey
          ssl_client_renegotiation:
            aliases: ['ssl-client-renegotiation']
            type: str
            description: Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.
            choices: ['deny', 'allow', 'secure']
          ssl_client_session_state_max:
            aliases: ['ssl-client-session-state-max']
            type: int
            description: Maximum number of client to FortiGate SSL session states to keep.
          ssl_client_session_state_timeout:
            aliases: ['ssl-client-session-state-timeout']
            type: int
            description: Number of minutes to keep client to FortiGate SSL session state.
          ssl_client_session_state_type:
            aliases: ['ssl-client-session-state-type']
            type: str
            description: How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.
            choices: ['disable', 'time', 'count', 'both']
          ssl_dh_bits:
            aliases: ['ssl-dh-bits']
            type: str
            description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
            choices: ['768', '1024', '1536', '2048', '3072', '4096']
          ssl_hpkp:
            aliases: ['ssl-hpkp']
            type: str
            description: Enable/disable including HPKP header in response.
            choices: ['disable', 'enable', 'report-only']
          ssl_hpkp_age:
            aliases: ['ssl-hpkp-age']
            type: int
            description: Number of minutes the web browser should keep HPKP.
          ssl_hpkp_backup:
            aliases: ['ssl-hpkp-backup']
            type: list
            elements: str
            description: Certificate to generate backup HPKP pin from.
          ssl_hpkp_include_subdomains:
            aliases: ['ssl-hpkp-include-subdomains']
            type: str
            description: Indicate that HPKP header applies to all subdomains.
            choices: ['disable', 'enable']
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
            choices: ['disable', 'enable']
          ssl_hsts_age:
            aliases: ['ssl-hsts-age']
            type: int
            description: Number of seconds the client should honor the HSTS setting.
          ssl_hsts_include_subdomains:
            aliases: ['ssl-hsts-include-subdomains']
            type: str
            description: Indicate that HSTS header applies to all subdomains.
            choices: ['disable', 'enable']
          ssl_http_location_conversion:
            aliases: ['ssl-http-location-conversion']
            type: str
            description: Enable to replace HTTP with HTTPS in the replys Location HTTP header field.
            choices: ['disable', 'enable']
          ssl_http_match_host:
            aliases: ['ssl-http-match-host']
            type: str
            description: Enable/disable HTTP host matching for location conversion.
            choices: ['disable', 'enable']
          ssl_max_version:
            aliases: ['ssl-max-version']
            type: str
            description: Highest SSL/TLS version acceptable from a client.
            choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
          ssl_min_version:
            aliases: ['ssl-min-version']
            type: str
            description: Lowest SSL/TLS version acceptable from a client.
            choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
          ssl_mode:
            aliases: ['ssl-mode']
            type: str
            description: Apply SSL offloading between the client and the FortiGate
            choices: ['half', 'full']
          ssl_pfs:
            aliases: ['ssl-pfs']
            type: str
            description: Select the cipher suites that can be used for SSL perfect forward secrecy
            choices: ['require', 'deny', 'allow']
          ssl_send_empty_frags:
            aliases: ['ssl-send-empty-frags']
            type: str
            description: Enable/disable sending empty fragments to avoid CBC IV attacks
            choices: ['disable', 'enable']
          ssl_server_algorithm:
            aliases: ['ssl-server-algorithm']
            type: str
            description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
            choices: ['high', 'low', 'medium', 'custom', 'client']
          ssl_server_max_version:
            aliases: ['ssl-server-max-version']
            type: str
            description: Highest SSL/TLS version acceptable from a server.
            choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3']
          ssl_server_min_version:
            aliases: ['ssl-server-min-version']
            type: str
            description: Lowest SSL/TLS version acceptable from a server.
            choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3']
          ssl_server_renegotiation:
            aliases: ['ssl-server-renegotiation']
            type: str
            description: Enable/disable secure renegotiation to comply with RFC 5746.
            choices: ['disable', 'enable']
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
            choices: ['disable', 'time', 'count', 'both']
          type:
            type: str
            description: Configure a static NAT server load balance VIP or access proxy.
            choices: ['static-nat', 'server-load-balance', 'access-proxy']
          uuid:
            type: str
            description: Universally Unique Identifier
          weblogic_server:
            aliases: ['weblogic-server']
            type: str
            description: Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.
            choices: ['disable', 'enable']
          websphere_server:
            aliases: ['websphere-server']
            type: str
            description: Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.
            choices: ['disable', 'enable']
          client_cert:
            aliases: ['client-cert']
            type: str
            description: Enable/disable requesting client certificate.
            choices: ['disable', 'enable']
          empty_cert_action:
            aliases: ['empty-cert-action']
            type: str
            description: Action for an empty client certificate.
            choices: ['accept', 'block', 'accept-unmanageable']
          user_agent_detect:
            aliases: ['user-agent-detect']
            type: str
            description: Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
            choices: ['disable', 'enable']
          vip_id:
            aliases: ['vip-id']
            type: int
            description: Vip id.
          auth_virtual_host:
            aliases: ['auth-virtual-host']
            type: list
            elements: str
            description: Virtual host for authentication portal.
          ssl_http_strip_secure_cookies:
            aliases: ['ssl-http-strip-secure-cookies']
            type: str
            description: Enable/disable removal of HTTPS-only directives in the replys Set-Cookie HTTP header fields.
            choices: ['disable', 'enable']
          ssl_server_client_certificate:
            aliases: ['ssl-server-client-certificate']
            type: list
            elements: str
            description: Name of the client certificate presented to realserver during SSL/TLS handshake if requested.
          ssl_upstream:
            aliases: ['ssl-upstream']
            type: str
            description: Apply SSL encryption between the FortiGate and the upstream server
            choices: ['disable', 'enable']
      embedded_ipv4_address:
        aliases: ['embedded-ipv4-address']
        type: str
        description: Enable/disable use of the lower 32 bits of the external IPv6 address as mapped IPv4 address.
        choices: ['disable', 'enable']
      extip:
        type: list
        elements: str
        description:
          - Support meta variable
          - IPv6 address or address range on the external interface that you want to map to an address or address range on the destination network.
      extport:
        type: str
        description:
          - Support meta variable
          - Incoming port number range that you want to map to a port number range on the destination network.
      h2_support:
        aliases: ['h2-support']
        type: str
        description: Enable/disable HTTP2 support
        choices: ['disable', 'enable']
      h3_support:
        aliases: ['h3-support']
        type: str
        description: Enable/disable HTTP3/QUIC support
        choices: ['disable', 'enable']
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
        choices: ['disable', 'enable']
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
        description: Control sharing of cookies across virtual servers.
        choices: ['disable', 'same-ip']
      http_ip_header:
        aliases: ['http-ip-header']
        type: str
        description: For HTTP multiplexing, enable to add the original client IP address in the XForwarded-For HTTP header.
        choices: ['disable', 'enable']
      http_ip_header_name:
        aliases: ['http-ip-header-name']
        type: str
        description:
          - Support meta variable
          - For HTTP multiplexing, enter a custom HTTPS header name.
      http_multiplex:
        aliases: ['http-multiplex']
        type: str
        description: Enable/disable HTTP multiplexing.
        choices: ['disable', 'enable']
      http_redirect:
        aliases: ['http-redirect']
        type: str
        description: Enable/disable redirection of HTTP to HTTPS.
        choices: ['disable', 'enable']
      https_cookie_secure:
        aliases: ['https-cookie-secure']
        type: str
        description: Enable/disable verification that inserted HTTPS cookies are secure.
        choices: ['disable', 'enable']
      id:
        type: int
        description: Custom defined ID.
        required: true
      ipv4_mappedip:
        aliases: ['ipv4-mappedip']
        type: str
        description:
          - Support meta variable
          - Range of mapped IP addresses.
      ipv4_mappedport:
        aliases: ['ipv4-mappedport']
        type: str
        description:
          - Support meta variable
          - IPv4 port number range on the destination network to which the external port number range is mapped.
      ldb_method:
        aliases: ['ldb-method']
        type: str
        description: Method used to distribute sessions to real servers.
        choices: ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt',
                  'first-alive', 'http-host']
      mappedip:
        type: list
        elements: str
        description:
          - Support meta variable
          - Mapped IPv6 address range in the format startIP-endIP.
      mappedport:
        type: str
        description:
          - Support meta variable
          - Port number range on the destination network to which the external port number range is mapped.
      max_embryonic_connections:
        aliases: ['max-embryonic-connections']
        type: int
        description: Maximum number of incomplete connections.
      monitor:
        type: list
        elements: str
        description: Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
      name:
        type: str
        description: Virtual ip6 name.
      nat_source_vip:
        aliases: ['nat-source-vip']
        type: str
        description: Enable to perform SNAT on traffic from mappedip to the extip for all egress interfaces.
        choices: ['disable', 'enable']
      nat64:
        type: str
        description: Enable/disable DNAT64.
        choices: ['disable', 'enable']
      nat66:
        type: str
        description: Enable/disable DNAT66.
        choices: ['disable', 'enable']
      ndp_reply:
        aliases: ['ndp-reply']
        type: str
        description: Enable/disable this FortiGate units ability to respond to NDP requests for this virtual IP address
        choices: ['disable', 'enable']
      outlook_web_access:
        aliases: ['outlook-web-access']
        type: str
        description: Enable to add the Front-End-Https header for Microsoft Outlook Web Access.
        choices: ['disable', 'enable']
      persistence:
        type: str
        description: Configure how to make sure that clients connect to the same server every time they make a request that is part of the same session.
        choices: ['none', 'http-cookie', 'ssl-session-id']
      portforward:
        type: str
        description: Enable port forwarding.
        choices: ['disable', 'enable']
      protocol:
        type: str
        description: Protocol to use when forwarding packets.
        choices: ['tcp', 'udp', 'sctp']
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
            choices: ['disable', 'enable']
          grease_quic_bit:
            aliases: ['grease-quic-bit']
            type: str
            description: Enable/disable grease QUIC bit
            choices: ['disable', 'enable']
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
          client_ip:
            aliases: ['client-ip']
            type: str
            description: Only clients in this IP range can connect to this real server.
          healthcheck:
            type: str
            description: Enable to check the responsiveness of the real server before forwarding traffic.
            choices: ['disable', 'enable', 'vip']
          holddown_interval:
            aliases: ['holddown-interval']
            type: int
            description: Time in seconds that the system waits before re-activating a previously down active server in the active-standby mode.
          http_host:
            aliases: ['http-host']
            type: str
            description: HTTP server domain name in HTTP header.
          id:
            type: int
            description: Real server ID.
          ip:
            type: str
            description: IP address of the real server.
          max_connections:
            aliases: ['max-connections']
            type: int
            description: Max number of active connections that can directed to the real server.
          monitor:
            type: list
            elements: str
            description: Name of the health check monitor to use when polling to determine a virtual servers connectivity status.
          port:
            type: int
            description: Port for communicating with the real server.
          status:
            type: str
            description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
            choices: ['active', 'standby', 'disable']
          translate_host:
            aliases: ['translate-host']
            type: str
            description: Enable/disable translation of hostname/IP from virtual server to real server.
            choices: ['disable', 'enable']
          weight:
            type: int
            description: Weight of the real server.
          verify_cert:
            aliases: ['verify-cert']
            type: str
            description: Enable/disable certificate verification of the real server.
            choices: ['disable', 'enable']
      server_type:
        aliases: ['server-type']
        type: str
        description: Protocol to be load balanced by the virtual server
        choices: ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps']
      src_filter:
        aliases: ['src-filter']
        type: list
        elements: str
        description:
          - Support meta variable
          - Source IP6 filter
      src_vip_filter:
        aliases: ['src-vip-filter']
        type: str
        description: Enable/disable use of src-filter to match destinations for the reverse SNAT rule.
        choices: ['disable', 'enable']
      ssl_accept_ffdhe_groups:
        aliases: ['ssl-accept-ffdhe-groups']
        type: str
        description: Enable/disable FFDHE cipher suite for SSL key exchange.
        choices: ['disable', 'enable']
      ssl_algorithm:
        aliases: ['ssl-algorithm']
        type: str
        description: Permitted encryption algorithms for SSL sessions according to encryption strength.
        choices: ['high', 'low', 'medium', 'custom']
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
            choices: ['TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA',
                      'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                      'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                      'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256',
                      'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                      'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                      'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                      'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                      'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                      'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                      'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                      'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                      'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                      'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                      'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                      'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                      'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                      'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                      'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                      'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                      'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                      'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                      'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                      'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                      'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                      'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                      'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                      'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                      'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                      'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                      'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                      'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                      'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                      'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                      'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                      'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                      'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                      'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                      'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384',
                      'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA']
          priority:
            type: int
            description: SSL/TLS cipher suites priority.
          versions:
            type: list
            elements: str
            description: SSL/TLS versions that the cipher suite can be used with.
            choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
      ssl_client_fallback:
        aliases: ['ssl-client-fallback']
        type: str
        description: Enable/disable support for preventing Downgrade Attacks on client connections
        choices: ['disable', 'enable']
      ssl_client_rekey_count:
        aliases: ['ssl-client-rekey-count']
        type: int
        description: Maximum length of data in MB before triggering a client rekey
      ssl_client_renegotiation:
        aliases: ['ssl-client-renegotiation']
        type: str
        description: Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.
        choices: ['deny', 'allow', 'secure']
      ssl_client_session_state_max:
        aliases: ['ssl-client-session-state-max']
        type: int
        description: Maximum number of client to FortiGate SSL session states to keep.
      ssl_client_session_state_timeout:
        aliases: ['ssl-client-session-state-timeout']
        type: int
        description: Number of minutes to keep client to FortiGate SSL session state.
      ssl_client_session_state_type:
        aliases: ['ssl-client-session-state-type']
        type: str
        description: How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.
        choices: ['disable', 'time', 'count', 'both']
      ssl_dh_bits:
        aliases: ['ssl-dh-bits']
        type: str
        description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
        choices: ['768', '1024', '1536', '2048', '3072', '4096']
      ssl_hpkp:
        aliases: ['ssl-hpkp']
        type: str
        description: Enable/disable including HPKP header in response.
        choices: ['disable', 'enable', 'report-only']
      ssl_hpkp_age:
        aliases: ['ssl-hpkp-age']
        type: int
        description: Number of minutes the web browser should keep HPKP.
      ssl_hpkp_backup:
        aliases: ['ssl-hpkp-backup']
        type: list
        elements: str
        description: Certificate to generate backup HPKP pin from.
      ssl_hpkp_include_subdomains:
        aliases: ['ssl-hpkp-include-subdomains']
        type: str
        description: Indicate that HPKP header applies to all subdomains.
        choices: ['disable', 'enable']
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
        choices: ['disable', 'enable']
      ssl_hsts_age:
        aliases: ['ssl-hsts-age']
        type: int
        description: Number of seconds the client should honor the HSTS setting.
      ssl_hsts_include_subdomains:
        aliases: ['ssl-hsts-include-subdomains']
        type: str
        description: Indicate that HSTS header applies to all subdomains.
        choices: ['disable', 'enable']
      ssl_http_location_conversion:
        aliases: ['ssl-http-location-conversion']
        type: str
        description: Enable to replace HTTP with HTTPS in the replys Location HTTP header field.
        choices: ['disable', 'enable']
      ssl_http_match_host:
        aliases: ['ssl-http-match-host']
        type: str
        description: Enable/disable HTTP host matching for location conversion.
        choices: ['disable', 'enable']
      ssl_max_version:
        aliases: ['ssl-max-version']
        type: str
        description: Highest SSL/TLS version acceptable from a client.
        choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
      ssl_min_version:
        aliases: ['ssl-min-version']
        type: str
        description: Lowest SSL/TLS version acceptable from a client.
        choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
      ssl_mode:
        aliases: ['ssl-mode']
        type: str
        description: Apply SSL offloading between the client and the FortiGate
        choices: ['half', 'full']
      ssl_pfs:
        aliases: ['ssl-pfs']
        type: str
        description: Select the cipher suites that can be used for SSL perfect forward secrecy
        choices: ['require', 'deny', 'allow']
      ssl_send_empty_frags:
        aliases: ['ssl-send-empty-frags']
        type: str
        description: Enable/disable sending empty fragments to avoid CBC IV attacks
        choices: ['disable', 'enable']
      ssl_server_algorithm:
        aliases: ['ssl-server-algorithm']
        type: str
        description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
        choices: ['high', 'low', 'medium', 'custom', 'client']
      ssl_server_cipher_suites:
        aliases: ['ssl-server-cipher-suites']
        type: list
        elements: dict
        description: Ssl server cipher suites.
        suboptions:
          cipher:
            type: str
            description: Cipher suite name.
            choices: ['TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA',
                      'TLS-RSA-WITH-DES-CBC-SHA', 'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                      'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                      'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256',
                      'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                      'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                      'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA',
                      'TLS-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                      'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                      'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                      'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                      'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                      'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                      'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                      'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                      'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                      'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                      'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                      'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                      'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                      'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                      'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                      'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                      'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                      'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                      'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                      'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                      'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                      'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                      'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                      'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                      'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                      'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                      'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                      'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                      'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                      'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                      'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                      'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                      'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                      'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                      'TLS-AES-128-GCM-SHA256', 'TLS-AES-256-GCM-SHA384',
                      'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA']
          priority:
            type: int
            description: SSL/TLS cipher suites priority.
          versions:
            type: list
            elements: str
            description: SSL/TLS versions that the cipher suite can be used with.
            choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3']
      ssl_server_max_version:
        aliases: ['ssl-server-max-version']
        type: str
        description: Highest SSL/TLS version acceptable from a server.
        choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3']
      ssl_server_min_version:
        aliases: ['ssl-server-min-version']
        type: str
        description: Lowest SSL/TLS version acceptable from a server.
        choices: ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3']
      ssl_server_renegotiation:
        aliases: ['ssl-server-renegotiation']
        type: str
        description: Enable/disable secure renegotiation to comply with RFC 5746.
        choices: ['disable', 'enable']
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
        choices: ['disable', 'time', 'count', 'both']
      type:
        type: str
        description: Configure a static NAT server load balance VIP or access proxy.
        choices: ['static-nat', 'server-load-balance', 'access-proxy']
      uuid:
        type: str
        description: Universally Unique Identifier
      weblogic_server:
        aliases: ['weblogic-server']
        type: str
        description: Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.
        choices: ['disable', 'enable']
      websphere_server:
        aliases: ['websphere-server']
        type: str
        description: Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.
        choices: ['disable', 'enable']
      arp_reply:
        aliases: ['arp-reply']
        type: str
        description: Enable to respond to ARP requests for this virtual IP address.
        choices: ['disable', 'enable']
      client_cert:
        aliases: ['client-cert']
        type: str
        description: Enable/disable requesting client certificate.
        choices: ['disable', 'enable']
      empty_cert_action:
        aliases: ['empty-cert-action']
        type: str
        description: Action for an empty client certificate.
        choices: ['accept', 'block', 'accept-unmanageable']
      user_agent_detect:
        aliases: ['user-agent-detect']
        type: str
        description: Enable/disable detecting device type by HTTP user-agent if no client certificate is provided.
        choices: ['disable', 'enable']
      vip_id:
        aliases: ['vip-id']
        type: int
        description: Vip id.
      auth_virtual_host:
        aliases: ['auth-virtual-host']
        type: list
        elements: str
        description: Virtual host for authentication portal.
      ssl_http_strip_secure_cookies:
        aliases: ['ssl-http-strip-secure-cookies']
        type: str
        description: Enable/disable removal of HTTPS-only directives in the replys Set-Cookie HTTP header fields.
        choices: ['disable', 'enable']
      ssl_server_client_certificate:
        aliases: ['ssl-server-client-certificate']
        type: list
        elements: str
        description: Name of the client certificate presented to realserver during SSL/TLS handshake if requested.
      ssl_upstream:
        aliases: ['ssl-upstream']
        type: str
        description: Apply SSL encryption between the FortiGate and the upstream server
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure virtual IP for IPv6.
      fortinet.fmgdevice.fmgd_firewall_vip6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_vip6:
          id: 0 # Required variable, integer
          # add_nat64_route: <value in [disable, enable]>
          # color: <integer>
          # comment: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     add_nat64_route: <value in [disable, enable]>
          #     arp_reply: <value in [disable, enable]>
          #     color: <integer>
          #     comment: <string>
          #     embedded_ipv4_address: <value in [disable, enable]>
          #     extip: <list or string>
          #     extport: <string>
          #     h2_support: <value in [disable, enable]>
          #     h3_support: <value in [disable, enable]>
          #     http_cookie_age: <integer>
          #     http_cookie_domain: <string>
          #     http_cookie_domain_from_host: <value in [disable, enable]>
          #     http_cookie_generation: <integer>
          #     http_cookie_path: <string>
          #     http_cookie_share: <value in [disable, same-ip]>
          #     http_ip_header: <value in [disable, enable]>
          #     http_ip_header_name: <string>
          #     http_multiplex: <value in [disable, enable]>
          #     http_redirect: <value in [disable, enable]>
          #     https_cookie_secure: <value in [disable, enable]>
          #     id: <integer>
          #     ipv4_mappedip: <string>
          #     ipv4_mappedport: <string>
          #     ldb_method: <value in [static, round-robin, weighted, ...]>
          #     mappedip: <list or string>
          #     mappedport: <string>
          #     max_embryonic_connections: <integer>
          #     monitor: <list or string>
          #     nat_source_vip: <value in [disable, enable]>
          #     nat64: <value in [disable, enable]>
          #     nat66: <value in [disable, enable]>
          #     ndp_reply: <value in [disable, enable]>
          #     outlook_web_access: <value in [disable, enable]>
          #     persistence: <value in [none, http-cookie, ssl-session-id]>
          #     portforward: <value in [disable, enable]>
          #     protocol: <value in [tcp, udp, sctp]>
          #     realservers:
          #       - client_ip: <string>
          #         healthcheck: <value in [disable, enable, vip]>
          #         holddown_interval: <integer>
          #         http_host: <string>
          #         id: <integer>
          #         ip: <string>
          #         max_connections: <integer>
          #         monitor: <list or string>
          #         port: <integer>
          #         status: <value in [active, standby, disable]>
          #         translate_host: <value in [disable, enable]>
          #         weight: <integer>
          #         verify_cert: <value in [disable, enable]>
          #     server_type: <value in [http, https, ssl, ...]>
          #     src_filter: <list or string>
          #     src_vip_filter: <value in [disable, enable]>
          #     ssl_accept_ffdhe_groups: <value in [disable, enable]>
          #     ssl_algorithm: <value in [high, low, medium, ...]>
          #     ssl_certificate: <list or string>
          #     ssl_cipher_suites:
          #       - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #         priority: <integer>
          #         versions: ["ssl-3.0", "tls-1.0", "tls-1.1", "tls-1.2", "tls-1.3"]
          #     ssl_client_fallback: <value in [disable, enable]>
          #     ssl_client_rekey_count: <integer>
          #     ssl_client_renegotiation: <value in [deny, allow, secure]>
          #     ssl_client_session_state_max: <integer>
          #     ssl_client_session_state_timeout: <integer>
          #     ssl_client_session_state_type: <value in [disable, time, count, ...]>
          #     ssl_dh_bits: <value in [768, 1024, 1536, ...]>
          #     ssl_hpkp: <value in [disable, enable, report-only]>
          #     ssl_hpkp_age: <integer>
          #     ssl_hpkp_backup: <list or string>
          #     ssl_hpkp_include_subdomains: <value in [disable, enable]>
          #     ssl_hpkp_primary: <list or string>
          #     ssl_hpkp_report_uri: <string>
          #     ssl_hsts: <value in [disable, enable]>
          #     ssl_hsts_age: <integer>
          #     ssl_hsts_include_subdomains: <value in [disable, enable]>
          #     ssl_http_location_conversion: <value in [disable, enable]>
          #     ssl_http_match_host: <value in [disable, enable]>
          #     ssl_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #     ssl_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #     ssl_mode: <value in [half, full]>
          #     ssl_pfs: <value in [require, deny, allow]>
          #     ssl_send_empty_frags: <value in [disable, enable]>
          #     ssl_server_algorithm: <value in [high, low, medium, ...]>
          #     ssl_server_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #     ssl_server_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          #     ssl_server_renegotiation: <value in [disable, enable]>
          #     ssl_server_session_state_max: <integer>
          #     ssl_server_session_state_timeout: <integer>
          #     ssl_server_session_state_type: <value in [disable, time, count, ...]>
          #     type: <value in [static-nat, server-load-balance, access-proxy]>
          #     uuid: <string>
          #     weblogic_server: <value in [disable, enable]>
          #     websphere_server: <value in [disable, enable]>
          #     client_cert: <value in [disable, enable]>
          #     empty_cert_action: <value in [accept, block, accept-unmanageable]>
          #     user_agent_detect: <value in [disable, enable]>
          #     vip_id: <integer>
          #     auth_virtual_host: <list or string>
          #     ssl_http_strip_secure_cookies: <value in [disable, enable]>
          #     ssl_server_client_certificate: <list or string>
          #     ssl_upstream: <value in [disable, enable]>
          # embedded_ipv4_address: <value in [disable, enable]>
          # extip: <list or string>
          # extport: <string>
          # h2_support: <value in [disable, enable]>
          # h3_support: <value in [disable, enable]>
          # http_cookie_age: <integer>
          # http_cookie_domain: <string>
          # http_cookie_domain_from_host: <value in [disable, enable]>
          # http_cookie_generation: <integer>
          # http_cookie_path: <string>
          # http_cookie_share: <value in [disable, same-ip]>
          # http_ip_header: <value in [disable, enable]>
          # http_ip_header_name: <string>
          # http_multiplex: <value in [disable, enable]>
          # http_redirect: <value in [disable, enable]>
          # https_cookie_secure: <value in [disable, enable]>
          # ipv4_mappedip: <string>
          # ipv4_mappedport: <string>
          # ldb_method: <value in [static, round-robin, weighted, ...]>
          # mappedip: <list or string>
          # mappedport: <string>
          # max_embryonic_connections: <integer>
          # monitor: <list or string>
          # name: <string>
          # nat_source_vip: <value in [disable, enable]>
          # nat64: <value in [disable, enable]>
          # nat66: <value in [disable, enable]>
          # ndp_reply: <value in [disable, enable]>
          # outlook_web_access: <value in [disable, enable]>
          # persistence: <value in [none, http-cookie, ssl-session-id]>
          # portforward: <value in [disable, enable]>
          # protocol: <value in [tcp, udp, sctp]>
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
          #   - client_ip: <string>
          #     healthcheck: <value in [disable, enable, vip]>
          #     holddown_interval: <integer>
          #     http_host: <string>
          #     id: <integer>
          #     ip: <string>
          #     max_connections: <integer>
          #     monitor: <list or string>
          #     port: <integer>
          #     status: <value in [active, standby, disable]>
          #     translate_host: <value in [disable, enable]>
          #     weight: <integer>
          #     verify_cert: <value in [disable, enable]>
          # server_type: <value in [http, https, ssl, ...]>
          # src_filter: <list or string>
          # src_vip_filter: <value in [disable, enable]>
          # ssl_accept_ffdhe_groups: <value in [disable, enable]>
          # ssl_algorithm: <value in [high, low, medium, ...]>
          # ssl_certificate: <list or string>
          # ssl_cipher_suites:
          #   - cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
          #     priority: <integer>
          #     versions: ["ssl-3.0", "tls-1.0", "tls-1.1", "tls-1.2", "tls-1.3"]
          # ssl_client_fallback: <value in [disable, enable]>
          # ssl_client_rekey_count: <integer>
          # ssl_client_renegotiation: <value in [deny, allow, secure]>
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
          #     versions: ["ssl-3.0", "tls-1.0", "tls-1.1", "tls-1.2", "tls-1.3"]
          # ssl_server_max_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_server_min_version: <value in [ssl-3.0, tls-1.0, tls-1.1, ...]>
          # ssl_server_renegotiation: <value in [disable, enable]>
          # ssl_server_session_state_max: <integer>
          # ssl_server_session_state_timeout: <integer>
          # ssl_server_session_state_type: <value in [disable, time, count, ...]>
          # type: <value in [static-nat, server-load-balance, access-proxy]>
          # uuid: <string>
          # weblogic_server: <value in [disable, enable]>
          # websphere_server: <value in [disable, enable]>
          # arp_reply: <value in [disable, enable]>
          # client_cert: <value in [disable, enable]>
          # empty_cert_action: <value in [accept, block, accept-unmanageable]>
          # user_agent_detect: <value in [disable, enable]>
          # vip_id: <integer>
          # auth_virtual_host: <list or string>
          # ssl_http_strip_secure_cookies: <value in [disable, enable]>
          # ssl_server_client_certificate: <list or string>
          # ssl_upstream: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/vip6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_vip6': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'add-nat64-route': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'add-nat64-route': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'arp-reply': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'embedded-ipv4-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'extip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'extport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'h2-support': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'h3-support': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-age': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'http-cookie-domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'http-cookie-domain-from-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-cookie-generation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'http-cookie-path': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'http-cookie-share': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                        'http-ip-header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-ip-header-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'http-multiplex': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'http-redirect': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'https-cookie-secure': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ipv4-mappedip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'ipv4-mappedport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'ldb-method': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive', 'http-host'],
                            'type': 'str'
                        },
                        'mappedip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'mappedport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'max-embryonic-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'monitor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'nat-source-vip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nat64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'nat66': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ndp-reply': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'outlook-web-access': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'persistence': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['none', 'http-cookie', 'ssl-session-id'],
                            'type': 'str'
                        },
                        'portforward': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['tcp', 'udp', 'sctp'], 'type': 'str'},
                        'realservers': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'client-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'healthcheck': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                                'holddown-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'http-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'max-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'monitor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                                'translate-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'weight': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'verify-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'server-type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps'],
                            'type': 'str'
                        },
                        'src-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'src-vip-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-accept-ffdhe-groups': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-algorithm': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                        'ssl-certificate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'ssl-cipher-suites': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'cipher': {
                                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                                    'choices': [
                                        'TLS-RSA-WITH-RC4-128-MD5', 'TLS-RSA-WITH-RC4-128-SHA', 'TLS-RSA-WITH-DES-CBC-SHA',
                                        'TLS-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-RSA-WITH-AES-128-CBC-SHA', 'TLS-RSA-WITH-AES-256-CBC-SHA',
                                        'TLS-RSA-WITH-AES-128-CBC-SHA256', 'TLS-RSA-WITH-AES-256-CBC-SHA256', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-RSA-WITH-SEED-CBC-SHA', 'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                        'TLS-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-DHE-RSA-WITH-DES-CBC-SHA', 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-AES-128-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA', 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                        'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256', 'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                        'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                        'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA', 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA', 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256', 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                        'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256', 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA', 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                        'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256', 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                        'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384', 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA', 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                        'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-RSA-WITH-AES-128-GCM-SHA256', 'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                        'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                        'TLS-DHE-DSS-WITH-SEED-CBC-SHA', 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256', 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256', 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                        'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA', 'TLS-DHE-DSS-WITH-DES-CBC-SHA', 'TLS-AES-128-GCM-SHA256',
                                        'TLS-AES-256-GCM-SHA384', 'TLS-CHACHA20-POLY1305-SHA256', 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                                    ],
                                    'type': 'str'
                                },
                                'priority': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                                'versions': {
                                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                                    'type': 'list',
                                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'ssl-client-fallback': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-client-rekey-count': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'int'},
                        'ssl-client-renegotiation': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['deny', 'allow', 'secure'],
                            'type': 'str'
                        },
                        'ssl-client-session-state-max': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-client-session-state-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-client-session-state-type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'time', 'count', 'both'],
                            'type': 'str'
                        },
                        'ssl-dh-bits': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['768', '1024', '1536', '2048', '3072', '4096'],
                            'type': 'str'
                        },
                        'ssl-hpkp': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                        'ssl-hpkp-age': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-hpkp-backup': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'ssl-hpkp-include-subdomains': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-hpkp-primary': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'ssl-hpkp-report-uri': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'ssl-hsts': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-hsts-age': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-hsts-include-subdomains': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-http-location-conversion': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-http-match-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-max-version': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'ssl-min-version': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'type': 'str'
                        },
                        'ssl-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['half', 'full'], 'type': 'str'},
                        'ssl-pfs': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                        'ssl-send-empty-frags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-algorithm': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['high', 'low', 'medium', 'custom', 'client'],
                            'type': 'str'
                        },
                        'ssl-server-max-version': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                            'type': 'str'
                        },
                        'ssl-server-min-version': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                            'type': 'str'
                        },
                        'ssl-server-renegotiation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-session-state-max': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-server-session-state-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-server-session-state-type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['disable', 'time', 'count', 'both'],
                            'type': 'str'
                        },
                        'type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['static-nat', 'server-load-balance', 'access-proxy'],
                            'type': 'str'
                        },
                        'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'weblogic-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'websphere-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'client-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'empty-cert-action': {'v_range': [['7.6.4', '']], 'choices': ['accept', 'block', 'accept-unmanageable'], 'type': 'str'},
                        'user-agent-detect': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vip-id': {'v_range': [['7.6.5', '']], 'type': 'int'},
                        'auth-virtual-host': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'ssl-http-strip-secure-cookies': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ssl-server-client-certificate': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'ssl-upstream': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'embedded-ipv4-address': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'extport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'h2-support': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'h3-support': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-age': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'http-cookie-domain': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-cookie-domain-from-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-cookie-generation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'http-cookie-path': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-cookie-share': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'same-ip'], 'type': 'str'},
                'http-ip-header': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-ip-header-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'http-multiplex': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-redirect': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'https-cookie-secure': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'ipv4-mappedip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ipv4-mappedport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ldb-method': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['static', 'round-robin', 'weighted', 'least-session', 'least-rtt', 'first-alive', 'http-host'],
                    'type': 'str'
                },
                'mappedip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'mappedport': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'max-embryonic-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'monitor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'nat-source-vip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat66': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ndp-reply': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outlook-web-access': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'persistence': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['none', 'http-cookie', 'ssl-session-id'], 'type': 'str'},
                'portforward': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'protocol': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['tcp', 'udp', 'sctp'], 'type': 'str'},
                'quic': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'dict',
                    'options': {
                        'ack-delay-exponent': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'active-connection-id-limit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'active-migration': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'grease-quic-bit': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-ack-delay': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'max-datagram-frame-size': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'max-idle-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'max-udp-payload-size': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'}
                    }
                },
                'realservers': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'client-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'healthcheck': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'vip'], 'type': 'str'},
                        'holddown-interval': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'http-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'max-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'monitor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'status': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['active', 'standby', 'disable'], 'type': 'str'},
                        'translate-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'weight': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'verify-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'server-type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['http', 'https', 'ssl', 'tcp', 'udp', 'ip', 'imaps', 'pop3s', 'smtps'],
                    'type': 'str'
                },
                'src-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'src-vip-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-accept-ffdhe-groups': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-algorithm': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['high', 'low', 'medium', 'custom'], 'type': 'str'},
                'ssl-certificate': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-cipher-suites': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
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
                        'priority': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-client-fallback': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-client-rekey-count': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'int'},
                'ssl-client-renegotiation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['deny', 'allow', 'secure'], 'type': 'str'},
                'ssl-client-session-state-max': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-client-session-state-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-client-session-state-type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'time', 'count', 'both'],
                    'type': 'str'
                },
                'ssl-dh-bits': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['768', '1024', '1536', '2048', '3072', '4096'],
                    'type': 'str'
                },
                'ssl-hpkp': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable', 'report-only'], 'type': 'str'},
                'ssl-hpkp-age': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-hpkp-backup': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-hpkp-include-subdomains': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hpkp-primary': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ssl-hpkp-report-uri': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'ssl-hsts': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-hsts-age': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-hsts-include-subdomains': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-location-conversion': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-http-match-host': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-max-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-min-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-mode': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['half', 'full'], 'type': 'str'},
                'ssl-pfs': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['require', 'deny', 'allow'], 'type': 'str'},
                'ssl-send-empty-frags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-algorithm': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['high', 'low', 'medium', 'custom', 'client'],
                    'type': 'str'
                },
                'ssl-server-cipher-suites': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
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
                        'priority': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'versions': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-server-max-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-server-min-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'client', 'tls-1.3'],
                    'type': 'str'
                },
                'ssl-server-renegotiation': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-session-state-max': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-server-session-state-timeout': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-server-session-state-type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['disable', 'time', 'count', 'both'],
                    'type': 'str'
                },
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['static-nat', 'server-load-balance', 'access-proxy'], 'type': 'str'},
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'weblogic-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'websphere-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'arp-reply': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'client-cert': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'empty-cert-action': {'v_range': [['7.6.4', '']], 'choices': ['accept', 'block', 'accept-unmanageable'], 'type': 'str'},
                'user-agent-detect': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vip-id': {'v_range': [['7.6.5', '']], 'type': 'int'},
                'auth-virtual-host': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'ssl-http-strip-secure-cookies': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-server-client-certificate': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'ssl-upstream': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_vip6'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
