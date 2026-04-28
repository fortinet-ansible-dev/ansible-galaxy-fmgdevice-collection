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
module: fmgd_user_radius
short_description: Configure RADIUS server entries.
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
    user_radius:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accounting_server:
                aliases: ['accounting-server']
                type: list
                elements: dict
                description: Accounting server.
                suboptions:
                    id:
                        type: int
                        description: ID
                    interface:
                        type: list
                        elements: str
                        description: Specify outgoing interface to reach server.
                    interface_select_method:
                        aliases: ['interface-select-method']
                        type: str
                        description: Specify how to select outgoing interface to reach server.
                        choices:
                            - 'auto'
                            - 'sdwan'
                            - 'specify'
                    port:
                        type: int
                        description: RADIUS accounting port number.
                    secret:
                        type: list
                        elements: str
                        description: Secret key.
                    server:
                        type: str
                        description: Server CN domain name or IP address.
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description:
                            - Support meta variable
                            - Source IP address for communications to the RADIUS server.
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            acct_all_servers:
                aliases: ['acct-all-servers']
                type: str
                description: Enable/disable sending of accounting messages to all configured servers
                choices:
                    - 'disable'
                    - 'enable'
            acct_interim_interval:
                aliases: ['acct-interim-interval']
                type: int
                description: Time in seconds between each accounting interim update message.
            all_usergroup:
                aliases: ['all-usergroup']
                type: str
                description: Enable/disable automatically including this RADIUS server in all user groups.
                choices:
                    - 'disable'
                    - 'enable'
            auth_type:
                aliases: ['auth-type']
                type: str
                description: Authentication methods/protocols permitted for this RADIUS server.
                choices:
                    - 'pap'
                    - 'chap'
                    - 'ms_chap'
                    - 'ms_chap_v2'
                    - 'auto'
            class:
                type: list
                elements: str
                description: Class attribute name
            delimiter:
                type: str
                description: Configure delimiter to be used for separating profile group names in the SSO attribute
                choices:
                    - 'plus'
                    - 'comma'
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
                    account_key_cert_field:
                        aliases: ['account-key-cert-field']
                        type: str
                        description: Define subject identity field in certificate for user access right checking.
                        choices:
                            - 'othername'
                            - 'rfc822name'
                            - 'dnsname'
                            - 'cn'
                    account_key_processing:
                        aliases: ['account-key-processing']
                        type: str
                        description: Account key processing operation.
                        choices:
                            - 'same'
                            - 'strip'
                    accounting_server:
                        aliases: ['accounting-server']
                        type: list
                        elements: dict
                        description: Accounting server.
                        suboptions:
                            id:
                                type: int
                                description: ID
                            interface:
                                type: list
                                elements: str
                                description: Specify outgoing interface to reach server.
                            interface_select_method:
                                aliases: ['interface-select-method']
                                type: str
                                description: Specify how to select outgoing interface to reach server.
                                choices:
                                    - 'auto'
                                    - 'sdwan'
                                    - 'specify'
                            port:
                                type: int
                                description: RADIUS accounting port number.
                            secret:
                                type: list
                                elements: str
                                description: Secret key.
                            server:
                                type: str
                                description: Server CN domain name or IP address.
                            source_ip:
                                aliases: ['source-ip']
                                type: str
                                description:
                                    - Support meta variable
                                    - Source IP address for communications to the RADIUS server.
                            status:
                                type: str
                                description: Status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            vrf_select:
                                aliases: ['vrf-select']
                                type: int
                                description: VRF ID used for connection to server.
                    acct_all_servers:
                        aliases: ['acct-all-servers']
                        type: str
                        description: Enable/disable sending of accounting messages to all configured servers
                        choices:
                            - 'disable'
                            - 'enable'
                    acct_interim_interval:
                        aliases: ['acct-interim-interval']
                        type: int
                        description: Time in seconds between each accounting interim update message.
                    all_usergroup:
                        aliases: ['all-usergroup']
                        type: str
                        description: Enable/disable automatically including this RADIUS server in all user groups.
                        choices:
                            - 'disable'
                            - 'enable'
                    auth_type:
                        aliases: ['auth-type']
                        type: str
                        description: Authentication methods/protocols permitted for this RADIUS server.
                        choices:
                            - 'pap'
                            - 'chap'
                            - 'ms_chap'
                            - 'ms_chap_v2'
                            - 'auto'
                    ca_cert:
                        aliases: ['ca-cert']
                        type: list
                        elements: str
                        description: CA of server to trust under TLS.
                    call_station_id_type:
                        aliases: ['call-station-id-type']
                        type: str
                        description: Calling & Called station identifier type configuration
                        choices:
                            - 'legacy'
                            - 'IP'
                            - 'MAC'
                    class:
                        type: list
                        elements: str
                        description: Class attribute name
                    client_cert:
                        aliases: ['client-cert']
                        type: list
                        elements: str
                        description: Client certificate to use under TLS.
                    delimiter:
                        type: str
                        description: Configure delimiter to be used for separating profile group names in the SSO attribute
                        choices:
                            - 'plus'
                            - 'comma'
                    dp_carrier_endpoint_attribute:
                        aliases: ['dp-carrier-endpoint-attribute']
                        type: str
                        description: Dp carrier endpoint attribute.
                        choices:
                            - 'User-Name'
                            - 'User-Password'
                            - 'CHAP-Password'
                            - 'NAS-IP-Address'
                            - 'NAS-Port'
                            - 'Service-Type'
                            - 'Framed-Protocol'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Framed-Routing'
                            - 'Filter-Id'
                            - 'Framed-MTU'
                            - 'Framed-Compression'
                            - 'Login-IP-Host'
                            - 'Login-Service'
                            - 'Login-TCP-Port'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'State'
                            - 'Class'
                            - 'Vendor-Specific'
                            - 'Session-Timeout'
                            - 'Idle-Timeout'
                            - 'Termination-Action'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Link'
                            - 'Framed-AppleTalk-Network'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Status-Type'
                            - 'Acct-Delay-Time'
                            - 'Acct-Input-Octets'
                            - 'Acct-Output-Octets'
                            - 'Acct-Session-Id'
                            - 'Acct-Authentic'
                            - 'Acct-Session-Time'
                            - 'Acct-Input-Packets'
                            - 'Acct-Output-Packets'
                            - 'Acct-Terminate-Cause'
                            - 'Acct-Multi-Session-Id'
                            - 'Acct-Link-Count'
                            - 'CHAP-Challenge'
                            - 'NAS-Port-Type'
                            - 'Port-Limit'
                            - 'Login-LAT-Port'
                    dp_carrier_endpoint_block_attribute:
                        aliases: ['dp-carrier-endpoint-block-attribute']
                        type: str
                        description: Dp carrier endpoint block attribute.
                        choices:
                            - 'User-Name'
                            - 'User-Password'
                            - 'CHAP-Password'
                            - 'NAS-IP-Address'
                            - 'NAS-Port'
                            - 'Service-Type'
                            - 'Framed-Protocol'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Framed-Routing'
                            - 'Filter-Id'
                            - 'Framed-MTU'
                            - 'Framed-Compression'
                            - 'Login-IP-Host'
                            - 'Login-Service'
                            - 'Login-TCP-Port'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'State'
                            - 'Class'
                            - 'Vendor-Specific'
                            - 'Session-Timeout'
                            - 'Idle-Timeout'
                            - 'Termination-Action'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Link'
                            - 'Framed-AppleTalk-Network'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Status-Type'
                            - 'Acct-Delay-Time'
                            - 'Acct-Input-Octets'
                            - 'Acct-Output-Octets'
                            - 'Acct-Session-Id'
                            - 'Acct-Authentic'
                            - 'Acct-Session-Time'
                            - 'Acct-Input-Packets'
                            - 'Acct-Output-Packets'
                            - 'Acct-Terminate-Cause'
                            - 'Acct-Multi-Session-Id'
                            - 'Acct-Link-Count'
                            - 'CHAP-Challenge'
                            - 'NAS-Port-Type'
                            - 'Port-Limit'
                            - 'Login-LAT-Port'
                    dp_context_timeout:
                        aliases: ['dp-context-timeout']
                        type: int
                        description: Dp context timeout.
                    dp_flush_ip_session:
                        aliases: ['dp-flush-ip-session']
                        type: str
                        description: Dp flush ip session.
                        choices:
                            - 'disable'
                            - 'enable'
                    dp_hold_time:
                        aliases: ['dp-hold-time']
                        type: int
                        description: Dp hold time.
                    dp_http_header:
                        aliases: ['dp-http-header']
                        type: str
                        description: Dp http header.
                    dp_http_header_fallback:
                        aliases: ['dp-http-header-fallback']
                        type: str
                        description: Dp http header fallback.
                        choices:
                            - 'ip-header-address'
                            - 'default-profile'
                    dp_http_header_status:
                        aliases: ['dp-http-header-status']
                        type: str
                        description: Dp http header status.
                        choices:
                            - 'disable'
                            - 'enable'
                    dp_http_header_suppress:
                        aliases: ['dp-http-header-suppress']
                        type: str
                        description: Dp http header suppress.
                        choices:
                            - 'disable'
                            - 'enable'
                    dp_log_dyn_flags:
                        aliases: ['dp-log-dyn_flags']
                        type: list
                        elements: str
                        description: Dp log dyn flags.
                        choices:
                            - 'none'
                            - 'protocol-error'
                            - 'profile-missing'
                            - 'context-missing'
                            - 'accounting-stop-missed'
                            - 'accounting-event'
                            - 'radiusd-other'
                            - 'endpoint-block'
                    dp_log_period:
                        aliases: ['dp-log-period']
                        type: int
                        description: Dp log period.
                    dp_mem_percent:
                        aliases: ['dp-mem-percent']
                        type: int
                        description: Dp mem percent.
                    dp_profile_attribute:
                        aliases: ['dp-profile-attribute']
                        type: str
                        description: Dp profile attribute.
                        choices:
                            - 'User-Name'
                            - 'User-Password'
                            - 'CHAP-Password'
                            - 'NAS-IP-Address'
                            - 'NAS-Port'
                            - 'Service-Type'
                            - 'Framed-Protocol'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Framed-Routing'
                            - 'Filter-Id'
                            - 'Framed-MTU'
                            - 'Framed-Compression'
                            - 'Login-IP-Host'
                            - 'Login-Service'
                            - 'Login-TCP-Port'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'State'
                            - 'Class'
                            - 'Vendor-Specific'
                            - 'Session-Timeout'
                            - 'Idle-Timeout'
                            - 'Termination-Action'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Link'
                            - 'Framed-AppleTalk-Network'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Status-Type'
                            - 'Acct-Delay-Time'
                            - 'Acct-Input-Octets'
                            - 'Acct-Output-Octets'
                            - 'Acct-Session-Id'
                            - 'Acct-Authentic'
                            - 'Acct-Session-Time'
                            - 'Acct-Input-Packets'
                            - 'Acct-Output-Packets'
                            - 'Acct-Terminate-Cause'
                            - 'Acct-Multi-Session-Id'
                            - 'Acct-Link-Count'
                            - 'CHAP-Challenge'
                            - 'NAS-Port-Type'
                            - 'Port-Limit'
                            - 'Login-LAT-Port'
                    dp_profile_attribute_key:
                        aliases: ['dp-profile-attribute-key']
                        type: str
                        description: Dp profile attribute key.
                    dp_radius_response:
                        aliases: ['dp-radius-response']
                        type: str
                        description: Dp radius response.
                        choices:
                            - 'disable'
                            - 'enable'
                    dp_radius_server_port:
                        aliases: ['dp-radius-server-port']
                        type: int
                        description: Dp radius server port.
                    dp_secret:
                        aliases: ['dp-secret']
                        type: list
                        elements: str
                        description: Dp secret.
                    dp_validate_request_secret:
                        aliases: ['dp-validate-request-secret']
                        type: str
                        description: Dp validate request secret.
                        choices:
                            - 'disable'
                            - 'enable'
                    dynamic_profile:
                        aliases: ['dynamic-profile']
                        type: str
                        description: Dynamic profile.
                        choices:
                            - 'disable'
                            - 'enable'
                    endpoint_translation:
                        aliases: ['endpoint-translation']
                        type: str
                        description: Endpoint translation.
                        choices:
                            - 'disable'
                            - 'enable'
                    ep_carrier_endpoint_convert_hex:
                        aliases: ['ep-carrier-endpoint-convert-hex']
                        type: str
                        description: Ep carrier endpoint convert hex.
                        choices:
                            - 'disable'
                            - 'enable'
                    ep_carrier_endpoint_header:
                        aliases: ['ep-carrier-endpoint-header']
                        type: str
                        description: Ep carrier endpoint header.
                    ep_carrier_endpoint_header_suppress:
                        aliases: ['ep-carrier-endpoint-header-suppress']
                        type: str
                        description: Ep carrier endpoint header suppress.
                        choices:
                            - 'disable'
                            - 'enable'
                    ep_carrier_endpoint_prefix:
                        aliases: ['ep-carrier-endpoint-prefix']
                        type: str
                        description: Ep carrier endpoint prefix.
                        choices:
                            - 'disable'
                            - 'enable'
                    ep_carrier_endpoint_prefix_range_max:
                        aliases: ['ep-carrier-endpoint-prefix-range-max']
                        type: int
                        description: Ep carrier endpoint prefix range max.
                    ep_carrier_endpoint_prefix_range_min:
                        aliases: ['ep-carrier-endpoint-prefix-range-min']
                        type: int
                        description: Ep carrier endpoint prefix range min.
                    ep_carrier_endpoint_prefix_string:
                        aliases: ['ep-carrier-endpoint-prefix-string']
                        type: str
                        description: Ep carrier endpoint prefix string.
                    ep_carrier_endpoint_source:
                        aliases: ['ep-carrier-endpoint-source']
                        type: str
                        description: Ep carrier endpoint source.
                        choices:
                            - 'http-header'
                            - 'cookie'
                    ep_ip_header:
                        aliases: ['ep-ip-header']
                        type: str
                        description: Ep ip header.
                    ep_ip_header_suppress:
                        aliases: ['ep-ip-header-suppress']
                        type: str
                        description: Ep ip header suppress.
                        choices:
                            - 'disable'
                            - 'enable'
                    ep_missing_header_fallback:
                        aliases: ['ep-missing-header-fallback']
                        type: str
                        description: Ep missing header fallback.
                        choices:
                            - 'session-ip'
                            - 'policy-profile'
                    ep_profile_query_type:
                        aliases: ['ep-profile-query-type']
                        type: str
                        description: Ep profile query type.
                        choices:
                            - 'session-ip'
                            - 'extract-ip'
                            - 'extract-carrier-endpoint'
                    group_override_attr_type:
                        aliases: ['group-override-attr-type']
                        type: str
                        description: RADIUS attribute type to override user group information.
                        choices:
                            - 'filter-Id'
                            - 'class'
                    h3c_compatibility:
                        aliases: ['h3c-compatibility']
                        type: str
                        description: Enable/disable compatibility with the H3C, a mechanism that performs security checking for authentication.
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
                            - 'auto'
                            - 'specify'
                            - 'sdwan'
                    mac_case:
                        aliases: ['mac-case']
                        type: str
                        description: MAC authentication case
                        choices:
                            - 'uppercase'
                            - 'lowercase'
                    mac_password_delimiter:
                        aliases: ['mac-password-delimiter']
                        type: str
                        description: MAC authentication password delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    mac_username_delimiter:
                        aliases: ['mac-username-delimiter']
                        type: str
                        description: MAC authentication username delimiter
                        choices:
                            - 'hyphen'
                            - 'single-hyphen'
                            - 'colon'
                            - 'none'
                    nas_id:
                        aliases: ['nas-id']
                        type: str
                        description: Custom NAS identifier.
                    nas_id_type:
                        aliases: ['nas-id-type']
                        type: str
                        description: NAS identifier type configuration
                        choices:
                            - 'legacy'
                            - 'custom'
                            - 'hostname'
                    nas_ip:
                        aliases: ['nas-ip']
                        type: str
                        description: IP address used to communicate with the RADIUS server and used as NAS-IP-Address and Called-Station-ID attributes.
                    password_encoding:
                        aliases: ['password-encoding']
                        type: str
                        description: Password encoding.
                        choices:
                            - 'ISO-8859-1'
                            - 'auto'
                    password_renewal:
                        aliases: ['password-renewal']
                        type: str
                        description: Enable/disable password renewal.
                        choices:
                            - 'disable'
                            - 'enable'
                    radius_coa:
                        aliases: ['radius-coa']
                        type: str
                        description: Enable to allow a mechanism to change the attributes of an authentication, authorization, and accounting session a...
                        choices:
                            - 'disable'
                            - 'enable'
                    radius_port:
                        aliases: ['radius-port']
                        type: int
                        description: RADIUS service port number.
                    require_message_authenticator:
                        aliases: ['require-message-authenticator']
                        type: str
                        description: Require message authenticator in authentication response.
                        choices:
                            - 'disable'
                            - 'enable'
                    rsso:
                        type: str
                        description: Enable/disable RADIUS based single sign on feature.
                        choices:
                            - 'disable'
                            - 'enable'
                    rsso_context_timeout:
                        aliases: ['rsso-context-timeout']
                        type: int
                        description: Time in seconds before the logged out user is removed from the user context list of logged on users.
                    rsso_endpoint_attribute:
                        aliases: ['rsso-endpoint-attribute']
                        type: str
                        description: RADIUS attributes used to extract the user end point identifier from the RADIUS Start record.
                        choices:
                            - 'User-Name'
                            - 'NAS-IP-Address'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Filter-Id'
                            - 'Login-IP-Host'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'Class'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Session-Id'
                            - 'Acct-Multi-Session-Id'
                    rsso_endpoint_block_attribute:
                        aliases: ['rsso-endpoint-block-attribute']
                        type: str
                        description: RADIUS attributes used to block a user.
                        choices:
                            - 'User-Name'
                            - 'NAS-IP-Address'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Filter-Id'
                            - 'Login-IP-Host'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'Class'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Session-Id'
                            - 'Acct-Multi-Session-Id'
                    rsso_ep_one_ip_only:
                        aliases: ['rsso-ep-one-ip-only']
                        type: str
                        description: Enable/disable the replacement of old IP addresses with new ones for the same endpoint on RADIUS accounting Start ...
                        choices:
                            - 'disable'
                            - 'enable'
                    rsso_flush_ip_session:
                        aliases: ['rsso-flush-ip-session']
                        type: str
                        description: Enable/disable flushing user IP sessions on RADIUS accounting Stop messages.
                        choices:
                            - 'disable'
                            - 'enable'
                    rsso_log_flags:
                        aliases: ['rsso-log-flags']
                        type: list
                        elements: str
                        description: Events to log.
                        choices:
                            - 'none'
                            - 'protocol-error'
                            - 'profile-missing'
                            - 'accounting-stop-missed'
                            - 'accounting-event'
                            - 'radiusd-other'
                            - 'endpoint-block'
                    rsso_log_period:
                        aliases: ['rsso-log-period']
                        type: int
                        description: Time interval in seconds that group event log messages will be generated for dynamic profile events.
                    rsso_radius_response:
                        aliases: ['rsso-radius-response']
                        type: str
                        description: Enable/disable sending RADIUS response packets after receiving Start and Stop records.
                        choices:
                            - 'disable'
                            - 'enable'
                    rsso_radius_server_port:
                        aliases: ['rsso-radius-server-port']
                        type: int
                        description: UDP port to listen on for RADIUS Start and Stop records.
                    rsso_secret:
                        aliases: ['rsso-secret']
                        type: list
                        elements: str
                        description: RADIUS secret used by the RADIUS accounting server.
                    rsso_validate_request_secret:
                        aliases: ['rsso-validate-request-secret']
                        type: str
                        description: Enable/disable validating the RADIUS request shared secret in the Start or End record.
                        choices:
                            - 'disable'
                            - 'enable'
                    secondary_secret:
                        aliases: ['secondary-secret']
                        type: list
                        elements: str
                        description: Secret key to access the secondary server.
                    secondary_server:
                        aliases: ['secondary-server']
                        type: str
                        description: Secondary RADIUS CN domain name or IP address.
                    secret:
                        type: list
                        elements: str
                        description: Pre-shared secret key used to access the primary RADIUS server.
                    server:
                        type: str
                        description: Primary RADIUS server CN domain name or IP address.
                    server_identity_check:
                        aliases: ['server-identity-check']
                        type: str
                        description: Enable/disable RADIUS server identity check
                        choices:
                            - 'disable'
                            - 'enable'
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description:
                            - Support meta variable
                            - Source IP address for communications to the RADIUS server.
                    sso_attribute:
                        aliases: ['sso-attribute']
                        type: str
                        description: RADIUS attribute that contains the profile group name to be extracted from the RADIUS Start record.
                        choices:
                            - 'User-Name'
                            - 'NAS-IP-Address'
                            - 'Framed-IP-Address'
                            - 'Framed-IP-Netmask'
                            - 'Filter-Id'
                            - 'Login-IP-Host'
                            - 'Reply-Message'
                            - 'Callback-Number'
                            - 'Callback-Id'
                            - 'Framed-Route'
                            - 'Framed-IPX-Network'
                            - 'Class'
                            - 'Called-Station-Id'
                            - 'Calling-Station-Id'
                            - 'NAS-Identifier'
                            - 'Proxy-State'
                            - 'Login-LAT-Service'
                            - 'Login-LAT-Node'
                            - 'Login-LAT-Group'
                            - 'Framed-AppleTalk-Zone'
                            - 'Acct-Session-Id'
                            - 'Acct-Multi-Session-Id'
                    sso_attribute_key:
                        aliases: ['sso-attribute-key']
                        type: str
                        description: Key prefix for SSO group value in the SSO attribute.
                    sso_attribute_value_override:
                        aliases: ['sso-attribute-value-override']
                        type: str
                        description: Enable/disable override old attribute value with new value for the same endpoint.
                        choices:
                            - 'disable'
                            - 'enable'
                    status_ttl:
                        aliases: ['status-ttl']
                        type: int
                        description: Time for which server reachability is cached so that when a server is unreachable, it will not be retried for at l...
                    switch_controller_acct_fast_framedip_detect:
                        aliases: ['switch-controller-acct-fast-framedip-detect']
                        type: int
                        description: Switch controller accounting message Framed-IP detection from DHCP snooping
                    switch_controller_nas_ip_dynamic:
                        aliases: ['switch-controller-nas-ip-dynamic']
                        type: str
                        description: Enable/Disable switch-controller nas-ip dynamic to dynamically set nas-ip.
                        choices:
                            - 'disable'
                            - 'enable'
                    switch_controller_service_type:
                        aliases: ['switch-controller-service-type']
                        type: list
                        elements: str
                        description: RADIUS service type.
                        choices:
                            - 'login'
                            - 'framed'
                            - 'callback-login'
                            - 'callback-framed'
                            - 'outbound'
                            - 'administrative'
                            - 'nas-prompt'
                            - 'authenticate-only'
                            - 'callback-nas-prompt'
                            - 'call-check'
                            - 'callback-administrative'
                    tertiary_secret:
                        aliases: ['tertiary-secret']
                        type: list
                        elements: str
                        description: Secret key to access the tertiary server.
                    tertiary_server:
                        aliases: ['tertiary-server']
                        type: str
                        description: Tertiary RADIUS CN domain name or IP address.
                    timeout:
                        type: int
                        description: Time in seconds to retry connecting server.
                    tls_min_proto_version:
                        aliases: ['tls-min-proto-version']
                        type: str
                        description: Minimum supported protocol version for TLS connections
                        choices:
                            - 'default'
                            - 'TLSv1'
                            - 'TLSv1-1'
                            - 'TLSv1-2'
                            - 'SSLv3'
                            - 'TLSv1-3'
                    transport_protocol:
                        aliases: ['transport-protocol']
                        type: str
                        description: Transport protocol to be used
                        choices:
                            - 'udp'
                            - 'tcp'
                            - 'tls'
                    use_group_for_profile:
                        aliases: ['use-group-for-profile']
                        type: str
                        description: Use group for profile.
                        choices:
                            - 'disable'
                            - 'enable'
                    use_management_vdom:
                        aliases: ['use-management-vdom']
                        type: str
                        description: Enable/disable using management VDOM to send requests.
                        choices:
                            - 'disable'
                            - 'enable'
                    username_case_sensitive:
                        aliases: ['username-case-sensitive']
                        type: str
                        description: Enable/disable case sensitive user names.
                        choices:
                            - 'disable'
                            - 'enable'
                    source_ip_interface:
                        aliases: ['source-ip-interface']
                        type: list
                        elements: str
                        description: Source interface for communication with the RADIUS server.
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            group_override_attr_type:
                aliases: ['group-override-attr-type']
                type: str
                description: RADIUS attribute type to override user group information.
                choices:
                    - 'filter-Id'
                    - 'class'
            h3c_compatibility:
                aliases: ['h3c-compatibility']
                type: str
                description: Enable/disable compatibility with the H3C, a mechanism that performs security checking for authentication.
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
                    - 'auto'
                    - 'specify'
                    - 'sdwan'
            mac_case:
                aliases: ['mac-case']
                type: str
                description: MAC authentication case
                choices:
                    - 'uppercase'
                    - 'lowercase'
            mac_password_delimiter:
                aliases: ['mac-password-delimiter']
                type: str
                description: MAC authentication password delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            mac_username_delimiter:
                aliases: ['mac-username-delimiter']
                type: str
                description: MAC authentication username delimiter
                choices:
                    - 'hyphen'
                    - 'single-hyphen'
                    - 'colon'
                    - 'none'
            name:
                type: str
                description: RADIUS server entry name.
                required: true
            nas_id:
                aliases: ['nas-id']
                type: str
                description: Custom NAS identifier.
            nas_id_type:
                aliases: ['nas-id-type']
                type: str
                description: NAS identifier type configuration
                choices:
                    - 'legacy'
                    - 'custom'
                    - 'hostname'
            nas_ip:
                aliases: ['nas-ip']
                type: str
                description: IP address used to communicate with the RADIUS server and used as NAS-IP-Address and Called-Station-ID attributes.
            password_encoding:
                aliases: ['password-encoding']
                type: str
                description: Password encoding.
                choices:
                    - 'ISO-8859-1'
                    - 'auto'
            password_renewal:
                aliases: ['password-renewal']
                type: str
                description: Enable/disable password renewal.
                choices:
                    - 'disable'
                    - 'enable'
            radius_coa:
                aliases: ['radius-coa']
                type: str
                description: Enable to allow a mechanism to change the attributes of an authentication, authorization, and accounting session after it ...
                choices:
                    - 'disable'
                    - 'enable'
            radius_port:
                aliases: ['radius-port']
                type: int
                description: RADIUS service port number.
            require_message_authenticator:
                aliases: ['require-message-authenticator']
                type: str
                description: Require message authenticator in authentication response.
                choices:
                    - 'disable'
                    - 'enable'
            rsso:
                type: str
                description: Enable/disable RADIUS based single sign on feature.
                choices:
                    - 'disable'
                    - 'enable'
            rsso_context_timeout:
                aliases: ['rsso-context-timeout']
                type: int
                description: Time in seconds before the logged out user is removed from the user context list of logged on users.
            rsso_endpoint_attribute:
                aliases: ['rsso-endpoint-attribute']
                type: str
                description: RADIUS attributes used to extract the user end point identifier from the RADIUS Start record.
                choices:
                    - 'User-Name'
                    - 'NAS-IP-Address'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Filter-Id'
                    - 'Login-IP-Host'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'Class'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Session-Id'
                    - 'Acct-Multi-Session-Id'
            rsso_endpoint_block_attribute:
                aliases: ['rsso-endpoint-block-attribute']
                type: str
                description: RADIUS attributes used to block a user.
                choices:
                    - 'User-Name'
                    - 'NAS-IP-Address'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Filter-Id'
                    - 'Login-IP-Host'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'Class'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Session-Id'
                    - 'Acct-Multi-Session-Id'
            rsso_ep_one_ip_only:
                aliases: ['rsso-ep-one-ip-only']
                type: str
                description: Enable/disable the replacement of old IP addresses with new ones for the same endpoint on RADIUS accounting Start messages.
                choices:
                    - 'disable'
                    - 'enable'
            rsso_flush_ip_session:
                aliases: ['rsso-flush-ip-session']
                type: str
                description: Enable/disable flushing user IP sessions on RADIUS accounting Stop messages.
                choices:
                    - 'disable'
                    - 'enable'
            rsso_log_flags:
                aliases: ['rsso-log-flags']
                type: list
                elements: str
                description: Events to log.
                choices:
                    - 'none'
                    - 'protocol-error'
                    - 'profile-missing'
                    - 'accounting-stop-missed'
                    - 'accounting-event'
                    - 'radiusd-other'
                    - 'endpoint-block'
            rsso_log_period:
                aliases: ['rsso-log-period']
                type: int
                description: Time interval in seconds that group event log messages will be generated for dynamic profile events.
            rsso_radius_response:
                aliases: ['rsso-radius-response']
                type: str
                description: Enable/disable sending RADIUS response packets after receiving Start and Stop records.
                choices:
                    - 'disable'
                    - 'enable'
            rsso_radius_server_port:
                aliases: ['rsso-radius-server-port']
                type: int
                description: UDP port to listen on for RADIUS Start and Stop records.
            rsso_secret:
                aliases: ['rsso-secret']
                type: list
                elements: str
                description: RADIUS secret used by the RADIUS accounting server.
            rsso_validate_request_secret:
                aliases: ['rsso-validate-request-secret']
                type: str
                description: Enable/disable validating the RADIUS request shared secret in the Start or End record.
                choices:
                    - 'disable'
                    - 'enable'
            secondary_secret:
                aliases: ['secondary-secret']
                type: list
                elements: str
                description: Secret key to access the secondary server.
            secondary_server:
                aliases: ['secondary-server']
                type: str
                description: Secondary RADIUS CN domain name or IP address.
            secret:
                type: list
                elements: str
                description: Pre-shared secret key used to access the primary RADIUS server.
            server:
                type: str
                description: Primary RADIUS server CN domain name or IP address.
            source_ip:
                aliases: ['source-ip']
                type: str
                description:
                    - Support meta variable
                    - Source IP address for communications to the RADIUS server.
            sso_attribute:
                aliases: ['sso-attribute']
                type: str
                description: RADIUS attribute that contains the profile group name to be extracted from the RADIUS Start record.
                choices:
                    - 'User-Name'
                    - 'NAS-IP-Address'
                    - 'Framed-IP-Address'
                    - 'Framed-IP-Netmask'
                    - 'Filter-Id'
                    - 'Login-IP-Host'
                    - 'Reply-Message'
                    - 'Callback-Number'
                    - 'Callback-Id'
                    - 'Framed-Route'
                    - 'Framed-IPX-Network'
                    - 'Class'
                    - 'Called-Station-Id'
                    - 'Calling-Station-Id'
                    - 'NAS-Identifier'
                    - 'Proxy-State'
                    - 'Login-LAT-Service'
                    - 'Login-LAT-Node'
                    - 'Login-LAT-Group'
                    - 'Framed-AppleTalk-Zone'
                    - 'Acct-Session-Id'
                    - 'Acct-Multi-Session-Id'
            sso_attribute_key:
                aliases: ['sso-attribute-key']
                type: str
                description: Key prefix for SSO group value in the SSO attribute.
            sso_attribute_value_override:
                aliases: ['sso-attribute-value-override']
                type: str
                description: Enable/disable override old attribute value with new value for the same endpoint.
                choices:
                    - 'disable'
                    - 'enable'
            switch_controller_acct_fast_framedip_detect:
                aliases: ['switch-controller-acct-fast-framedip-detect']
                type: int
                description: Switch controller accounting message Framed-IP detection from DHCP snooping
            switch_controller_service_type:
                aliases: ['switch-controller-service-type']
                type: list
                elements: str
                description: RADIUS service type.
                choices:
                    - 'login'
                    - 'framed'
                    - 'callback-login'
                    - 'callback-framed'
                    - 'outbound'
                    - 'administrative'
                    - 'nas-prompt'
                    - 'authenticate-only'
                    - 'callback-nas-prompt'
                    - 'call-check'
                    - 'callback-administrative'
            tertiary_secret:
                aliases: ['tertiary-secret']
                type: list
                elements: str
                description: Secret key to access the tertiary server.
            tertiary_server:
                aliases: ['tertiary-server']
                type: str
                description: Tertiary RADIUS CN domain name or IP address.
            timeout:
                type: int
                description: Time in seconds to retry connecting server.
            use_management_vdom:
                aliases: ['use-management-vdom']
                type: str
                description: Enable/disable using management VDOM to send requests.
                choices:
                    - 'disable'
                    - 'enable'
            username_case_sensitive:
                aliases: ['username-case-sensitive']
                type: str
                description: Enable/disable case sensitive user names.
                choices:
                    - 'disable'
                    - 'enable'
            tls_min_proto_version:
                aliases: ['tls-min-proto-version']
                type: str
                description: Minimum supported protocol version for TLS connections
                choices:
                    - 'default'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1-3'
            status_ttl:
                aliases: ['status-ttl']
                type: int
                description: Time for which server reachability is cached so that when a server is unreachable, it will not be retried for at least thi...
            account_key_cert_field:
                aliases: ['account-key-cert-field']
                type: str
                description: Define subject identity field in certificate for user access right checking.
                choices:
                    - 'othername'
                    - 'rfc822name'
                    - 'dnsname'
                    - 'cn'
            switch_controller_nas_ip_dynamic:
                aliases: ['switch-controller-nas-ip-dynamic']
                type: str
                description: Enable/Disable switch-controller nas-ip dynamic to dynamically set nas-ip.
                choices:
                    - 'disable'
                    - 'enable'
            account_key_processing:
                aliases: ['account-key-processing']
                type: str
                description: Account key processing operation.
                choices:
                    - 'same'
                    - 'strip'
            server_identity_check:
                aliases: ['server-identity-check']
                type: str
                description: Enable/disable RADIUS server identity check
                choices:
                    - 'disable'
                    - 'enable'
            transport_protocol:
                aliases: ['transport-protocol']
                type: str
                description: Transport protocol to be used
                choices:
                    - 'udp'
                    - 'tcp'
                    - 'tls'
            client_cert:
                aliases: ['client-cert']
                type: list
                elements: str
                description: Client certificate to use under TLS.
            ca_cert:
                aliases: ['ca-cert']
                type: list
                elements: str
                description: CA of server to trust under TLS.
            call_station_id_type:
                aliases: ['call-station-id-type']
                type: str
                description: Calling & Called station identifier type configuration
                choices:
                    - 'legacy'
                    - 'IP'
                    - 'MAC'
            source_ip_interface:
                aliases: ['source-ip-interface']
                type: list
                elements: str
                description: Source interface for communication with the RADIUS server.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Configure RADIUS server entries.
      fortinet.fmgdevice.fmgd_user_radius:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_radius:
          name: "your value" # Required variable, string
          # accounting_server:
          #   - id: <integer>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, sdwan, specify]>
          #     port: <integer>
          #     secret: <list or string>
          #     server: <string>
          #     source_ip: <string>
          #     status: <value in [disable, enable]>
          #     vrf_select: <integer>
          # acct_all_servers: <value in [disable, enable]>
          # acct_interim_interval: <integer>
          # all_usergroup: <value in [disable, enable]>
          # auth_type: <value in [pap, chap, ms_chap, ...]>
          # class: <list or string>
          # delimiter: <value in [plus, comma]>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     account_key_cert_field: <value in [othername, rfc822name, dnsname, ...]>
          #     account_key_processing: <value in [same, strip]>
          #     accounting_server:
          #       - id: <integer>
          #         interface: <list or string>
          #         interface_select_method: <value in [auto, sdwan, specify]>
          #         port: <integer>
          #         secret: <list or string>
          #         server: <string>
          #         source_ip: <string>
          #         status: <value in [disable, enable]>
          #         vrf_select: <integer>
          #     acct_all_servers: <value in [disable, enable]>
          #     acct_interim_interval: <integer>
          #     all_usergroup: <value in [disable, enable]>
          #     auth_type: <value in [pap, chap, ms_chap, ...]>
          #     ca_cert: <list or string>
          #     call_station_id_type: <value in [legacy, IP, MAC]>
          #     class: <list or string>
          #     client_cert: <list or string>
          #     delimiter: <value in [plus, comma]>
          #     dp_carrier_endpoint_attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
          #     dp_carrier_endpoint_block_attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
          #     dp_context_timeout: <integer>
          #     dp_flush_ip_session: <value in [disable, enable]>
          #     dp_hold_time: <integer>
          #     dp_http_header: <string>
          #     dp_http_header_fallback: <value in [ip-header-address, default-profile]>
          #     dp_http_header_status: <value in [disable, enable]>
          #     dp_http_header_suppress: <value in [disable, enable]>
          #     dp_log_dyn_flags:
          #       - "none"
          #       - "protocol-error"
          #       - "profile-missing"
          #       - "context-missing"
          #       - "accounting-stop-missed"
          #       - "accounting-event"
          #       - "radiusd-other"
          #       - "endpoint-block"
          #     dp_log_period: <integer>
          #     dp_mem_percent: <integer>
          #     dp_profile_attribute: <value in [User-Name, User-Password, CHAP-Password, ...]>
          #     dp_profile_attribute_key: <string>
          #     dp_radius_response: <value in [disable, enable]>
          #     dp_radius_server_port: <integer>
          #     dp_secret: <list or string>
          #     dp_validate_request_secret: <value in [disable, enable]>
          #     dynamic_profile: <value in [disable, enable]>
          #     endpoint_translation: <value in [disable, enable]>
          #     ep_carrier_endpoint_convert_hex: <value in [disable, enable]>
          #     ep_carrier_endpoint_header: <string>
          #     ep_carrier_endpoint_header_suppress: <value in [disable, enable]>
          #     ep_carrier_endpoint_prefix: <value in [disable, enable]>
          #     ep_carrier_endpoint_prefix_range_max: <integer>
          #     ep_carrier_endpoint_prefix_range_min: <integer>
          #     ep_carrier_endpoint_prefix_string: <string>
          #     ep_carrier_endpoint_source: <value in [http-header, cookie]>
          #     ep_ip_header: <string>
          #     ep_ip_header_suppress: <value in [disable, enable]>
          #     ep_missing_header_fallback: <value in [session-ip, policy-profile]>
          #     ep_profile_query_type: <value in [session-ip, extract-ip, extract-carrier-endpoint]>
          #     group_override_attr_type: <value in [filter-Id, class]>
          #     h3c_compatibility: <value in [disable, enable]>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, specify, sdwan]>
          #     mac_case: <value in [uppercase, lowercase]>
          #     mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #     mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          #     nas_id: <string>
          #     nas_id_type: <value in [legacy, custom, hostname]>
          #     nas_ip: <string>
          #     password_encoding: <value in [ISO-8859-1, auto]>
          #     password_renewal: <value in [disable, enable]>
          #     radius_coa: <value in [disable, enable]>
          #     radius_port: <integer>
          #     require_message_authenticator: <value in [disable, enable]>
          #     rsso: <value in [disable, enable]>
          #     rsso_context_timeout: <integer>
          #     rsso_endpoint_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          #     rsso_endpoint_block_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          #     rsso_ep_one_ip_only: <value in [disable, enable]>
          #     rsso_flush_ip_session: <value in [disable, enable]>
          #     rsso_log_flags:
          #       - "none"
          #       - "protocol-error"
          #       - "profile-missing"
          #       - "accounting-stop-missed"
          #       - "accounting-event"
          #       - "radiusd-other"
          #       - "endpoint-block"
          #     rsso_log_period: <integer>
          #     rsso_radius_response: <value in [disable, enable]>
          #     rsso_radius_server_port: <integer>
          #     rsso_secret: <list or string>
          #     rsso_validate_request_secret: <value in [disable, enable]>
          #     secondary_secret: <list or string>
          #     secondary_server: <string>
          #     secret: <list or string>
          #     server: <string>
          #     server_identity_check: <value in [disable, enable]>
          #     source_ip: <string>
          #     sso_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          #     sso_attribute_key: <string>
          #     sso_attribute_value_override: <value in [disable, enable]>
          #     status_ttl: <integer>
          #     switch_controller_acct_fast_framedip_detect: <integer>
          #     switch_controller_nas_ip_dynamic: <value in [disable, enable]>
          #     switch_controller_service_type:
          #       - "login"
          #       - "framed"
          #       - "callback-login"
          #       - "callback-framed"
          #       - "outbound"
          #       - "administrative"
          #       - "nas-prompt"
          #       - "authenticate-only"
          #       - "callback-nas-prompt"
          #       - "call-check"
          #       - "callback-administrative"
          #     tertiary_secret: <list or string>
          #     tertiary_server: <string>
          #     timeout: <integer>
          #     tls_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          #     transport_protocol: <value in [udp, tcp, tls]>
          #     use_group_for_profile: <value in [disable, enable]>
          #     use_management_vdom: <value in [disable, enable]>
          #     username_case_sensitive: <value in [disable, enable]>
          #     source_ip_interface: <list or string>
          #     vrf_select: <integer>
          # group_override_attr_type: <value in [filter-Id, class]>
          # h3c_compatibility: <value in [disable, enable]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, specify, sdwan]>
          # mac_case: <value in [uppercase, lowercase]>
          # mac_password_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # mac_username_delimiter: <value in [hyphen, single-hyphen, colon, ...]>
          # nas_id: <string>
          # nas_id_type: <value in [legacy, custom, hostname]>
          # nas_ip: <string>
          # password_encoding: <value in [ISO-8859-1, auto]>
          # password_renewal: <value in [disable, enable]>
          # radius_coa: <value in [disable, enable]>
          # radius_port: <integer>
          # require_message_authenticator: <value in [disable, enable]>
          # rsso: <value in [disable, enable]>
          # rsso_context_timeout: <integer>
          # rsso_endpoint_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          # rsso_endpoint_block_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          # rsso_ep_one_ip_only: <value in [disable, enable]>
          # rsso_flush_ip_session: <value in [disable, enable]>
          # rsso_log_flags:
          #   - "none"
          #   - "protocol-error"
          #   - "profile-missing"
          #   - "accounting-stop-missed"
          #   - "accounting-event"
          #   - "radiusd-other"
          #   - "endpoint-block"
          # rsso_log_period: <integer>
          # rsso_radius_response: <value in [disable, enable]>
          # rsso_radius_server_port: <integer>
          # rsso_secret: <list or string>
          # rsso_validate_request_secret: <value in [disable, enable]>
          # secondary_secret: <list or string>
          # secondary_server: <string>
          # secret: <list or string>
          # server: <string>
          # source_ip: <string>
          # sso_attribute: <value in [User-Name, NAS-IP-Address, Framed-IP-Address, ...]>
          # sso_attribute_key: <string>
          # sso_attribute_value_override: <value in [disable, enable]>
          # switch_controller_acct_fast_framedip_detect: <integer>
          # switch_controller_service_type:
          #   - "login"
          #   - "framed"
          #   - "callback-login"
          #   - "callback-framed"
          #   - "outbound"
          #   - "administrative"
          #   - "nas-prompt"
          #   - "authenticate-only"
          #   - "callback-nas-prompt"
          #   - "call-check"
          #   - "callback-administrative"
          # tertiary_secret: <list or string>
          # tertiary_server: <string>
          # timeout: <integer>
          # use_management_vdom: <value in [disable, enable]>
          # username_case_sensitive: <value in [disable, enable]>
          # tls_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # status_ttl: <integer>
          # account_key_cert_field: <value in [othername, rfc822name, dnsname, ...]>
          # switch_controller_nas_ip_dynamic: <value in [disable, enable]>
          # account_key_processing: <value in [same, strip]>
          # server_identity_check: <value in [disable, enable]>
          # transport_protocol: <value in [udp, tcp, tls]>
          # client_cert: <list or string>
          # ca_cert: <list or string>
          # call_station_id_type: <value in [legacy, IP, MAC]>
          # source_ip_interface: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/radius'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_radius': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'accounting-server': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'acct-all-servers': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'acct-interim-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'all-usergroup': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['pap', 'chap', 'ms_chap', 'ms_chap_v2', 'auto'], 'type': 'str'},
                'class': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'delimiter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['plus', 'comma'], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'account-key-cert-field': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['othername', 'rfc822name', 'dnsname', 'cn'],
                            'type': 'str'
                        },
                        'account-key-processing': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['same', 'strip'], 'type': 'str'},
                        'accounting-server': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                                'interface-select-method': {
                                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                                    'choices': ['auto', 'sdwan', 'specify'],
                                    'type': 'str'
                                },
                                'port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                                'secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                                'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'acct-all-servers': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'acct-interim-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'all-usergroup': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'auth-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['pap', 'chap', 'ms_chap', 'ms_chap_v2', 'auto'],
                            'type': 'str'
                        },
                        'ca-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'call-station-id-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['legacy', 'IP', 'MAC'], 'type': 'str'},
                        'class': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'client-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'delimiter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['plus', 'comma'], 'type': 'str'},
                        'dp-carrier-endpoint-attribute': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': [
                                'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                                'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression',
                                'Login-IP-Host', 'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route',
                                'Framed-IPX-Network', 'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action',
                                'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node',
                                'Login-LAT-Group', 'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type',
                                'Acct-Delay-Time', 'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time',
                                'Acct-Input-Packets', 'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count',
                                'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit', 'Login-LAT-Port'
                            ],
                            'type': 'str'
                        },
                        'dp-carrier-endpoint-block-attribute': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': [
                                'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                                'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression',
                                'Login-IP-Host', 'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route',
                                'Framed-IPX-Network', 'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action',
                                'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node',
                                'Login-LAT-Group', 'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type',
                                'Acct-Delay-Time', 'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time',
                                'Acct-Input-Packets', 'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count',
                                'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit', 'Login-LAT-Port'
                            ],
                            'type': 'str'
                        },
                        'dp-context-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'dp-flush-ip-session': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dp-hold-time': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'dp-http-header': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'dp-http-header-fallback': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ip-header-address', 'default-profile'],
                            'type': 'str'
                        },
                        'dp-http-header-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dp-http-header-suppress': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dp-log-dyn_flags': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'none', 'protocol-error', 'profile-missing', 'context-missing', 'accounting-stop-missed', 'accounting-event',
                                'radiusd-other', 'endpoint-block'
                            ],
                            'elements': 'str'
                        },
                        'dp-log-period': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'dp-mem-percent': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'dp-profile-attribute': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': [
                                'User-Name', 'User-Password', 'CHAP-Password', 'NAS-IP-Address', 'NAS-Port', 'Service-Type', 'Framed-Protocol',
                                'Framed-IP-Address', 'Framed-IP-Netmask', 'Framed-Routing', 'Filter-Id', 'Framed-MTU', 'Framed-Compression',
                                'Login-IP-Host', 'Login-Service', 'Login-TCP-Port', 'Reply-Message', 'Callback-Number', 'Callback-Id', 'Framed-Route',
                                'Framed-IPX-Network', 'State', 'Class', 'Vendor-Specific', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action',
                                'Called-Station-Id', 'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node',
                                'Login-LAT-Group', 'Framed-AppleTalk-Link', 'Framed-AppleTalk-Network', 'Framed-AppleTalk-Zone', 'Acct-Status-Type',
                                'Acct-Delay-Time', 'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Session-Id', 'Acct-Authentic', 'Acct-Session-Time',
                                'Acct-Input-Packets', 'Acct-Output-Packets', 'Acct-Terminate-Cause', 'Acct-Multi-Session-Id', 'Acct-Link-Count',
                                'CHAP-Challenge', 'NAS-Port-Type', 'Port-Limit', 'Login-LAT-Port'
                            ],
                            'type': 'str'
                        },
                        'dp-profile-attribute-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                        'dp-radius-response': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dp-radius-server-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'dp-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'dp-validate-request-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dynamic-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'endpoint-translation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ep-carrier-endpoint-convert-hex': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'ep-carrier-endpoint-header': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'ep-carrier-endpoint-header-suppress': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'ep-carrier-endpoint-prefix': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ep-carrier-endpoint-prefix-range-max': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ep-carrier-endpoint-prefix-range-min': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'ep-carrier-endpoint-prefix-string': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'ep-carrier-endpoint-source': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['http-header', 'cookie'],
                            'type': 'str'
                        },
                        'ep-ip-header': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'ep-ip-header-suppress': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ep-missing-header-fallback': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['session-ip', 'policy-profile'],
                            'type': 'str'
                        },
                        'ep-profile-query-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['session-ip', 'extract-ip', 'extract-carrier-endpoint'],
                            'type': 'str'
                        },
                        'group-override-attr-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['filter-Id', 'class'], 'type': 'str'},
                        'h3c-compatibility': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['auto', 'specify', 'sdwan'],
                            'type': 'str'
                        },
                        'mac-case': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                        'mac-password-delimiter': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'mac-username-delimiter': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                            'type': 'str'
                        },
                        'nas-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'nas-id-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['legacy', 'custom', 'hostname'], 'type': 'str'},
                        'nas-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'password-encoding': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['ISO-8859-1', 'auto'], 'type': 'str'},
                        'password-renewal': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-coa': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'radius-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'require-message-authenticator': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'rsso': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rsso-context-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'rsso-endpoint-attribute': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': [
                                'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                                'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id',
                                'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group',
                                'Framed-AppleTalk-Zone', 'Acct-Session-Id', 'Acct-Multi-Session-Id'
                            ],
                            'type': 'str'
                        },
                        'rsso-endpoint-block-attribute': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': [
                                'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                                'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id',
                                'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group',
                                'Framed-AppleTalk-Zone', 'Acct-Session-Id', 'Acct-Multi-Session-Id'
                            ],
                            'type': 'str'
                        },
                        'rsso-ep-one-ip-only': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rsso-flush-ip-session': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rsso-log-flags': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'none', 'protocol-error', 'profile-missing', 'accounting-stop-missed', 'accounting-event', 'radiusd-other',
                                'endpoint-block'
                            ],
                            'elements': 'str'
                        },
                        'rsso-log-period': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'rsso-radius-response': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rsso-radius-server-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'rsso-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'rsso-validate-request-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'secondary-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'secondary-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'server-identity-check': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'sso-attribute': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': [
                                'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                                'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id',
                                'Calling-Station-Id', 'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group',
                                'Framed-AppleTalk-Zone', 'Acct-Session-Id', 'Acct-Multi-Session-Id'
                            ],
                            'type': 'str'
                        },
                        'sso-attribute-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                        'sso-attribute-value-override': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'switch-controller-acct-fast-framedip-detect': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'switch-controller-nas-ip-dynamic': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'switch-controller-service-type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': [
                                'login', 'framed', 'callback-login', 'callback-framed', 'outbound', 'administrative', 'nas-prompt', 'authenticate-only',
                                'callback-nas-prompt', 'call-check', 'callback-administrative'
                            ],
                            'elements': 'str'
                        },
                        'tertiary-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'tertiary-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'tls-min-proto-version': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                            'type': 'str'
                        },
                        'transport-protocol': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['udp', 'tcp', 'tls'], 'type': 'str'},
                        'use-group-for-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'use-management-vdom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'username-case-sensitive': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-ip-interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'group-override-attr-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['filter-Id', 'class'], 'type': 'str'},
                'h3c-compatibility': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['auto', 'specify', 'sdwan'], 'type': 'str'},
                'mac-case': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['uppercase', 'lowercase'], 'type': 'str'},
                'mac-password-delimiter': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                    'type': 'str'
                },
                'mac-username-delimiter': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['hyphen', 'single-hyphen', 'colon', 'none'],
                    'type': 'str'
                },
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'nas-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'nas-id-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['legacy', 'custom', 'hostname'], 'type': 'str'},
                'nas-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'password-encoding': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['ISO-8859-1', 'auto'], 'type': 'str'},
                'password-renewal': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-coa': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'require-message-authenticator': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-context-timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'rsso-endpoint-attribute': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                        'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Zone',
                        'Acct-Session-Id', 'Acct-Multi-Session-Id'
                    ],
                    'type': 'str'
                },
                'rsso-endpoint-block-attribute': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                        'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Zone',
                        'Acct-Session-Id', 'Acct-Multi-Session-Id'
                    ],
                    'type': 'str'
                },
                'rsso-ep-one-ip-only': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-flush-ip-session': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-log-flags': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': [
                        'none', 'protocol-error', 'profile-missing', 'accounting-stop-missed', 'accounting-event', 'radiusd-other', 'endpoint-block'
                    ],
                    'elements': 'str'
                },
                'rsso-log-period': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'rsso-radius-response': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso-radius-server-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'rsso-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'rsso-validate-request-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'secondary-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'secondary-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'sso-attribute': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'User-Name', 'NAS-IP-Address', 'Framed-IP-Address', 'Framed-IP-Netmask', 'Filter-Id', 'Login-IP-Host', 'Reply-Message',
                        'Callback-Number', 'Callback-Id', 'Framed-Route', 'Framed-IPX-Network', 'Class', 'Called-Station-Id', 'Calling-Station-Id',
                        'NAS-Identifier', 'Proxy-State', 'Login-LAT-Service', 'Login-LAT-Node', 'Login-LAT-Group', 'Framed-AppleTalk-Zone',
                        'Acct-Session-Id', 'Acct-Multi-Session-Id'
                    ],
                    'type': 'str'
                },
                'sso-attribute-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'sso-attribute-value-override': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'switch-controller-acct-fast-framedip-detect': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'switch-controller-service-type': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': [
                        'login', 'framed', 'callback-login', 'callback-framed', 'outbound', 'administrative', 'nas-prompt', 'authenticate-only',
                        'callback-nas-prompt', 'call-check', 'callback-administrative'
                    ],
                    'elements': 'str'
                },
                'tertiary-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'tertiary-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'timeout': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'use-management-vdom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username-case-sensitive': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tls-min-proto-version': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'status-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'account-key-cert-field': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['othername', 'rfc822name', 'dnsname', 'cn'],
                    'type': 'str'
                },
                'switch-controller-nas-ip-dynamic': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'account-key-processing': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['same', 'strip'], 'type': 'str'},
                'server-identity-check': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transport-protocol': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['udp', 'tcp', 'tls'], 'type': 'str'},
                'client-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'ca-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'call-station-id-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['legacy', 'IP', 'MAC'], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_radius'),
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
