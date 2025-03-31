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
module: fmgd_router_bgp_neighborgroup
short_description: BGP neighbor group table.
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
    router_bgp_neighborgroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            activate:
                type: str
                description: Enable/disable address family IPv4 for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            activate_evpn:
                aliases: ['activate-evpn']
                type: str
                description: Enable/disable address family L2VPN EVPN for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            activate_vpnv4:
                aliases: ['activate-vpnv4']
                type: str
                description: Enable/disable address family VPNv4 for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            activate_vpnv6:
                aliases: ['activate-vpnv6']
                type: str
                description: Enable/disable address family VPNv6 for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            activate6:
                type: str
                description: Enable/disable address family IPv6 for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            additional_path:
                aliases: ['additional-path']
                type: str
                description: Enable/disable IPv4 additional-path capability.
                choices:
                    - 'send'
                    - 'receive'
                    - 'both'
                    - 'disable'
            additional_path_vpnv4:
                aliases: ['additional-path-vpnv4']
                type: str
                description: Enable/disable VPNv4 additional-path capability.
                choices:
                    - 'send'
                    - 'receive'
                    - 'both'
                    - 'disable'
            additional_path_vpnv6:
                aliases: ['additional-path-vpnv6']
                type: str
                description: Enable/disable VPNv6 additional-path capability.
                choices:
                    - 'send'
                    - 'receive'
                    - 'both'
                    - 'disable'
            additional_path6:
                aliases: ['additional-path6']
                type: str
                description: Enable/disable IPv6 additional-path capability.
                choices:
                    - 'send'
                    - 'receive'
                    - 'both'
                    - 'disable'
            adv_additional_path:
                aliases: ['adv-additional-path']
                type: int
                description: Number of IPv4 additional paths that can be advertised to this neighbor.
            adv_additional_path_vpnv4:
                aliases: ['adv-additional-path-vpnv4']
                type: int
                description: Number of VPNv4 additional paths that can be advertised to this neighbor.
            adv_additional_path_vpnv6:
                aliases: ['adv-additional-path-vpnv6']
                type: int
                description: Number of VPNv6 additional paths that can be advertised to this neighbor.
            adv_additional_path6:
                aliases: ['adv-additional-path6']
                type: int
                description: Number of IPv6 additional paths that can be advertised to this neighbor.
            advertisement_interval:
                aliases: ['advertisement-interval']
                type: int
                description: Minimum interval
            allowas_in:
                aliases: ['allowas-in']
                type: int
                description: IPv4 The maximum number of occurrence of my AS number allowed.
            allowas_in_enable:
                aliases: ['allowas-in-enable']
                type: str
                description: Enable/disable IPv4 Enable to allow my AS in AS path.
                choices:
                    - 'disable'
                    - 'enable'
            allowas_in_enable_evpn:
                aliases: ['allowas-in-enable-evpn']
                type: str
                description: Enable/disable to allow my AS in AS path for L2VPN EVPN route.
                choices:
                    - 'disable'
                    - 'enable'
            allowas_in_enable_vpnv4:
                aliases: ['allowas-in-enable-vpnv4']
                type: str
                description: Enable/disable to allow my AS in AS path for VPNv4 route.
                choices:
                    - 'disable'
                    - 'enable'
            allowas_in_enable_vpnv6:
                aliases: ['allowas-in-enable-vpnv6']
                type: str
                description: Enable/disable use of my AS in AS path for VPNv6 route.
                choices:
                    - 'disable'
                    - 'enable'
            allowas_in_enable6:
                aliases: ['allowas-in-enable6']
                type: str
                description: Enable/disable IPv6 Enable to allow my AS in AS path.
                choices:
                    - 'disable'
                    - 'enable'
            allowas_in_evpn:
                aliases: ['allowas-in-evpn']
                type: int
                description: The maximum number of occurrence of my AS number allowed for L2VPN EVPN route.
            allowas_in_vpnv4:
                aliases: ['allowas-in-vpnv4']
                type: int
                description: The maximum number of occurrence of my AS number allowed for VPNv4 route.
            allowas_in_vpnv6:
                aliases: ['allowas-in-vpnv6']
                type: int
                description: The maximum number of occurrence of my AS number allowed for VPNv6 route.
            allowas_in6:
                aliases: ['allowas-in6']
                type: int
                description: IPv6 The maximum number of occurrence of my AS number allowed.
            as_override:
                aliases: ['as-override']
                type: str
                description: Enable/disable replace peer AS with own AS for IPv4.
                choices:
                    - 'disable'
                    - 'enable'
            as_override6:
                aliases: ['as-override6']
                type: str
                description: Enable/disable replace peer AS with own AS for IPv6.
                choices:
                    - 'disable'
                    - 'enable'
            attribute_unchanged:
                aliases: ['attribute-unchanged']
                type: list
                elements: str
                description: IPv4 List of attributes that should be unchanged.
                choices:
                    - 'as-path'
                    - 'med'
                    - 'next-hop'
            attribute_unchanged_vpnv4:
                aliases: ['attribute-unchanged-vpnv4']
                type: list
                elements: str
                description: List of attributes that should be unchanged for VPNv4 route.
                choices:
                    - 'as-path'
                    - 'med'
                    - 'next-hop'
            attribute_unchanged_vpnv6:
                aliases: ['attribute-unchanged-vpnv6']
                type: list
                elements: str
                description: List of attributes that should not be changed for VPNv6 route.
                choices:
                    - 'as-path'
                    - 'med'
                    - 'next-hop'
            attribute_unchanged6:
                aliases: ['attribute-unchanged6']
                type: list
                elements: str
                description: IPv6 List of attributes that should be unchanged.
                choices:
                    - 'as-path'
                    - 'med'
                    - 'next-hop'
            auth_options:
                aliases: ['auth-options']
                type: list
                elements: str
                description: Key-chain name for TCP authentication options.
            bfd:
                type: str
                description: Enable/disable BFD for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_default_originate:
                aliases: ['capability-default-originate']
                type: str
                description: Enable/disable advertise default IPv4 route to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_default_originate6:
                aliases: ['capability-default-originate6']
                type: str
                description: Enable/disable advertise default IPv6 route to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_dynamic:
                aliases: ['capability-dynamic']
                type: str
                description: Enable/disable advertise dynamic capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_graceful_restart:
                aliases: ['capability-graceful-restart']
                type: str
                description: Enable/disable advertise IPv4 graceful restart capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_graceful_restart_evpn:
                aliases: ['capability-graceful-restart-evpn']
                type: str
                description: Enable/disable advertisement of L2VPN EVPN graceful restart capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_graceful_restart_vpnv4:
                aliases: ['capability-graceful-restart-vpnv4']
                type: str
                description: Enable/disable advertise VPNv4 graceful restart capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_graceful_restart_vpnv6:
                aliases: ['capability-graceful-restart-vpnv6']
                type: str
                description: Enable/disable advertisement of VPNv6 graceful restart capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_graceful_restart6:
                aliases: ['capability-graceful-restart6']
                type: str
                description: Enable/disable advertise IPv6 graceful restart capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            capability_orf:
                aliases: ['capability-orf']
                type: str
                description: Accept/Send IPv4 ORF lists to/from this neighbor.
                choices:
                    - 'none'
                    - 'send'
                    - 'receive'
                    - 'both'
            capability_orf6:
                aliases: ['capability-orf6']
                type: str
                description: Accept/Send IPv6 ORF lists to/from this neighbor.
                choices:
                    - 'none'
                    - 'send'
                    - 'receive'
                    - 'both'
            capability_route_refresh:
                aliases: ['capability-route-refresh']
                type: str
                description: Enable/disable advertise route refresh capability to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            connect_timer:
                aliases: ['connect-timer']
                type: int
                description: Interval
            default_originate_routemap:
                aliases: ['default-originate-routemap']
                type: list
                elements: str
                description: Route map to specify criteria to originate IPv4 default.
            default_originate_routemap6:
                aliases: ['default-originate-routemap6']
                type: list
                elements: str
                description: Route map to specify criteria to originate IPv6 default.
            description:
                type: str
                description: Description.
            distribute_list_in:
                aliases: ['distribute-list-in']
                type: list
                elements: str
                description: Filter for IPv4 updates from this neighbor.
            distribute_list_in_vpnv4:
                aliases: ['distribute-list-in-vpnv4']
                type: list
                elements: str
                description: Filter for VPNv4 updates from this neighbor.
            distribute_list_in_vpnv6:
                aliases: ['distribute-list-in-vpnv6']
                type: list
                elements: str
                description: Filter for VPNv6 updates from this neighbor.
            distribute_list_in6:
                aliases: ['distribute-list-in6']
                type: list
                elements: str
                description: Filter for IPv6 updates from this neighbor.
            distribute_list_out:
                aliases: ['distribute-list-out']
                type: list
                elements: str
                description: Filter for IPv4 updates to this neighbor.
            distribute_list_out_vpnv4:
                aliases: ['distribute-list-out-vpnv4']
                type: list
                elements: str
                description: Filter for VPNv4 updates to this neighbor.
            distribute_list_out_vpnv6:
                aliases: ['distribute-list-out-vpnv6']
                type: list
                elements: str
                description: Filter for VPNv6 updates to this neighbor.
            distribute_list_out6:
                aliases: ['distribute-list-out6']
                type: list
                elements: str
                description: Filter for IPv6 updates to this neighbor.
            dont_capability_negotiate:
                aliases: ['dont-capability-negotiate']
                type: str
                description: Do not negotiate capabilities with this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            ebgp_enforce_multihop:
                aliases: ['ebgp-enforce-multihop']
                type: str
                description: Enable/disable allow multi-hop EBGP neighbors.
                choices:
                    - 'disable'
                    - 'enable'
            ebgp_multihop_ttl:
                aliases: ['ebgp-multihop-ttl']
                type: int
                description: EBGP multihop TTL for this peer.
            filter_list_in:
                aliases: ['filter-list-in']
                type: list
                elements: str
                description: BGP filter for IPv4 inbound routes.
            filter_list_in_vpnv4:
                aliases: ['filter-list-in-vpnv4']
                type: list
                elements: str
                description: BGP filter for VPNv4 inbound routes.
            filter_list_in_vpnv6:
                aliases: ['filter-list-in-vpnv6']
                type: list
                elements: str
                description: BGP filter for VPNv6 inbound routes.
            filter_list_in6:
                aliases: ['filter-list-in6']
                type: list
                elements: str
                description: BGP filter for IPv6 inbound routes.
            filter_list_out:
                aliases: ['filter-list-out']
                type: list
                elements: str
                description: BGP filter for IPv4 outbound routes.
            filter_list_out_vpnv4:
                aliases: ['filter-list-out-vpnv4']
                type: list
                elements: str
                description: BGP filter for VPNv4 outbound routes.
            filter_list_out_vpnv6:
                aliases: ['filter-list-out-vpnv6']
                type: list
                elements: str
                description: BGP filter for VPNv6 outbound routes.
            filter_list_out6:
                aliases: ['filter-list-out6']
                type: list
                elements: str
                description: BGP filter for IPv6 outbound routes.
            holdtime_timer:
                aliases: ['holdtime-timer']
                type: int
                description: Interval
            interface:
                type: list
                elements: str
                description: Specify outgoing interface for peer connection.
            keep_alive_timer:
                aliases: ['keep-alive-timer']
                type: int
                description: Keep alive timer interval
            link_down_failover:
                aliases: ['link-down-failover']
                type: str
                description: Enable/disable failover upon link down.
                choices:
                    - 'disable'
                    - 'enable'
            local_as:
                aliases: ['local-as']
                type: int
                description: Local AS number of neighbor.
            local_as_no_prepend:
                aliases: ['local-as-no-prepend']
                type: str
                description: Do not prepend local-as to incoming updates.
                choices:
                    - 'disable'
                    - 'enable'
            local_as_replace_as:
                aliases: ['local-as-replace-as']
                type: str
                description: Replace real AS with local-as in outgoing updates.
                choices:
                    - 'disable'
                    - 'enable'
            maximum_prefix:
                aliases: ['maximum-prefix']
                type: int
                description: Maximum number of IPv4 prefixes to accept from this peer.
            maximum_prefix_evpn:
                aliases: ['maximum-prefix-evpn']
                type: int
                description: Maximum number of L2VPN EVPN prefixes to accept from this peer.
            maximum_prefix_threshold:
                aliases: ['maximum-prefix-threshold']
                type: int
                description: Maximum IPv4 prefix threshold value
            maximum_prefix_threshold_evpn:
                aliases: ['maximum-prefix-threshold-evpn']
                type: int
                description: Maximum L2VPN EVPN prefix threshold value
            maximum_prefix_threshold_vpnv4:
                aliases: ['maximum-prefix-threshold-vpnv4']
                type: int
                description: Maximum VPNv4 prefix threshold value
            maximum_prefix_threshold_vpnv6:
                aliases: ['maximum-prefix-threshold-vpnv6']
                type: int
                description: Maximum VPNv6 prefix threshold value
            maximum_prefix_threshold6:
                aliases: ['maximum-prefix-threshold6']
                type: int
                description: Maximum IPv6 prefix threshold value
            maximum_prefix_vpnv4:
                aliases: ['maximum-prefix-vpnv4']
                type: int
                description: Maximum number of VPNv4 prefixes to accept from this peer.
            maximum_prefix_vpnv6:
                aliases: ['maximum-prefix-vpnv6']
                type: int
                description: Maximum number of VPNv6 prefixes to accept from this peer.
            maximum_prefix_warning_only:
                aliases: ['maximum-prefix-warning-only']
                type: str
                description: Enable/disable IPv4 Only give warning message when limit is exceeded.
                choices:
                    - 'disable'
                    - 'enable'
            maximum_prefix_warning_only_evpn:
                aliases: ['maximum-prefix-warning-only-evpn']
                type: str
                description: Enable/disable only sending warning message when exceeding limit of L2VPN EVPN routes.
                choices:
                    - 'disable'
                    - 'enable'
            maximum_prefix_warning_only_vpnv4:
                aliases: ['maximum-prefix-warning-only-vpnv4']
                type: str
                description: Enable/disable only giving warning message when limit is exceeded for VPNv4 routes.
                choices:
                    - 'disable'
                    - 'enable'
            maximum_prefix_warning_only_vpnv6:
                aliases: ['maximum-prefix-warning-only-vpnv6']
                type: str
                description: Enable/disable warning message when limit is exceeded for VPNv6 routes.
                choices:
                    - 'disable'
                    - 'enable'
            maximum_prefix_warning_only6:
                aliases: ['maximum-prefix-warning-only6']
                type: str
                description: Enable/disable IPv6 Only give warning message when limit is exceeded.
                choices:
                    - 'disable'
                    - 'enable'
            maximum_prefix6:
                aliases: ['maximum-prefix6']
                type: int
                description: Maximum number of IPv6 prefixes to accept from this peer.
            name:
                type: str
                description: Neighbor group name.
                required: true
            next_hop_self:
                aliases: ['next-hop-self']
                type: str
                description: Enable/disable IPv4 next-hop calculation for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            next_hop_self_rr:
                aliases: ['next-hop-self-rr']
                type: str
                description: Enable/disable setting nexthops address to interfaces IPv4 address for route-reflector routes.
                choices:
                    - 'disable'
                    - 'enable'
            next_hop_self_rr6:
                aliases: ['next-hop-self-rr6']
                type: str
                description: Enable/disable setting nexthops address to interfaces IPv6 address for route-reflector routes.
                choices:
                    - 'disable'
                    - 'enable'
            next_hop_self_vpnv4:
                aliases: ['next-hop-self-vpnv4']
                type: str
                description: Enable/disable setting VPNv4 next-hop to interfaces IP address for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            next_hop_self_vpnv6:
                aliases: ['next-hop-self-vpnv6']
                type: str
                description: Enable/disable use of outgoing interfaces IP address as VPNv6 next-hop for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            next_hop_self6:
                aliases: ['next-hop-self6']
                type: str
                description: Enable/disable IPv6 next-hop calculation for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            override_capability:
                aliases: ['override-capability']
                type: str
                description: Enable/disable override result of capability negotiation.
                choices:
                    - 'disable'
                    - 'enable'
            passive:
                type: str
                description: Enable/disable sending of open messages to this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            password:
                type: list
                elements: str
                description: Password used in MD5 authentication.
            prefix_list_in:
                aliases: ['prefix-list-in']
                type: list
                elements: str
                description: IPv4 Inbound filter for updates from this neighbor.
            prefix_list_in_vpnv4:
                aliases: ['prefix-list-in-vpnv4']
                type: list
                elements: str
                description: Inbound filter for VPNv4 updates from this neighbor.
            prefix_list_in_vpnv6:
                aliases: ['prefix-list-in-vpnv6']
                type: list
                elements: str
                description: Inbound filter for VPNv6 updates from this neighbor.
            prefix_list_in6:
                aliases: ['prefix-list-in6']
                type: list
                elements: str
                description: IPv6 Inbound filter for updates from this neighbor.
            prefix_list_out:
                aliases: ['prefix-list-out']
                type: list
                elements: str
                description: IPv4 Outbound filter for updates to this neighbor.
            prefix_list_out_vpnv4:
                aliases: ['prefix-list-out-vpnv4']
                type: list
                elements: str
                description: Outbound filter for VPNv4 updates to this neighbor.
            prefix_list_out_vpnv6:
                aliases: ['prefix-list-out-vpnv6']
                type: list
                elements: str
                description: Outbound filter for VPNv6 updates to this neighbor.
            prefix_list_out6:
                aliases: ['prefix-list-out6']
                type: list
                elements: str
                description: IPv6 Outbound filter for updates to this neighbor.
            remote_as:
                aliases: ['remote-as']
                type: int
                description: AS number of neighbor.
            remote_as_filter:
                aliases: ['remote-as-filter']
                type: list
                elements: str
                description: BGP filter for remote AS.
            remove_private_as:
                aliases: ['remove-private-as']
                type: str
                description: Enable/disable remove private AS number from IPv4 outbound updates.
                choices:
                    - 'disable'
                    - 'enable'
            remove_private_as_evpn:
                aliases: ['remove-private-as-evpn']
                type: str
                description: Enable/disable removing private AS number from L2VPN EVPN outbound updates.
                choices:
                    - 'disable'
                    - 'enable'
            remove_private_as_vpnv4:
                aliases: ['remove-private-as-vpnv4']
                type: str
                description: Enable/disable remove private AS number from VPNv4 outbound updates.
                choices:
                    - 'disable'
                    - 'enable'
            remove_private_as_vpnv6:
                aliases: ['remove-private-as-vpnv6']
                type: str
                description: Enable/disable to remove private AS number from VPNv6 outbound updates.
                choices:
                    - 'disable'
                    - 'enable'
            remove_private_as6:
                aliases: ['remove-private-as6']
                type: str
                description: Enable/disable remove private AS number from IPv6 outbound updates.
                choices:
                    - 'disable'
                    - 'enable'
            restart_time:
                aliases: ['restart-time']
                type: int
                description: Graceful restart delay time
            retain_stale_time:
                aliases: ['retain-stale-time']
                type: int
                description: Time to retain stale routes.
            route_map_in:
                aliases: ['route-map-in']
                type: list
                elements: str
                description: IPv4 Inbound route map filter.
            route_map_in_evpn:
                aliases: ['route-map-in-evpn']
                type: list
                elements: str
                description: L2VPN EVPN inbound route map filter.
            route_map_in_vpnv4:
                aliases: ['route-map-in-vpnv4']
                type: list
                elements: str
                description: VPNv4 inbound route map filter.
            route_map_in_vpnv6:
                aliases: ['route-map-in-vpnv6']
                type: list
                elements: str
                description: VPNv6 inbound route map filter.
            route_map_in6:
                aliases: ['route-map-in6']
                type: list
                elements: str
                description: IPv6 Inbound route map filter.
            route_map_out:
                aliases: ['route-map-out']
                type: list
                elements: str
                description: IPv4 outbound route map filter.
            route_map_out_evpn:
                aliases: ['route-map-out-evpn']
                type: list
                elements: str
                description: L2VPN EVPN outbound route map filter.
            route_map_out_preferable:
                aliases: ['route-map-out-preferable']
                type: list
                elements: str
                description: IPv4 outbound route map filter if the peer is preferred.
            route_map_out_vpnv4:
                aliases: ['route-map-out-vpnv4']
                type: list
                elements: str
                description: VPNv4 outbound route map filter.
            route_map_out_vpnv4_preferable:
                aliases: ['route-map-out-vpnv4-preferable']
                type: list
                elements: str
                description: VPNv4 outbound route map filter if the peer is preferred.
            route_map_out_vpnv6:
                aliases: ['route-map-out-vpnv6']
                type: list
                elements: str
                description: VPNv6 outbound route map filter.
            route_map_out_vpnv6_preferable:
                aliases: ['route-map-out-vpnv6-preferable']
                type: list
                elements: str
                description: VPNv6 outbound route map filter if this neighbor is preferred.
            route_map_out6:
                aliases: ['route-map-out6']
                type: list
                elements: str
                description: IPv6 Outbound route map filter.
            route_map_out6_preferable:
                aliases: ['route-map-out6-preferable']
                type: list
                elements: str
                description: IPv6 outbound route map filter if the peer is preferred.
            route_reflector_client:
                aliases: ['route-reflector-client']
                type: str
                description: Enable/disable IPv4 AS route reflector client.
                choices:
                    - 'disable'
                    - 'enable'
            route_reflector_client_evpn:
                aliases: ['route-reflector-client-evpn']
                type: str
                description: Enable/disable L2VPN EVPN AS route reflector client for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            route_reflector_client_vpnv4:
                aliases: ['route-reflector-client-vpnv4']
                type: str
                description: Enable/disable VPNv4 AS route reflector client for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            route_reflector_client_vpnv6:
                aliases: ['route-reflector-client-vpnv6']
                type: str
                description: Enable/disable VPNv6 AS route reflector client for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            route_reflector_client6:
                aliases: ['route-reflector-client6']
                type: str
                description: Enable/disable IPv6 AS route reflector client.
                choices:
                    - 'disable'
                    - 'enable'
            route_server_client:
                aliases: ['route-server-client']
                type: str
                description: Enable/disable IPv4 AS route server client.
                choices:
                    - 'disable'
                    - 'enable'
            route_server_client_evpn:
                aliases: ['route-server-client-evpn']
                type: str
                description: Enable/disable L2VPN EVPN AS route server client for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            route_server_client_vpnv4:
                aliases: ['route-server-client-vpnv4']
                type: str
                description: Enable/disable VPNv4 AS route server client for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            route_server_client_vpnv6:
                aliases: ['route-server-client-vpnv6']
                type: str
                description: Enable/disable VPNv6 AS route server client for this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            route_server_client6:
                aliases: ['route-server-client6']
                type: str
                description: Enable/disable IPv6 AS route server client.
                choices:
                    - 'disable'
                    - 'enable'
            send_community:
                aliases: ['send-community']
                type: str
                description: IPv4 Send community attribute to neighbor.
                choices:
                    - 'disable'
                    - 'standard'
                    - 'extended'
                    - 'both'
            send_community_evpn:
                aliases: ['send-community-evpn']
                type: str
                description: Enable/disable sending community attribute to neighbor for L2VPN EVPN address family.
                choices:
                    - 'disable'
                    - 'standard'
                    - 'extended'
                    - 'both'
            send_community_vpnv4:
                aliases: ['send-community-vpnv4']
                type: str
                description: Send community attribute to neighbor for VPNv4 address family.
                choices:
                    - 'disable'
                    - 'standard'
                    - 'extended'
                    - 'both'
            send_community_vpnv6:
                aliases: ['send-community-vpnv6']
                type: str
                description: Enable/disable sending community attribute to this neighbor for VPNv6 address family.
                choices:
                    - 'disable'
                    - 'standard'
                    - 'extended'
                    - 'both'
            send_community6:
                aliases: ['send-community6']
                type: str
                description: IPv6 Send community attribute to neighbor.
                choices:
                    - 'disable'
                    - 'standard'
                    - 'extended'
                    - 'both'
            shutdown:
                type: str
                description: Enable/disable shutdown this neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            soft_reconfiguration:
                aliases: ['soft-reconfiguration']
                type: str
                description: Enable/disable allow IPv4 inbound soft reconfiguration.
                choices:
                    - 'disable'
                    - 'enable'
            soft_reconfiguration_evpn:
                aliases: ['soft-reconfiguration-evpn']
                type: str
                description: Enable/disable L2VPN EVPN inbound soft reconfiguration.
                choices:
                    - 'disable'
                    - 'enable'
            soft_reconfiguration_vpnv4:
                aliases: ['soft-reconfiguration-vpnv4']
                type: str
                description: Enable/disable allow VPNv4 inbound soft reconfiguration.
                choices:
                    - 'disable'
                    - 'enable'
            soft_reconfiguration_vpnv6:
                aliases: ['soft-reconfiguration-vpnv6']
                type: str
                description: Enable/disable VPNv6 inbound soft reconfiguration.
                choices:
                    - 'disable'
                    - 'enable'
            soft_reconfiguration6:
                aliases: ['soft-reconfiguration6']
                type: str
                description: Enable/disable allow IPv6 inbound soft reconfiguration.
                choices:
                    - 'disable'
                    - 'enable'
            stale_route:
                aliases: ['stale-route']
                type: str
                description: Enable/disable stale route after neighbor down.
                choices:
                    - 'disable'
                    - 'enable'
            strict_capability_match:
                aliases: ['strict-capability-match']
                type: str
                description: Enable/disable strict capability matching.
                choices:
                    - 'disable'
                    - 'enable'
            unsuppress_map:
                aliases: ['unsuppress-map']
                type: list
                elements: str
                description: IPv4 Route map to selectively unsuppress suppressed routes.
            unsuppress_map6:
                aliases: ['unsuppress-map6']
                type: list
                elements: str
                description: IPv6 Route map to selectively unsuppress suppressed routes.
            update_source:
                aliases: ['update-source']
                type: list
                elements: str
                description: Interface to use as source IP/IPv6 address of TCP connections.
            weight:
                type: int
                description: Neighbor weight.
            rr_attr_allow_change:
                aliases: ['rr-attr-allow-change']
                type: str
                description: Enable/disable allowing change of route attributes when advertising to IPv4 route reflector clients.
                choices:
                    - 'disable'
                    - 'enable'
            rr_attr_allow_change_evpn:
                aliases: ['rr-attr-allow-change-evpn']
                type: str
                description: Enable/disable allowing change of route attributes when advertising to L2VPN EVPN route reflector clients.
                choices:
                    - 'disable'
                    - 'enable'
            rr_attr_allow_change_vpnv4:
                aliases: ['rr-attr-allow-change-vpnv4']
                type: str
                description: Enable/disable allowing change of route attributes when advertising to VPNv4 route reflector clients.
                choices:
                    - 'disable'
                    - 'enable'
            rr_attr_allow_change_vpnv6:
                aliases: ['rr-attr-allow-change-vpnv6']
                type: str
                description: Enable/disable allowing change of route attributes when advertising to VPNv6 route reflector clients.
                choices:
                    - 'disable'
                    - 'enable'
            rr_attr_allow_change6:
                aliases: ['rr-attr-allow-change6']
                type: str
                description: Enable/disable allowing change of route attributes when advertising to IPv6 route reflector clients.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: BGP neighbor group table.
      fortinet.fmgdevice.fmgd_router_bgp_neighborgroup:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_bgp_neighborgroup:
          name: "your value" # Required variable, string
          # activate: <value in [disable, enable]>
          # activate_evpn: <value in [disable, enable]>
          # activate_vpnv4: <value in [disable, enable]>
          # activate_vpnv6: <value in [disable, enable]>
          # activate6: <value in [disable, enable]>
          # additional_path: <value in [send, receive, both, ...]>
          # additional_path_vpnv4: <value in [send, receive, both, ...]>
          # additional_path_vpnv6: <value in [send, receive, both, ...]>
          # additional_path6: <value in [send, receive, both, ...]>
          # adv_additional_path: <integer>
          # adv_additional_path_vpnv4: <integer>
          # adv_additional_path_vpnv6: <integer>
          # adv_additional_path6: <integer>
          # advertisement_interval: <integer>
          # allowas_in: <integer>
          # allowas_in_enable: <value in [disable, enable]>
          # allowas_in_enable_evpn: <value in [disable, enable]>
          # allowas_in_enable_vpnv4: <value in [disable, enable]>
          # allowas_in_enable_vpnv6: <value in [disable, enable]>
          # allowas_in_enable6: <value in [disable, enable]>
          # allowas_in_evpn: <integer>
          # allowas_in_vpnv4: <integer>
          # allowas_in_vpnv6: <integer>
          # allowas_in6: <integer>
          # as_override: <value in [disable, enable]>
          # as_override6: <value in [disable, enable]>
          # attribute_unchanged:
          #   - "as-path"
          #   - "med"
          #   - "next-hop"
          # attribute_unchanged_vpnv4:
          #   - "as-path"
          #   - "med"
          #   - "next-hop"
          # attribute_unchanged_vpnv6:
          #   - "as-path"
          #   - "med"
          #   - "next-hop"
          # attribute_unchanged6:
          #   - "as-path"
          #   - "med"
          #   - "next-hop"
          # auth_options: <list or string>
          # bfd: <value in [disable, enable]>
          # capability_default_originate: <value in [disable, enable]>
          # capability_default_originate6: <value in [disable, enable]>
          # capability_dynamic: <value in [disable, enable]>
          # capability_graceful_restart: <value in [disable, enable]>
          # capability_graceful_restart_evpn: <value in [disable, enable]>
          # capability_graceful_restart_vpnv4: <value in [disable, enable]>
          # capability_graceful_restart_vpnv6: <value in [disable, enable]>
          # capability_graceful_restart6: <value in [disable, enable]>
          # capability_orf: <value in [none, send, receive, ...]>
          # capability_orf6: <value in [none, send, receive, ...]>
          # capability_route_refresh: <value in [disable, enable]>
          # connect_timer: <integer>
          # default_originate_routemap: <list or string>
          # default_originate_routemap6: <list or string>
          # description: <string>
          # distribute_list_in: <list or string>
          # distribute_list_in_vpnv4: <list or string>
          # distribute_list_in_vpnv6: <list or string>
          # distribute_list_in6: <list or string>
          # distribute_list_out: <list or string>
          # distribute_list_out_vpnv4: <list or string>
          # distribute_list_out_vpnv6: <list or string>
          # distribute_list_out6: <list or string>
          # dont_capability_negotiate: <value in [disable, enable]>
          # ebgp_enforce_multihop: <value in [disable, enable]>
          # ebgp_multihop_ttl: <integer>
          # filter_list_in: <list or string>
          # filter_list_in_vpnv4: <list or string>
          # filter_list_in_vpnv6: <list or string>
          # filter_list_in6: <list or string>
          # filter_list_out: <list or string>
          # filter_list_out_vpnv4: <list or string>
          # filter_list_out_vpnv6: <list or string>
          # filter_list_out6: <list or string>
          # holdtime_timer: <integer>
          # interface: <list or string>
          # keep_alive_timer: <integer>
          # link_down_failover: <value in [disable, enable]>
          # local_as: <integer>
          # local_as_no_prepend: <value in [disable, enable]>
          # local_as_replace_as: <value in [disable, enable]>
          # maximum_prefix: <integer>
          # maximum_prefix_evpn: <integer>
          # maximum_prefix_threshold: <integer>
          # maximum_prefix_threshold_evpn: <integer>
          # maximum_prefix_threshold_vpnv4: <integer>
          # maximum_prefix_threshold_vpnv6: <integer>
          # maximum_prefix_threshold6: <integer>
          # maximum_prefix_vpnv4: <integer>
          # maximum_prefix_vpnv6: <integer>
          # maximum_prefix_warning_only: <value in [disable, enable]>
          # maximum_prefix_warning_only_evpn: <value in [disable, enable]>
          # maximum_prefix_warning_only_vpnv4: <value in [disable, enable]>
          # maximum_prefix_warning_only_vpnv6: <value in [disable, enable]>
          # maximum_prefix_warning_only6: <value in [disable, enable]>
          # maximum_prefix6: <integer>
          # next_hop_self: <value in [disable, enable]>
          # next_hop_self_rr: <value in [disable, enable]>
          # next_hop_self_rr6: <value in [disable, enable]>
          # next_hop_self_vpnv4: <value in [disable, enable]>
          # next_hop_self_vpnv6: <value in [disable, enable]>
          # next_hop_self6: <value in [disable, enable]>
          # override_capability: <value in [disable, enable]>
          # passive: <value in [disable, enable]>
          # password: <list or string>
          # prefix_list_in: <list or string>
          # prefix_list_in_vpnv4: <list or string>
          # prefix_list_in_vpnv6: <list or string>
          # prefix_list_in6: <list or string>
          # prefix_list_out: <list or string>
          # prefix_list_out_vpnv4: <list or string>
          # prefix_list_out_vpnv6: <list or string>
          # prefix_list_out6: <list or string>
          # remote_as: <integer>
          # remote_as_filter: <list or string>
          # remove_private_as: <value in [disable, enable]>
          # remove_private_as_evpn: <value in [disable, enable]>
          # remove_private_as_vpnv4: <value in [disable, enable]>
          # remove_private_as_vpnv6: <value in [disable, enable]>
          # remove_private_as6: <value in [disable, enable]>
          # restart_time: <integer>
          # retain_stale_time: <integer>
          # route_map_in: <list or string>
          # route_map_in_evpn: <list or string>
          # route_map_in_vpnv4: <list or string>
          # route_map_in_vpnv6: <list or string>
          # route_map_in6: <list or string>
          # route_map_out: <list or string>
          # route_map_out_evpn: <list or string>
          # route_map_out_preferable: <list or string>
          # route_map_out_vpnv4: <list or string>
          # route_map_out_vpnv4_preferable: <list or string>
          # route_map_out_vpnv6: <list or string>
          # route_map_out_vpnv6_preferable: <list or string>
          # route_map_out6: <list or string>
          # route_map_out6_preferable: <list or string>
          # route_reflector_client: <value in [disable, enable]>
          # route_reflector_client_evpn: <value in [disable, enable]>
          # route_reflector_client_vpnv4: <value in [disable, enable]>
          # route_reflector_client_vpnv6: <value in [disable, enable]>
          # route_reflector_client6: <value in [disable, enable]>
          # route_server_client: <value in [disable, enable]>
          # route_server_client_evpn: <value in [disable, enable]>
          # route_server_client_vpnv4: <value in [disable, enable]>
          # route_server_client_vpnv6: <value in [disable, enable]>
          # route_server_client6: <value in [disable, enable]>
          # send_community: <value in [disable, standard, extended, ...]>
          # send_community_evpn: <value in [disable, standard, extended, ...]>
          # send_community_vpnv4: <value in [disable, standard, extended, ...]>
          # send_community_vpnv6: <value in [disable, standard, extended, ...]>
          # send_community6: <value in [disable, standard, extended, ...]>
          # shutdown: <value in [disable, enable]>
          # soft_reconfiguration: <value in [disable, enable]>
          # soft_reconfiguration_evpn: <value in [disable, enable]>
          # soft_reconfiguration_vpnv4: <value in [disable, enable]>
          # soft_reconfiguration_vpnv6: <value in [disable, enable]>
          # soft_reconfiguration6: <value in [disable, enable]>
          # stale_route: <value in [disable, enable]>
          # strict_capability_match: <value in [disable, enable]>
          # unsuppress_map: <list or string>
          # unsuppress_map6: <list or string>
          # update_source: <list or string>
          # weight: <integer>
          # rr_attr_allow_change: <value in [disable, enable]>
          # rr_attr_allow_change_evpn: <value in [disable, enable]>
          # rr_attr_allow_change_vpnv4: <value in [disable, enable]>
          # rr_attr_allow_change_vpnv6: <value in [disable, enable]>
          # rr_attr_allow_change6: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-group'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_bgp_neighborgroup': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'activate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'activate-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'activate-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'activate-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'activate6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'additional-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['send', 'receive', 'both', 'disable'], 'type': 'str'},
                'additional-path-vpnv4': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['send', 'receive', 'both', 'disable'],
                    'type': 'str'
                },
                'additional-path-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['send', 'receive', 'both', 'disable'], 'type': 'str'},
                'additional-path6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['send', 'receive', 'both', 'disable'], 'type': 'str'},
                'adv-additional-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'adv-additional-path-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'adv-additional-path-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'adv-additional-path6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'advertisement-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'allowas-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'allowas-in-enable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allowas-in-enable-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allowas-in-enable-vpnv4': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allowas-in-enable-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allowas-in-enable6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'allowas-in-evpn': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'allowas-in-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'allowas-in-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'allowas-in6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'as-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'as-override6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'attribute-unchanged': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['as-path', 'med', 'next-hop'],
                    'elements': 'str'
                },
                'attribute-unchanged-vpnv4': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['as-path', 'med', 'next-hop'],
                    'elements': 'str'
                },
                'attribute-unchanged-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'choices': ['as-path', 'med', 'next-hop'], 'elements': 'str'},
                'attribute-unchanged6': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['as-path', 'med', 'next-hop'],
                    'elements': 'str'
                },
                'auth-options': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-default-originate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-default-originate6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-dynamic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-graceful-restart': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-graceful-restart-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-graceful-restart-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-graceful-restart-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-graceful-restart6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability-orf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'send', 'receive', 'both'], 'type': 'str'},
                'capability-orf6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'send', 'receive', 'both'], 'type': 'str'},
                'capability-route-refresh': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'connect-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'default-originate-routemap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'default-originate-routemap6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'distribute-list-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-in-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-in-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-in6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-out-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-out-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distribute-list-out6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dont-capability-negotiate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ebgp-enforce-multihop': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ebgp-multihop-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'filter-list-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-in-vpnv4': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-in-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-in6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-out-vpnv4': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-out-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-list-out6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'holdtime-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'keep-alive-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'link-down-failover': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-as': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'local-as-no-prepend': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-as-replace-as': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'maximum-prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-evpn': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-threshold-evpn': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-threshold-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-threshold-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-threshold6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'maximum-prefix-warning-only': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'maximum-prefix-warning-only-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'maximum-prefix-warning-only-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'maximum-prefix-warning-only-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'maximum-prefix-warning-only6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'maximum-prefix6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'next-hop-self': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'next-hop-self-rr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'next-hop-self-rr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'next-hop-self-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'next-hop-self-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'next-hop-self6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-capability': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'passive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'prefix-list-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-in-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-in-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-in6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-out-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-out-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'prefix-list-out6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'remote-as': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'remote-as-filter': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'remove-private-as': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remove-private-as-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remove-private-as-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remove-private-as-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remove-private-as6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'restart-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'retain-stale-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'route-map-in': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-in-evpn': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-in-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-in-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-in6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out-evpn': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out-preferable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out-vpnv4-preferable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out-vpnv6': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out-vpnv6-preferable': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-map-out6-preferable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'route-reflector-client': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-reflector-client-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-reflector-client-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-reflector-client-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-reflector-client6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-server-client': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-server-client-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-server-client-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-server-client-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-server-client6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'send-community': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'standard', 'extended', 'both'], 'type': 'str'},
                'send-community-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'standard', 'extended', 'both'], 'type': 'str'},
                'send-community-vpnv4': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'standard', 'extended', 'both'],
                    'type': 'str'
                },
                'send-community-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'standard', 'extended', 'both'], 'type': 'str'},
                'send-community6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'standard', 'extended', 'both'], 'type': 'str'},
                'shutdown': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'soft-reconfiguration': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'soft-reconfiguration-evpn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'soft-reconfiguration-vpnv4': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'soft-reconfiguration-vpnv6': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'soft-reconfiguration6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'stale-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strict-capability-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unsuppress-map': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'unsuppress-map6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'update-source': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'rr-attr-allow-change': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rr-attr-allow-change-evpn': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rr-attr-allow-change-vpnv4': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rr-attr-allow-change-vpnv6': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rr-attr-allow-change6': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_bgp_neighborgroup'),
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
