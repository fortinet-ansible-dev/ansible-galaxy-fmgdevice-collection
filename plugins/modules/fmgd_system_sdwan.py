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
module: fmgd_system_sdwan
short_description: Configure redundant Internet connections with multiple outbound links and health-check profiles.
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
    system_sdwan:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            app_perf_log_period:
                aliases: ['app-perf-log-period']
                type: int
                description: Time interval in seconds that application performance logs are generated
            duplication:
                type: list
                elements: dict
                description: Duplication.
                suboptions:
                    dstaddr:
                        type: list
                        elements: str
                        description: Destination address or address group names.
                    dstaddr6:
                        type: list
                        elements: str
                        description: Destination address6 or address6 group names.
                    dstintf:
                        type: list
                        elements: str
                        description: Outgoing
                    id:
                        type: int
                        description: Duplication rule ID
                    packet_de_duplication:
                        aliases: ['packet-de-duplication']
                        type: str
                        description: Enable/disable discarding of packets that have been duplicated.
                        choices:
                            - 'disable'
                            - 'enable'
                    packet_duplication:
                        aliases: ['packet-duplication']
                        type: str
                        description: Configure packet duplication method.
                        choices:
                            - 'disable'
                            - 'force'
                            - 'on-demand'
                    service:
                        type: list
                        elements: str
                        description: Service and service group name.
                    service_id:
                        aliases: ['service-id']
                        type: list
                        elements: str
                        description: SD-WAN service rule ID list.
                    sla_match_service:
                        aliases: ['sla-match-service']
                        type: str
                        description: Enable/disable packet duplication matching health-check SLAs in service rule.
                        choices:
                            - 'disable'
                            - 'enable'
                    srcaddr:
                        type: list
                        elements: str
                        description: Source address or address group names.
                    srcaddr6:
                        type: list
                        elements: str
                        description: Source address6 or address6 group names.
                    srcintf:
                        type: list
                        elements: str
                        description: Incoming
            duplication_max_num:
                aliases: ['duplication-max-num']
                type: int
                description: Maximum number of interface members a packet is duplicated in the SD-WAN zone
            fail_alert_interfaces:
                aliases: ['fail-alert-interfaces']
                type: list
                elements: str
                description:
                    - Support meta variable
                    - Physical interfaces that will be alerted.
            fail_detect:
                aliases: ['fail-detect']
                type: str
                description: Enable/disable SD-WAN Internet connection status checking
                choices:
                    - 'disable'
                    - 'enable'
            health_check:
                aliases: ['health-check']
                type: list
                elements: dict
                description: Health check.
                suboptions:
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    class_id:
                        aliases: ['class-id']
                        type: list
                        elements: str
                        description: Traffic class ID.
                    detect_mode:
                        aliases: ['detect-mode']
                        type: str
                        description: The mode determining how to detect the server.
                        choices:
                            - 'active'
                            - 'passive'
                            - 'prefer-passive'
                            - 'remote'
                            - 'agent-based'
                    diffservcode:
                        type: str
                        description: Differentiated services code point
                    dns_match_ip:
                        aliases: ['dns-match-ip']
                        type: str
                        description: Response IP expected from DNS server if the protocol is DNS.
                    dns_request_domain:
                        aliases: ['dns-request-domain']
                        type: str
                        description: Fully qualified domain name to resolve for the DNS probe.
                    embed_measured_health:
                        aliases: ['embed-measured-health']
                        type: str
                        description: Enable/disable embedding measured health information.
                        choices:
                            - 'disable'
                            - 'enable'
                    failtime:
                        type: int
                        description:
                            - Support meta variable
                            - Number of failures before server is considered lost
                    ftp_file:
                        aliases: ['ftp-file']
                        type: str
                        description: Full path and file name on the FTP server to download for FTP health-check to probe.
                    ftp_mode:
                        aliases: ['ftp-mode']
                        type: str
                        description: FTP mode.
                        choices:
                            - 'passive'
                            - 'port'
                    ha_priority:
                        aliases: ['ha-priority']
                        type: int
                        description: HA election priority
                    http_agent:
                        aliases: ['http-agent']
                        type: str
                        description: String in the http-agent field in the HTTP header.
                    http_get:
                        aliases: ['http-get']
                        type: str
                        description: URL used to communicate with the server if the protocol if the protocol is HTTP.
                    http_match:
                        aliases: ['http-match']
                        type: str
                        description: Response string expected from the server if the protocol is HTTP.
                    interval:
                        type: int
                        description:
                            - Support meta variable
                            - Status check interval in milliseconds, or the time between attempting to connect to the server
                    members:
                        type: list
                        elements: str
                        description: Member sequence number list.
                    mos_codec:
                        aliases: ['mos-codec']
                        type: str
                        description: Codec to use for MOS calculation
                        choices:
                            - 'g711'
                            - 'g722'
                            - 'g729'
                    name:
                        type: str
                        description: Status check or health check name.
                    packet_size:
                        aliases: ['packet-size']
                        type: int
                        description: Packet size of a TWAMP test session.
                    password:
                        type: list
                        elements: str
                        description: TWAMP controller password in authentication mode.
                    port:
                        type: int
                        description: Port number used to communicate with the server over the selected protocol
                    probe_count:
                        aliases: ['probe-count']
                        type: int
                        description: Number of most recent probes that should be used to calculate latency and jitter
                    probe_packets:
                        aliases: ['probe-packets']
                        type: str
                        description: Enable/disable transmission of probe packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    probe_timeout:
                        aliases: ['probe-timeout']
                        type: int
                        description:
                            - Support meta variable
                            - Time to wait before a probe packet is considered lost
                    protocol:
                        type: str
                        description: Protocol used to determine if the FortiGate can communicate with the server.
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                            - 'twamp'
                            - 'ping6'
                            - 'dns'
                            - 'tcp-connect'
                            - 'ftp'
                            - 'https'
                    quality_measured_method:
                        aliases: ['quality-measured-method']
                        type: str
                        description: Method to measure the quality of tcp-connect.
                        choices:
                            - 'half-close'
                            - 'half-open'
                    recoverytime:
                        type: int
                        description:
                            - Support meta variable
                            - Number of successful responses received before server is considered recovered
                    security_mode:
                        aliases: ['security-mode']
                        type: str
                        description: Twamp controller security mode.
                        choices:
                            - 'none'
                            - 'authentication'
                    server:
                        type: list
                        elements: str
                        description:
                            - Support meta variable
                            - IP address or FQDN name of the server.
                    sla:
                        type: list
                        elements: dict
                        description: Sla.
                        suboptions:
                            id:
                                type: int
                                description: SLA ID.
                            jitter_threshold:
                                aliases: ['jitter-threshold']
                                type: int
                                description:
                                    - Support meta variable
                                    - Jitter for SLA to make decision in milliseconds.
                            latency_threshold:
                                aliases: ['latency-threshold']
                                type: int
                                description:
                                    - Support meta variable
                                    - Latency for SLA to make decision in milliseconds.
                            link_cost_factor:
                                aliases: ['link-cost-factor']
                                type: list
                                elements: str
                                description: Criteria on which to base link selection.
                                choices:
                                    - 'latency'
                                    - 'jitter'
                                    - 'packet-loss'
                                    - 'mos'
                                    - 'remote'
                            mos_threshold:
                                aliases: ['mos-threshold']
                                type: str
                                description:
                                    - Support meta variable
                                    - Minimum Mean Opinion Score for SLA to be marked as pass.
                            packetloss_threshold:
                                aliases: ['packetloss-threshold']
                                type: int
                                description:
                                    - Support meta variable
                                    - Packet loss for SLA to make decision in percentage.
                            priority_in_sla:
                                aliases: ['priority-in-sla']
                                type: int
                                description: Value to be distributed into routing table when in-sla
                            priority_out_sla:
                                aliases: ['priority-out-sla']
                                type: int
                                description: Value to be distributed into routing table when out-sla
                    sla_fail_log_period:
                        aliases: ['sla-fail-log-period']
                        type: int
                        description: Time interval in seconds that SLA fail log messages will be generated
                    sla_id_redistribute:
                        aliases: ['sla-id-redistribute']
                        type: int
                        description: Select the ID from the SLA sub-table.
                    sla_pass_log_period:
                        aliases: ['sla-pass-log-period']
                        type: int
                        description: Time interval in seconds that SLA pass log messages will be generated
                    source:
                        type: str
                        description:
                            - Support meta variable
                            - Source IP address used in the health-check packet to the server.
                    source6:
                        type: str
                        description: Source IPv6 address used in the health-check packet to server.
                    system_dns:
                        aliases: ['system-dns']
                        type: str
                        description: Enable/disable system DNS as the probe server.
                        choices:
                            - 'disable'
                            - 'enable'
                    threshold_alert_jitter:
                        aliases: ['threshold-alert-jitter']
                        type: int
                        description: Alert threshold for jitter
                    threshold_alert_latency:
                        aliases: ['threshold-alert-latency']
                        type: int
                        description: Alert threshold for latency
                    threshold_alert_packetloss:
                        aliases: ['threshold-alert-packetloss']
                        type: int
                        description: Alert threshold for packet loss
                    threshold_warning_jitter:
                        aliases: ['threshold-warning-jitter']
                        type: int
                        description: Warning threshold for jitter
                    threshold_warning_latency:
                        aliases: ['threshold-warning-latency']
                        type: int
                        description: Warning threshold for latency
                    threshold_warning_packetloss:
                        aliases: ['threshold-warning-packetloss']
                        type: int
                        description: Warning threshold for packet loss
                    update_cascade_interface:
                        aliases: ['update-cascade-interface']
                        type: str
                        description: Enable/disable update cascade interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    update_static_route:
                        aliases: ['update-static-route']
                        type: str
                        description: Enable/disable updating the static route.
                        choices:
                            - 'disable'
                            - 'enable'
                    user:
                        type: str
                        description: The user name to access probe server.
                    vrf:
                        type: int
                        description: Virtual Routing Forwarding ID.
                    fortiguard:
                        type: str
                        description: Enable/disable use of FortiGuard predefined server.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortiguard_name:
                        aliases: ['fortiguard-name']
                        type: list
                        elements: str
                        description: Predefined health-check target name.
            load_balance_mode:
                aliases: ['load-balance-mode']
                type: str
                description: Algorithm or mode to use for load balancing Internet traffic to SD-WAN members.
                choices:
                    - 'source-ip-based'
                    - 'weight-based'
                    - 'usage-based'
                    - 'source-dest-ip-based'
                    - 'measured-volume-based'
            members:
                type: list
                elements: dict
                description: Members.
                suboptions:
                    comment:
                        type: str
                        description: Comments.
                    cost:
                        type: int
                        description:
                            - Support meta variable
                            - Cost of this interface for services in SLA mode
                    gateway:
                        type: str
                        description:
                            - Support meta variable
                            - The default gateway for this interface.
                    gateway6:
                        type: str
                        description:
                            - Support meta variable
                            - IPv6 gateway.
                    ingress_spillover_threshold:
                        aliases: ['ingress-spillover-threshold']
                        type: int
                        description:
                            - Support meta variable
                            - Ingress spillover threshold for this interface
                    interface:
                        type: list
                        elements: str
                        description:
                            - Support meta variable
                            - Interface name.
                    preferred_source:
                        aliases: ['preferred-source']
                        type: str
                        description: Preferred source of route for this member.
                    priority:
                        type: int
                        description:
                            - Support meta variable
                            - Priority of the interface for IPv4
                    priority6:
                        type: int
                        description:
                            - Support meta variable
                            - Priority of the interface for IPv6
                    seq_num:
                        aliases: ['seq-num']
                        type: int
                        description: Sequence number
                    source:
                        type: str
                        description:
                            - Support meta variable
                            - Source IP address used in the health-check packet to the server.
                    source6:
                        type: str
                        description:
                            - Support meta variable
                            - Source IPv6 address used in the health-check packet to the server.
                    spillover_threshold:
                        aliases: ['spillover-threshold']
                        type: int
                        description:
                            - Support meta variable
                            - Egress spillover threshold for this interface
                    status:
                        type: str
                        description: Enable/disable this interface in the SD-WAN.
                        choices:
                            - 'disable'
                            - 'enable'
                    transport_group:
                        aliases: ['transport-group']
                        type: int
                        description: Measured transport group
                    volume_ratio:
                        aliases: ['volume-ratio']
                        type: int
                        description:
                            - Support meta variable
                            - Measured volume ratio
                    weight:
                        type: int
                        description:
                            - Support meta variable
                            - Weight of this interface for weighted load balancing.
                    zone:
                        type: list
                        elements: str
                        description: Zone name.
                    priority_in_sla:
                        aliases: ['priority-in-sla']
                        type: int
                        description: Preferred priority of routes to this member when this member is in-sla
                    priority_out_sla:
                        aliases: ['priority-out-sla']
                        type: int
                        description: Preferred priority of routes to this member when this member is out-of-sla
            neighbor:
                type: list
                elements: dict
                description: Neighbor.
                suboptions:
                    health_check:
                        aliases: ['health-check']
                        type: list
                        elements: str
                        description: SD-WAN health-check name.
                    ip:
                        type: list
                        elements: str
                        description:
                            - Support meta variable
                            - IP/IPv6 address of neighbor or neighbor-group name.
                    member:
                        type: list
                        elements: str
                        description: Member sequence number list.
                    minimum_sla_meet_members:
                        aliases: ['minimum-sla-meet-members']
                        type: int
                        description: Minimum number of members which meet SLA when the neighbor is preferred.
                    mode:
                        type: str
                        description: What metric to select the neighbor.
                        choices:
                            - 'sla'
                            - 'speedtest'
                    role:
                        type: str
                        description: Role of neighbor.
                        choices:
                            - 'primary'
                            - 'secondary'
                            - 'standalone'
                    service_id:
                        aliases: ['service-id']
                        type: list
                        elements: str
                        description: SD-WAN service ID to work with the neighbor.
                    sla_id:
                        aliases: ['sla-id']
                        type: int
                        description: SLA ID.
                    route_metric:
                        aliases: ['route-metric']
                        type: str
                        description: Route-metric of neighbor.
                        choices:
                            - 'preferable'
                            - 'priority'
            neighbor_hold_boot_time:
                aliases: ['neighbor-hold-boot-time']
                type: int
                description: Waiting period in seconds when switching from the primary neighbor to the secondary neighbor from the neighbor start.
            neighbor_hold_down:
                aliases: ['neighbor-hold-down']
                type: str
                description: Enable/disable hold switching from the secondary neighbor to the primary neighbor.
                choices:
                    - 'disable'
                    - 'enable'
            neighbor_hold_down_time:
                aliases: ['neighbor-hold-down-time']
                type: int
                description: Waiting period in seconds when switching from the secondary neighbor to the primary neighbor when hold-down is disabled.
            service:
                type: list
                elements: dict
                description: Service.
                suboptions:
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    agent_exclusive:
                        aliases: ['agent-exclusive']
                        type: str
                        description: Set/unset the service as agent use exclusively.
                        choices:
                            - 'disable'
                            - 'enable'
                    bandwidth_weight:
                        aliases: ['bandwidth-weight']
                        type: int
                        description: Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
                    default:
                        type: str
                        description: Enable/disable use of SD-WAN as default service.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp_forward:
                        aliases: ['dscp-forward']
                        type: str
                        description: Enable/disable forward traffic DSCP tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp_forward_tag:
                        aliases: ['dscp-forward-tag']
                        type: str
                        description: Forward traffic DSCP tag.
                    dscp_reverse:
                        aliases: ['dscp-reverse']
                        type: str
                        description: Enable/disable reverse traffic DSCP tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp_reverse_tag:
                        aliases: ['dscp-reverse-tag']
                        type: str
                        description: Reverse traffic DSCP tag.
                    dst:
                        type: list
                        elements: str
                        description: Destination address name.
                    dst_negate:
                        aliases: ['dst-negate']
                        type: str
                        description: Enable/disable negation of destination address match.
                        choices:
                            - 'disable'
                            - 'enable'
                    dst6:
                        type: list
                        elements: str
                        description: Destination address6 name.
                    end_port:
                        aliases: ['end-port']
                        type: int
                        description: End destination port number.
                    end_src_port:
                        aliases: ['end-src-port']
                        type: int
                        description: End source port number.
                    gateway:
                        type: str
                        description: Enable/disable SD-WAN service gateway.
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: list
                        elements: str
                        description: User groups.
                    hash_mode:
                        aliases: ['hash-mode']
                        type: str
                        description: Hash algorithm for selected priority members for load balance mode.
                        choices:
                            - 'round-robin'
                            - 'source-ip-based'
                            - 'source-dest-ip-based'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                    health_check:
                        aliases: ['health-check']
                        type: list
                        elements: str
                        description: Health check list.
                    hold_down_time:
                        aliases: ['hold-down-time']
                        type: int
                        description: Waiting period in seconds when switching from the back-up member to the primary member
                    id:
                        type: int
                        description: SD-WAN rule ID
                    input_device:
                        aliases: ['input-device']
                        type: list
                        elements: str
                        description: Source interface name.
                    input_device_negate:
                        aliases: ['input-device-negate']
                        type: str
                        description: Enable/disable negation of input device match.
                        choices:
                            - 'disable'
                            - 'enable'
                    input_zone:
                        aliases: ['input-zone']
                        type: list
                        elements: str
                        description: Source input-zone name.
                    internet_service:
                        aliases: ['internet-service']
                        type: str
                        description: Enable/disable use of Internet service for application-based load balancing.
                        choices:
                            - 'disable'
                            - 'enable'
                    internet_service_app_ctrl:
                        aliases: ['internet-service-app-ctrl']
                        type: list
                        elements: int
                        description: Application control based Internet Service ID list.
                    internet_service_app_ctrl_category:
                        aliases: ['internet-service-app-ctrl-category']
                        type: list
                        elements: int
                        description: IDs of one or more application control categories.
                    internet_service_app_ctrl_group:
                        aliases: ['internet-service-app-ctrl-group']
                        type: list
                        elements: str
                        description: Application control based Internet Service group list.
                    internet_service_custom:
                        aliases: ['internet-service-custom']
                        type: list
                        elements: str
                        description: Custom Internet service name list.
                    internet_service_custom_group:
                        aliases: ['internet-service-custom-group']
                        type: list
                        elements: str
                        description: Custom Internet Service group list.
                    internet_service_group:
                        aliases: ['internet-service-group']
                        type: list
                        elements: str
                        description: Internet Service group list.
                    internet_service_name:
                        aliases: ['internet-service-name']
                        type: list
                        elements: str
                        description: Internet service name list.
                    jitter_weight:
                        aliases: ['jitter-weight']
                        type: int
                        description: Coefficient of jitter in the formula of custom-profile-1.
                    latency_weight:
                        aliases: ['latency-weight']
                        type: int
                        description: Coefficient of latency in the formula of custom-profile-1.
                    link_cost_factor:
                        aliases: ['link-cost-factor']
                        type: str
                        description: Link cost factor.
                        choices:
                            - 'latency'
                            - 'jitter'
                            - 'packet-loss'
                            - 'inbandwidth'
                            - 'outbandwidth'
                            - 'bibandwidth'
                            - 'custom-profile-1'
                    link_cost_threshold:
                        aliases: ['link-cost-threshold']
                        type: int
                        description: Percentage threshold change of link cost values that will result in policy route regeneration
                    load_balance:
                        aliases: ['load-balance']
                        type: str
                        description: Enable/disable load-balance.
                        choices:
                            - 'disable'
                            - 'enable'
                    minimum_sla_meet_members:
                        aliases: ['minimum-sla-meet-members']
                        type: int
                        description: Minimum number of members which meet SLA.
                    mode:
                        type: str
                        description: Control how the SD-WAN rule sets the priority of interfaces in the SD-WAN.
                        choices:
                            - 'auto'
                            - 'manual'
                            - 'priority'
                            - 'sla'
                            - 'load-balance'
                    name:
                        type: str
                        description: SD-WAN rule name.
                    packet_loss_weight:
                        aliases: ['packet-loss-weight']
                        type: int
                        description: Coefficient of packet-loss in the formula of custom-profile-1.
                    passive_measurement:
                        aliases: ['passive-measurement']
                        type: str
                        description: Enable/disable passive measurement based on the service criteria.
                        choices:
                            - 'disable'
                            - 'enable'
                    priority_members:
                        aliases: ['priority-members']
                        type: list
                        elements: str
                        description: Member sequence number list.
                    priority_zone:
                        aliases: ['priority-zone']
                        type: list
                        elements: str
                        description: Priority zone name list.
                    protocol:
                        type: int
                        description: Protocol number.
                    quality_link:
                        aliases: ['quality-link']
                        type: int
                        description: Quality grade.
                    role:
                        type: str
                        description: Service role to work with neighbor.
                        choices:
                            - 'primary'
                            - 'secondary'
                            - 'standalone'
                    shortcut:
                        type: str
                        description: Enable/disable shortcut for this service.
                        choices:
                            - 'disable'
                            - 'enable'
                    shortcut_priority:
                        aliases: ['shortcut-priority']
                        type: str
                        description: High priority of ADVPN shortcut for this service.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'auto'
                    sla:
                        type: list
                        elements: dict
                        description: Sla.
                        suboptions:
                            health_check:
                                aliases: ['health-check']
                                type: list
                                elements: str
                                description: SD-WAN health-check.
                            id:
                                type: int
                                description: SLA ID.
                    sla_compare_method:
                        aliases: ['sla-compare-method']
                        type: str
                        description: Method to compare SLA value for SLA mode.
                        choices:
                            - 'order'
                            - 'number'
                    sla_stickiness:
                        aliases: ['sla-stickiness']
                        type: str
                        description: Enable/disable SLA stickiness
                        choices:
                            - 'disable'
                            - 'enable'
                    src:
                        type: list
                        elements: str
                        description: Source address name.
                    src_negate:
                        aliases: ['src-negate']
                        type: str
                        description: Enable/disable negation of source address match.
                        choices:
                            - 'disable'
                            - 'enable'
                    src6:
                        type: list
                        elements: str
                        description: Source address6 name.
                    standalone_action:
                        aliases: ['standalone-action']
                        type: str
                        description: Enable/disable service when selected neighbor role is standalone while service role is not standalone.
                        choices:
                            - 'disable'
                            - 'enable'
                    start_port:
                        aliases: ['start-port']
                        type: int
                        description: Start destination port number.
                    start_src_port:
                        aliases: ['start-src-port']
                        type: int
                        description: Start source port number.
                    status:
                        type: str
                        description: Enable/disable SD-WAN service.
                        choices:
                            - 'disable'
                            - 'enable'
                    tie_break:
                        aliases: ['tie-break']
                        type: str
                        description: Method of selecting member if more than one meets the SLA.
                        choices:
                            - 'zone'
                            - 'cfg-order'
                            - 'fib-best-match'
                            - 'input-device'
                    tos:
                        type: str
                        description: Type of service bit pattern.
                    tos_mask:
                        aliases: ['tos-mask']
                        type: str
                        description: Type of service evaluated bits.
                    use_shortcut_sla:
                        aliases: ['use-shortcut-sla']
                        type: str
                        description: Enable/disable use of ADVPN shortcut for quality comparison.
                        choices:
                            - 'disable'
                            - 'enable'
                    users:
                        type: list
                        elements: str
                        description: User name.
                    zone_mode:
                        aliases: ['zone-mode']
                        type: str
                        description: Enable/disable zone mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    route_tag:
                        aliases: ['route-tag']
                        type: int
                        description: IPv4 route map route-tag.
                    comment:
                        type: str
                        description: Comments.
            speedtest_bypass_routing:
                aliases: ['speedtest-bypass-routing']
                type: str
                description: Enable/disable bypass routing when speedtest on a SD-WAN member.
                choices:
                    - 'disable'
                    - 'enable'
            status:
                type: str
                description: Enable/disable SD-WAN.
                choices:
                    - 'disable'
                    - 'enable'
            zone:
                type: list
                elements: dict
                description: Zone.
                suboptions:
                    advpn_health_check:
                        aliases: ['advpn-health-check']
                        type: list
                        elements: str
                        description: Health check for ADVPN local overlay link quality.
                    advpn_select:
                        aliases: ['advpn-select']
                        type: str
                        description: Enable/disable selection of ADVPN based on SDWAN information.
                        choices:
                            - 'disable'
                            - 'enable'
                    minimum_sla_meet_members:
                        aliases: ['minimum-sla-meet-members']
                        type: int
                        description: Minimum number of members which meet SLA when the neighbor is preferred.
                    name:
                        type: str
                        description: Zone name.
                    service_sla_tie_break:
                        aliases: ['service-sla-tie-break']
                        type: str
                        description: Method of selecting member if more than one meets the SLA.
                        choices:
                            - 'cfg-order'
                            - 'fib-best-match'
                            - 'input-device'
            health_check_fortiguard:
                aliases: ['health-check-fortiguard']
                type: list
                elements: dict
                description: Health check fortiguard.
                suboptions:
                    addr_mode:
                        aliases: ['addr-mode']
                        type: str
                        description: Address mode
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    class_id:
                        aliases: ['class-id']
                        type: list
                        elements: str
                        description: Traffic class ID.
                    detect_mode:
                        aliases: ['detect-mode']
                        type: str
                        description: The mode determining how to detect the server.
                        choices:
                            - 'active'
                            - 'passive'
                            - 'prefer-passive'
                            - 'remote'
                            - 'agent-based'
                    diffservcode:
                        type: str
                        description: Differentiated services code point
                    dns_match_ip:
                        aliases: ['dns-match-ip']
                        type: str
                        description: Response IP expected from DNS server if the protocol is DNS.
                    dns_request_domain:
                        aliases: ['dns-request-domain']
                        type: str
                        description: Fully qualified domain name to resolve for the DNS probe.
                    embed_measured_health:
                        aliases: ['embed-measured-health']
                        type: str
                        description: Enable/disable embedding measured health information.
                        choices:
                            - 'disable'
                            - 'enable'
                    failtime:
                        type: int
                        description: Number of failures before server is considered lost
                    ftp_file:
                        aliases: ['ftp-file']
                        type: str
                        description: Full path and file name on the FTP server to download for FTP health-check to probe.
                    ftp_mode:
                        aliases: ['ftp-mode']
                        type: str
                        description: FTP mode.
                        choices:
                            - 'passive'
                            - 'port'
                    ha_priority:
                        aliases: ['ha-priority']
                        type: int
                        description: HA election priority
                    http_agent:
                        aliases: ['http-agent']
                        type: str
                        description: String in the http-agent field in the HTTP header.
                    http_get:
                        aliases: ['http-get']
                        type: str
                        description: URL used to communicate with the server if the protocol if the protocol is HTTP.
                    http_match:
                        aliases: ['http-match']
                        type: str
                        description: Response string expected from the server if the protocol is HTTP.
                    interval:
                        type: int
                        description: Status check interval in milliseconds, or the time between attempting to connect to the server
                    members:
                        type: list
                        elements: str
                        description: Member sequence number list.
                    mos_codec:
                        aliases: ['mos-codec']
                        type: str
                        description: Codec to use for MOS calculation
                        choices:
                            - 'g711'
                            - 'g722'
                            - 'g729'
                    packet_size:
                        aliases: ['packet-size']
                        type: int
                        description: Packet size of a TWAMP test session.
                    password:
                        type: list
                        elements: str
                        description: TWAMP controller password in authentication mode.
                    port:
                        type: int
                        description: Port number used to communicate with the server over the selected protocol
                    probe_count:
                        aliases: ['probe-count']
                        type: int
                        description: Number of most recent probes that should be used to calculate latency and jitter
                    probe_packets:
                        aliases: ['probe-packets']
                        type: str
                        description: Enable/disable transmission of probe packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    probe_timeout:
                        aliases: ['probe-timeout']
                        type: int
                        description: Time to wait before a probe packet is considered lost
                    protocol:
                        type: str
                        description: Protocol used to determine if the FortiGate can communicate with the server.
                        choices:
                            - 'ping'
                            - 'tcp-echo'
                            - 'udp-echo'
                            - 'http'
                            - 'twamp'
                            - 'dns'
                            - 'tcp-connect'
                            - 'ftp'
                            - 'https'
                    quality_measured_method:
                        aliases: ['quality-measured-method']
                        type: str
                        description: Method to measure the quality of tcp-connect.
                        choices:
                            - 'half-close'
                            - 'half-open'
                    recoverytime:
                        type: int
                        description: Number of successful responses received before server is considered recovered
                    security_mode:
                        aliases: ['security-mode']
                        type: str
                        description: Twamp controller security mode.
                        choices:
                            - 'none'
                            - 'authentication'
                    server:
                        type: list
                        elements: str
                        description: Predefined IP address or FQDN name from FortiGuard.
                    sla:
                        type: list
                        elements: dict
                        description: Sla.
                        suboptions:
                            id:
                                type: int
                                description: SLA ID.
                            jitter_threshold:
                                aliases: ['jitter-threshold']
                                type: int
                                description: Jitter for SLA to make decision in milliseconds.
                            latency_threshold:
                                aliases: ['latency-threshold']
                                type: int
                                description: Latency for SLA to make decision in milliseconds.
                            link_cost_factor:
                                aliases: ['link-cost-factor']
                                type: list
                                elements: str
                                description: Criteria on which to base link selection.
                                choices:
                                    - 'latency'
                                    - 'jitter'
                                    - 'packet-loss'
                                    - 'mos'
                                    - 'remote'
                            mos_threshold:
                                aliases: ['mos-threshold']
                                type: str
                                description: Minimum Mean Opinion Score for SLA to be marked as pass.
                            packetloss_threshold:
                                aliases: ['packetloss-threshold']
                                type: int
                                description: Packet loss for SLA to make decision in percentage.
                            priority_in_sla:
                                aliases: ['priority-in-sla']
                                type: int
                                description: Value to be distributed into routing table when in-sla
                            priority_out_sla:
                                aliases: ['priority-out-sla']
                                type: int
                                description: Value to be distributed into routing table when out-sla
                    sla_fail_log_period:
                        aliases: ['sla-fail-log-period']
                        type: int
                        description: Time interval in seconds that SLA fail log messages will be generated
                    sla_id_redistribute:
                        aliases: ['sla-id-redistribute']
                        type: int
                        description: Select the ID from the SLA sub-table.
                    sla_pass_log_period:
                        aliases: ['sla-pass-log-period']
                        type: int
                        description: Time interval in seconds that SLA pass log messages will be generated
                    source:
                        type: str
                        description: Source IP address used in the health-check packet to the server.
                    source6:
                        type: str
                        description: Source IPv6 address used in the health-check packet to server.
                    system_dns:
                        aliases: ['system-dns']
                        type: str
                        description: Enable/disable system DNS as the probe server.
                        choices:
                            - 'disable'
                            - 'enable'
                    target_name:
                        aliases: ['target-name']
                        type: str
                        description: Status check or predefined health-check targets name.
                    threshold_alert_jitter:
                        aliases: ['threshold-alert-jitter']
                        type: int
                        description: Alert threshold for jitter
                    threshold_alert_latency:
                        aliases: ['threshold-alert-latency']
                        type: int
                        description: Alert threshold for latency
                    threshold_alert_packetloss:
                        aliases: ['threshold-alert-packetloss']
                        type: int
                        description: Alert threshold for packet loss
                    threshold_warning_jitter:
                        aliases: ['threshold-warning-jitter']
                        type: int
                        description: Warning threshold for jitter
                    threshold_warning_latency:
                        aliases: ['threshold-warning-latency']
                        type: int
                        description: Warning threshold for latency
                    threshold_warning_packetloss:
                        aliases: ['threshold-warning-packetloss']
                        type: int
                        description: Warning threshold for packet loss
                    update_cascade_interface:
                        aliases: ['update-cascade-interface']
                        type: str
                        description: Enable/disable update cascade interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    update_static_route:
                        aliases: ['update-static-route']
                        type: str
                        description: Enable/disable updating the static route.
                        choices:
                            - 'disable'
                            - 'enable'
                    user:
                        type: str
                        description: The user name to access probe server.
                    vrf:
                        type: int
                        description: Virtual Routing Forwarding ID.
            option:
                type: list
                elements: str
                description: Option.
                choices:
                    - 'sdwan-overlay'
                    - 'sdwan-manager'
            duplication_max_discrepancy:
                aliases: ['duplication-max-discrepancy']
                type: int
                description: Maximum discrepancy between two packets for deduplication in milliseconds
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
    - name: Configure redundant Internet connections with multiple outbound links and health-check profiles.
      fortinet.fmgdevice.fmgd_system_sdwan:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        system_sdwan:
          # app_perf_log_period: <integer>
          # duplication:
          #   - dstaddr: <list or string>
          #     dstaddr6: <list or string>
          #     dstintf: <list or string>
          #     id: <integer>
          #     packet_de_duplication: <value in [disable, enable]>
          #     packet_duplication: <value in [disable, force, on-demand]>
          #     service: <list or string>
          #     service_id: <list or string>
          #     sla_match_service: <value in [disable, enable]>
          #     srcaddr: <list or string>
          #     srcaddr6: <list or string>
          #     srcintf: <list or string>
          # duplication_max_num: <integer>
          # fail_alert_interfaces: <list or string>
          # fail_detect: <value in [disable, enable]>
          # health_check:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     class_id: <list or string>
          #     detect_mode: <value in [active, passive, prefer-passive, ...]>
          #     diffservcode: <string>
          #     dns_match_ip: <string>
          #     dns_request_domain: <string>
          #     embed_measured_health: <value in [disable, enable]>
          #     failtime: <integer>
          #     ftp_file: <string>
          #     ftp_mode: <value in [passive, port]>
          #     ha_priority: <integer>
          #     http_agent: <string>
          #     http_get: <string>
          #     http_match: <string>
          #     interval: <integer>
          #     members: <list or string>
          #     mos_codec: <value in [g711, g722, g729]>
          #     name: <string>
          #     packet_size: <integer>
          #     password: <list or string>
          #     port: <integer>
          #     probe_count: <integer>
          #     probe_packets: <value in [disable, enable]>
          #     probe_timeout: <integer>
          #     protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          #     quality_measured_method: <value in [half-close, half-open]>
          #     recoverytime: <integer>
          #     security_mode: <value in [none, authentication]>
          #     server: <list or string>
          #     sla:
          #       - id: <integer>
          #         jitter_threshold: <integer>
          #         latency_threshold: <integer>
          #         link_cost_factor:
          #           - "latency"
          #           - "jitter"
          #           - "packet-loss"
          #           - "mos"
          #           - "remote"
          #         mos_threshold: <string>
          #         packetloss_threshold: <integer>
          #         priority_in_sla: <integer>
          #         priority_out_sla: <integer>
          #     sla_fail_log_period: <integer>
          #     sla_id_redistribute: <integer>
          #     sla_pass_log_period: <integer>
          #     source: <string>
          #     source6: <string>
          #     system_dns: <value in [disable, enable]>
          #     threshold_alert_jitter: <integer>
          #     threshold_alert_latency: <integer>
          #     threshold_alert_packetloss: <integer>
          #     threshold_warning_jitter: <integer>
          #     threshold_warning_latency: <integer>
          #     threshold_warning_packetloss: <integer>
          #     update_cascade_interface: <value in [disable, enable]>
          #     update_static_route: <value in [disable, enable]>
          #     user: <string>
          #     vrf: <integer>
          #     fortiguard: <value in [disable, enable]>
          #     fortiguard_name: <list or string>
          # load_balance_mode: <value in [source-ip-based, weight-based, usage-based, ...]>
          # members:
          #   - comment: <string>
          #     cost: <integer>
          #     gateway: <string>
          #     gateway6: <string>
          #     ingress_spillover_threshold: <integer>
          #     interface: <list or string>
          #     preferred_source: <string>
          #     priority: <integer>
          #     priority6: <integer>
          #     seq_num: <integer>
          #     source: <string>
          #     source6: <string>
          #     spillover_threshold: <integer>
          #     status: <value in [disable, enable]>
          #     transport_group: <integer>
          #     volume_ratio: <integer>
          #     weight: <integer>
          #     zone: <list or string>
          #     priority_in_sla: <integer>
          #     priority_out_sla: <integer>
          # neighbor:
          #   - health_check: <list or string>
          #     ip: <list or string>
          #     member: <list or string>
          #     minimum_sla_meet_members: <integer>
          #     mode: <value in [sla, speedtest]>
          #     role: <value in [primary, secondary, standalone]>
          #     service_id: <list or string>
          #     sla_id: <integer>
          #     route_metric: <value in [preferable, priority]>
          # neighbor_hold_boot_time: <integer>
          # neighbor_hold_down: <value in [disable, enable]>
          # neighbor_hold_down_time: <integer>
          # service:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     agent_exclusive: <value in [disable, enable]>
          #     bandwidth_weight: <integer>
          #     default: <value in [disable, enable]>
          #     dscp_forward: <value in [disable, enable]>
          #     dscp_forward_tag: <string>
          #     dscp_reverse: <value in [disable, enable]>
          #     dscp_reverse_tag: <string>
          #     dst: <list or string>
          #     dst_negate: <value in [disable, enable]>
          #     dst6: <list or string>
          #     end_port: <integer>
          #     end_src_port: <integer>
          #     gateway: <value in [disable, enable]>
          #     groups: <list or string>
          #     hash_mode: <value in [round-robin, source-ip-based, source-dest-ip-based, ...]>
          #     health_check: <list or string>
          #     hold_down_time: <integer>
          #     id: <integer>
          #     input_device: <list or string>
          #     input_device_negate: <value in [disable, enable]>
          #     input_zone: <list or string>
          #     internet_service: <value in [disable, enable]>
          #     internet_service_app_ctrl: <list or integer>
          #     internet_service_app_ctrl_category: <list or integer>
          #     internet_service_app_ctrl_group: <list or string>
          #     internet_service_custom: <list or string>
          #     internet_service_custom_group: <list or string>
          #     internet_service_group: <list or string>
          #     internet_service_name: <list or string>
          #     jitter_weight: <integer>
          #     latency_weight: <integer>
          #     link_cost_factor: <value in [latency, jitter, packet-loss, ...]>
          #     link_cost_threshold: <integer>
          #     load_balance: <value in [disable, enable]>
          #     minimum_sla_meet_members: <integer>
          #     mode: <value in [auto, manual, priority, ...]>
          #     name: <string>
          #     packet_loss_weight: <integer>
          #     passive_measurement: <value in [disable, enable]>
          #     priority_members: <list or string>
          #     priority_zone: <list or string>
          #     protocol: <integer>
          #     quality_link: <integer>
          #     role: <value in [primary, secondary, standalone]>
          #     shortcut: <value in [disable, enable]>
          #     shortcut_priority: <value in [disable, enable, auto]>
          #     sla:
          #       - health_check: <list or string>
          #         id: <integer>
          #     sla_compare_method: <value in [order, number]>
          #     sla_stickiness: <value in [disable, enable]>
          #     src: <list or string>
          #     src_negate: <value in [disable, enable]>
          #     src6: <list or string>
          #     standalone_action: <value in [disable, enable]>
          #     start_port: <integer>
          #     start_src_port: <integer>
          #     status: <value in [disable, enable]>
          #     tie_break: <value in [zone, cfg-order, fib-best-match, ...]>
          #     tos: <string>
          #     tos_mask: <string>
          #     use_shortcut_sla: <value in [disable, enable]>
          #     users: <list or string>
          #     zone_mode: <value in [disable, enable]>
          #     route_tag: <integer>
          #     comment: <string>
          # speedtest_bypass_routing: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # zone:
          #   - advpn_health_check: <list or string>
          #     advpn_select: <value in [disable, enable]>
          #     minimum_sla_meet_members: <integer>
          #     name: <string>
          #     service_sla_tie_break: <value in [cfg-order, fib-best-match, input-device]>
          # health_check_fortiguard:
          #   - addr_mode: <value in [ipv4, ipv6]>
          #     class_id: <list or string>
          #     detect_mode: <value in [active, passive, prefer-passive, ...]>
          #     diffservcode: <string>
          #     dns_match_ip: <string>
          #     dns_request_domain: <string>
          #     embed_measured_health: <value in [disable, enable]>
          #     failtime: <integer>
          #     ftp_file: <string>
          #     ftp_mode: <value in [passive, port]>
          #     ha_priority: <integer>
          #     http_agent: <string>
          #     http_get: <string>
          #     http_match: <string>
          #     interval: <integer>
          #     members: <list or string>
          #     mos_codec: <value in [g711, g722, g729]>
          #     packet_size: <integer>
          #     password: <list or string>
          #     port: <integer>
          #     probe_count: <integer>
          #     probe_packets: <value in [disable, enable]>
          #     probe_timeout: <integer>
          #     protocol: <value in [ping, tcp-echo, udp-echo, ...]>
          #     quality_measured_method: <value in [half-close, half-open]>
          #     recoverytime: <integer>
          #     security_mode: <value in [none, authentication]>
          #     server: <list or string>
          #     sla:
          #       - id: <integer>
          #         jitter_threshold: <integer>
          #         latency_threshold: <integer>
          #         link_cost_factor:
          #           - "latency"
          #           - "jitter"
          #           - "packet-loss"
          #           - "mos"
          #           - "remote"
          #         mos_threshold: <string>
          #         packetloss_threshold: <integer>
          #         priority_in_sla: <integer>
          #         priority_out_sla: <integer>
          #     sla_fail_log_period: <integer>
          #     sla_id_redistribute: <integer>
          #     sla_pass_log_period: <integer>
          #     source: <string>
          #     source6: <string>
          #     system_dns: <value in [disable, enable]>
          #     target_name: <string>
          #     threshold_alert_jitter: <integer>
          #     threshold_alert_latency: <integer>
          #     threshold_alert_packetloss: <integer>
          #     threshold_warning_jitter: <integer>
          #     threshold_warning_latency: <integer>
          #     threshold_warning_packetloss: <integer>
          #     update_cascade_interface: <value in [disable, enable]>
          #     update_static_route: <value in [disable, enable]>
          #     user: <string>
          #     vrf: <integer>
          # option:
          #   - "sdwan-overlay"
          #   - "sdwan-manager"
          # duplication_max_discrepancy: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/sdwan'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_sdwan': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'app-perf-log-period': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'duplication': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'dstaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'dstaddr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'dstintf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'packet-de-duplication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'packet-duplication': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['disable', 'force', 'on-demand'],
                            'type': 'str'
                        },
                        'service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'service-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sla-match-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'srcaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'srcaddr6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'srcintf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'duplication-max-num': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fail-alert-interfaces': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fail-detect': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'health-check': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'class-id': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'detect-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['active', 'passive', 'prefer-passive', 'remote', 'agent-based'],
                            'type': 'str'
                        },
                        'diffservcode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'dns-match-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'dns-request-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'embed-measured-health': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'failtime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ftp-file': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'ftp-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['passive', 'port'], 'type': 'str'},
                        'ha-priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'http-agent': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'http-get': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'http-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'mos-codec': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['g711', 'g722', 'g729'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'packet-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'probe-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'probe-packets': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'probe-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'protocol': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'ping6', 'dns', 'tcp-connect', 'ftp', 'https'],
                            'type': 'str'
                        },
                        'quality-measured-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['half-close', 'half-open'], 'type': 'str'},
                        'recoverytime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'security-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'authentication'], 'type': 'str'},
                        'server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sla': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'jitter-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'latency-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'link-cost-factor': {
                                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                                    'type': 'list',
                                    'choices': ['latency', 'jitter', 'packet-loss', 'mos', 'remote'],
                                    'elements': 'str'
                                },
                                'mos-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'packetloss-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'priority-in-sla': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'priority-out-sla': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'sla-fail-log-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'sla-id-redistribute': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'sla-pass-log-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                        'source': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'source6': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'system-dns': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'threshold-alert-jitter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'threshold-alert-latency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'threshold-alert-packetloss': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'threshold-warning-jitter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'threshold-warning-latency': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'threshold-warning-packetloss': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'update-cascade-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'update-static-route': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'user': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vrf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'fortiguard': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortiguard-name': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'load-balance-mode': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['source-ip-based', 'weight-based', 'usage-based', 'source-dest-ip-based', 'measured-volume-based'],
                    'type': 'str'
                },
                'members': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'comment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'gateway6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'ingress-spillover-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'preferred-source': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'priority6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'seq-num': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'source': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'source6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'spillover-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'transport-group': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'volume-ratio': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'zone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'priority-in-sla': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'priority-out-sla': {'v_range': [['7.6.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'neighbor': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'health-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'member': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'minimum-sla-meet-members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['sla', 'speedtest'], 'type': 'str'},
                        'role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'},
                        'service-id': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sla-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'route-metric': {'v_range': [['7.6.2', '']], 'choices': ['preferable', 'priority'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'neighbor-hold-boot-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'neighbor-hold-down': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'neighbor-hold-down-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'service': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'agent-exclusive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bandwidth-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'default': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp-forward': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp-forward-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'dscp-reverse': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp-reverse-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'dst': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'dst-negate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dst6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'end-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'end-src-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'groups': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'hash-mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['round-robin', 'source-ip-based', 'source-dest-ip-based', 'inbandwidth', 'outbandwidth', 'bibandwidth'],
                            'type': 'str'
                        },
                        'health-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'hold-down-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'input-device': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'input-device-negate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'input-zone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'internet-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'internet-service-app-ctrl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                        'internet-service-app-ctrl-category': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                        'internet-service-app-ctrl-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'internet-service-custom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'internet-service-custom-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'internet-service-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'internet-service-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'jitter-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'latency-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'link-cost-factor': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['latency', 'jitter', 'packet-loss', 'inbandwidth', 'outbandwidth', 'bibandwidth', 'custom-profile-1'],
                            'type': 'str'
                        },
                        'link-cost-threshold': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'load-balance': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'minimum-sla-meet-members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'mode': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['auto', 'manual', 'priority', 'sla', 'load-balance'],
                            'type': 'str'
                        },
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'packet-loss-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'passive-measurement': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'priority-members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'priority-zone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'quality-link': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['primary', 'secondary', 'standalone'], 'type': 'str'},
                        'shortcut': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'shortcut-priority': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable', 'auto'], 'type': 'str'},
                        'sla': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'health-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'sla-compare-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['order', 'number'], 'type': 'str'},
                        'sla-stickiness': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'src': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'src-negate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'src6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'standalone-action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'start-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'start-src-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tie-break': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['zone', 'cfg-order', 'fib-best-match', 'input-device'],
                            'type': 'str'
                        },
                        'tos': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'tos-mask': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'use-shortcut-sla': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'users': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'zone-mode': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'route-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'comment': {'v_range': [['7.6.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'speedtest-bypass-routing': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'zone': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'advpn-health-check': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'advpn-select': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'minimum-sla-meet-members': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'service-sla-tie-break': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['cfg-order', 'fib-best-match', 'input-device'],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'health-check-fortiguard': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'addr-mode': {'v_range': [['7.6.0', '']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                        'class-id': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                        'detect-mode': {
                            'v_range': [['7.6.0', '']],
                            'choices': ['active', 'passive', 'prefer-passive', 'remote', 'agent-based'],
                            'type': 'str'
                        },
                        'diffservcode': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'dns-match-ip': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'dns-request-domain': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'embed-measured-health': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'failtime': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'ftp-file': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'ftp-mode': {'v_range': [['7.6.0', '']], 'choices': ['passive', 'port'], 'type': 'str'},
                        'ha-priority': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'http-agent': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'http-get': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'http-match': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'interval': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'members': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                        'mos-codec': {'v_range': [['7.6.0', '']], 'choices': ['g711', 'g722', 'g729'], 'type': 'str'},
                        'packet-size': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'password': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'port': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'probe-count': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'probe-packets': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'probe-timeout': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'protocol': {
                            'v_range': [['7.6.0', '']],
                            'choices': ['ping', 'tcp-echo', 'udp-echo', 'http', 'twamp', 'dns', 'tcp-connect', 'ftp', 'https'],
                            'type': 'str'
                        },
                        'quality-measured-method': {'v_range': [['7.6.0', '']], 'choices': ['half-close', 'half-open'], 'type': 'str'},
                        'recoverytime': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'security-mode': {'v_range': [['7.6.0', '']], 'choices': ['none', 'authentication'], 'type': 'str'},
                        'server': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                        'sla': {
                            'v_range': [['7.6.0', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.6.0', '']], 'type': 'int'},
                                'jitter-threshold': {'v_range': [['7.6.0', '']], 'type': 'int'},
                                'latency-threshold': {'v_range': [['7.6.0', '']], 'type': 'int'},
                                'link-cost-factor': {
                                    'v_range': [['7.6.0', '']],
                                    'type': 'list',
                                    'choices': ['latency', 'jitter', 'packet-loss', 'mos', 'remote'],
                                    'elements': 'str'
                                },
                                'mos-threshold': {'v_range': [['7.6.0', '']], 'type': 'str'},
                                'packetloss-threshold': {'v_range': [['7.6.0', '']], 'type': 'int'},
                                'priority-in-sla': {'v_range': [['7.6.0', '']], 'type': 'int'},
                                'priority-out-sla': {'v_range': [['7.6.0', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'sla-fail-log-period': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'sla-id-redistribute': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'sla-pass-log-period': {'v_range': [['7.6.0', '']], 'no_log': True, 'type': 'int'},
                        'source': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'source6': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'system-dns': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'target-name': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'threshold-alert-jitter': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'threshold-alert-latency': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'threshold-alert-packetloss': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'threshold-warning-jitter': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'threshold-warning-latency': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'threshold-warning-packetloss': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'update-cascade-interface': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'update-static-route': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'user': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'vrf': {'v_range': [['7.6.0', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'option': {'v_range': [['7.6.0', '']], 'type': 'list', 'choices': ['sdwan-overlay', 'sdwan-manager'], 'elements': 'str'},
                'duplication-max-discrepancy': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdwan'),
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
