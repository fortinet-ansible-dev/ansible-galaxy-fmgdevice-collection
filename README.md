![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

# fortinet.fmgdevice:1.0.0 - configuring FortiManager

## Description

FortiManager Ansible Collection includes the modules that are able to configure FortiManager.

[Documentation](https://ansible-galaxy-fmgdevice-docs.readthedocs.io/en/latest) for the collection.

## Requirements

- Ansible 2.15.0 or above
- Python 3.9 or above

## Installation

This collection is distributed via [ansible-galaxy](https://galaxy.ansible.com/fortinet/fmgdevice).

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install fortinet.fmgdevice
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: fortinet.fmgdevice
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install fortinet.fmgdevice --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 2.0.0:

```
ansible-galaxy collection install fortinet.fmgdevice:==2.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.


## Use Cases

See [example here](https://ansible-galaxy-fmgdevice-docs.readthedocs.io/en/latest/playbook.html) to run your first playbook.


## Testing

Testing is done by the Fortinet team. Before each new FMG Ansible release, it is tested with the latest patches from all FMG minor releases.


## Support

For any questions regarding FortiManager Ansible, please create a [github issue](https://github.com/fortinet-ansible-dev/ansible-galaxy-fmgdevice-collection/issues).


## Release Notes and Roadmap

Please check [release note here](https://ansible-galaxy-fmgdevice-docs.readthedocs.io/en/latest/release.html).

FortiManager Ansible is expected to be updated every two months.

## Related Information

[Documentation](https://ansible-galaxy-fmgdevice-docs.readthedocs.io/en/latest) for the collection.

## Modules
The collection provides the following modules:

* `fmgd_alertemail_setting`  Configure alert email settings.
* `fmgd_antivirus_exemptlist`  Configure a list of hashes to be exempt from AV scanning.
* `fmgd_antivirus_heuristic`  Configure global heuristic options.
* `fmgd_antivirus_quarantine`  Configure quarantine options.
* `fmgd_antivirus_settings`  Configure AntiVirus settings.
* `fmgd_application_name`  Configure application signatures.
* `fmgd_application_rulesettings`  Configure application rule settings.
* `fmgd_automation_setting`  Automation setting configuration.
* `fmgd_aws_vpce`  Configure AWS VPC configuration.
* `fmgd_azure_vwaningresspublicips`  Display Azure vWAN SLB ingress public IPs.
* `fmgd_azure_vwanslb`  Configure Azure vWAN slb setting.
* `fmgd_azure_vwanslb_permanentsecurityrules`  Configure permanent security rules.
* `fmgd_azure_vwanslb_permanentsecurityrules_rules`  Configure security rules.
* `fmgd_azure_vwanslb_temporarysecurityrules`  Configure temporary security rules.
* `fmgd_azure_vwanslb_temporarysecurityrules_rules`  Configure security rules.
* `fmgd_casb_attributematch`  Configure CASB SaaS application.
* `fmgd_casb_attributematch_attribute`  CASB tenant match rules.
* `fmgd_certificate_remote`  Remote certificate as a PEM file.
* `fmgd_dlp_exactdatamatch`  Configure exact-data-match template used by DLP scan.
* `fmgd_dlp_exactdatamatch_columns`  DLP exact-data-match column types.
* `fmgd_dlp_fpdocsource`  Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints.
* `fmgd_dlp_settings`  Designate logical storage for DLP fingerprint database.
* `fmgd_dpdk_cpus`  Configure CPUs enabled to run engines in each DPDK stage.
* `fmgd_dpdk_global`  Configure global DPDK options.
* `fmgd_emailfilter_fortiguard`  Device emailfilter fortiguard.
* `fmgd_endpointcontrol_fctemsoverride`  Configure FortiClient Enterprise Management Server.
* `fmgd_endpointcontrol_settings`  Configure endpoint control settings.
* `fmgd_ethernetoam_cfm`  CFM domain configuration.
* `fmgd_ethernetoam_cfm_service`  CFM service configuration.
* `fmgd_extendercontroller_extender`  Device vdom extender controller extender.
* `fmgd_extendercontroller_extender_controllerreport`  FortiExtender controller report configuration.
* `fmgd_extendercontroller_extender_modem1`  Configuration options for modem 1.
* `fmgd_extendercontroller_extender_modem1_autoswitch`  FortiExtender auto switch configuration.
* `fmgd_extendercontroller_extender_modem2`  Configuration options for modem 2.
* `fmgd_extendercontroller_extender_modem2_autoswitch`  FortiExtender auto switch configuration.
* `fmgd_extendercontroller_extender_wanextension`  Device vdom extender controller extender wan extension.
* `fmgd_extensioncontroller_extender`  Extender controller configuration.
* `fmgd_extensioncontroller_extender_wanextension`  FortiExtender wan extension configuration.
* `fmgd_extensioncontroller_extendervap`  FortiExtender wifi vap configuration.
* `fmgd_extensioncontroller_fortigate`  FortiGate controller configuration.
* `fmgd_extensioncontroller_fortigateprofile`  FortiGate connector profile configuration.
* `fmgd_extensioncontroller_fortigateprofile_lanextension`  FortiGate connector LAN extension configuration.
* `fmgd_firewall_accessproxysshclientcert`  Configure Access Proxy SSH client certificate.
* `fmgd_firewall_accessproxysshclientcert_certextension`  Configure certificate extension for user certificate.
* `fmgd_firewall_authportal`  Configure firewall authentication portals.
* `fmgd_firewall_dnstranslation`  Configure DNS translation.
* `fmgd_firewall_global`  Global firewall settings.
* `fmgd_firewall_internetserviceappend`  Configure additional port mappings for Internet Services.
* `fmgd_firewall_internetservicedefinition`  Configure Internet Service definition.
* `fmgd_firewall_internetservicedefinition_entry`  Protocol and port information in an Internet Service entry.
* `fmgd_firewall_internetservicedefinition_entry_portrange`  Port ranges in the definition entry.
* `fmgd_firewall_internetserviceextension`  Configure Internet Services Extension.
* `fmgd_firewall_internetserviceextension_disableentry`  Disable entries in the Internet Service database.
* `fmgd_firewall_internetserviceextension_disableentry_ip6range`  IPv6 ranges in the disable entry.
* `fmgd_firewall_internetserviceextension_disableentry_iprange`  IPv4 ranges in the disable entry.
* `fmgd_firewall_internetserviceextension_disableentry_portrange`  Port ranges in the disable entry.
* `fmgd_firewall_internetserviceextension_entry`  Entries added to the Internet Service extension database.
* `fmgd_firewall_internetserviceextension_entry_portrange`  Port ranges in the custom entry.
* `fmgd_firewall_ipmacbinding_setting`  Configure IP to MAC binding settings.
* `fmgd_firewall_ipmacbinding_table`  Configure IP to MAC address pairs in the IP/MAC binding table.
* `fmgd_firewall_iptranslation`  Configure firewall IP-translation.
* `fmgd_firewall_ipv6ehfilter`  Configure IPv6 extension header filter.
* `fmgd_firewall_ondemandsniffer`  Configure on-demand packet sniffer.
* `fmgd_firewall_pfcp`  Configure PFCP.
* `fmgd_firewall_policy`  Configure IPv4 policies.
* `fmgd_firewall_sniffer`  Configure sniffer.
* `fmgd_firewall_sniffer_anomaly`  Configuration method to edit Denial of Service.
* `fmgd_firewall_ssh_hostkey`  SSH proxy host public keys.
* `fmgd_firewall_ssh_localkey`  SSH proxy local keys.
* `fmgd_firewall_ssh_setting`  SSH proxy settings.
* `fmgd_firewall_ssl_setting`  SSL proxy settings.
* `fmgd_firewall_sslserver`  Configure SSL servers.
* `fmgd_firewall_ttlpolicy`  Configure TTL policies.
* `fmgd_ftpproxy_explicit`  Configure explicit FTP proxy settings.
* `fmgd_gtp_apnshaper`  Global per-APN shaper.
* `fmgd_gtp_ieallowlist`  IE allow list.
* `fmgd_gtp_ieallowlist_entries`  Entries of allow list for unknown or out-of-state IEs.
* `fmgd_gtp_rattimeoutprofile`  RAT timeout profile.
* `fmgd_icap_profile`  Configure ICAP profiles.
* `fmgd_icap_server`  Configure ICAP servers.
* `fmgd_icap_servergroup`  Configure an ICAP server group consisting of multiple forward servers.
* `fmgd_icap_servergroup_serverlist`  Add ICAP servers to a list to form a server group.
* `fmgd_ips_decoder`  Configure IPS decoder.
* `fmgd_ips_decoder_parameter`  IPS group parameters.
* `fmgd_ips_global`  Configure IPS global parameter.
* `fmgd_ips_rule`  Configure IPS rules.
* `fmgd_ips_rulesettings`  Configure IPS rule setting.
* `fmgd_ips_settings`  Configure IPS VDOM parameter.
* `fmgd_ips_tlsactiveprobe`  TLS active probe configuration.
* `fmgd_loadbalance_flowrule`  flow rule configuration.
* `fmgd_loadbalance_setting`  load balance setting.
* `fmgd_loadbalance_setting_workers`  Worker blade used by this group.
* `fmgd_loadbalance_workergroup`  Worker group configuration.
* `fmgd_log_azuresecuritycenter2_filter`  Filters for Azure Security Center.
* `fmgd_log_azuresecuritycenter2_filter_freestyle`  Free style filters.
* `fmgd_log_azuresecuritycenter2_setting`  Settings for Azure Security Center.
* `fmgd_log_azuresecuritycenter2_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_azuresecuritycenter_filter`  Filters for Azure Security Center.
* `fmgd_log_azuresecuritycenter_filter_freestyle`  Free style filters.
* `fmgd_log_azuresecuritycenter_setting`  Settings for Azure Security Center.
* `fmgd_log_azuresecuritycenter_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_disk_filter`  Configure filters for local disk logging.
* `fmgd_log_disk_filter_freestyle`  Free style filters.
* `fmgd_log_disk_setting`  Settings for local disk logging.
* `fmgd_log_eventfilter`  Configure log event filters.
* `fmgd_log_fortianalyzer2_filter`  Filters for FortiAnalyzer.
* `fmgd_log_fortianalyzer2_filter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzer2_overridefilter`  Override filters for FortiAnalyzer.
* `fmgd_log_fortianalyzer2_overridefilter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzer2_overridesetting`  Override FortiAnalyzer settings.
* `fmgd_log_fortianalyzer2_setting`  Global FortiAnalyzer settings.
* `fmgd_log_fortianalyzer3_filter`  Filters for FortiAnalyzer.
* `fmgd_log_fortianalyzer3_filter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzer3_overridefilter`  Override filters for FortiAnalyzer.
* `fmgd_log_fortianalyzer3_overridefilter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzer3_overridesetting`  Override FortiAnalyzer settings.
* `fmgd_log_fortianalyzer3_setting`  Global FortiAnalyzer settings.
* `fmgd_log_fortianalyzer_filter`  Filters for FortiAnalyzer.
* `fmgd_log_fortianalyzer_filter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzer_overridefilter`  Override filters for FortiAnalyzer.
* `fmgd_log_fortianalyzer_overridefilter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzer_overridesetting`  Override FortiAnalyzer settings.
* `fmgd_log_fortianalyzer_setting`  Global FortiAnalyzer settings.
* `fmgd_log_fortianalyzercloud_filter`  Filters for FortiAnalyzer Cloud.
* `fmgd_log_fortianalyzercloud_filter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzercloud_overridefilter`  Override filters for FortiAnalyzer Cloud.
* `fmgd_log_fortianalyzercloud_overridefilter_freestyle`  Free style filters.
* `fmgd_log_fortianalyzercloud_overridesetting`  Override FortiAnalyzer Cloud settings.
* `fmgd_log_fortianalyzercloud_setting`  Global FortiAnalyzer Cloud settings.
* `fmgd_log_fortiguard_filter`  Filters for FortiCloud.
* `fmgd_log_fortiguard_filter_freestyle`  Free style filters.
* `fmgd_log_fortiguard_overridefilter`  Override filters for FortiCloud.
* `fmgd_log_fortiguard_overridefilter_freestyle`  Free style filters.
* `fmgd_log_fortiguard_overridesetting`  Override global FortiCloud logging settings for this VDOM.
* `fmgd_log_fortiguard_setting`  Configure logging to FortiCloud.
* `fmgd_log_guidisplay`  Configure how log messages are displayed on the GUI.
* `fmgd_log_memory_filter`  Filters for memory buffer.
* `fmgd_log_memory_filter_freestyle`  Free style filters.
* `fmgd_log_memory_globalsetting`  Global settings for memory logging.
* `fmgd_log_memory_setting`  Settings for memory buffer.
* `fmgd_log_nulldevice_filter`  Filters for null device logging.
* `fmgd_log_nulldevice_filter_freestyle`  Free style filters.
* `fmgd_log_nulldevice_setting`  Settings for null device logging.
* `fmgd_log_setting`  Configure general log settings.
* `fmgd_log_slbc_globalsetting`  LOG Global settings for SLBC platform.
* `fmgd_log_syslogd2_filter`  Filters for remote system server.
* `fmgd_log_syslogd2_filter_freestyle`  Free style filters.
* `fmgd_log_syslogd2_overridefilter`  Override filters for remote system server.
* `fmgd_log_syslogd2_overridefilter_freestyle`  Free style filters.
* `fmgd_log_syslogd2_overridesetting`  Override settings for remote syslog server.
* `fmgd_log_syslogd2_overridesetting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd2_setting`  Global settings for remote syslog server.
* `fmgd_log_syslogd2_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd3_filter`  Filters for remote system server.
* `fmgd_log_syslogd3_filter_freestyle`  Free style filters.
* `fmgd_log_syslogd3_overridefilter`  Override filters for remote system server.
* `fmgd_log_syslogd3_overridefilter_freestyle`  Free style filters.
* `fmgd_log_syslogd3_overridesetting`  Override settings for remote syslog server.
* `fmgd_log_syslogd3_overridesetting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd3_setting`  Global settings for remote syslog server.
* `fmgd_log_syslogd3_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd4_filter`  Filters for remote system server.
* `fmgd_log_syslogd4_filter_freestyle`  Free style filters.
* `fmgd_log_syslogd4_overridefilter`  Override filters for remote system server.
* `fmgd_log_syslogd4_overridefilter_freestyle`  Free style filters.
* `fmgd_log_syslogd4_overridesetting`  Override settings for remote syslog server.
* `fmgd_log_syslogd4_overridesetting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd4_setting`  Global settings for remote syslog server.
* `fmgd_log_syslogd4_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd_filter`  Filters for remote system server.
* `fmgd_log_syslogd_filter_freestyle`  Free style filters.
* `fmgd_log_syslogd_overridefilter`  Override filters for remote system server.
* `fmgd_log_syslogd_overridefilter_freestyle`  Free style filters.
* `fmgd_log_syslogd_overridesetting`  Override settings for remote syslog server.
* `fmgd_log_syslogd_overridesetting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_syslogd_setting`  Global settings for remote syslog server.
* `fmgd_log_syslogd_setting_customfieldname`  Custom field name for CEF format logging.
* `fmgd_log_tacacsaccounting2_filter`  Settings for TACACS+ accounting events filter.
* `fmgd_log_tacacsaccounting2_setting`  Settings for TACACS+ accounting.
* `fmgd_log_tacacsaccounting3_filter`  Settings for TACACS+ accounting events filter.
* `fmgd_log_tacacsaccounting3_setting`  Settings for TACACS+ accounting.
* `fmgd_log_tacacsaccounting_filter`  Settings for TACACS+ accounting events filter.
* `fmgd_log_tacacsaccounting_setting`  Settings for TACACS+ accounting.
* `fmgd_log_webtrends_filter`  Filters for WebTrends.
* `fmgd_log_webtrends_filter_freestyle`  Free style filters.
* `fmgd_log_webtrends_setting`  Settings for WebTrends.
* `fmgd_monitoring_np6ipsecengine`  Configure NP6 IPsec engine status monitoring.
* `fmgd_monitoring_npuhpe`  Configure npu-hpe status monitoring.
* `fmgd_notification`  Event notification configuration.
* `fmgd_nsx_profile`  List NSX Profile.
* `fmgd_nsxt_servicechain`  Configure NSX-T service chain.
* `fmgd_nsxt_servicechain_serviceindex`  Configure service index.
* `fmgd_nsxt_setting`  Configure NSX-T setting.
* `fmgd_pfcp_messagefilter`  Message filter for PFCP messages.
* `fmgd_report_chart`  Report chart widget configuration.
* `fmgd_report_chart_categoryseries`  Category series of pie chart.
* `fmgd_report_chart_column`  Table column definition.
* `fmgd_report_chart_column_mapping`  Show detail in certain display value for certain condition.
* `fmgd_report_chart_drilldowncharts`  Drill down charts.
* `fmgd_report_chart_valueseries`  Value series of pie chart.
* `fmgd_report_chart_xseries`  X-series of chart.
* `fmgd_report_chart_yseries`  Y-series of chart.
* `fmgd_report_dataset`  Report dataset configuration.
* `fmgd_report_dataset_field`  Fields.
* `fmgd_report_dataset_parameters`  Parameters.
* `fmgd_report_layout`  Report layout configuration.
* `fmgd_report_layout_bodyitem`  Configure report body item.
* `fmgd_report_layout_bodyitem_list`  Configure report list item.
* `fmgd_report_layout_bodyitem_parameters`  Parameters.
* `fmgd_report_layout_page`  Configure report page.
* `fmgd_report_layout_page_footer`  Configure report page footer.
* `fmgd_report_layout_page_footer_footeritem`  Configure report footer item.
* `fmgd_report_layout_page_header`  Configure report page header.
* `fmgd_report_layout_page_header_headeritem`  Configure report header item.
* `fmgd_report_setting`  Report setting configuration.
* `fmgd_report_style`  Report style configuration.
* `fmgd_report_theme`  Report themes configuration.
* `fmgd_router_authpath`  Configure authentication based routing.
* `fmgd_router_bfd`  Configure BFD.
* `fmgd_router_bfd6`  Configure IPv6 BFD.
* `fmgd_router_bfd6_multihoptemplate`  BFD IPv6 multi-hop template table.
* `fmgd_router_bfd6_neighbor`  Configure neighbor of IPv6 BFD.
* `fmgd_router_bfd_multihoptemplate`  BFD multi-hop template table.
* `fmgd_router_bfd_neighbor`  Neighbor.
* `fmgd_router_bgp`  Configure BGP.
* `fmgd_router_bgp_admindistance`  Administrative distance modifications.
* `fmgd_router_bgp_aggregateaddress`  BGP aggregate address table.
* `fmgd_router_bgp_aggregateaddress6`  BGP IPv6 aggregate address table.
* `fmgd_router_bgp_neighbor`  BGP neighbor table.
* `fmgd_router_bgp_neighbor_conditionaladvertise`  Conditional advertisement.
* `fmgd_router_bgp_neighbor_conditionaladvertise6`  IPv6 conditional advertisement.
* `fmgd_router_bgp_neighborgroup`  BGP neighbor group table.
* `fmgd_router_bgp_neighborrange`  BGP neighbor range table.
* `fmgd_router_bgp_neighborrange6`  BGP IPv6 neighbor range table.
* `fmgd_router_bgp_network`  BGP network table.
* `fmgd_router_bgp_network6`  BGP IPv6 network table.
* `fmgd_router_bgp_redistribute`  BGP IPv4 redistribute table.
* `fmgd_router_bgp_redistribute6`  BGP IPv6 redistribute table.
* `fmgd_router_bgp_vrf`  BGP VRF leaking table.
* `fmgd_router_bgp_vrf6`  BGP IPv6 VRF leaking table.
* `fmgd_router_bgp_vrf6_leaktarget`  Target VRF table.
* `fmgd_router_bgp_vrf_leaktarget`  Target VRF table.
* `fmgd_router_bgp_vrfleak`  BGP VRF leaking table.
* `fmgd_router_bgp_vrfleak6`  BGP IPv6 VRF leaking table.
* `fmgd_router_bgp_vrfleak6_target`  Target VRF table.
* `fmgd_router_bgp_vrfleak_target`  Target VRF table.
* `fmgd_router_extcommunitylist`  Configure extended community lists.
* `fmgd_router_extcommunitylist_rule`  Extended community list rule.
* `fmgd_router_isis`  Configure IS-IS.
* `fmgd_router_isis_isisinterface`  IS-IS interface configuration.
* `fmgd_router_isis_isisnet`  IS-IS net configuration.
* `fmgd_router_isis_redistribute`  IS-IS redistribute protocols.
* `fmgd_router_isis_redistribute6`  IS-IS IPv6 redistribution for routing protocols.
* `fmgd_router_isis_summaryaddress`  IS-IS summary addresses.
* `fmgd_router_isis_summaryaddress6`  IS-IS IPv6 summary address.
* `fmgd_router_keychain`  Configure key-chain.
* `fmgd_router_keychain_key`  Configuration method to edit key settings.
* `fmgd_router_multicast`  Configure router multicast.
* `fmgd_router_multicast6`  Configure IPv6 multicast.
* `fmgd_router_multicast6_interface`  Protocol Independent Multicast.
* `fmgd_router_multicast6_pimsmglobal`  PIM sparse-mode global settings.
* `fmgd_router_multicast6_pimsmglobal_rpaddress`  Statically configured RP addresses.
* `fmgd_router_multicast_interface`  PIM interfaces.
* `fmgd_router_multicast_interface_igmp`  IGMP configuration options.
* `fmgd_router_multicast_interface_joingroup`  Join multicast groups.
* `fmgd_router_multicast_pimsmglobal`  PIM sparse-mode global settings.
* `fmgd_router_multicast_pimsmglobal_rpaddress`  Statically configure RP addresses.
* `fmgd_router_multicast_pimsmglobalvrf`  per-VRF PIM sparse-mode global settings.
* `fmgd_router_multicast_pimsmglobalvrf_rpaddress`  Statically configure RP addresses.
* `fmgd_router_multicastflow`  Configure multicast-flow.
* `fmgd_router_multicastflow_flows`  Multicast-flow entries.
* `fmgd_router_ospf`  Configure OSPF.
* `fmgd_router_ospf6`  Configure IPv6 OSPF.
* `fmgd_router_ospf6_area`  OSPF6 area configuration.
* `fmgd_router_ospf6_area_ipseckeys`  IPsec authentication and encryption keys.
* `fmgd_router_ospf6_area_range`  OSPF6 area range configuration.
* `fmgd_router_ospf6_area_virtuallink`  OSPF6 virtual link configuration.
* `fmgd_router_ospf6_area_virtuallink_ipseckeys`  IPsec authentication and encryption keys.
* `fmgd_router_ospf6_ospf6interface`  OSPF6 interface configuration.
* `fmgd_router_ospf6_ospf6interface_ipseckeys`  IPsec authentication and encryption keys.
* `fmgd_router_ospf6_ospf6interface_neighbor`  OSPFv3 neighbors are used when OSPFv3 runs on non-broadcast media.
* `fmgd_router_ospf6_redistribute`  Redistribute configuration.
* `fmgd_router_ospf6_summaryaddress`  IPv6 address summary configuration.
* `fmgd_router_ospf_area`  OSPF area configuration.
* `fmgd_router_ospf_area_filterlist`  OSPF area filter-list configuration.
* `fmgd_router_ospf_area_range`  OSPF area range configuration.
* `fmgd_router_ospf_area_virtuallink`  OSPF virtual link configuration.
* `fmgd_router_ospf_area_virtuallink_md5keys`  MD5 key.
* `fmgd_router_ospf_distributelist`  Distribute list configuration.
* `fmgd_router_ospf_neighbor`  OSPF neighbor configuration are used when OSPF runs on non-broadcast media.
* `fmgd_router_ospf_network`  OSPF network configuration.
* `fmgd_router_ospf_ospfinterface`  OSPF interface configuration.
* `fmgd_router_ospf_ospfinterface_md5keys`  MD5 key.
* `fmgd_router_ospf_redistribute`  Redistribute configuration.
* `fmgd_router_ospf_summaryaddress`  IP address summary configuration.
* `fmgd_router_policy`  Configure IPv4 routing policies.
* `fmgd_router_policy6`  Configure IPv6 routing policies.
* `fmgd_router_rip`  Configure RIP.
* `fmgd_router_rip_distance`  Distance.
* `fmgd_router_rip_distributelist`  Distribute list.
* `fmgd_router_rip_interface`  RIP interface configuration.
* `fmgd_router_rip_neighbor`  Neighbor.
* `fmgd_router_rip_network`  Network.
* `fmgd_router_rip_offsetlist`  Offset list.
* `fmgd_router_rip_redistribute`  Redistribute configuration.
* `fmgd_router_ripng`  Configure RIPng.
* `fmgd_router_ripng_aggregateaddress`  Aggregate address.
* `fmgd_router_ripng_distance`  Distance.
* `fmgd_router_ripng_distributelist`  Distribute list.
* `fmgd_router_ripng_interface`  RIPng interface configuration.
* `fmgd_router_ripng_neighbor`  Neighbor.
* `fmgd_router_ripng_network`  Network.
* `fmgd_router_ripng_offsetlist`  Offset list.
* `fmgd_router_ripng_redistribute`  Redistribute configuration.
* `fmgd_router_routemap`  Configure route maps.
* `fmgd_router_setting`  Configure router settings.
* `fmgd_router_static`  Configure IPv4 static routing tables.
* `fmgd_router_static6`  Configure IPv6 static routing tables.
* `fmgd_rule_fmwp`  Show FMWP signatures.
* `fmgd_rule_otdt`  Show OT detection signatures.
* `fmgd_rule_otvp`  Show OT patch signatures.
* `fmgd_switchcontroller_8021xsettings`  Configure global 802.
* `fmgd_switchcontroller_acl_group`  Configure ACL groups to be applied on managed FortiSwitch ports.
* `fmgd_switchcontroller_acl_ingress`  Configure ingress ACL policies to be applied on managed FortiSwitch ports.
* `fmgd_switchcontroller_acl_ingress_action`  ACL actions.
* `fmgd_switchcontroller_acl_ingress_classifier`  ACL classifiers.
* `fmgd_switchcontroller_autoconfig_custom`  Policies which can override the default for specific ISL/ICL/FortiLink interface.
* `fmgd_switchcontroller_autoconfig_custom_switchbinding`  Switch binding list.
* `fmgd_switchcontroller_autoconfig_default`  Policies which are applied automatically to all ISL/ICL/FortiLink interfaces.
* `fmgd_switchcontroller_autoconfig_policy`  Policy definitions which can define the behavior on auto configured interfaces.
* `fmgd_switchcontroller_customcommand`  Configure the FortiGate switch controller to send custom commands to managed FortiSwitch devices.
* `fmgd_switchcontroller_dsl_policy`  DSL policy.
* `fmgd_switchcontroller_dynamicportpolicy`  Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
* `fmgd_switchcontroller_dynamicportpolicy_policy`  Port policies with matching criteria and actions.
* `fmgd_switchcontroller_flowtracking`  Configure FortiSwitch flow tracking and export via ipfix/netflow.
* `fmgd_switchcontroller_flowtracking_aggregates`  Configure aggregates in which all traffic sessions matching the IP Address will be grouped into the same flow.
* `fmgd_switchcontroller_flowtracking_collectors`  Configure collectors for the flow.
* `fmgd_switchcontroller_fortilinksettings`  Configure integrated FortiLink settings for FortiSwitch.
* `fmgd_switchcontroller_fortilinksettings_nacports`  NAC specific configuration.
* `fmgd_switchcontroller_global`  Configure FortiSwitch global settings.
* `fmgd_switchcontroller_igmpsnooping`  Configure FortiSwitch IGMP snooping global settings.
* `fmgd_switchcontroller_initialconfig_template`  Configure template for auto-generated VLANs.
* `fmgd_switchcontroller_initialconfig_vlans`  Configure initial template for auto-generated VLAN interfaces.
* `fmgd_switchcontroller_lldpprofile`  Configure FortiSwitch LLDP profiles.
* `fmgd_switchcontroller_lldpprofile_customtlvs`  Configuration method to edit custom TLV entries.
* `fmgd_switchcontroller_lldpprofile_medlocationservice`  Configuration method to edit Media Endpoint Discovery.
* `fmgd_switchcontroller_lldpprofile_mednetworkpolicy`  Configuration method to edit Media Endpoint Discovery.
* `fmgd_switchcontroller_lldpsettings`  Configure FortiSwitch LLDP settings.
* `fmgd_switchcontroller_location`  Configure FortiSwitch location services.
* `fmgd_switchcontroller_location_addresscivic`  Configure location civic address.
* `fmgd_switchcontroller_location_coordinates`  Configure location GPS coordinates.
* `fmgd_switchcontroller_location_elinnumber`  Configure location ELIN number.
* `fmgd_switchcontroller_macpolicy`  Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device.
* `fmgd_switchcontroller_managedswitch`  Configure FortiSwitch devices that are managed by this FortiGate.
* `fmgd_switchcontroller_managedswitch_8021xsettings`  Configuration method to edit FortiSwitch 802.
* `fmgd_switchcontroller_managedswitch_customcommand`  Configuration method to edit FortiSwitch commands to be pushed to this FortiSwitch device upon rebooting the FortiGate switch contro...
* `fmgd_switchcontroller_managedswitch_dhcpsnoopingstaticclient`  Configure FortiSwitch DHCP snooping static clients.
* `fmgd_switchcontroller_managedswitch_igmpsnooping`  Configure FortiSwitch IGMP snooping global settings.
* `fmgd_switchcontroller_managedswitch_igmpsnooping_vlans`  Configure IGMP snooping VLAN.
* `fmgd_switchcontroller_managedswitch_ipsourceguard`  IP source guard.
* `fmgd_switchcontroller_managedswitch_ipsourceguard_bindingentry`  IP and MAC address configuration.
* `fmgd_switchcontroller_managedswitch_mirror`  Configuration method to edit FortiSwitch packet mirror.
* `fmgd_switchcontroller_managedswitch_ports`  Managed-switch port list.
* `fmgd_switchcontroller_managedswitch_ports_dhcpsnoopoption82override`  Configure DHCP snooping option 82 override.
* `fmgd_switchcontroller_managedswitch_remotelog`  Configure logging by FortiSwitch device to a remote syslog server.
* `fmgd_switchcontroller_managedswitch_routeoffloadrouter`  Configure route offload MCLAG IP address.
* `fmgd_switchcontroller_managedswitch_snmpcommunity`  Configuration method to edit Simple Network Management Protocol.
* `fmgd_switchcontroller_managedswitch_snmpcommunity_hosts`  Configure IPv4 SNMP managers.
* `fmgd_switchcontroller_managedswitch_snmpsysinfo`  Configuration method to edit Simple Network Management Protocol.
* `fmgd_switchcontroller_managedswitch_snmptrapthreshold`  Configuration method to edit Simple Network Management Protocol.
* `fmgd_switchcontroller_managedswitch_snmpuser`  Configuration method to edit Simple Network Management Protocol.
* `fmgd_switchcontroller_managedswitch_staticmac`  Configuration method to edit FortiSwitch Static and Sticky MAC.
* `fmgd_switchcontroller_managedswitch_stormcontrol`  Configuration method to edit FortiSwitch storm control for measuring traffic activity using data rates to prevent traffic disruption.
* `fmgd_switchcontroller_managedswitch_stpinstance`  Configuration method to edit Spanning Tree Protocol.
* `fmgd_switchcontroller_managedswitch_stpsettings`  Configuration method to edit Spanning Tree Protocol.
* `fmgd_switchcontroller_managedswitch_switchlog`  Configuration method to edit FortiSwitch logging settings.
* `fmgd_switchcontroller_managedswitch_vlan`  Configure VLAN assignment priority.
* `fmgd_switchcontroller_nacdevice`  Configure/list NAC devices learned on the managed FortiSwitch ports which matches NAC policy.
* `fmgd_switchcontroller_nacsettings`  Configure integrated NAC settings for FortiSwitch.
* `fmgd_switchcontroller_networkmonitorsettings`  Configure network monitor settings.
* `fmgd_switchcontroller_portpolicy`  Configure port policy to be applied on the managed FortiSwitch ports through NAC device.
* `fmgd_switchcontroller_ptp_interfacepolicy`  PTP interface-policy configuration.
* `fmgd_switchcontroller_ptp_policy`  PTP policy configuration.
* `fmgd_switchcontroller_ptp_profile`  Global PTP profile.
* `fmgd_switchcontroller_ptp_settings`  Global PTP settings.
* `fmgd_switchcontroller_qos_dot1pmap`  Configure FortiSwitch QoS 802.
* `fmgd_switchcontroller_qos_ipdscpmap`  Configure FortiSwitch QoS IP precedence/DSCP.
* `fmgd_switchcontroller_qos_ipdscpmap_map`  Maps between IP-DSCP value to COS queue.
* `fmgd_switchcontroller_qos_qospolicy`  Configure FortiSwitch QoS policy.
* `fmgd_switchcontroller_qos_queuepolicy`  Configure FortiSwitch QoS egress queue policy.
* `fmgd_switchcontroller_qos_queuepolicy_cosqueue`  COS queue configuration.
* `fmgd_switchcontroller_remotelog`  Configure logging by FortiSwitch device to a remote syslog server.
* `fmgd_switchcontroller_securitypolicy_8021x`  Configure 802.
* `fmgd_switchcontroller_securitypolicy_localaccess`  Configure allowaccess list for mgmt and internal interfaces on managed FortiSwitch units.
* `fmgd_switchcontroller_sflow`  Configure FortiSwitch sFlow.
* `fmgd_switchcontroller_snmpcommunity`  Configure FortiSwitch SNMP v1/v2c communities globally.
* `fmgd_switchcontroller_snmpcommunity_hosts`  Configure IPv4 SNMP managers.
* `fmgd_switchcontroller_snmpsysinfo`  Configure FortiSwitch SNMP system information globally.
* `fmgd_switchcontroller_snmptrapthreshold`  Configure FortiSwitch SNMP trap threshold values globally.
* `fmgd_switchcontroller_snmpuser`  Configure FortiSwitch SNMP v3 users globally.
* `fmgd_switchcontroller_stormcontrol`  Configure FortiSwitch storm control.
* `fmgd_switchcontroller_stormcontrolpolicy`  Configure FortiSwitch storm control policy to be applied on managed-switch ports.
* `fmgd_switchcontroller_stpinstance`  Configure FortiSwitch multiple spanning tree protocol.
* `fmgd_switchcontroller_stpsettings`  Configure FortiSwitch spanning tree protocol.
* `fmgd_switchcontroller_switchgroup`  Configure FortiSwitch switch groups.
* `fmgd_switchcontroller_switchinterfacetag`  Configure switch object tags.
* `fmgd_switchcontroller_switchlog`  Configure FortiSwitch logging.
* `fmgd_switchcontroller_switchprofile`  Configure FortiSwitch switch profile.
* `fmgd_switchcontroller_system`  Configure system-wide switch controller settings.
* `fmgd_switchcontroller_trafficpolicy`  Configure FortiSwitch traffic policy.
* `fmgd_switchcontroller_trafficsniffer`  Configure FortiSwitch RSPAN/ERSPAN traffic sniffing parameters.
* `fmgd_switchcontroller_trafficsniffer_targetip`  Sniffer IPs to filter.
* `fmgd_switchcontroller_trafficsniffer_targetmac`  Sniffer MACs to filter.
* `fmgd_switchcontroller_trafficsniffer_targetport`  Sniffer ports to filter.
* `fmgd_switchcontroller_virtualportpool`  Configure virtual pool.
* `fmgd_switchcontroller_vlanpolicy`  Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy.
* `fmgd_system_3gmodem_custom`  3G MODEM custom.
* `fmgd_system_5gmodem`  Configure USB 5G modems.
* `fmgd_system_5gmodem_dataplan`  Configure data plan.
* `fmgd_system_5gmodem_modem1`  Configure 5G Modem1.
* `fmgd_system_5gmodem_modem1_simswitch`  Configure SIM card switch.
* `fmgd_system_5gmodem_modem2`  Configure 5G Modem2.
* `fmgd_system_accprofile`  Configure access profiles for system administrators.
* `fmgd_system_accprofile_fwgrppermission`  Custom firewall permission.
* `fmgd_system_accprofile_loggrppermission`  Custom Log & Report permission.
* `fmgd_system_accprofile_netgrppermission`  Custom network permission.
* `fmgd_system_accprofile_sysgrppermission`  Custom system permission.
* `fmgd_system_accprofile_utmgrppermission`  Custom Security Profile permissions.
* `fmgd_system_acme`  Configure ACME client.
* `fmgd_system_acme_accounts`  ACME accounts list.
* `fmgd_system_admin`  Configure admin users.
* `fmgd_system_affinityinterrupt`  Configure interrupt affinity.
* `fmgd_system_affinitypacketredistribution`  Configure packet redistribution.
* `fmgd_system_alias`  Configure alias command.
* `fmgd_system_apiuser`  Configure API users.
* `fmgd_system_apiuser_trusthost`  Trusthost.
* `fmgd_system_arptable`  Configure ARP table.
* `fmgd_system_autoinstall`  Configure USB auto installation.
* `fmgd_system_automationaction`  Action for automation stitches.
* `fmgd_system_automationaction_httpheaders`  Request headers.
* `fmgd_system_automationcondition`  Condition for automation stitches.
* `fmgd_system_automationdestination`  Automation destinations.
* `fmgd_system_automationstitch`  Automation stitches.
* `fmgd_system_automationstitch_actions`  Configure stitch actions.
* `fmgd_system_automationtrigger`  Trigger for automation stitches.
* `fmgd_system_automationtrigger_fields`  Customized trigger field settings.
* `fmgd_system_autoscale`  Configure system auto-scaling.
* `fmgd_system_autoscript`  Configure auto script.
* `fmgd_system_autoupdate_pushupdate`  Configure push updates.
* `fmgd_system_autoupdate_schedule`  Configure update schedule.
* `fmgd_system_autoupdate_tunneling`  Configure web proxy tunneling for the FDN.
* `fmgd_system_bypass`  Configure system bypass.
* `fmgd_system_centralmanagement`  Configure central management.
* `fmgd_system_centralmanagement_serverlist`  Additional severs that the FortiGate can use for updates.
* `fmgd_system_clustersync`  Device system cluster sync.
* `fmgd_system_clustersync_sessionsyncfilter`  Device system cluster sync session sync filter.
* `fmgd_system_clustersync_sessionsyncfilter_customservice`  Device system cluster sync session sync filter custom service.
* `fmgd_system_console`  Configure console.
* `fmgd_system_consoleserver`  Configure Console Server.
* `fmgd_system_consoleserver_entries`  Entry used by console server.
* `fmgd_system_csf`  Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
* `fmgd_system_csf_fabricconnector`  Fabric connector configuration.
* `fmgd_system_csf_fabricdevice`  Fabric device configuration.
* `fmgd_system_csf_trustedlist`  Pre-authorized and blocked security fabric nodes.
* `fmgd_system_ddns`  Configure DDNS.
* `fmgd_system_dedicatedmgmt`  Configure dedicated management.
* `fmgd_system_deviceupgrade`  Independent upgrades for managed devices.
* `fmgd_system_deviceupgrade_knownhamembers`  Known members of the HA cluster.
* `fmgd_system_dhcp6_server`  Configure DHCPv6 servers.
* `fmgd_system_dhcp6_server_iprange`  DHCP IP range configuration.
* `fmgd_system_dhcp6_server_options`  DHCPv6 options.
* `fmgd_system_dhcp6_server_prefixrange`  DHCP prefix configuration.
* `fmgd_system_digitalio`  Configure digital-io.
* `fmgd_system_dnp3proxy`  Configure dnpproxy settings.
* `fmgd_system_dns`  Configure DNS.
* `fmgd_system_dns64`  Configure DNS64.
* `fmgd_system_dnsdatabase`  Configure DNS databases.
* `fmgd_system_dnsdatabase_dnsentry`  DNS entry.
* `fmgd_system_dnsserver`  Configure DNS servers.
* `fmgd_system_dscpbasedpriority`  Configure DSCP based priority table.
* `fmgd_system_elbc`  Configure enhanced load balance cluster.
* `fmgd_system_emailserver`  Configure the email server used by the FortiGate various things.
* `fmgd_system_evpn`  Configure EVPN instance.
* `fmgd_system_fabricvpn`  Setup for self orchestrated fabric auto discovery VPN.
* `fmgd_system_fabricvpn_advertisedsubnets`  Local advertised subnets.
* `fmgd_system_fabricvpn_overlays`  Local overlay interfaces table.
* `fmgd_system_federatedupgrade`  Coordinate federated upgrades within the Security Fabric.
* `fmgd_system_federatedupgrade_knownhamembers`  Known members of the HA cluster.
* `fmgd_system_federatedupgrade_nodelist`  Nodes which will be included in the upgrade.
* `fmgd_system_fipscc`  Configure FIPS-CC mode.
* `fmgd_system_fortiai`  Configure FortiAI.
* `fmgd_system_fortindr`  Configure FortiNDR.
* `fmgd_system_fortisandbox`  Configure FortiSandbox.
* `fmgd_system_fssopolling`  Configure Fortinet Single Sign On.
* `fmgd_system_ftmpush`  Configure FortiToken Mobile push services.
* `fmgd_system_geneve`  Configure GENEVE devices.
* `fmgd_system_gigk`  Configure Gi Firewall Gatekeeper.
* `fmgd_system_global`  Configure global attributes.
* `fmgd_system_gretunnel`  Configure GRE tunnel.
* `fmgd_system_ha`  Configure HA.
* `fmgd_system_ha_frupsettings`  Device system ha frup settings.
* `fmgd_system_ha_hamgmtinterfaces`  Reserve interfaces to manage individual cluster units.
* `fmgd_system_ha_secondaryvcluster`  Configure virtual cluster 2.
* `fmgd_system_ha_unicastpeers`  Number of unicast peers.
* `fmgd_system_ha_vcluster`  Virtual cluster table.
* `fmgd_system_hamonitor`  Configure HA monitor.
* `fmgd_system_healthcheckfortiguard`  SD-WAN status checking or health checking.
* `fmgd_system_icond`  Configure Industrial Connectivity.
* `fmgd_system_ike`  Configure IKE global attributes.
* `fmgd_system_ike_dhgroup1`  Diffie-Hellman group 1.
* `fmgd_system_ike_dhgroup14`  Diffie-Hellman group 14.
* `fmgd_system_ike_dhgroup15`  Diffie-Hellman group 15.
* `fmgd_system_ike_dhgroup16`  Diffie-Hellman group 16.
* `fmgd_system_ike_dhgroup17`  Diffie-Hellman group 17.
* `fmgd_system_ike_dhgroup18`  Diffie-Hellman group 18.
* `fmgd_system_ike_dhgroup19`  Diffie-Hellman group 19.
* `fmgd_system_ike_dhgroup2`  Diffie-Hellman group 2.
* `fmgd_system_ike_dhgroup20`  Diffie-Hellman group 20.
* `fmgd_system_ike_dhgroup21`  Diffie-Hellman group 21.
* `fmgd_system_ike_dhgroup27`  Diffie-Hellman group 27.
* `fmgd_system_ike_dhgroup28`  Diffie-Hellman group 28.
* `fmgd_system_ike_dhgroup29`  Diffie-Hellman group 29.
* `fmgd_system_ike_dhgroup30`  Diffie-Hellman group 30.
* `fmgd_system_ike_dhgroup31`  Diffie-Hellman group 31.
* `fmgd_system_ike_dhgroup32`  Diffie-Hellman group 32.
* `fmgd_system_ike_dhgroup5`  Diffie-Hellman group 5.
* `fmgd_system_interface`  Configure interfaces.
* `fmgd_system_interface_clientoptions`  DHCP client options.
* `fmgd_system_interface_dhcpsnoopingserverlist`  Configure DHCP server access list.
* `fmgd_system_interface_egressqueues`  Configure queues of NP port on egress path.
* `fmgd_system_interface_ipv6`  IPv6 of interface.
* `fmgd_system_interface_ipv6_clientoptions`  DHCP6 client options.
* `fmgd_system_interface_ipv6_dhcp6iapdlist`  DHCPv6 IA-PD list.
* `fmgd_system_interface_ipv6_ip6delegatedprefixlist`  Advertised IPv6 delegated prefix list.
* `fmgd_system_interface_ipv6_ip6dnssllist`  Advertised IPv6 DNSS list.
* `fmgd_system_interface_ipv6_ip6extraaddr`  Extra IPv6 address prefixes of interface.
* `fmgd_system_interface_ipv6_ip6prefixlist`  Advertised prefix list.
* `fmgd_system_interface_ipv6_ip6rdnsslist`  Advertised IPv6 RDNSS list.
* `fmgd_system_interface_ipv6_ip6routelist`  Advertised route list.
* `fmgd_system_interface_ipv6_vrrp6`  IPv6 VRRP configuration.
* `fmgd_system_interface_l2tpclientsettings`  L2TP client settings.
* `fmgd_system_interface_mirroringfilter`  Mirroring filter.
* `fmgd_system_interface_secondaryip`  Second IP address of interface.
* `fmgd_system_interface_tagging`  Config object tagging.
* `fmgd_system_interface_vrrp`  VRRP configuration.
* `fmgd_system_interface_vrrp_proxyarp`  VRRP Proxy ARP configuration.
* `fmgd_system_interface_wifinetworks`  WiFi network table.
* `fmgd_system_ipam`  Configure IP address management services.
* `fmgd_system_ipam_pools`  Configure IPAM pools.
* `fmgd_system_ipam_pools_exclude`  Configure pool exclude subnets.
* `fmgd_system_ipam_rules`  Configure IPAM allocation rules.
* `fmgd_system_ipiptunnel`  Configure IP in IP Tunneling.
* `fmgd_system_ips`  Configure IPS system settings.
* `fmgd_system_ipsecaggregate`  Configure an aggregate of IPsec tunnels.
* `fmgd_system_ipsurlfilterdns`  Configure IPS URL filter DNS servers.
* `fmgd_system_ipsurlfilterdns6`  Configure IPS URL filter IPv6 DNS servers.
* `fmgd_system_ipv6neighborcache`  Configure IPv6 neighbor cache table.
* `fmgd_system_ipv6tunnel`  Configure IPv6/IPv4 in IPv6 tunnel.
* `fmgd_system_iscsi`  Configure system iSCSI.
* `fmgd_system_isfqueueprofile`  Create a queue profile of switch.
* `fmgd_system_linkmonitor`  Configure Link Health Monitor.
* `fmgd_system_linkmonitor_serverlist`  Servers for link-monitor to monitor.
* `fmgd_system_lldp_networkpolicy`  Configure LLDP network policy.
* `fmgd_system_lldp_networkpolicy_guest`  Guest.
* `fmgd_system_lldp_networkpolicy_guestvoicesignaling`  Guest Voice Signaling.
* `fmgd_system_lldp_networkpolicy_softphone`  Softphone.
* `fmgd_system_lldp_networkpolicy_streamingvideo`  Streaming Video.
* `fmgd_system_lldp_networkpolicy_videoconferencing`  Video Conferencing.
* `fmgd_system_lldp_networkpolicy_videosignaling`  Video Signaling.
* `fmgd_system_lldp_networkpolicy_voice`  Voice.
* `fmgd_system_lldp_networkpolicy_voicesignaling`  Voice signaling.
* `fmgd_system_ltemodem`  Configure USB LTE/WIMAX devices.
* `fmgd_system_ltemodem_dataplan`  Configure data plan.
* `fmgd_system_ltemodem_simswitch`  Configure SIM card switch.
* `fmgd_system_macaddresstable`  Configure MAC address tables.
* `fmgd_system_memmgr`  Configure memory manager.
* `fmgd_system_mobiletunnel`  Configure Mobile tunnels, an implementation of Network Mobility.
* `fmgd_system_mobiletunnel_network`  NEMO network configuration.
* `fmgd_system_modem`  Configure MODEM.
* `fmgd_system_nat64`  Device vdom system nat64.
* `fmgd_system_nat64_secondaryprefix`  Device vdom system nat64 secondary prefix.
* `fmgd_system_ndproxy`  Configure IPv6 neighbor discovery proxy.
* `fmgd_system_netflow`  Configure NetFlow.
* `fmgd_system_netflow_collectors`  Netflow collectors.
* `fmgd_system_netflow_exclusionfilters`  Exclusion filters.
* `fmgd_system_networkvisibility`  Configure network visibility settings.
* `fmgd_system_ngfwsettings`  Configure IPS NGFW policy-mode VDOM settings.
* `fmgd_system_np6`  Configure NP6 attributes.
* `fmgd_system_np6_fpanomaly`  NP6 IPv4 anomaly protection.
* `fmgd_system_np6_hpe`  HPE configuration.
* `fmgd_system_np6xlite`  Configure NP6XLITE attributes.
* `fmgd_system_np6xlite_fpanomaly`  NP6XLITE IPv4 anomaly protection.
* `fmgd_system_np6xlite_hpe`  HPE configuration.
* `fmgd_system_npupost`  Configure NPU attributes after interface initialization.
* `fmgd_system_npupost_portnpumap`  Configure port to NPU group list.
* `fmgd_system_npusetting_prp`  Configure NPU PRP attributes.
* `fmgd_system_npuvlink`  Configure NPU VDOM link.
* `fmgd_system_ntp`  Configure system NTP information.
* `fmgd_system_ntp_ntpserver`  Configure the FortiGate to connect to any available third-party NTP server.
* `fmgd_system_passwordpolicy`  Configure password policy for locally defined administrator passwords and IPsec VPN pre-shared keys.
* `fmgd_system_passwordpolicyguestadmin`  Configure the password policy for guest administrators.
* `fmgd_system_pcpserver`  Configure PCP server information.
* `fmgd_system_pcpserver_pools`  Configure PCP pools.
* `fmgd_system_physicalswitch`  Configure physical switches.
* `fmgd_system_pppoeinterface`  Configure the PPPoE interfaces.
* `fmgd_system_proberesponse`  Configure system probe response.
* `fmgd_system_proxyarp`  Configure proxy-ARP.
* `fmgd_system_ptp`  Configure system PTP information.
* `fmgd_system_ptp_serverinterface`  FortiGate interface.
* `fmgd_system_replacemsg_admin`  Replacement messages.
* `fmgd_system_replacemsg_alertmail`  Replacement messages.
* `fmgd_system_replacemsg_auth`  Replacement messages.
* `fmgd_system_replacemsg_automation`  Replacement messages.
* `fmgd_system_replacemsg_custommessage`  Replacement messages.
* `fmgd_system_replacemsg_devicedetectionportal`  Device system replacemsg device detection portal.
* `fmgd_system_replacemsg_fortiguardwf`  Replacement messages.
* `fmgd_system_replacemsg_ftp`  Replacement messages.
* `fmgd_system_replacemsg_http`  Replacement messages.
* `fmgd_system_replacemsg_icap`  Replacement messages.
* `fmgd_system_replacemsg_mail`  Replacement messages.
* `fmgd_system_replacemsg_mm1`  Replacement messages.
* `fmgd_system_replacemsg_mm3`  Replacement messages.
* `fmgd_system_replacemsg_mm4`  Replacement messages.
* `fmgd_system_replacemsg_mm7`  Replacement messages.
* `fmgd_system_replacemsg_mms`  Replacement messages.
* `fmgd_system_replacemsg_nacquar`  Replacement messages.
* `fmgd_system_replacemsg_nntp`  Device system replacemsg nntp.
* `fmgd_system_replacemsg_spam`  Replacement messages.
* `fmgd_system_replacemsg_sslvpn`  Replacement messages.
* `fmgd_system_replacemsg_trafficquota`  Replacement messages.
* `fmgd_system_replacemsg_utm`  Replacement messages.
* `fmgd_system_replacemsg_webproxy`  Replacement messages.
* `fmgd_system_saml`  Global settings for SAML authentication.
* `fmgd_system_saml_serviceproviders`  Authorized service providers.
* `fmgd_system_saml_serviceproviders_assertionattributes`  Customized SAML attributes to send along with assertion.
* `fmgd_system_sdnvpn`  Configure public cloud VPN service.
* `fmgd_system_sdwan`  Configure redundant Internet connections with multiple outbound links and health-check profiles.
* `fmgd_system_sdwan_duplication`  Create SD-WAN duplication rule.
* `fmgd_system_sdwan_healthcheck`  SD-WAN status checking or health checking.
* `fmgd_system_sdwan_healthcheck_sla`  Service level agreement.
* `fmgd_system_sdwan_healthcheckfortiguard`  SD-WAN status checking or health checking.
* `fmgd_system_sdwan_healthcheckfortiguard_sla`  Service level agreement.
* `fmgd_system_sdwan_members`  FortiGate interfaces added to the SD-WAN.
* `fmgd_system_sdwan_neighbor`  Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
* `fmgd_system_sdwan_service`  Create SD-WAN rules.
* `fmgd_system_sdwan_service_sla`  Service level agreement.
* `fmgd_system_sdwan_zone`  Configure SD-WAN zones.
* `fmgd_system_securityrating_controls`  Settings for individual Security Rating controls.
* `fmgd_system_securityrating_settings`  Settings for Security Rating.
* `fmgd_system_sessionhelper`  Configure session helper.
* `fmgd_system_sessionttl`  Configure global session TTL timers for this FortiGate.
* `fmgd_system_sessionttl_port`  Session TTL port.
* `fmgd_system_settings`  Configure VDOM settings.
* `fmgd_system_sflow`  Configure sFlow.
* `fmgd_system_sflow_collectors`  sFlow collectors.
* `fmgd_system_sittunnel`  Configure IPv6 tunnel over IPv4.
* `fmgd_system_smcntp`  Configure SMC NTP information.
* `fmgd_system_smcntp_ntpserver`  Configure the FortiGate SMC to connect to an NTP server.
* `fmgd_system_snmp_community`  SNMP community configuration.
* `fmgd_system_snmp_community_hosts`  Configure IPv4 SNMP managers.
* `fmgd_system_snmp_community_hosts6`  Configure IPv6 SNMP managers.
* `fmgd_system_snmp_mibview`  SNMP Access Control MIB View configuration.
* `fmgd_system_snmp_rmonstat`  SNMP Remote Network Monitoring.
* `fmgd_system_snmp_sysinfo`  SNMP system info configuration.
* `fmgd_system_snmp_user`  SNMP user configuration.
* `fmgd_system_speedtestschedule`  Speed test schedule for each interface.
* `fmgd_system_speedtestserver`  Configure speed test server list.
* `fmgd_system_speedtestserver_host`  Hosts of the server.
* `fmgd_system_speedtestsetting`  Configure speed test setting.
* `fmgd_system_splitportmode`  Configure split port mode of ports.
* `fmgd_system_sshconfig`  Configure SSH config.
* `fmgd_system_ssoadmin`  Configure SSO admin users.
* `fmgd_system_ssoforticloudadmin`  Configure FortiCloud SSO admin users.
* `fmgd_system_ssofortigatecloudadmin`  Configure FortiCloud SSO admin users.
* `fmgd_system_standalonecluster`  Configure FortiGate Session Life Support Protocol.
* `fmgd_system_standalonecluster_clusterpeer`  Configure FortiGate Session Life Support Protocol.
* `fmgd_system_standalonecluster_clusterpeer_sessionsyncfilter`  Add one or more filters if you only want to synchronize some sessions.
* `fmgd_system_standalonecluster_clusterpeer_sessionsyncfilter_customservice`  Only sessions using these custom services are synchronized.
* `fmgd_system_standalonecluster_monitorprefix`  Configure a list of routing prefixes to monitor.
* `fmgd_system_storage`  Configure logical storage.
* `fmgd_system_stp`  Configure Spanning Tree Protocol.
* `fmgd_system_switchinterface`  Configure software switch interfaces by grouping physical and WiFi interfaces.
* `fmgd_system_timezone`  Show timezone.
* `fmgd_system_tosbasedpriority`  Configure Type of Service.
* `fmgd_system_vdom`  Configure virtual domain.
* `fmgd_system_vdomdns`  Configure DNS servers for a non-management VDOM.
* `fmgd_system_vdomexception`  Global configuration objects that can be configured independently across different ha peers for all VDOMs or for the defined VDOM scope.
* `fmgd_system_vdomlink`  Configure VDOM links.
* `fmgd_system_vdomnetflow`  Configure NetFlow per VDOM.
* `fmgd_system_vdomnetflow_collectors`  Netflow collectors.
* `fmgd_system_vdomproperty`  Configure VDOM property.
* `fmgd_system_vdomradiusserver`  Configure a RADIUS server to use as a RADIUS Single Sign On.
* `fmgd_system_vdomsflow`  Configure sFlow per VDOM to add or change the IP address and UDP port that FortiGate sFlow agents in this VDOM use to send sFlow dat...
* `fmgd_system_vdomsflow_collectors`  sFlow collectors.
* `fmgd_system_vinalarm`  Configure vin alarm settings.
* `fmgd_system_virtualswitch`  Configure virtual hardware switch interfaces.
* `fmgd_system_virtualswitch_port`  Configure member ports.
* `fmgd_system_virtualwanlink`  Configure redundant internet connections using SD-WAN.
* `fmgd_system_virtualwanlink_healthcheck`  SD-WAN status checking or health checking.
* `fmgd_system_virtualwanlink_healthcheck_sla`  Service level agreement.
* `fmgd_system_virtualwanlink_members`  FortiGate interfaces added to the virtual-wan-link.
* `fmgd_system_virtualwanlink_neighbor`  Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
* `fmgd_system_virtualwanlink_service`  Create SD-WAN rules.
* `fmgd_system_virtualwanlink_service_sla`  Service level agreement.
* `fmgd_system_vneinterface`  Configure virtual network enabler tunnels.
* `fmgd_system_vnetunnel`  Configure virtual network enabler tunnel.
* `fmgd_system_vpce`  Configure system VPC configuration.
* `fmgd_system_vxlan`  Configure VXLAN devices.
* `fmgd_system_wccp`  Configure WCCP.
* `fmgd_system_wireless_apstatus`  Configure accepted wireless AP.
* `fmgd_system_wireless_settings`  Wireless radio configuration.
* `fmgd_system_zone`  Configure zones to group two or more interfaces.
* `fmgd_system_zone_tagging`  Config object tagging.
* `fmgd_user_nacpolicy`  Configure NAC policy matching pattern to identify matching NAC devices.
* `fmgd_user_quarantine`  Configure quarantine support.
* `fmgd_user_quarantine_targets`  Quarantine entry to hold multiple MACs.
* `fmgd_user_quarantine_targets_macs`  Quarantine MACs.
* `fmgd_user_scim`  Configure SCIM client entries.
* `fmgd_user_setting`  Configure user authentication setting.
* `fmgd_user_setting_authports`  Set up non-standard ports for authentication with HTTP, HTTPS, FTP, and TELNET.
* `fmgd_videofilter_youtubekey`  Configure YouTube API keys.
* `fmgd_vpn_certificate_crl`  Certificate Revocation List as a PEM file.
* `fmgd_vpn_certificate_local`  Local keys and certificates.
* `fmgd_vpn_certificate_setting`  VPN certificate setting.
* `fmgd_vpn_certificate_setting_crlverification`  CRL verification options.
* `fmgd_vpn_ipsec_concentrator`  Concentrator configuration.
* `fmgd_vpn_ipsec_forticlient`  Configure FortiClient policy realm.
* `fmgd_vpn_ipsec_manualkey`  Configure IPsec manual keys.
* `fmgd_vpn_ipsec_manualkeyinterface`  Configure IPsec manual keys.
* `fmgd_vpn_ipsec_phase1`  Configure VPN remote gateway.
* `fmgd_vpn_ipsec_phase1_ipv4excluderange`  Configuration Method IPv4 exclude ranges.
* `fmgd_vpn_ipsec_phase1_ipv6excluderange`  Configuration method IPv6 exclude ranges.
* `fmgd_vpn_ipsec_phase1interface`  Configure VPN remote gateway.
* `fmgd_vpn_ipsec_phase1interface_ipv4excluderange`  Configuration Method IPv4 exclude ranges.
* `fmgd_vpn_ipsec_phase1interface_ipv6excluderange`  Configuration method IPv6 exclude ranges.
* `fmgd_vpn_ipsec_phase2`  Configure VPN autokey tunnel.
* `fmgd_vpn_ipsec_phase2interface`  Configure VPN autokey tunnel.
* `fmgd_vpn_kmipserver`  KMIP server entry configuration.
* `fmgd_vpn_kmipserver_serverlist`  KMIP server list.
* `fmgd_vpn_l2tp`  Configure L2TP.
* `fmgd_vpn_ocvpn`  Configure Overlay Controller VPN settings.
* `fmgd_vpn_ocvpn_forticlientaccess`  Configure FortiClient settings.
* `fmgd_vpn_ocvpn_forticlientaccess_authgroups`  FortiClient user authentication groups.
* `fmgd_vpn_ocvpn_overlays`  Network overlays to register with Overlay Controller VPN service.
* `fmgd_vpn_ocvpn_overlays_subnets`  Internal subnets to register with OCVPN service.
* `fmgd_vpn_pptp`  Configure PPTP.
* `fmgd_vpn_qkd`  Configure Quantum Key Distribution servers.
* `fmgd_vpn_ssl_client`  Client.
* `fmgd_vpn_ssl_settings`  Configure SSL VPN.
* `fmgd_vpn_ssl_settings_authenticationrule`  Authentication rule for SSL VPN.
* `fmgd_vpnsslweb_userbookmark`  Configure SSL-VPN user bookmark.
* `fmgd_vpnsslweb_userbookmark_bookmarks`  Bookmark table.
* `fmgd_vpnsslweb_userbookmark_bookmarks_formdata`  Form data.
* `fmgd_vpnsslweb_usergroupbookmark`  Configure SSL-VPN user group bookmark.
* `fmgd_vpnsslweb_usergroupbookmark_bookmarks`  Bookmark table.
* `fmgd_vpnsslweb_usergroupbookmark_bookmarks_formdata`  Form data.
* `fmgd_wanopt_cacheservice`  Designate cache-service for wan-optimization and webcache.
* `fmgd_wanopt_cacheservice_dstpeer`  Modify cache-service destination peer list.
* `fmgd_wanopt_cacheservice_srcpeer`  Modify cache-service source peer list.
* `fmgd_wanopt_contentdeliverynetworkrule`  Configure WAN optimization content delivery network rules.
* `fmgd_wanopt_contentdeliverynetworkrule_rules`  WAN optimization content delivery network rule entries.
* `fmgd_wanopt_contentdeliverynetworkrule_rules_contentid`  Content ID settings.
* `fmgd_wanopt_contentdeliverynetworkrule_rules_matchentries`  List of entries to match.
* `fmgd_wanopt_contentdeliverynetworkrule_rules_skipentries`  List of entries to skip.
* `fmgd_wanopt_remotestorage`  Configure a remote cache device as Web cache storage.
* `fmgd_wanopt_settings`  Configure WAN optimization settings.
* `fmgd_wanopt_webcache`  Configure global Web cache settings.
* `fmgd_webfilter_fortiguard`  Configure FortiGuard Web Filter service.
* `fmgd_webfilter_ftgdlocalrisk`  Configure FortiGuard Web Filter local risk score.
* `fmgd_webfilter_ftgdrisklevel`  Configure FortiGuard Web Filter risk level.
* `fmgd_webfilter_ipsurlfiltercachesetting`  Configure IPS URL filter cache settings.
* `fmgd_webfilter_ipsurlfiltersetting`  Configure IPS URL filter settings.
* `fmgd_webfilter_ipsurlfiltersetting6`  Configure IPS URL filter settings for IPv6.
* `fmgd_webfilter_override`  Configure FortiGuard Web Filter administrative overrides.
* `fmgd_webfilter_searchengine`  Configure web filter search engines.
* `fmgd_webproxy_debugurl`  Configure debug URL addresses.
* `fmgd_webproxy_explicit`  Configure explicit Web proxy settings.
* `fmgd_webproxy_explicit_pacpolicy`  PAC policies.
* `fmgd_webproxy_fastfallback`  Proxy destination connection fast-fallback.
* `fmgd_webproxy_global`  Configure Web proxy global settings.
* `fmgd_webproxy_urlmatch`  Exempt URLs from web proxy forwarding and caching.
* `fmgd_wireless_accesscontrollist`  Configure WiFi bridge access control list.
* `fmgd_wireless_accesscontrollist_layer3ipv4rules`  AP ACL layer3 ipv4 rule list.
* `fmgd_wireless_accesscontrollist_layer3ipv6rules`  AP ACL layer3 ipv6 rule list.
* `fmgd_wireless_apcfgprofile`  Configure AP local configuration profiles.
* `fmgd_wireless_apcfgprofile_commandlist`  AP local configuration command list.
* `fmgd_wireless_apstatus`  Configure access point status.
* `fmgd_wireless_arrpprofile`  Configure WiFi Automatic Radio Resource Provisioning.
* `fmgd_wireless_bleprofile`  Configure Bluetooth Low Energy profile.
* `fmgd_wireless_bonjourprofile`  Configure Bonjour profiles.
* `fmgd_wireless_bonjourprofile_policylist`  Bonjour policy list.
* `fmgd_wireless_global`  Configure wireless controller global settings.
* `fmgd_wireless_hotspot20_anqp3gppcellular`  Configure 3GPP public land mobile network.
* `fmgd_wireless_hotspot20_anqp3gppcellular_mccmnclist`  Mobile Country Code and Mobile Network Code configuration.
* `fmgd_wireless_hotspot20_anqpipaddresstype`  Configure IP address type availability.
* `fmgd_wireless_hotspot20_anqpnairealm`  Configure network access identifier.
* `fmgd_wireless_hotspot20_anqpnairealm_nailist`  NAI list.
* `fmgd_wireless_hotspot20_anqpnairealm_nailist_eapmethod`  EAP Methods.
* `fmgd_wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam`  EAP auth param.
* `fmgd_wireless_hotspot20_anqpnetworkauthtype`  Configure network authentication type.
* `fmgd_wireless_hotspot20_anqproamingconsortium`  Configure roaming consortium.
* `fmgd_wireless_hotspot20_anqproamingconsortium_oilist`  Organization identifier list.
* `fmgd_wireless_hotspot20_anqpvenuename`  Configure venue name duple.
* `fmgd_wireless_hotspot20_anqpvenuename_valuelist`  Name list.
* `fmgd_wireless_hotspot20_anqpvenueurl`  Configure venue URL.
* `fmgd_wireless_hotspot20_anqpvenueurl_valuelist`  URL list.
* `fmgd_wireless_hotspot20_h2qpadviceofcharge`  Configure advice of charge.
* `fmgd_wireless_hotspot20_h2qpadviceofcharge_aoclist`  AOC list.
* `fmgd_wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo`  Plan info.
* `fmgd_wireless_hotspot20_h2qpconncapability`  Configure connection capability.
* `fmgd_wireless_hotspot20_h2qpoperatorname`  Configure operator friendly name.
* `fmgd_wireless_hotspot20_h2qpoperatorname_valuelist`  Name list.
* `fmgd_wireless_hotspot20_h2qposuprovider`  Configure online sign up.
* `fmgd_wireless_hotspot20_h2qposuprovider_friendlyname`  OSU provider friendly name.
* `fmgd_wireless_hotspot20_h2qposuprovider_servicedescription`  OSU service name.
* `fmgd_wireless_hotspot20_h2qposuprovidernai`  Configure online sign up.
* `fmgd_wireless_hotspot20_h2qposuprovidernai_nailist`  OSU NAI list.
* `fmgd_wireless_hotspot20_h2qptermsandconditions`  Configure terms and conditions.
* `fmgd_wireless_hotspot20_h2qpwanmetric`  Configure WAN metrics.
* `fmgd_wireless_hotspot20_hsprofile`  Configure hotspot profile.
* `fmgd_wireless_hotspot20_icon`  Configure OSU provider icon.
* `fmgd_wireless_hotspot20_icon_iconlist`  Icon list.
* `fmgd_wireless_hotspot20_qosmap`  Configure QoS map set.
* `fmgd_wireless_hotspot20_qosmap_dscpexcept`  Differentiated Services Code Point.
* `fmgd_wireless_hotspot20_qosmap_dscprange`  Differentiated Services Code Point.
* `fmgd_wireless_intercontroller`  Configure inter wireless controller operation.
* `fmgd_wireless_intercontroller_intercontrollerpeer`  Fast failover peer wireless controller list.
* `fmgd_wireless_log`  Configure wireless controller event log filters.
* `fmgd_wireless_mpskprofile`  Configure MPSK profile.
* `fmgd_wireless_mpskprofile_mpskgroup`  List of multiple PSK groups.
* `fmgd_wireless_mpskprofile_mpskgroup_mpskkey`  List of multiple PSK entries.
* `fmgd_wireless_nacprofile`  Configure WiFi network access control.
* `fmgd_wireless_qosprofile`  Configure WiFi quality of service.
* `fmgd_wireless_region`  Configure FortiAP regions.
* `fmgd_wireless_setting`  VDOM wireless controller configuration.
* `fmgd_wireless_setting_offendingssid`  Configure offending SSID.
* `fmgd_wireless_snmp`  Configure SNMP.
* `fmgd_wireless_snmp_community`  SNMP Community Configuration.
* `fmgd_wireless_snmp_community_hosts`  Configure IPv4 SNMP managers.
* `fmgd_wireless_snmp_user`  SNMP User Configuration.
* `fmgd_wireless_ssidpolicy`  Configure WiFi SSID policies.
* `fmgd_wireless_syslogprofile`  Configure Wireless Termination Points.
* `fmgd_wireless_timers`  Configure CAPWAP timers.
* `fmgd_wireless_utmprofile`  Configure UTM.
* `fmgd_wireless_vap`  Configure Virtual Access Points.
* `fmgd_wireless_vap_dynamicmapping`  Configure Virtual Access Points.
* `fmgd_wireless_vap_macfilterlist`  Create a list of MAC addresses for MAC address filtering.
* `fmgd_wireless_vap_mpskkey`  Device vdom wireless controller vap mpsk key.
* `fmgd_wireless_vap_portalmessageoverrides`  Individual message overrides.
* `fmgd_wireless_vap_vlanname`  Table for mapping VLAN name to VLAN ID.
* `fmgd_wireless_vap_vlanpool`  VLAN pool.
* `fmgd_wireless_vapgroup`  Configure virtual Access Point.
* `fmgd_wireless_wagprofile`  Configure wireless access gateway.
* `fmgd_wireless_widsprofile`  Configure wireless intrusion detection system.
* `fmgd_wireless_wtp`  Configure Wireless Termination Points.
* `fmgd_wireless_wtp_lan`  WTP LAN port mapping.
* `fmgd_wireless_wtp_radio1`  Configuration options for radio 1.
* `fmgd_wireless_wtp_radio2`  Configuration options for radio 2.
* `fmgd_wireless_wtp_radio3`  Configuration options for radio 3.
* `fmgd_wireless_wtp_radio4`  Configuration options for radio 4.
* `fmgd_wireless_wtp_splittunnelingacl`  Split tunneling ACL filter list.
* `fmgd_wireless_wtpgroup`  Configure WTP groups.
* `fmgd_wireless_wtpprofile`  Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms.
* `fmgd_wireless_wtpprofile_denymaclist`  List of MAC addresses that are denied access to this WTP, FortiAP, or AP.
* `fmgd_wireless_wtpprofile_eslsesdongle`  ESL SES-imagotag dongle configuration.
* `fmgd_wireless_wtpprofile_lan`  WTP LAN port mapping.
* `fmgd_wireless_wtpprofile_lbs`  Set various location based service.
* `fmgd_wireless_wtpprofile_platform`  WTP, FortiAP, or AP platform.
* `fmgd_wireless_wtpprofile_radio1`  Configuration options for radio 1.
* `fmgd_wireless_wtpprofile_radio2`  Configuration options for radio 2.
* `fmgd_wireless_wtpprofile_radio3`  Configuration options for radio 3.
* `fmgd_wireless_wtpprofile_radio4`  Configuration options for radio 4.
* `fmgd_wireless_wtpprofile_splittunnelingacl`  Split tunneling ACL filter list.
* `fmgd_ztna_reverseconnector`  Configure ZTNA Reverse-Connector.
* `fmgd_ztna_trafficforwardproxy`  Configure ZTNA traffic forward proxy.
* `fmgd_ztna_trafficforwardproxy_quic`  QUIC setting.
* `fmgd_ztna_trafficforwardproxy_sslciphersuites`  SSL/TLS cipher suites acceptable from a client, ordered by priority.
* `fmgd_ztna_trafficforwardproxy_sslserverciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgd_ztna_trafficforwardproxyreverseservice`  Configure ZTNA traffic forward proxy reverse service.
* `fmgd_ztna_trafficforwardproxyreverseservice_remoteservers`  Connector Remote server.
* `fmgd_ztna_webportal`  Configure ztna web-portal.
* `fmgd_ztna_webportalbookmark`  Configure ztna web-portal bookmark.
* `fmgd_ztna_webportalbookmark_bookmarks`  Bookmark table.
* `fmgd_ztna_webproxy`  Configure ZTNA web-proxy.
* `fmgd_ztna_webproxy_apigateway`  Set IPv4 API Gateway.
* `fmgd_ztna_webproxy_apigateway6`  Set IPv6 API Gateway.
* `fmgd_ztna_webproxy_apigateway6_quic`  QUIC setting.
* `fmgd_ztna_webproxy_apigateway6_realservers`  Select the real servers that this Access Proxy will distribute traffic to.
* `fmgd_ztna_webproxy_apigateway6_sslciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.
* `fmgd_ztna_webproxy_apigateway_quic`  QUIC setting.
* `fmgd_ztna_webproxy_apigateway_realservers`  Select the real servers that this Access Proxy will distribute traffic to.
* `fmgd_ztna_webproxy_apigateway_sslciphersuites`  SSL/TLS cipher suites to offer to a server, ordered by priority.



## License Information

FortiManager Ansible Collection follows [GNU General Public License v3.0](https://github.com/fortinet-ansible-dev/ansible-galaxy-fmgdevice-collection/blob/main/LICENSE).