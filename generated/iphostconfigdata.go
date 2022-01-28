/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */

package generated

import "github.com/deckarep/golang-set"

// IpHostConfigDataClassID is the 16-bit ID for the OMCI
// Managed entity IP host config data
const IpHostConfigDataClassID = ClassID(134) // 0x0086

var iphostconfigdataBME *ManagedEntityDefinition

// IpHostConfigData (Class ID: #134 / 0x0086)
//	The IP host config data configures IPv4 based services offered on the ONU. The ONU automatically
//	creates instances of this ME if IP host services are available. A possible IPv6 stack is
//	supported through the IPv6 host config data ME. In this clause, references to IP addresses are
//	understood to mean IPv4.
//
//	Relationships
//		An instance of this ME is associated with the ONU ME. Any number of TCP/UDP config data MEs can
//		point to the IP host config data, to model any number of ports and protocols. Performance may be
//		monitored through an implicitly linked IP host PM history data ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The ONU creates as many instances
//			as there are independent IPv4 stacks on the ONU. To facilitate discovery, IP host config data
//			MEs should be numbered from 0 upwards. The ONU should create IP(v4) and IPv6 host config data
//			MEs with separate ME IDs, such that other MEs can use a single TP type attribute to link with
//			either. (R) (mandatory) (2 bytes)
//
//		Ip Options
//			This attribute is a bit map that enables or disables IP-related options. The value 1 enables the
//			option while 0 disables it. The default value of this attribute is 0.
//
//			0x01	Enable DHCP
//
//			0x02	Respond to pings
//
//			0x04	Respond to traceroute messages
//
//			0x08	Enable IP stack
//
//			0x10..0x80	Reserved
//
//			(R,-W) (mandatory) (1-byte)
//
//		Mac Address
//			This attribute indicates the MAC address used by the IP node. (R) (mandatory) (6-bytes)
//
//		Onu Identifier
//			A unique ONU identifier string. If set to a non-null value, this string is used instead of the
//			MAC address in retrieving dynamic host configuration protocol (DHCP) parameters. If the string
//			is shorter than 25 characters, it must be null terminated. Its default value is 25 null bytes.
//			(R,-W) (mandatory) (25-bytes)
//
//			Several attributes of this ME may be paired together into two categories, manual settings and
//			current values.
//
//			While the IP stack is disabled, there is no IP connectivity to the external world from this ME
//			instance.
//
//			While DHCP is disabled, the current values are always the same as the manual settings. While
//			DHCP is enabled, the current values are those assigned by DHCP, or undefined (0) if DHCP has
//			never assigned values.
//
//		Ip Address
//			The address used for IP host services; this attribute has the default value 0. (R,-W)
//			(mandatory) (4-bytes)
//
//		Mask
//			The subnet mask for IP host services; this attribute has the default value 0. (R,-W) (mandatory)
//			(4-bytes)
//
//		Gateway
//			The default gateway address used for IP host services; this attribute has the default value 0.
//			(R,-W) (mandatory) (4-bytes)
//
//		Primary Dns
//			The address of the primary DNS server; this attribute has the default value 0. (R,-W)
//			(mandatory) (4-bytes)
//
//		Secondary Dns
//			The address of the secondary DNS server; this attribute has the default value 0. (R,-W)
//			(mandatory) (4-bytes)
//
//		Current Address
//			Current address of the IP host service. (R) (optional) (4-bytes)
//
//		Current Mask
//			Current subnet mask for the IP host service. (R) (optional) (4-bytes)
//
//		Current Gateway
//			Current default gateway address for the IP host service. (R) (optional) (4-bytes)
//
//		Current Primary Dns
//			Current primary DNS server address. (R) (optional) (4-bytes)
//
//		Current Secondary Dns
//			Current secondary DNS server address. (R) (optional) (4-bytes)
//
//		Domain Name
//			If DHCP indicates a domain name, it is presented here. If no domain name is indicated, this
//			attribute is set to a null string. If the string is shorter than 25-bytes, it must be null
//			terminated. The default value is 25 null bytes. (R) (mandatory) (25-bytes)
//
//		Host Name
//			If DHCP indicates a host name, it is presented here. If no host name is indicated, this
//			attribute is set to a null string. If the string is shorter than 25-bytes, it must be null
//			terminated. The default value is 25 null bytes. (R) (mandatory) (25-bytes)
//
//		Relay Agent Options
//			This attribute is a pointer to a large string ME whose content specifies one or more DHCP relay
//			agent options. (R, W) (optional) (2-bytes)
//
//			The contents of the large string are parsed by the ONU and converted into text strings. Variable
//			substitution is based on defined three-character groups, each of which begins with the '%'
//			character. The string '%%' is an escape mechanism whose output is a single '%' character. When
//			the ONU cannot perform variable substitution on a substring of the large string, it generates
//			the specified option as an exact quotation of the provisioned substring value.
//
//			Provisioning of the large string is separate from the operation of setting the pointer in this
//			attribute. It is the responsibility of the OLT to ensure that the large string contents are
//			correct and meaningful.
//
//			Three-character variable definitions are as follows. The first variable in the large string must
//			specify one of the option types. Both options for a given IP version may be present if desired,
//			each introduced by its option identifier. Terminology is taken from clause 3.9.3 of [b-BBF
//			TR-101].
//
//			%01, %18 Specifies that the following string is for option 82 sub-option 1, agent circuit-ID
//			(IPv4) or option 18, interface-ID (IPv6). The equivalence permits the same large string to be
//			used in both IP environments.
//
//			%02, %37 Specifies that the following string is for option 82 sub-option 2, relay agent remote-
//			ID (IPv4) or option 37, relay agent remote-ID (IPv6). The equivalence permits the same large
//			string to be used in both IP environments.
//
//			%SL	In [b-BBF TR-101], this is called a slot. In an ONU, this variable refers to a shelf. It
//			would be meaningful if the ONU has multiple shelves internally or is daisy-chained to multiple
//			equipment modules. The range of this variable is "0".. "99"
//
//			%SU	In TR-101, this is called a sub-slot. In fact, it represents a cardholder. The range of this
//			variable is "0".. "99"
//
//			%PO	UNI port number. The range of this variable is "0".. "999"
//
//			%AE	ATM or Ethernet. This variable can take on the values "atm" or "eth".
//
//			%SV	S-VID for Ethernet UNI, or ATM virtual path identifier (VPI) for ATM UNI, as it exists on
//			the DHCP request received upstream across the UNI. Range "0".. "4096" for S-VID; range "0"..
//			"255" for VPI. The value "4096" indicates no S-VID tag.
//
//			%CV	C-VID (Q-VID) for Ethernet UNI, or ATM virtual circuit identifier (VCI) for ATM UNI, as it
//			exists on the DHCP request received upstream across the UNI. Range "0".. "4096" for C-VID; range
//			"0".."65535" for VCI. The value "4096" indicates no C-VID tag.
//
//			Spaces in the provisioned string are significant.
//
//			Example: if the large string were provisioned with the value
//
//			%01%SL/%SU/%PO:%AE/%SV.%CV<null>,
//
//			then the ONU would generate the following DHCP option 82 agent circuit-ID string for an Ethernet
//			UNI that sent a DHCP request with no S tag and C tag = 3210 on shelf 2, slot 3, port 4.
//
//			2/3/4:eth/4096.3210
//
//			With the same provisioning, the ONU would generate the following DHCP option 82 agent circuit-ID
//			string for an ATM UNI that sent a DHCP request on VPI = 123 and VCI = 4567 on shelf 2, slot 3,
//			port 4.
//
//			2/3/4:atm/123.4567
//
type IpHostConfigData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const IpHostConfigData_IpOptions = "IpOptions"
const IpHostConfigData_MacAddress = "MacAddress"
const IpHostConfigData_OnuIdentifier = "OnuIdentifier"
const IpHostConfigData_IpAddress = "IpAddress"
const IpHostConfigData_Mask = "Mask"
const IpHostConfigData_Gateway = "Gateway"
const IpHostConfigData_PrimaryDns = "PrimaryDns"
const IpHostConfigData_SecondaryDns = "SecondaryDns"
const IpHostConfigData_CurrentAddress = "CurrentAddress"
const IpHostConfigData_CurrentMask = "CurrentMask"
const IpHostConfigData_CurrentGateway = "CurrentGateway"
const IpHostConfigData_CurrentPrimaryDns = "CurrentPrimaryDns"
const IpHostConfigData_CurrentSecondaryDns = "CurrentSecondaryDns"
const IpHostConfigData_DomainName = "DomainName"
const IpHostConfigData_HostName = "HostName"
const IpHostConfigData_RelayAgentOptions = "RelayAgentOptions"

func init() {
	iphostconfigdataBME = &ManagedEntityDefinition{
		Name:    "IpHostConfigData",
		ClassID: IpHostConfigDataClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
			Test,
		),
		AllowedAttributeMask: 0xffff,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField(IpHostConfigData_IpOptions, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2:  MultiByteField(IpHostConfigData_MacAddress, OctetsAttributeType, 0x4000, 6, toOctets("AAAAAAAA"), mapset.NewSetWith(Read), false, false, false, 2),
			3:  MultiByteField(IpHostConfigData_OnuIdentifier, OctetsAttributeType, 0x2000, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, Write), false, false, false, 3),
			4:  Uint32Field(IpHostConfigData_IpAddress, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, false, false, 4),
			5:  Uint32Field(IpHostConfigData_Mask, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
			6:  Uint32Field(IpHostConfigData_Gateway, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7:  Uint32Field(IpHostConfigData_PrimaryDns, UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, Write), false, false, false, 7),
			8:  Uint32Field(IpHostConfigData_SecondaryDns, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, false, false, 8),
			9:  Uint32Field(IpHostConfigData_CurrentAddress, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read), true, true, false, 9),
			10: Uint32Field(IpHostConfigData_CurrentMask, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read), true, true, false, 10),
			11: Uint32Field(IpHostConfigData_CurrentGateway, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read), true, true, false, 11),
			12: Uint32Field(IpHostConfigData_CurrentPrimaryDns, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read), true, true, false, 12),
			13: Uint32Field(IpHostConfigData_CurrentSecondaryDns, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read), true, true, false, 13),
			14: MultiByteField(IpHostConfigData_DomainName, OctetsAttributeType, 0x0004, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), true, false, false, 14),
			15: MultiByteField(IpHostConfigData_HostName, OctetsAttributeType, 0x0002, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), true, false, false, 15),
			16: Uint16Field(IpHostConfigData_RelayAgentOptions, UnsignedIntegerAttributeType, 0x0001, 0, mapset.NewSetWith(Read, Write), true, true, false, 16),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewIpHostConfigData (class ID 134) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewIpHostConfigData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*iphostconfigdataBME, params...)
}
