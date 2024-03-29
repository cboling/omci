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

// MulticastOperationsProfileClassID is the 16-bit ID for the OMCI
// Managed entity Multicast operations profile
const MulticastOperationsProfileClassID = ClassID(309) // 0x0135

var multicastoperationsprofileBME *ManagedEntityDefinition

// MulticastOperationsProfile (Class ID: #309 / 0x0135)
//	This ME expresses multicast policy. A multi-dwelling unit ONU may have several such policies,
//	which are linked to subscribers as required. Some of the attributes configure IGMP snooping and
//	proxy parameters if the defaults do not suffice, as described in [IETF-RFC-2236], [IETF-RFC
//	3376], [IETF RFC 3810] and [IETF RFC 5519]. Instances of this ME are created and deleted by the
//	OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the multicast subscriber
//		config info ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The values 0 and 0xFFFF are
//			reserved. (R, setbycreate) (mandatory) (2-bytes)
//
//		Igmp Version
//			This attribute specifies the version of IGMP to be supported. Support of a given version implies
//			compatible support of previous versions. If the ONU cannot support the version requested, it
//			should deny an attempt to set the attribute. (R,W, set-by-create) (mandatory) (1 byte)
//
//			1	IGMP version 1 (deprecated)
//
//			2	IGMP version 2
//
//			3	IGMP version 3
//
//			16	MLD version 1
//
//			17	MLD version 2
//
//			Other values are reserved.
//
//		Igmp Function
//			This attribute enables an IGMP function. The value 0 specifies transparent IGMP snooping only.
//			The value 1 specifies snooping with proxy reporting (SPR); the value 2 specifies IGMP proxy. The
//			function must be consistent with the capabilities specified by the other IGMP configuration
//			attributes. (R,W, setbycreate) (mandatory) (1-byte)
//
//		Immediate Leave
//			This Boolean attribute controls the immediate leave function. The value false disables immediate
//			leave; true enables immediate leave. (R,W, setbycreate) (mandatory) (1-byte)
//
//		Upstream Igmp Tci
//			Under control of the upstream IGMP tag control attribute, the upstream IGMP TCI attribute
//			defines a VLAN ID and P-bits to add to upstream IGMP messages. (R,-W, setbycreate) (optional)
//			(2-bytes)
//
//		Upstream Igmp Tag Control
//			2	Replace the entire TCI (VLAN ID plus P bits) on upstream IGMP/MLD traffic. The new tag is
//			specified by the upstream IGMP/MLD TCI attribute. If the received IGMP/MLD traffic is untagged,
//			an add operation is performed.
//
//			3	Replace only the VLAN ID on upstream IGMP/MLD traffic, retaining the original DEI and P bits.
//			The new VLAN ID is specified by the VLAN ID field of the upstream IGMP TCI attribute. If the
//			received IGMP/MLD traffic is untagged, an add operation is performed, with DEI and P bits also
//			taken from the upstream IGMP TCI attribute.
//
//			Other values are reserved.
//
//			This attribute controls the upstream IGMP TCI attribute. If this attribute is non-zero, a
//			possible extended VLAN tagging operation ME is ignored for upstream frames containing IGMP/MLD
//			packets. (R,-W, setbycreate) (optional) (1-byte)
//
//			Value	Meaning
//
//			0	Pass upstream IGMP/MLD traffic transparently, neither adding, stripping nor modifying tags
//			that may be present.
//
//			1	Add a VLAN tag (including P bits) to upstream IGMP/MLD traffic. The tag is specified by the
//			upstream IGMP TCI attribute.
//
//		Upstream Igmp Rate
//			This attribute limits the maximum rate of upstream IGMP traffic. Traffic in excess of this limit
//			is silently discarded. The attribute value is specified in messages/second. The recommended
//			default value 0 imposes no rate limit on this traffic. (R,-W, setbycreate) (optional) (4-bytes)
//
//		Dynamic Access Control List Table
//			This attribute is a list that specifies one or more multicast group address ranges. Each row in
//			the list comprises up to three row parts, where each row part is 24-bytes long. Each entry must
//			include row part 0. The ONU may also support row parts 1-2, thus allowing the table to contain
//			logical rows that exceed the 24-byte definition of row part 0.
//
//		Static Access Control List Table
//			This attribute is a list that specifies one or more multicast group address ranges. Groups
//			defined in this list are multicast on the associated UNI(s) unconditionally, i.e., without the
//			need for an IGMP join. The bandwidth of static multicast groups is not included in the current
//			multicast bandwidth measurement maintained by the multicast subscriber monitor ME. If a join
//			message is always expected, this table may be empty. Table entries have the same format as those
//			in the dynamic access control list table. The preview fields are not meaningful. (R,-W)
//			(mandatory) (each row part: 24 bytes)
//
//		Lost Groups List Table
//			This attribute is a list of groups from the dynamic access control list table for which there is
//			an active join, but no downstream flow is present, possibly because of source failure, but also
//			possibly because of misconfiguration somewhere upstream. Be aware of possible ambiguity between
//			overlapping service providers and IPv4/IPv6 addresses. After a join, the ONU should wait a
//			reasonable time for upstream processing before declaring a group to be lost. Each entry is a
//			vector of the following components:
//
//			-	VLAN ID, 0 if not used (2-bytes)
//
//			-	Source IP address, 0.0.0.0 if not used. In IPv6, this field captures only the four least
//			significant bytes. (4-bytes)
//
//			-	Multicast destination IP address. In IPv6, this field captures only the four least significant
//			bytes. (4-bytes)
//
//			(R) (optional) (10N bytes)
//
//		Robustness
//			This attribute allows tuning for possible packet loss in the network. The recommended default
//			value 0 causes the ONU to follow [IETF RFC 3376] to copy the robustness value from query
//			messages originating further upstream. (R,-W, setbycreate) (optional) (1-byte)
//
//		Querier Ip Address
//			This attribute specifies the IP address to be used by a proxy querier. Although it is not a
//			legitimate IP address, the recommended default value 0.0.0.0 is legal in this case (see [b-IETF
//			RFC 4541]). (R,-W, setbycreate) (optional) (4-bytes)
//
//		Query Interval
//			This attribute specifies the interval between general queries in seconds. The value 0 specifies
//			that the ONU uses its own default, which may or may not be the same as the recommended default
//			of 125-s. (R,-W, set-by-create) (optional) (4-bytes)
//
//		Query Max Response Time
//			This attribute is the max response time added by the proxy into general query messages directed
//			to UNIs. It is expressed in units of 0.1-s. The value 0 specifies that the ONU uses its own
//			default, which may or may not be the same as the recommended default of 100 (10-s). (R,-W,
//			setby-create) (optional) (4-bytes)
//
//		Last Member Query Interval
//			This attribute specifies the maximum response time inserted into group-specific queries sent to
//			UNIs in response to group leave messages. It is also the repetition rate of [robustness]
//			transmissions of the query. It is specified in units of 0.1-s, with a default of 10 (1-s).
//			(R,-W) (optional) (4-bytes)
//
//		Unauthorized Join Request Behaviour
//			This Boolean attribute specifies the ONU's behaviour when it receives an IGMP join request for a
//			group that is not authorized in the dynamic address control list table, or an IGMPv3 membership
//			report for groups, none of which are authorized in the dynamic ACL. The default value false
//			specifies that the ONU silently discard the IGMP request; the value true specifies that the ONU
//			forwards the request upstream. The ONU does not attempt to honour the request for the
//			unauthorized group(s) in either case. (R,-W) (optional) (1-byte)
//
//		Downstream IGMP and multicast TCI
//			This attribute controls the downstream tagging of both the IGMP/MLD and multicast frames. If the
//			first byte of this attribute is non-zero, a possible extended VLAN tagging operation ME is
//			ignored for downstream IGMP/MLD and multicast frames. (R,-W, set-by-create) (optional) (3-bytes)
//
//			The first byte defines the control type:
//
//			Value	Meaning
//
//			0	Pass the downstream IGMP/MLD and multicast traffic transparently, neither stripping nor
//			modifying tags that may be present.
//
//			1	Strip the outer VLAN tag (including P bits) from the downstream IGMP/MLD and multicast
//			traffic.
//
//			2	Add a tag on to the downstream IGMP/MLD and multicast traffic. The new tag is specified by the
//			second and third bytes of this attribute.
//
//			3	Replace the tag on the downstream IGMP/MLD and multicast traffic. The new tag is specified by
//			the second and third bytes of this attribute.
//
//			4	Replace only the VLAN ID on the downstream IGMP/MLD and multicast traffic, retaining the
//			original DEI and P bits. The new VLAN ID is specified by the VLAN ID field of the second and
//			third bytes of this attribute.
//
//			5	Add a tag on to the downstream IGMP/MLD and multicast traffic. The new tag is specified by the
//			VID (UNI) field of the multicast service package table row of the multicast subscriber config
//			info ME that is associated with this profile. If the VID (UNI) field is unspecified (0xFFFF) or
//			specifies untagged traffic, the new tag is specified by the second and third bytes of this
//			attribute.
//
//			6	Replace the tag on the downstream IGMP/MLD and multicast traffic. The new tag is specified by
//			the VID (UNI) field of the multicast service package table row of the multicast subscriber
//			config info ME that is associated with this profile. If the VID (UNI) field specifies untagged
//			traffic, the outer VLAN tag (including P bits) is stripped from the downstream IGMP/MLD and
//			multicast traffic. If the value of the VID (UNI) is unspecified (0xFFFF), the new tag is
//			specified by the second and third bytes of this attribute.
//
//			7	Replace only the VID on the downstream IGMP/MLD and multicast traffic, retaining the original
//			DEI and P bits. The new VLAN ID is specified by the VID (UNI) field of the multicast service
//			package table row of the multicast subscriber config info ME that is associated with this
//			profile. If the VID (UNI) field specifies untagged traffic, the outer VLAN tag (including P
//			bits) is stripped from the downstream IGMP/MLD and multicast traffic. If the value of the VID
//			(UNI) is unspecified (0xFFFF), the new tag is specified by the second and third bytes of this
//			attribute.
//
//			Other values are reserved.
//
//			The second and third bytes define the TCI (VLAN ID and P bits) to be applied on the downstream
//			IGMP/MLD and multicast streams in case the replace or add option is selected.
//
type MulticastOperationsProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const MulticastOperationsProfile_IgmpVersion = "IgmpVersion"
const MulticastOperationsProfile_IgmpFunction = "IgmpFunction"
const MulticastOperationsProfile_ImmediateLeave = "ImmediateLeave"
const MulticastOperationsProfile_UpstreamIgmpTci = "UpstreamIgmpTci"
const MulticastOperationsProfile_UpstreamIgmpTagControl = "UpstreamIgmpTagControl"
const MulticastOperationsProfile_UpstreamIgmpRate = "UpstreamIgmpRate"
const MulticastOperationsProfile_DynamicAccessControlListTable = "DynamicAccessControlListTable"
const MulticastOperationsProfile_StaticAccessControlListTable = "StaticAccessControlListTable"
const MulticastOperationsProfile_LostGroupsListTable = "LostGroupsListTable"
const MulticastOperationsProfile_Robustness = "Robustness"
const MulticastOperationsProfile_QuerierIpAddress = "QuerierIpAddress"
const MulticastOperationsProfile_QueryInterval = "QueryInterval"
const MulticastOperationsProfile_QueryMaxResponseTime = "QueryMaxResponseTime"
const MulticastOperationsProfile_LastMemberQueryInterval = "LastMemberQueryInterval"
const MulticastOperationsProfile_UnauthorizedJoinRequestBehaviour = "UnauthorizedJoinRequestBehaviour"
const MulticastOperationsProfile_DownstreamIgmpAndMulticastTci = "DownstreamIgmpAndMulticastTci"

func init() {
	multicastoperationsprofileBME = &ManagedEntityDefinition{
		Name:    "MulticastOperationsProfile",
		ClassID: MulticastOperationsProfileClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
			SetTable,
		),
		AllowedAttributeMask: 0xffff,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField(MulticastOperationsProfile_IgmpVersion, EnumerationAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  ByteField(MulticastOperationsProfile_IgmpFunction, EnumerationAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  ByteField(MulticastOperationsProfile_ImmediateLeave, EnumerationAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4:  Uint16Field(MulticastOperationsProfile_UpstreamIgmpTci, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 4),
			5:  ByteField(MulticastOperationsProfile_UpstreamIgmpTagControl, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 5),
			6:  Uint32Field(MulticastOperationsProfile_UpstreamIgmpRate, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 6),
			7:  TableField(MulticastOperationsProfile_DynamicAccessControlListTable, TableAttributeType, 0x0200, TableInfo{nil, 24}, mapset.NewSetWith(Read, Write), false, false, false, 7),
			8:  TableField(MulticastOperationsProfile_StaticAccessControlListTable, TableAttributeType, 0x0100, TableInfo{nil, 24}, mapset.NewSetWith(Read, Write), false, false, false, 8),
			9:  TableField(MulticastOperationsProfile_LostGroupsListTable, TableAttributeType, 0x0080, TableInfo{nil, 10}, mapset.NewSetWith(Read), false, true, false, 9),
			10: ByteField(MulticastOperationsProfile_Robustness, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 10),
			11: Uint32Field(MulticastOperationsProfile_QuerierIpAddress, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 11),
			12: Uint32Field(MulticastOperationsProfile_QueryInterval, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 12),
			13: Uint32Field(MulticastOperationsProfile_QueryMaxResponseTime, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 13),
			14: Uint32Field(MulticastOperationsProfile_LastMemberQueryInterval, UnsignedIntegerAttributeType, 0x0004, 0, mapset.NewSetWith(Read, Write), false, true, false, 14),
			15: ByteField(MulticastOperationsProfile_UnauthorizedJoinRequestBehaviour, UnsignedIntegerAttributeType, 0x0002, 0, mapset.NewSetWith(Read, Write), false, true, false, 15),
			16: MultiByteField(MulticastOperationsProfile_DownstreamIgmpAndMulticastTci, OctetsAttributeType, 0x0001, 3, toOctets("AAAA"), mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 16),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewMulticastOperationsProfile (class ID 309) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewMulticastOperationsProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*multicastoperationsprofileBME, params...)
}
