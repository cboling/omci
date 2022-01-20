/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

// Dot1AgCfmStackClassID is the 16-bit ID for the OMCI
// Managed entity Dot1ag CFM stack
const Dot1AgCfmStackClassID = ClassID(305) // 0x0131

var dot1agcfmstackBME *ManagedEntityDefinition

// Dot1AgCfmStack (Class ID: #305 / 0x0131)
//	This ME reports the maintenance status of a bridge port at any given time. An ONU that supports
//	[IEEE 802.1ag] functionality automatically creates an instance of the dot1ag CFM stack ME for
//	each MAC bridge or IEEE 802.1p mapper, depending on its provisioning model.
//
//	The dot1ag CFM stack also lists any VLANs and bridge ports against which configuration errors
//	are currently identified. The ONU should reject operations that create configuration errors.
//	However, these errors can arise because of operations on other MEs that are not necessarily
//	possible to detect during CFM configuration.
//
//	Relationships
//		An ONU that supports [IEEE 802.1ag] creates one instance of this ME for each MAC bridge or IEEE
//		802.1p mapper, depending on its provisioning model. It should not create an instance for an
//		IEEE-802.1p mapper that is associated with a MAC bridge.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies an instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the MAC bridge service profile ME or an IEEE 802.1p mapper
//			ME. It is expected that an ONU will implement CFM on bridges or on IEEE-802.1p mappers, but not
//			both. For precision, the reference is disambiguated by the value of the layer 2 type pointer
//			attribute. (R) (mandatory) (2-bytes)
//
//		Layer 2 Type
//			This attribute specifies whether the dot1ag CFM stack is associated with a MAC bridge service
//			profile (value 0) or an IEEE 802.1p mapper (value 1). (R) (mandatory) (1-byte)
//
//		Mp Status Table
//			This attribute is a list of entries, each entry reporting one aspect of the maintenance status
//			of one port. If a port is associated with more than one CFM maintenance entity, each is
//			represented as a separate item in this table attribute; a port that has no current maintenance
//			functions is not represented in the table (so the table may be empty). Each entry is defined as
//			follows.
//
//			Port ID: The ME ID of the MAC bridge port config data whose information is reported in this
//			entry. If the layer 2 parent is an IEEE 802.1p mapper, a null pointer. (2-bytes)
//
//			Level: The level at which the reported maintenance function exists, 0..7. (1-byte)
//
//			Direction: The value 1 (down) or 2 (up). (1-byte)
//
//			VLAN ID: If this table entry reports a maintenance function associated with a VLAN, this field
//			contains the value of the primary VLAN ID. If no VLAN is associated with this entry, this field
//			contains the value 0. (2-bytes)
//
//			MD: A pointer to the associated dot1ag maintenance domain ME. If no MD is associated with this
//			entry, a null pointer. (2-bytes)
//
//			MA: A pointer to the associated dot1ag maintenance association ME. If no MA is associated with
//			this entry, a null pointer. (2-bytes)
//
//			MEP ID: If this table entry reports an MEP, this field contains the value of its MEP ID (range
//			1..8191). If this table entry reports an MHF, this field contains the value 0. (2-bytes)
//
//			MAC address: The MAC address of the MP. (6-bytes)
//
//			(R) (mandatory) (18N bytes)
//
//		Configuration Error List Table
//			This attribute is based on the [IEEE 802.1ag] configuration error list. It is a list of entries,
//			each entry reporting a VLAN and a bridge port against which a configuration error has been
//			detected. The table may be empty at any given time. Entries are defined as follows:
//
//			VLAN ID: If this table entry reports a maintenance function associated with a VLAN, this field
//			contains the value of the VLAN ID in error. If no VLAN is associated with this entry, this field
//			contains the value 0. (2-bytes)
//
//			Port ID: A pointer to the MAC bridge port config data whose information is reported in this
//			entry. If the layer 2 parent is an IEEE 802.1p mapper, a null pointer. (2-bytes)
//
//			Detected configuration error: A bit mask with the following meanings. A list entry exists if and
//			only if at least one of these bits is set. Definitions appear in clause 22.2.4 of [IEEE
//			802.1ag]: (1-byte)
//
//			0x01	CFM leak. MA x is associated with a specific VID list, one or more of the VIDs in MA x can
//			pass through the bridge port, no up MEP is configured for MA x on the bridge port, no down MEP
//			is configured on any bridge port for MA x, and another MA y, at a higher MD level than MA x, and
//			associated with at least one of the VID(s) also in MA x, does have an MEP configured on the
//			bridge port.
//
//			0x02	Conflicting VIDs. MA x is associated with a specific VID list, an up MEP is configured on
//			MA x on the bridge port, and another MA y, associated with at least one of the VID(s) also in MA
//			x, and at the same MD level as MA x, also has an up MEP configured on some bridge port.
//
//			0x04	Excessive levels. The number of different MD levels at which maintenance domain
//			intermediate points (MIPs) are to be created on this port exceeds the bridge's capabilities.
//
//			0x08	Overlapped levels. An MEP is created for one VID at one MD level, but an MEP is also
//			configured on another VID at that MD level or higher, exceeding the bridge's capabilities.
//
//			(R) (mandatory) (5N bytes)
//
type Dot1AgCfmStack struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	dot1agcfmstackBME = &ManagedEntityDefinition{
		Name:    "Dot1AgCfmStack",
		ClassID: 305,
		MessageTypes: mapset.NewSetWith(
			Get,
			GetNext,
		),
		AllowedAttributeMask: 0xe000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField("Layer2Type", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: TableField("MpStatusTable", TableAttributeType, 0x4000, TableInfo{nil, 18}, mapset.NewSetWith(Read), false, false, false, 2),
			3: TableField("ConfigurationErrorListTable", TableAttributeType, 0x2000, TableInfo{nil, 5}, mapset.NewSetWith(Read), true, false, false, 3),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewDot1AgCfmStack (class ID 305) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewDot1AgCfmStack(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*dot1agcfmstackBME, params...)
}
