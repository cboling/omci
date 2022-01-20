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

// EthernetFlowTerminationPointClassID is the 16-bit ID for the OMCI
// Managed entity Ethernet flow termination point
const EthernetFlowTerminationPointClassID = ClassID(286) // 0x011e

var ethernetflowterminationpointBME *ManagedEntityDefinition

// EthernetFlowTerminationPoint (Class ID: #286 / 0x011e)
//	The Ethernet flow TP contains the attributes necessary to originate and terminate Ethernet
//	frames in the ONU. It is appropriate when transporting pseudowire services via layer-2.
//	Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		One Ethernet flow TP ME exists for each distinct pseudowire service that is transported via
//		layer 2.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to a pseudowire TP ME. (R, setbycreate) (mandatory) (2-bytes)
//
//		Destination Mac
//			This attribute specifies the destination MAC address of upstream Ethernet frames. (R,-W,
//			setbycreate) (mandatory) (6-bytes)
//
//		Source Mac
//			This attribute specifies the near-end MAC address. It is established by nonOMCI means (e.g.,
//			factory programmed into ONU flash memory) and is included here for information only. (R)
//			(mandatory) (6-bytes)
//
//		Tag Policy
//			0	untagged frame
//
//			1	tagged frame
//
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//			This attribute specifies the tagging policy to be applied to upstream Ethernet frames.
//
//		Tci
//			If the tag policy calls for tagging of upstream Ethernet frames, this attribute specifies the
//			tag control information, which includes the VLAN tag, P bits and CFI bit. (R,-W) (optional)
//			(2-bytes)
//
//		Loopback
//			This attribute sets the loopback configuration as follows.
//
//			0	No loopback
//
//			1	Loopback of downstream traffic at MAC client
//
//			(R,-W) (mandatory) (1-byte)
//
type EthernetFlowTerminationPoint struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	ethernetflowterminationpointBME = &ManagedEntityDefinition{
		Name:    "EthernetFlowTerminationPoint",
		ClassID: 286,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xf800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: MultiByteField("DestinationMac", OctetsAttributeType, 0x8000, 6, toOctets("AAAAAAAA"), mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: MultiByteField("SourceMac", OctetsAttributeType, 0x4000, 6, toOctets("AAAAAAAA"), mapset.NewSetWith(Read), false, false, false, 2),
			3: ByteField("TagPolicy", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4: Uint16Field("Tci", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, true, false, 4),
			5: ByteField("Loopback", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewEthernetFlowTerminationPoint (class ID 286) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewEthernetFlowTerminationPoint(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*ethernetflowterminationpointBME, params...)
}
