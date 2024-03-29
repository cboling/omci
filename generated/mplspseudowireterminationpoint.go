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

// MplsPseudowireTerminationPointClassID is the 16-bit ID for the OMCI
// Managed entity MPLS pseudowire termination point
const MplsPseudowireTerminationPointClassID = ClassID(333) // 0x014d

var mplspseudowireterminationpointBME *ManagedEntityDefinition

// MplsPseudowireTerminationPoint (Class ID: #333 / 0x014d)
//	This ME contains the configuration data of a pseudowire whose underlying transport method is
//	MPLS. Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		Zero or one instance of this ME is associated with each instance of the pseudowire TP ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate)-(mandatory) (2
//			bytes)
//
//		Tp Type
//			This attribute specifies the type of ANI-side TP associated with this-ME.
//
//			1	Ethernet flow termination point
//
//			2	GEM IW TP
//
//			3	TCP/UDP config data
//
//			4	MPLS pseudowire termination point
//
//			NOTE - If this instance of the MPLS PW TP is pointed to by another instance of the MPLS PW TP
//			(i.e., whose TP type-= 4), this instance represents a tunnelled MPLS flow, and the following
//			attributes are not meaningful: MPLS PW direction; MPLS PW uplink label; MPLS PW downlink label;
//			and MPLS PW TC. These attributes should be set to the proper number of 0x00 bytes by the OLT and
//			ignored by the ONU.
//
//			(R, W, setbycreate) (mandatory) (1 byte)
//
//		Tp Pointer
//			This attribute points to the instance of the TP associated with this MPLS PW TP. The type of the
//			associated TP is determined by the TP type attribute. (R, W, setbycreate) (mandatory) (2 bytes)
//
//		Mpls Label Indicator
//			This attribute specifies the MPLS label stacking situation.
//
//			0	Single MPLS labelled
//
//			1	Double MPLS labelled
//
//			(R, W, setbycreate) (mandatory) (1 byte)
//
//		Mpls Pw Direction
//			This attribute specifies the inner MPLS direction.
//
//			0	Upstream only
//
//			1	Downstream only
//
//			2	Bidirectional
//
//			(R, W, setbycreate) (mandatory) (1 byte)
//
//		Mpls Pw Uplink Label
//			This attribute specifies the label of the inner MPLS pseudowire upstream. The attribute is not
//			meaningful for unidirectional downstream PWs. (R, W, setbycreate) (mandatory) (4 bytes)
//
//		Mpls Pw Downlink Label
//			This attribute specifies the label of the inner MPLS pseudowire downstream. The attribute is not
//			meaningful for unidirectional upstream PWs. (R, W, setbycreate) (mandatory) (4 bytes)
//
//		Mpls Pw Tc
//			NOTE 1 - The TC field was previously known as EXP. Refer to [bIETF-RFC-5462].
//
//			This attribute specifies the inner MPLS TC value in the upstream direction. The attribute is not
//			meaningful for unidirectional downstream PWs. (R, W, setbycreate) (mandatory) (1 byte)
//
//		Mpls Tunnel Direction
//			This attribute specifies the direction of the (outer) MPLS tunnel.
//
//			0	Upstream only
//
//			1	Downstream only
//
//			2	Bidirectional
//
//			(R, W, setbycreate) (mandatory for double-labelled case) (1 byte)
//
//		Mpls Tunnel Uplink Label
//			This attribute specifies the (outer) label for the upstream MPLS tunnel. If the MPLS tunnel is
//			downstream only, this attribute should be set to 0. (R, W, setbycreate) (mandatory for double-
//			labelled case) (4 bytes)
//
//		Mpls Tunnel Downlink Label
//			This attribute specifies the (outer) label for the downstream MPLS tunnel. If the MPLS tunnel is
//			upstream only, this attribute should be set to 0. (R, W, setbycreate) (mandatory for double-
//			labelled case) (4 bytes)
//
//		Mpls Tunnel Tc
//			This attribute specifies the TC value of the upstream MPLS tunnel. If the MPLS tunnel is
//			downstream only, this attribute should be set to 0. (R, W, setbycreate) (mandatory for double
//			MPLS labelled case) (1 byte)
//
//			NOTE 2 - The TC field was previously known as EXP. Refer to [bIETF-RFC-5462].
//
//		Pseudowire Type
//			This attribute specifies the emulated service to be carried over this PW. The values are from
//			[IETF RFC 4446].
//
//			2	ATM AAL5 SDU VCC transport
//
//			3	ATM transparent cell transport
//
//			5	Ethernet
//
//			9	ATM n-to-one VCC cell transport
//
//			10	ATM n-to-one VPC cell transport
//
//			12	ATM one-to-one VCC cell mode
//
//			13	ATM one-to-one VPC cell mode
//
//			14	ATM AAL5 PDU VCC transport
//
//			All other values are reserved.
//
//			(R, W, setbycreate) (mandatory) (2 bytes)
//
//		Pseudowire Control Word Preference
//			When set to true, this Boolean attribute specifies that a control word is to be sent with each
//			packet. Some PW types mandate the use of a control word in any event. In such cases, the value
//			configured for this attribute has no effect on the presence of the control word. (R, W,
//			setbycreate) (optional) (1 byte)
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by the MPLS pseudowire TP.
//			Administrative state is further described in clause-A.1.6. (R,-W) (optional) (1-byte)
//
//		Operational State
//			This attribute reports whether the ME is currently capable of performing its function. Valid
//			values are enabled (0) and disabled (1). (R) (optional) (1-byte)
//
type MplsPseudowireTerminationPoint struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const MplsPseudowireTerminationPoint_TpType = "TpType"
const MplsPseudowireTerminationPoint_TpPointer = "TpPointer"
const MplsPseudowireTerminationPoint_MplsLabelIndicator = "MplsLabelIndicator"
const MplsPseudowireTerminationPoint_MplsPwDirection = "MplsPwDirection"
const MplsPseudowireTerminationPoint_MplsPwUplinkLabel = "MplsPwUplinkLabel"
const MplsPseudowireTerminationPoint_MplsPwDownlinkLabel = "MplsPwDownlinkLabel"
const MplsPseudowireTerminationPoint_MplsPwTc = "MplsPwTc"
const MplsPseudowireTerminationPoint_MplsTunnelDirection = "MplsTunnelDirection"
const MplsPseudowireTerminationPoint_MplsTunnelUplinkLabel = "MplsTunnelUplinkLabel"
const MplsPseudowireTerminationPoint_MplsTunnelDownlinkLabel = "MplsTunnelDownlinkLabel"
const MplsPseudowireTerminationPoint_MplsTunnelTc = "MplsTunnelTc"
const MplsPseudowireTerminationPoint_PseudowireType = "PseudowireType"
const MplsPseudowireTerminationPoint_PseudowireControlWordPreference = "PseudowireControlWordPreference"
const MplsPseudowireTerminationPoint_AdministrativeState = "AdministrativeState"
const MplsPseudowireTerminationPoint_OperationalState = "OperationalState"

func init() {
	mplspseudowireterminationpointBME = &ManagedEntityDefinition{
		Name:    "MplsPseudowireTerminationPoint",
		ClassID: MplsPseudowireTerminationPointClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfffe,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField(MplsPseudowireTerminationPoint_TpType, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  Uint16Field(MplsPseudowireTerminationPoint_TpPointer, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  ByteField(MplsPseudowireTerminationPoint_MplsLabelIndicator, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4:  ByteField(MplsPseudowireTerminationPoint_MplsPwDirection, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5:  Uint32Field(MplsPseudowireTerminationPoint_MplsPwUplinkLabel, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 5),
			6:  Uint32Field(MplsPseudowireTerminationPoint_MplsPwDownlinkLabel, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 6),
			7:  ByteField(MplsPseudowireTerminationPoint_MplsPwTc, UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 7),
			8:  ByteField(MplsPseudowireTerminationPoint_MplsTunnelDirection, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 8),
			9:  Uint32Field(MplsPseudowireTerminationPoint_MplsTunnelUplinkLabel, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 9),
			10: Uint32Field(MplsPseudowireTerminationPoint_MplsTunnelDownlinkLabel, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 10),
			11: ByteField(MplsPseudowireTerminationPoint_MplsTunnelTc, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 11),
			12: Uint16Field(MplsPseudowireTerminationPoint_PseudowireType, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 12),
			13: ByteField(MplsPseudowireTerminationPoint_PseudowireControlWordPreference, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 13),
			14: ByteField(MplsPseudowireTerminationPoint_AdministrativeState, UnsignedIntegerAttributeType, 0x0004, 0, mapset.NewSetWith(Read, Write), false, true, false, 14),
			15: ByteField(MplsPseudowireTerminationPoint_OperationalState, UnsignedIntegerAttributeType, 0x0002, 0, mapset.NewSetWith(Read), true, true, false, 15),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewMplsPseudowireTerminationPoint (class ID 333) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewMplsPseudowireTerminationPoint(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*mplspseudowireterminationpointBME, params...)
}
