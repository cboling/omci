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

// Ieee8021PMapperServiceProfileClassID is the 16-bit ID for the OMCI
// Managed entity IEEE 802.1p mapper service profile
const Ieee8021PMapperServiceProfileClassID = ClassID(130) // 0x0082

var ieee8021pmapperserviceprofileBME *ManagedEntityDefinition

// Ieee8021PMapperServiceProfile (Class ID: #130 / 0x0082)
//	This ME associates the priorities of IEEE 802.1p [IEEE 802.1D] priority tagged frames with
//	specific connections. This ME directs upstream traffic to the designated GEM ports. Downstream
//	traffic arriving on any of the IEEE 802.1p mapper's GEM ports is directed to the mapper's root
//	TP. Other mechanisms exist to direct downstream traffic, specifically a direct pointer to a
//	downstream queue from the GEM port network CTP. If such an alternative is used, it should be
//	provisioned to be consistent with the flow model of the mapper.
//
//	Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		At its root, an instance of this ME may be associated with zero or one instance of a PPTP UNI,
//		MAC bridge port configuration data, or any type of IW TP ME that carries IEEE 802 traffic. Each
//		of its eight branches is associated with zero or one GEM IW TP.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Tp Pointer
//			This attribute points to an instance of the associated TP.
//
//			If the optional TP type attribute is not supported, the TP pointer indicates bridging mapping
//			with the value 0xFFFF; the TP pointer may also point to a PPTP Ethernet UNI.
//
//			The TP type value 0 also indicates bridging mapping, and the TP pointer should be set to 0xFFFF.
//
//			In all other cases, the TP type is determined by the TP type attribute.
//
//			(R,-W, setbycreate) (mandatory) (2-bytes)
//
//			Each of the following eight attributes points to the GEM IW TP associated with the stated P-bit
//			value. The null pointer 0xFFFF specifies that frames with the associated priority are to be
//			discarded.
//
//		Interwork Tp Pointer For P_Bit Priority 0
//			Interwork TP pointer for P-bit priority 0:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 1
//			Interwork TP pointer for P-bit priority 1:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 2
//			Interwork TP pointer for P-bit priority 2:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 3
//			Interwork TP pointer for P-bit priority 3:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 4
//			Interwork TP pointer for P-bit priority 4:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 5
//			Interwork TP pointer for P-bit priority 5:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 6
//			Interwork TP pointer for P-bit priority 6:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interwork Tp Pointer For P_Bit Priority 7
//			Interwork TP pointer for P-bit priority 7:	(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Unmarked Frame Option
//			This attribute specifies how the ONU should handle untagged Ethernet frames received across the
//			associated interface. Although it does not alter the frame in any way, the ONU routes the frame
//			as if it were tagged with P bits (PCP field) according to the following code points.
//
//			0	Derive implied PCP field from DSCP bits of received frame
//
//			1	Set implied PCP field to a fixed value specified by the default P-bit assumption attribute
//
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//			Untagged downstream frames are passed through the mapper transparently.
//
//		Dscp To P Bit Mapping
//			NOTE - If certain bits in the DSCP field are to be ignored in the mapping process, the attribute
//			should be provisioned such that all possible values of those bits produce the same P-bit
//			mapping. This can be applied to the case where instead of full DSCP, the operator wishes to
//			adopt the priority mechanism based on IP precedence, which needs only the three MSBs of the DSCP
//			field.
//
//			DSCP to P-bit mapping: This attribute is valid when the unmarked frame option attribute is set
//			to 0. The DSCP to P-bit attribute can be considered a bit string sequence of 64 3-bit groupings.
//			The 64 sequence entries represent the possible values of the 6-bit DSCP field. Each 3-bit
//			grouping specifies the P-bit value to which the associated DSCP value should be mapped. The
//			unmarked frame is then directed to the GEM IW TP indicated by the interwork TP pointer mappings.
//			(R,-W) (mandatory) (24-bytes)
//
//		Default P Bit Assumption
//			Default P-bit assumption: This attribute is valid when the unmarked frame option attribute is
//			set to 1. In its LSBs, the default Pbit assumption attribute contains the default PCP field to
//			be assumed. The unmodified frame is then directed to the GEM IW TP indicated by the interwork TP
//			pointer mappings. (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Tp Type
//			This attribute identifies the type of TP associated with the mapper.
//
//			0	Mapper used for bridging-mapping
//
//			1	Mapper directly associated with a PPTP Ethernet UNI
//
//			2	Mapper directly associated with an IP host config data or IPv6 host config data ME
//
//			3	Mapper directly associated with an Ethernet flow termination point
//
//			4	Mapper directly associated with a PPTP xDSL UNI
//
//			5	Reserved
//
//			6	Mapper directly associated with a PPTP MoCA UNI
//
//			7	Mapper directly associated with a virtual Ethernet interface point
//
//			8	Mapper directly associated with an IW VCC termination point
//
//			9	Mapper directly associated with an EFM bonding group
//
//			(R,-W, setbycreate) (optional) (1-byte)
//
type Ieee8021PMapperServiceProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	ieee8021pmapperserviceprofileBME = &ManagedEntityDefinition{
		Name:    "Ieee8021PMapperServiceProfile",
		ClassID: 130,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfff8,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  Uint16Field("TpPointer", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  Uint16Field("InterworkTpPointerForPBitPriority0", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint16Field("InterworkTpPointerForPBitPriority1", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4:  Uint16Field("InterworkTpPointerForPBitPriority2", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5:  Uint16Field("InterworkTpPointerForPBitPriority3", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 5),
			6:  Uint16Field("InterworkTpPointerForPBitPriority4", UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 6),
			7:  Uint16Field("InterworkTpPointerForPBitPriority5", UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 7),
			8:  Uint16Field("InterworkTpPointerForPBitPriority6", UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 8),
			9:  Uint16Field("InterworkTpPointerForPBitPriority7", UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 9),
			10: ByteField("UnmarkedFrameOption", UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 10),
			11: MultiByteField("DscpToPBitMapping", OctetsAttributeType, 0x0020, 24, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), mapset.NewSetWith(Read, Write), false, false, false, 11),
			12: ByteField("DefaultPBitAssumption", UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 12),
			13: ByteField("TpType", UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 13),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewIeee8021PMapperServiceProfile (class ID 130) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewIeee8021PMapperServiceProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*ieee8021pmapperserviceprofileBME, params...)
}
