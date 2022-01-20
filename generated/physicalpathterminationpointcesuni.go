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

// PhysicalPathTerminationPointCesUniClassID is the 16-bit ID for the OMCI
// Managed entity Physical path termination point CES UNI
const PhysicalPathTerminationPointCesUniClassID = ClassID(12) // 0x000c

var physicalpathterminationpointcesuniBME *ManagedEntityDefinition

// PhysicalPathTerminationPointCesUni (Class ID: #12 / 0x000c)
//	This ME represents the point at a CES UNI in the ONU where the physical path terminates and
//	physical level functions are performed.
//
//	The ONU automatically creates an instance of this ME per port:
//
//	o	when the ONU has CES ports built into its factory configuration;
//
//	o	when a cardholder is provisioned to expect a circuit pack of a CES type;
//
//	o	when a cardholder provisioned for plug-and-play is equipped with a circuit pack of a CES type.
//	Note that the installation of a plug-and-play card may indicate the presence of CES ports via
//	equipment ID as well as its type and indeed may cause the ONU to instantiate a port-mapping
//	package that specifies CES ports.
//
//	The ONU automatically deletes instances of this ME when a cardholder is neither provisioned to
//	expect a CES circuit pack, nor is it equipped with a CES circuit pack.
//
//	Relationships
//		An instance of this ME is associated with each real or pre-provisioned CES port. It can be
//		linked from a GEM IW TP, a pseudowire TP or a logical N * 64 kbit/s CTP.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. This 2 byte number indicates the
//			physical position of the UNI. The first byte is the slot ID (defined in clause 9.1.5). The
//			second byte is the port ID, with the range 1..255. (R) (mandatory) (2-bytes)
//
//		Expected Type
//			1 to 254	One of the values from Table-9.1.5-1 that is compatible with a CES circuit pack
//
//			Upon ME instantiation, the ONU sets this attribute to 0. (R,-W) (mandatory) (1-byte)
//
//			The following coding is used for this attribute-
//
//			0	Autosense
//
//		Sensed Type
//			If the value of expected type is not 0, then the value of sensed type equals the value of
//			expected type. If expected type-= 0, then the value of sensed type is one of the compatible
//			values from Table-9.1.5-1. Upon ME instantiation, the ONU sets this attribute to 0 or to the
//			value that reflects the physically present equipment. (R) (mandatory if the ONU supports circuit
//			packs with configurable interface types, e.g., C1.5/2/6.3) (1-byte)
//
//		Ces Loopback Configuration
//			This attribute specifies and reports the loopback configuration of the physical interface.
//
//			0	No loopback
//
//			1	Payload loopback
//
//			2	Line loopback
//
//			3	Operations system-directed (OS-directed) loopback 1 (loopback from/to PON side)
//
//			4	OS-directed loopback 2 (loopback from/to CES UNI side)
//
//			5	OS-directed loopback 3 (loopback of both PON side and CES UNI side)
//
//			6	Manual button-directed loopback [read only (RO)]
//
//			7	Network-side code inband-directed loopback (RO)
//
//			8	SmartJack-directed loopback (RO)
//
//			9	Network-side code inband-directed loopback (armed; RO)
//
//			10	Remote-line loopback via facility data link (FDL)
//
//			11	Remote-line loopback via inband code
//
//			12	Remote-payload loopback
//
//			Upon ME instantiation, the ONU sets this attribute to 0. (R,-W) (mandatory) (1-byte)
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by this ME. Administrative
//			state is further described in clause A.1.6. (R,-W) (mandatory) (1-byte)
//
//		Operational State
//			This attribute indicates whether the ME is capable of performing its function. Valid values are
//			enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Framing
//			6	Basic framing with CRC-4: clause 2.3.3 of [ITU-T G.704]
//
//			7	Basic framing with TS16 multiframe
//
//			8	Basic framing with CRC-4 and TS16 multiframe
//
//			Upon ME instantiation, the ONU sets this attribute to a value that reflects the vendor's
//			default. (R,-W) (optional) (1-byte)
//
//			This attribute specifies the framing structure.
//
//			These code points are for use with DS1 services. Code point 2 may also be used for an unframed
//			E1 service.
//
//			0	Extended superframe
//
//			1	Superframe
//
//			2	Unframed
//
//			3	ITUT-G.704
//
//			NOTE - [ITUT G.704] describes both SF and ESF framing for DS1 signals. This code point is
//			retained for backward compatibility, but its meaning is undefined.
//
//			4	JT-G.704
//
//			The following code points are for use with E1 services.
//
//			5	Basic framing: clause 2.3.2 of [ITU-T G.704]
//
//		Encoding
//			This attribute specifies the line coding scheme. Valid values are as follows.
//
//			0	B8ZS
//
//			1	AMI
//
//			2	HDB3
//
//			3	B3ZS
//
//			Upon ME instantiation, the ONU sets this attribute to 0. (R,-W) (mandatory for DS1 and DS3
//			interfaces) (1-byte)
//
//		Line Length
//			This attribute specifies the length of the twisted pair cable from a DS1 physical UNI to the
//			DSX-1 cross-connect point or the length of coaxial cable from a DS3 physical UNI to the DSX-3
//			cross-connect point. Valid values are given in Table 9.8.1-1. Upon ME instantiation for a DS1
//			interface, the ONU assigns the value 0 for non-power feed type DS1 and the value 6 for power
//			feed type DS1. Upon ME instantiation for a DS3 interface, the ONU sets this attribute to 0x0F.
//			(R,-W) (optional) (1-byte)
//
//		Ds1 Mode
//			This attribute specifies the mode of a DS1. Valid values are as follows.
//
//			In the event of conflicting values between this attribute and the (also optional) line length
//			attribute, the line length attribute is taken to be valid. This permits the separation of line
//			build-out (LBO) and power settings from smart jack and FDL behaviour. Upon ME instantiation, the
//			ONU sets this attribute to 0. (R,-W) (optional) (1-byte)
//
//		Arc
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Line Type
//			This attribute specifies the line type used in a DS3 or E3 application or when the sensed type
//			of the PPTP is configurable. Valid values are as follows.
//
//			0	Other
//
//			1	ds3 m23
//
//			2	ds3 syntran
//
//			3	ds3 Cbit parity
//
//			4	ds3 clear channel
//
//			5	e3 framed
//
//			6	e3 plcp
//
//			7	DS1
//
//			8	E1
//
//			9	J1
//
//			(R,-W) (mandatory for DS3, E3 and multi-configuration interfaces, not applicable to other
//			interfaces) (1-byte)
//
type PhysicalPathTerminationPointCesUni struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	physicalpathterminationpointcesuniBME = &ManagedEntityDefinition{
		Name:    "PhysicalPathTerminationPointCesUni",
		ClassID: 12,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfff0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField("ExpectedType", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2:  ByteField("SensedType", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), true, false, false, 2),
			3:  ByteField("CesLoopbackConfiguration", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), true, false, false, 3),
			4:  ByteField("AdministrativeState", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, false, false, 4),
			5:  ByteField("OperationalState", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read), true, true, false, 5),
			6:  ByteField("Framing", UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, true, false, 6),
			7:  ByteField("Encoding", UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, Write), false, false, false, 7),
			8:  ByteField("LineLength", UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, true, false, 8),
			9:  ByteField("Ds1Mode", UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, Write), false, true, false, 9),
			10: ByteField("Arc", UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, Write), true, true, false, 10),
			11: ByteField("ArcInterval", UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, Write), false, true, false, 11),
			12: ByteField("LineType", UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, false, false, 12),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0:  "TF",
			1:  "LOS",
			2:  "LOF",
			3:  "OOF",
			4:  "RAI",
			5:  "1.5 M BAIS",
			6:  "R-INH",
			7:  "6M REC",
			8:  "6M SEND",
			9:  "6M ERR",
			10: "6M BERR",
			11: "34M REC",
			12: "34M AIS",
			13: "2M REC",
			14: "2M AIS",
			15: "1.5M REC",
			16: "1.5 AIS",
			17: "INFO0",
			18: "45M RDI",
			19: "45M AIS",
			20: "AIS-CI",
			21: "DS1 idle",
			22: "RAI-CI",
		},
	}
}

// NewPhysicalPathTerminationPointCesUni (class ID 12) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewPhysicalPathTerminationPointCesUni(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*physicalpathterminationpointcesuniBME, params...)
}
