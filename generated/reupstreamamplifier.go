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

// ReUpstreamAmplifierClassID is the 16-bit ID for the OMCI
// Managed entity RE upstream amplifier
const ReUpstreamAmplifierClassID = ClassID(315) // 0x013b

var reupstreamamplifierBME *ManagedEntityDefinition

// ReUpstreamAmplifier (Class ID: #315 / 0x013b)
//	This ME organizes data associated with each upstream RE optical amplifier (OA) supported by the
//	RE. The management ONU automatically creates one instance of this ME for each upstream OA as
//	follows.
//
//	o	When the RE has mid-span PON RE upstream OA ports built into its factory configuration.
//
//	o	When a cardholder is provisioned to expect a circuit pack of the mid-span PON RE upstream OA
//	type.
//
//	o	When a cardholder provisioned for plug-and-play is equipped with a circuit pack of the mid-
//	span PON RE upstream OA type. Note that the installation of a plug-and-play card may indicate
//	the presence of a mid-span PON RE upstream OA via equipment ID as well as its type attribute,
//	and indeed may cause the management ONU to instantiate a port-mapping package to specify the
//	ports precisely.
//
//	The management ONU automatically deletes instances of this ME when a cardholder is neither
//	provisioned to expect a mid-span PON RE upstream OA circuit pack, nor is it equipped with a mid-
//	span PON RE upstream OA circuit pack.
//
//	Relationships
//		An instance of this ME is associated with an upstream OA, and with an instance of a circuit
//		pack. If the RE includes OEO regeneration in either direction, the RE upstream amplifier is also
//		associated with a PPTP RE UNI. Refer to clause-9.14.2 for further discussion.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Its value indicates the physical
//			position of the upstream OA. The first byte is the slot ID (defined in clause 9.1.5). The second
//			byte is the port ID. (R) (mandatory) (2-bytes)
//
//			NOTE 1 - This ME ID may be identical to that of a PPTP RE UNI if it shares the same physical
//			slot and port.
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by this ME. Administrative
//			state is further described in clause A.1.6. (R,-W) (mandatory) (1-byte)
//
//			NOTE 2 - Administrative lock of an RE upstream amplifier results in LOS from any downstream
//			ONUs.
//
//		Operational State
//			This attribute indicates whether the ME is capable of performing its function. Valid values are
//			enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Operational Mode
//			This attribute indicates the operational mode as follows.
//
//			0	Constant gain
//
//			1	Constant output power
//
//			2	Autonomous
//
//			(R,-W) (mandatory) (1-byte)
//
//		Arc
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Re Downstream Amplifier Pointer
//			This attribute points to an RE downstream amplifier instance. The default value is 0xFFFF, a
//			null pointer. (R,-W) (mandatory) (2-bytes)
//
//		Total Optical Receive Signal Level Table
//			This table attribute reports a series of measurements of time-averaged input upstream optical
//			signal power. The measurement circuit should have a temporal response similar to a simple 1 pole
//			low pass filter, with an effective time constant on the order of a GTC frame time. Each table
//			entry has a 2-byte frame counter field (most significant end), and a 2-byte power measurement
//			field. The frame counter field contains the least significant 16-bits of the superframe counter
//			received closest to the time of the measurement. The power measurement field is a 2s-complement
//			integer referred to 1-mW (i.e., dBm), with 0.002-dB granularity. (Coding -32768 to +32767, where
//			0x00 = 0-dBm, 0x03e8 = +2-dBm, etc.) The RE equipment should add entries to this table as
//			frequently as is reasonable. The RE should clear the table once it is read by the OLT. (R)
//			(optional) (4-* N-bytes, where N is the number of measurements present.)
//
//		Per Burst Receive Signal Level Table
//			This table attribute reports the most recent measurement of received burst upstream optical
//			signal power. Each table entry has a 2-byte ONU-ID field (most significant end), and a 2-byte
//			power measurement field. The power measurement field is a 2s-complement integer referred to 1-mW
//			(i.e.,-dBm), with 0.002-dB granularity. (Coding -32768 to +32767, where 0x00 = 0-dBm, 0x03e8 =
//			+2-dBm, etc.) (R) (optional) (4-* N-bytes, where N is the number of distinct ONUs connected to
//			the S'/R' interface.)
//
//		Lower Receive Optical Threshold
//			This attribute specifies the optical level that the RE uses to declare the low received optical
//			power alarm. Valid values are -127-dBm (coded as 254) to 0-dBm (coded as 0) in 0.5-dB
//			increments. The default value 0xFF selects the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Upper Receive Optical Threshold
//			This attribute specifies the optical level that the RE uses to declare the high received optical
//			power alarm. Valid values are -127-dBm (coded as 254) to 0-dBm (coded as 0) in 0.5-dB
//			increments. The default value 0xFF selects the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Transmit Optical Signal Level
//			This attribute reports the current measurement of the mean optical launch power of the upstream
//			OA. Its value is a 2s-complement integer referred to 1-mW (i.e., dBm), with 0.002-dB
//			granularity. (R) (optional) (2-bytes)
//
//		Lower Transmit Optical Threshold
//			This attribute specifies the minimum mean optical launch power that the RE uses to declare the
//			low transmit optical power alarm. Its value is a 2s-complement integer referred to 1-mW (i.e.,
//			dBm), with 0.5-dB granularity. The default value 0x7F selects the RE's internal policy. (R,-W)
//			(optional) (1-byte)
//
//		Upper Transmit Optical Threshold
//			This attribute specifies the maximum mean optical launch power that the RE uses to declare the
//			high transmit optical power alarm. Its value is a 2s complement integer referred to 1-mW (i.e.,
//			dBm), with 0.5-dB granularity. The default value 0x7F selects the RE's internal policy. (R,-W)
//			(optional) (1-byte)
//
type ReUpstreamAmplifier struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const ReUpstreamAmplifier_AdministrativeState = "AdministrativeState"
const ReUpstreamAmplifier_OperationalState = "OperationalState"
const ReUpstreamAmplifier_OperationalMode = "OperationalMode"
const ReUpstreamAmplifier_Arc = "Arc"
const ReUpstreamAmplifier_ArcInterval = "ArcInterval"
const ReUpstreamAmplifier_ReDownstreamAmplifierPointer = "ReDownstreamAmplifierPointer"
const ReUpstreamAmplifier_TotalOpticalReceiveSignalLevelTable = "TotalOpticalReceiveSignalLevelTable"
const ReUpstreamAmplifier_PerBurstReceiveSignalLevelTable = "PerBurstReceiveSignalLevelTable"
const ReUpstreamAmplifier_LowerReceiveOpticalThreshold = "LowerReceiveOpticalThreshold"
const ReUpstreamAmplifier_UpperReceiveOpticalThreshold = "UpperReceiveOpticalThreshold"
const ReUpstreamAmplifier_TransmitOpticalSignalLevel = "TransmitOpticalSignalLevel"
const ReUpstreamAmplifier_LowerTransmitOpticalThreshold = "LowerTransmitOpticalThreshold"
const ReUpstreamAmplifier_UpperTransmitOpticalThreshold = "UpperTransmitOpticalThreshold"

func init() {
	reupstreamamplifierBME = &ManagedEntityDefinition{
		Name:    "ReUpstreamAmplifier",
		ClassID: ReUpstreamAmplifierClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			GetNext,
			Set,
		),
		AllowedAttributeMask: 0xfff8,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField(ReUpstreamAmplifier_AdministrativeState, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2:  ByteField(ReUpstreamAmplifier_OperationalState, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), true, true, false, 2),
			3:  ByteField(ReUpstreamAmplifier_OperationalMode, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, false, false, 3),
			4:  ByteField(ReUpstreamAmplifier_Arc, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), true, true, false, 4),
			5:  ByteField(ReUpstreamAmplifier_ArcInterval, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, true, false, 5),
			6:  Uint16Field(ReUpstreamAmplifier_ReDownstreamAmplifierPointer, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7:  TableField(ReUpstreamAmplifier_TotalOpticalReceiveSignalLevelTable, TableAttributeType, 0x0200, TableInfo{nil, 4}, mapset.NewSetWith(Read), false, true, false, 7),
			8:  TableField(ReUpstreamAmplifier_PerBurstReceiveSignalLevelTable, TableAttributeType, 0x0100, TableInfo{nil, 4}, mapset.NewSetWith(Read), false, true, false, 8),
			9:  ByteField(ReUpstreamAmplifier_LowerReceiveOpticalThreshold, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, Write), false, true, false, 9),
			10: ByteField(ReUpstreamAmplifier_UpperReceiveOpticalThreshold, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, Write), false, true, false, 10),
			11: Uint16Field(ReUpstreamAmplifier_TransmitOpticalSignalLevel, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, true, false, 11),
			12: ByteField(ReUpstreamAmplifier_LowerTransmitOpticalThreshold, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, true, false, 12),
			13: ByteField(ReUpstreamAmplifier_UpperTransmitOpticalThreshold, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, Write), false, true, false, 13),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Low received optical power",
			1: "High received optical power",
			2: "Low transmit optical power",
			3: "High transmit optical power",
			4: "High laser bias current",
			5: "S'/R' LOS",
		},
	}
}

// NewReUpstreamAmplifier (class ID 315) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewReUpstreamAmplifier(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*reupstreamamplifierBME, params...)
}
