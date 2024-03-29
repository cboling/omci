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

// PhysicalPathTerminationPointReUniClassID is the 16-bit ID for the OMCI
// Managed entity Physical path termination point RE UNI
const PhysicalPathTerminationPointReUniClassID = ClassID(314) // 0x013a

var physicalpathterminationpointreuniBME *ManagedEntityDefinition

// PhysicalPathTerminationPointReUni (Class ID: #314 / 0x013a)
//	This ME represents an S'/R' interface in a mid-span PON RE that supports OEO regeneration in at
//	least one direction, where physical paths terminate and physical path level functions are
//	performed (transmit or receive).
//
//	Such an RE automatically creates an instance of this ME for each S'/R' interface port as
//	follows.
//
//	o	When the RE has mid-span PON RE UNI interface ports built into its factory configuration.
//
//	o	When a cardholder is provisioned to expect a circuit pack of the mid-span PON RE UNI type.
//
//	o	When a cardholder provisioned for plug-and-play is equipped with a circuit pack of the midspan
//	PON RE UNI type. Note that the installation of a plug-and-play card may indicate the presence of
//	a mid-span PON RE UNI port via equipment ID as well as its type attribute, and indeed may cause
//	the management ONU to instantiate a port-mapping package to specify the ports precisely.
//
//	The management ONU automatically deletes instances of this ME when a cardholder is neither
//	provisioned to expect a mid-span PON RE UNI circuit pack, nor is it equipped with a mid-span PON
//	RE UNI circuit pack.
//
//	As illustrated in Figure 8.2.10-3, a PPTP RE UNI may share the physical port with an RE upstream
//	amplifier. The ONU declares a shared configuration through the port-mapping package combined
//	port table, whose structure defines one ME as the master. It is recommended that the PPTP RE UNI
//	be the master, with the RE upstream amplifier as a secondary ME.
//
//	The administrative state, operational state and ARC attributes of the master ME override similar
//	attributes in secondary MEs associated with the same port. In the secondary ME, these attributes
//	are present, but cause no action when written and have undefined values when read. The RE
//	upstream amplifier should use its provisionable upstream alarm thresholds and should declare
//	upstream alarms as necessary; other isomorphic alarms should be declared by the PPTP RE UNI. The
//	test action should be addressed to the master ME.
//
//	Relationships
//		An instance of this ME is associated with each instance of a mid-span PON RE S'/R' physical
//		interface of an RE that includes OEO regeneration in either direction, and it may also be
//		associated with an RE upstream amplifier.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. This 2-byte number indicates the
//			physical position of the UNI. The first byte is the slot ID (defined in clause 9.1.5). The
//			second byte is the port ID, with the range 1..255. (R) (mandatory) (2-bytes)
//
//			NOTE 1 - This ME ID may be identical to that of an RE upstream amplifier if it shares the same
//			physical slot and port.
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by this ME. Administrative
//			state is further described in clause A.1.6. (R,-W) (mandatory) (1-byte)
//
//			NOTE 2 - Administrative lock of a PPTP RE UNI results in loss of signal to any downstream ONUs.
//
//		Operational State
//			This attribute indicates whether the ME is capable of performing its function. Valid values are
//			enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Arc
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Re Ani_G Pointer
//			RE ANI-G pointer: This attribute points to an RE ANI-G instance. (R,-W) (mandatory) (2-bytes)
//
//		Total Optical Receive Signal Level Table
//			This table attribute reports a series of measurements of time averaged received upstream optical
//			signal power. The measurement circuit should have a temporal response similar to a simple 1-pole
//			low pass filter, with an effective time constant of the order of a GTC frame time. Each table
//			entry has a 2-byte frame counter field (most significant end), and a 2-byte power measurement
//			field. The frame counter field contains the least significant 16-bits of the superframe counter
//			received closest to the time of the measurement. The power measurement field is a 2s complement
//			integer referred to 1-mW (i.e., dBm), with 0.002-dB granularity. (Coding -32768 to +32767, where
//			0x00 = 0-dBm, 0x03e8 = +2-dBm, etc.) The RE equipment should add entries to this table as
//			frequently as is reasonable. The RE should clear the table once it is read by the OLT. (R)
//			(optional) (4-* N-bytes, where N is the number of measurements present.)
//
//		Per Burst Receive Signal Level Table
//			This table attribute reports the most recent measurement of received burst upstream optical
//			signal power. Each table entry has a 2-byte ONU-ID field (most significant end), and a 2-byte
//			power measurement field. The power measurement field is a 2s complement integer referred to 1-mW
//			(i.e.,-dBm), with 0.002-dB granularity. (Coding -32768 to +32767, where 0x00 = 0-dBm, 0x03e8 =
//			+2-dBm, etc.) (R) (optional) (4-* N-bytes, where N is the number of distinct ONUs connected to
//			the S'/R' interface.)
//
//		Lower Receive Optical Threshold
//			This attribute specifies the optical level that the RE uses to declare the burst mode low
//			received optical power alarm. Valid values are  -127-dBm (coded as 254) to 0-dBm (coded as 0) in
//			0.5-dB increments. The default value 0xFF selects the RE's internal policy. (R,-W) (optional)
//			(1-byte)
//
//		Upper Receive Optical Threshold
//			This attribute specifies the optical level that the RE uses to declare the burst mode high
//			optical power alarm. Valid values are  -127-dBm (coded as 254) to 0-dBm (coded as 0) in 0.5-dB
//			increments. The default value 0xFF selects the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Transmit Optical Level
//			This attribute reports the current measurement of the downstream mean optical launch power. Its
//			value is a 2s complement integer referred to 1-mW (i.e., dBm), with 0.002-dB granularity. (R)
//			(optional) (2-bytes)
//
//		Lower Transmit Power Threshold
//			This attribute specifies the downstream minimum mean optical launch power at the S'/R' interface
//			that the RE uses to declare the low transmit optical power alarm. Its value is a 2s complement
//			integer referred to 1-mW (i.e., dBm), with 0.5-dB granularity. The default value 0x7F selects
//			the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Upper Transmit Power Threshold
//			This attribute specifies the downstream maximum mean optical launch power at the S'/R' interface
//			that the RE uses to declare the high transmit optical power alarm. Its value is a 2s complement
//			integer referred to 1-mW (i.e., dBm), with 0.5-dB granularity. The default value 0x7F selects
//			the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Additional Preamble
//			This attribute indicates the number of bytes of PLOu preamble that are unavoidably consumed
//			while passing the RE. (R) (mandatory) (1-byte)
//
//		Additional Guard Time
//			This attribute indicates the number of bytes of extra guard time that are needed to ensure
//			correct operation with the RE. (R) (mandatory) (1-byte)
//
//		Connected Onus Table
//			s attribute is used to pass ONU ID information of the connected ONUs per RE UNI. The get, get
//			next sequence must be used with this attribute since its size is unspecified. Upon ME
//			instantiation, this attribute is an empty list.
//
//			Each entry contains:
//
//			- ONU ID (2-bytes)
//
//			(R) (optional) (2N bytes, where N is the number of-ONUs)
//
//		Clear Onu Table
//			the attribute is used to notify RE to clear the entire Connected ONUs table by OLT. The OLT must
//			insure that the ONU IDs have been retrieved before clearing the table, or loss of data may
//			occur.
//
//			When the value of the byte is set to 1, the RE clears the entire Connected ONUs table and resets
//			the byte to 0.
//
//			(W) (optional) (1 byte)
//
type PhysicalPathTerminationPointReUni struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const PhysicalPathTerminationPointReUni_AdministrativeState = "AdministrativeState"
const PhysicalPathTerminationPointReUni_OperationalState = "OperationalState"
const PhysicalPathTerminationPointReUni_Arc = "Arc"
const PhysicalPathTerminationPointReUni_ArcInterval = "ArcInterval"
const PhysicalPathTerminationPointReUni_ReAniGPointer = "ReAniGPointer"
const PhysicalPathTerminationPointReUni_TotalOpticalReceiveSignalLevelTable = "TotalOpticalReceiveSignalLevelTable"
const PhysicalPathTerminationPointReUni_PerBurstReceiveSignalLevelTable = "PerBurstReceiveSignalLevelTable"
const PhysicalPathTerminationPointReUni_LowerReceiveOpticalThreshold = "LowerReceiveOpticalThreshold"
const PhysicalPathTerminationPointReUni_UpperReceiveOpticalThreshold = "UpperReceiveOpticalThreshold"
const PhysicalPathTerminationPointReUni_TransmitOpticalLevel = "TransmitOpticalLevel"
const PhysicalPathTerminationPointReUni_LowerTransmitPowerThreshold = "LowerTransmitPowerThreshold"
const PhysicalPathTerminationPointReUni_UpperTransmitPowerThreshold = "UpperTransmitPowerThreshold"
const PhysicalPathTerminationPointReUni_AdditionalPreamble = "AdditionalPreamble"
const PhysicalPathTerminationPointReUni_AdditionalGuardTime = "AdditionalGuardTime"
const PhysicalPathTerminationPointReUni_ConnectedOnusTable = "ConnectedOnusTable"
const PhysicalPathTerminationPointReUni_ClearOnuTable = "ClearOnuTable"

func init() {
	physicalpathterminationpointreuniBME = &ManagedEntityDefinition{
		Name:    "PhysicalPathTerminationPointReUni",
		ClassID: PhysicalPathTerminationPointReUniClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			GetNext,
			Set,
		),
		AllowedAttributeMask: 0xffff,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField(PhysicalPathTerminationPointReUni_AdministrativeState, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2:  ByteField(PhysicalPathTerminationPointReUni_OperationalState, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), true, true, false, 2),
			3:  ByteField(PhysicalPathTerminationPointReUni_Arc, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), true, true, false, 3),
			4:  ByteField(PhysicalPathTerminationPointReUni_ArcInterval, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, true, false, 4),
			5:  Uint16Field(PhysicalPathTerminationPointReUni_ReAniGPointer, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
			6:  TableField(PhysicalPathTerminationPointReUni_TotalOpticalReceiveSignalLevelTable, TableAttributeType, 0x0400, TableInfo{nil, 4}, mapset.NewSetWith(Read), false, true, false, 6),
			7:  TableField(PhysicalPathTerminationPointReUni_PerBurstReceiveSignalLevelTable, TableAttributeType, 0x0200, TableInfo{nil, 4}, mapset.NewSetWith(Read), false, true, false, 7),
			8:  ByteField(PhysicalPathTerminationPointReUni_LowerReceiveOpticalThreshold, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, true, false, 8),
			9:  ByteField(PhysicalPathTerminationPointReUni_UpperReceiveOpticalThreshold, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, Write), false, true, false, 9),
			10: Uint16Field(PhysicalPathTerminationPointReUni_TransmitOpticalLevel, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, true, false, 10),
			11: ByteField(PhysicalPathTerminationPointReUni_LowerTransmitPowerThreshold, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, Write), false, true, false, 11),
			12: ByteField(PhysicalPathTerminationPointReUni_UpperTransmitPowerThreshold, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, true, false, 12),
			13: ByteField(PhysicalPathTerminationPointReUni_AdditionalPreamble, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: ByteField(PhysicalPathTerminationPointReUni_AdditionalGuardTime, UnsignedIntegerAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, false, false, 14),
			15: TableField(PhysicalPathTerminationPointReUni_ConnectedOnusTable, TableAttributeType, 0x0002, TableInfo{nil, 2}, mapset.NewSetWith(Read), false, true, false, 15),
			16: TableField(PhysicalPathTerminationPointReUni_ClearOnuTable, TableAttributeType, 0x0001, TableInfo{nil, 1}, mapset.NewSetWith(Write), false, true, false, 16),
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

// NewPhysicalPathTerminationPointReUni (class ID 314) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewPhysicalPathTerminationPointReUni(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*physicalpathterminationpointreuniBME, params...)
}
