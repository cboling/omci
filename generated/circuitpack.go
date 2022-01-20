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

// CircuitPackClassID is the 16-bit ID for the OMCI
// Managed entity Circuit pack
const CircuitPackClassID = ClassID(6) // 0x0006

var circuitpackBME *ManagedEntityDefinition

// CircuitPack (Class ID: #6 / 0x0006)
//	This ME models a real or virtual circuit pack that is equipped in a real or virtual ONU slot.
//	For ONUs with integrated interfaces, this ME may be used to distinguish available types of
//	interfaces (the port-mapping package is another way).
//
//	For ONUs with integrated interfaces, the ONU automatically creates an instance of this ME for
//	each instance of the virtual cardholder ME. The ONU also creates an instance of this ME when the
//	OLT provisions the cardholder to expect a circuit pack, i.e., when the OLT sets the expected
//	plug-in unit type or equipment ID of the cardholder to a circuit pack type, as defined in Table
//	9.1.5-1. The ONU also creates an instance of this ME when a circuit pack is installed in a
//	cardholder whose expected plug-in unit type is 255-= plugandplay, and whose equipment ID is not
//	provisioned. Finally, when the cardholder is provisioned for plug-and-play, an instance of this
//	ME can be created at the request of the OLT.
//
//	The ONU deletes an instance of this ME when the OLT de-provisions the circuit pack (i.e., when
//	the OLT sets the expected plug-in unit type or equipment ID of the cardholder to 0-= no LIM).
//	The ONU also deletes an instance of this ME on request of the OLT if the expected plug-in unit
//	type attribute of the corresponding cardholder is equal to 255, plug-and-play, and the expected
//	equipment ID is blank (a string of all spaces). ONUs with integrated interfaces do not delete
//	circuit pack instances.
//
//	NOTE - Creation and deletion by the OLT is retained for backward compatibility.
//
//	Relationships
//		An instance of this ME is contained by an instance of the cardholder ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Its value is the same as that of
//			the cardholder ME containing this circuit pack instance. (R, setbycreate if applicable)
//			(mandatory) (2-bytes)
//
//		Type
//			This attribute identifies the circuit pack type. This attribute is a code as defined in Table
//			9.1.5-1. The value 255 means unknown or undefined, i.e., the inserted circuit pack is not
//			recognized by the ONU or is not mapped to an entry in Table 9.1.5-1. In the latter case, the
//			equipment ID attribute may contain inventory information. Upon autonomous ME instantiation, the
//			ONU sets this attribute to 0 or to the type of the circuit pack that is physically present. (R,
//			setbycreate if applicable) (mandatory) (1-byte)
//
//		Number Of Ports
//			This attribute is the number of access ports on the circuit pack. If the port-mapping package is
//			supported for this circuit pack, this attribute should be set to the total number of ports of
//			all types. (R) (optional) (1-byte)
//
//		Serial Number
//			The serial number is expected to be unique for each circuit pack, at least within the scope of
//			the given vendor. Note that the serial number may contain the vendor ID or version number. For
//			integrated ONUs, this value is identical to the value of the serial number attribute of the
//			ONU-G ME. Upon creation in the absence of a physical circuit pack, this attribute comprises all
//			spaces. (R) (mandatory) (8-bytes)
//
//		Version
//			This attribute is a string that identifies the version of the circuit pack as defined by the
//			vendor. The value 0 indicates that version information is not available or applicable. For
//			integrated ONUs, this value is identical to the value of the version attribute of the ONU-G ME.
//			Upon creation in the absence of a physical circuit pack, this attribute comprises all spaces.
//			(R) (mandatory) (14-bytes)
//
//		Vendor Id
//			This attribute identifies the vendor of the circuit pack. For ONUs with integrated interfaces,
//			this value is identical to the value of the vendor ID attribute of the ONU-G ME. Upon creation
//			in the absence of a physical circuit pack, this attribute comprises all spaces. (R) (optional)
//			(4-bytes)
//
//		Administrative State
//			This attribute locks (1) and unlocks (0) the functions performed by this ME. Administrative
//			state is further described in clause A.1.6. (R,-W) (mandatory) (1-byte)
//
//		Operational State
//			This attribute indicates whether the circuit pack is capable of performing its function. Valid
//			values are enabled (0), disabled (1) and unknown (2). Pending completion of initialization and
//			self-test on an installed circuit pack, the ONU sets this attribute to 2. (R) (optional)
//			(1-byte)
//
//		Bridged Or Ip Ind
//			This attribute specifies whether an Ethernet interface is bridged or derived from an IP router
//			function.
//
//			0	Bridged
//
//			1	IP router
//
//			2	Both bridged and IP router functions
//
//			(R,-W) (optional, only applicable for circuit packs with Ethernet interfaces) (1-byte)
//
//		Equipment Id
//			This attribute may be used to identify the vendor's specific type of circuit pack. In some
//			environments, this attribute may include the CLEI code. Upon ME instantiation, the ONU sets this
//			attribute to all spaces or to the equipment ID of the circuit pack that is physically present.
//			(R) (optional) (20-bytes)
//
//		Card Configuration
//			This attribute selects the appropriate configuration of configurable circuit packs. Table
//			9.1.5-1 specifies two configurable card types: C-DS1/E1 (code 16), and C-DS1/E1/J1 (code 17).
//			Values are indicated below for the allowed card types and configurations.
//
//			Upon autonomous instantiation, this attribute is set to 0. (R,-W, setbycreate if applicable)
//			(mandatory for configurable circuit packs) (1-byte)
//
//		Total T_Cont Buffer Number
//			Total T-CONT buffer number: This attribute reports the total number of T-CONT buffers associated
//			with the circuit pack. Upon ME instantiation, the ONU sets this attribute to 0 or to the value
//			supported by the physical circuit pack. (R) (mandatory for circuit packs that provide a traffic
//			scheduler function) (1-byte)
//
//		Total Priority Queue Number
//			This value reports the total number of priority queues associated with the circuit pack. Upon ME
//			instantiation, the ONU sets the attribute to 0 or to the value supported by the physical circuit
//			pack. (R) (mandatory for circuit packs that provide a traffic scheduler function) (1-byte)
//
//		Total Traffic Scheduler Number
//			This value reports the total number of traffic schedulers associated with the circuit pack. The
//			ONU supports null function, strict priority scheduling and WRR from the priority control, and
//			guarantee of minimum rate control points of view. If the circuit pack has no traffic scheduler,
//			this attribute should be absent or have the value 0. Upon ME instantiation, the ONU sets the
//			attribute to 0 or to the value supported by the physical circuit pack. (R) (mandatory for
//			circuit packs that provide a traffic scheduler function) (1-byte)
//
//		Power Shed Override
//			This attribute allows ports to be excluded from the power shed control defined in clause 9.1.7.
//			It is a bit mask that takes port 1 as the MSB; a bit value of 1 marks the corresponding port to
//			override the power shed timer. For hardware that cannot shed power per port, this attribute is a
//			slot override rather than a port override, with any non-zero port value causing the entire
//			circuit pack to override power shedding. (R,-W) (optional) (4-bytes)
//
type CircuitPack struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	circuitpackBME = &ManagedEntityDefinition{
		Name:    "CircuitPack",
		ClassID: 6,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
			Create,
			Delete,
		),
		AllowedAttributeMask: 0xfffc,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("Type", EnumerationAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 1),
			2:  ByteField("NumberOfPorts", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), false, true, false, 2),
			3:  MultiByteField("SerialNumber", OctetsAttributeType, 0x2000, 8, toOctets("ICAgICAgICA="), mapset.NewSetWith(Read), false, false, false, 3),
			4:  MultiByteField("Version", OctetsAttributeType, 0x1000, 14, toOctets("ICAgICAgICAgICAgICA="), mapset.NewSetWith(Read), false, false, false, 4),
			5:  MultiByteField("VendorId", StringAttributeType, 0x0800, 4, toOctets("ICAgIA=="), mapset.NewSetWith(Read), false, true, false, 5),
			6:  ByteField("AdministrativeState", EnumerationAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7:  ByteField("OperationalState", EnumerationAttributeType, 0x0200, 2, mapset.NewSetWith(Read), true, true, false, 7),
			8:  ByteField("BridgedOrIpInd", EnumerationAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, false, false, 8),
			9:  MultiByteField("EquipmentId", StringAttributeType, 0x0080, 20, toOctets("ICAgICAgICAgICAgICAgICAgICA="), mapset.NewSetWith(Read), false, true, false, 9),
			10: ByteField("CardConfiguration", EnumerationAttributeType, 0x0040, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 10),
			11: ByteField("TotalTContBufferNumber", UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: ByteField("TotalPriorityQueueNumber", UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: ByteField("TotalTrafficSchedulerNumber", UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field("PowerShedOverride", BitFieldAttributeType, 0x0004, 0, mapset.NewSetWith(Read, Write), false, true, false, 14),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Equipment alarm",
			1: "Powering alarm",
			2: "Self-test failure",
			3: "Laser end of life",
			4: "Temperature yellow",
			5: "Temperature red",
		},
	}
}

// NewCircuitPack (class ID 6) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewCircuitPack(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*circuitpackBME, params...)
}
