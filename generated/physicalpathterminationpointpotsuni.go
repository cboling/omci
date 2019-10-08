/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
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

// PhysicalPathTerminationPointPotsUniClassId is the 16-bit ID for the OMCI
// Managed entity Physical path termination point POTS UNI
const PhysicalPathTerminationPointPotsUniClassId ClassID = ClassID(53)

var physicalpathterminationpointpotsuniBME *ManagedEntityDefinition

// PhysicalPathTerminationPointPotsUni (class ID #53)
//	This ME represents a POTS UNI in the ONU, where a physical path terminates and physical path
//	level functions (analogue telephony) are performed.
//
//	The ONU automatically creates an instance of this ME per port as follows.
//
//	o	When the ONU has POTS ports built into its factory configuration.
//
//	o	When a cardholder is provisioned to expect a circuit pack of the POTS type.
//
//	o	When a cardholder provisioned for plug-and-play is equipped with a circuit pack of the POTS
//	type. Note that the installation of a plug-and-play card may indicate the presence of POTS ports
//	via equipment ID as well as type, and indeed may cause the ONU to instantiate a port-mapping
//	package that specifies POTS ports.
//
//	The ONU automatically deletes instances of this ME when a cardholder is neither provisioned to
//	expect a POTS circuit pack, nor is it equipped with a POTS circuit pack.
//
//	Relationships
//		An instance of this ME is associated with each real or pre-provisioned POTS port. Either a SIP
//		or a VoIP voice CTP links to the POTS UNI. Status is available from a VoIP line status ME, and
//		RTP and call control PM may be collected on this point.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. This 2-byte
//			number indicates the physical position of the UNI. The first byte is the slot ID (defined in
//			clause 9.1.5). The second byte is the port ID, with the range 1..255. (R) (mandatory) (2-bytes)
//
//		Administrative State
//			When the administrative state is set to lock, all user functions of this UNI are blocked, and
//			alarms, TCAs and AVCs for this ME and all dependent MEs are no longer generated. Selection of a
//			default value for this attribute is outside the scope of this Recommendation. (R, W) (mandatory)
//			(1 byte)
//
//		Deprecated
//			Deprecated: This attribute is not used and should not be supported. (R,-W) (optional) (2-bytes)
//
//		Arc
//			ARC:	See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			ARC interval: See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Impedance
//			where C1, R1, and R2 are related as shown in Figure 9.9.1-1. Upon ME instantiation, the ONU sets
//			this attribute to 0. (R,-W) (optional) (1-byte)
//
//		Transmission Path
//			Transmission path: This attribute allows setting the POTS UNI either to full-time on-hook
//			transmission (0) or part-time on-hook transmission (1). Upon ME instantiation, the ONU sets this
//			attribute to 0. (R,-W) (optional) (1-byte)
//
//		Rx Gain
//			Rx gain:	This attribute specifies a gain value for the received signal in the form of a 2s
//			complement number. Valid values are -120 (12.0-dB) to 60 (+6.0-dB). The direction of the
//			affected signal is in the D to A direction, towards the telephone set. Upon ME instantiation,
//			the ONU sets this attribute to 0. (R, W) (optional) (1 byte)
//
//		Tx Gain
//			Tx gain:	This attribute specifies a gain value for the transmit signal in the form of a 2s
//			complement number. Valid values are -120 (12.0-dB) to 60 (+6.0-dB). The direction of the
//			affected signal is in the A to D direction, away from the telephone set. Upon ME instantiation,
//			the ONU sets this attribute to 0. (R, W) (optional) (1 byte)
//
//		Operational State
//			Operational state: This attribute indicates whether the ME is capable of performing its
//			function. Valid values are enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Hook State
//			Hook state:	This attribute indicates the current state of the subscriber line: 0-= on hook, 1-=
//			off hook (R) (optional) (1-byte)
//
//		Pots Holdover Time
//			POTS holdover time: This attribute determines the time during which the POTS loop voltage is
//			held up when a LOS or softswitch connectivity is detected (please refer to the following table
//			for description of behaviours).. After the specified time elapses, the ONU drops the loop
//			voltage, and may thereby cause premises intrusion alarm or fire panel circuits to go active.
//			When the ONU ranges successfully on the PON or softswitch connectivity is restored, it restores
//			the POTS loop voltage immediately and resets the timer to zero. The attribute is expressed in
//			seconds. The default value 0 selects the vendor's factory policy. (R,-W) (optional) (2-bytes)
//
//		Nominal Feed Voltage
//			Nominal feed voltage: This attribute indicates the designed nominal feed voltage of the POTS
//			loop. It is an absolute value with resolution 1-V. This attribute does not represent the actual
//			voltage measured on the loop, which is available through the test command. (R,-W) (optional)
//			(1-byte)
//
//		Loss Of Softswitch
//			Loss of softswitch: This Boolean attribute controls whether the T/R holdover initiation
//			criteria. False disables loss of softswitch connectivity detection as criteria for initiating
//			the POTS holdover timer. True enables loss of softswitch connectivity detection as criteria for
//			initiating the POTS holdover timer. This attribute is optional (if not implemented, the POTS
//			holdover time is triggered on a LOS when POTS holdover is greater than zero). (R,-W) (optional)
//			(1-byte)
//
type PhysicalPathTerminationPointPotsUni struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	physicalpathterminationpointpotsuniBME = &ManagedEntityDefinition{
		Name:    "PhysicalPathTerminationPointPotsUni",
		ClassID: 53,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
			Test,
		),
		AllowedAttributeMask: 0XFFF8,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  ByteField("AdministrativeState", 0, mapset.NewSetWith(Read, Write), true, false, false, false, 1),
			2:  Uint16Field("Deprecated", 0, mapset.NewSetWith(Read, Write), false, false, true, true, 2),
			3:  ByteField("Arc", 0, mapset.NewSetWith(Read, Write), true, false, true, false, 3),
			4:  ByteField("ArcInterval", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 4),
			5:  ByteField("Impedance", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 5),
			6:  ByteField("TransmissionPath", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 6),
			7:  ByteField("RxGain", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 7),
			8:  ByteField("TxGain", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 8),
			9:  ByteField("OperationalState", 0, mapset.NewSetWith(Read), true, false, true, false, 9),
			10: ByteField("HookState", 0, mapset.NewSetWith(Read), false, false, true, false, 10),
			11: Uint16Field("PotsHoldoverTime", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 11),
			12: ByteField("NominalFeedVoltage", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 12),
			13: ByteField("LossOfSoftswitch", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 13),
		},
	}
}

// NewPhysicalPathTerminationPointPotsUni (class ID 53 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPhysicalPathTerminationPointPotsUni(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*physicalpathterminationpointpotsuniBME, params...)
}
