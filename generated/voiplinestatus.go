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

// VoipLineStatusClassID is the 16-bit ID for the OMCI
// Managed entity VoIP line status
const VoipLineStatusClassID ClassID = ClassID(141)

var voiplinestatusBME *ManagedEntityDefinition

// VoipLineStatus (class ID #141)
//	The VoIP line status ME contains line status information for POTS ports using VoIP services. An
//	ONU that supports VoIP automatically creates or deletes an instance of this ME upon creation or
//	deletion of a PPTP POTS UNI.
//
//	Relationships
//		An instance of this ME is associated with a PPTP POTS UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the PPTP POTS UNI. (R) (mandatory)
//			(2-bytes)
//
//		Voip Codec Used
//			(R) (mandatory) (2-bytes)
//
//		Voip Voice Server Status
//			(R) (mandatory) (1-byte)
//
//		Voip Port Session Type
//			(R) (mandatory) (1-byte)
//
//		Voip Call 1 Packet Period
//			Voip call 1 packet period: This attribute reports the packet period for the first call on the
//			VoIP POTS port. The value is defined in milliseconds. (R) (mandatory) (2-bytes)
//
//		Voip Call 2 Packet Period
//			Voip call 2 packet period: This attribute reports the packet period for the second call on the
//			VoIP POTS port. The value is defined in milliseconds. (R) (mandatory) (2-bytes)
//
//		Voip Call 1 Dest Addr
//			Voip call 1 dest addr: This attribute reports the DA for the first call on the VoIP POTS port.
//			The value is an ASCII string. (R) (mandatory) (25-bytes)
//
//		Voip Call 2 Dest Addr
//			Voip call 2 dest addr: This attribute reports the DA for the second call on the VoIP POTS port.
//			The value is an ASCII string. (R) (mandatory) (25-bytes)
//
//		Voip Line State
//			(R) (optional) (1 byte)
//
//		Emergency Call Status
//			(R) (Optional) (1-byte)
//
type VoipLineStatus struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	voiplinestatusBME = &ManagedEntityDefinition{
		Name:    "VoipLineStatus",
		ClassID: 141,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0xff80,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: Uint16Field("VoipCodecUsed", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2: ByteField("VoipVoiceServerStatus", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3: ByteField("VoipPortSessionType", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4: Uint16Field("VoipCall1PacketPeriod", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5: Uint16Field("VoipCall2PacketPeriod", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6: MultiByteField("VoipCall1DestAddr", 25, nil, mapset.NewSetWith(Read), false, false, false, false, 6),
			7: MultiByteField("VoipCall2DestAddr", 25, nil, mapset.NewSetWith(Read), false, false, false, false, 7),
			8: ByteField("VoipLineState", 0, mapset.NewSetWith(Read), false, false, true, false, 8),
			9: ByteField("EmergencyCallStatus", 0, mapset.NewSetWith(Read), true, false, true, false, 9),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewVoipLineStatus (class ID 141) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewVoipLineStatus(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*voiplinestatusBME, params...)
}
