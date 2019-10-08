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

// VoipMediaProfileClassId is the 16-bit ID for the OMCI
// Managed entity VoIP media profile
const VoipMediaProfileClassId ClassID = ClassID(142)

var voipmediaprofileBME *ManagedEntityDefinition

// VoipMediaProfile (class ID #142)
//	The VoIP media profile ME contains settings that apply to VoIP voice encoding. This entity is
//	conditionally required for ONUs that offer VoIP services. If a non-OMCI interface is used to
//	manage VoIP signalling, this ME is unnecessary.
//
//	An instance of this ME is created and deleted by the OLT. A VoIP media profile is needed for
//	each unique set of profile attributes.
//
//	Relationships
//		An instance of this ME may be associated with one or more VoIP voice CTP MEs.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. (R, setbycreate)
//			(mandatory) (2-bytes)
//
//		Fax Mode
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Voice Service Profile Pointer
//			Voice service profile pointer: Pointer to a voice service profile, which defines parameters such
//			as jitter buffering and echo cancellation. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Codec Selection 1st Order
//			(R,-W, set-by-create) (mandatory) (1-byte)
//
//		Packet Period Selection 1st Order
//			Packet period selection (1st order): This attribute specifies the packet period selection
//			interval in milliseconds. The recommended default value is 10-ms. Valid values are 10..30-ms.
//			(R,-W, set-by-create) (mandatory) (1-byte)
//
//		Silence Suppression 1st Order
//			Silence suppression (1st order): This attribute specifies whether silence suppression is on or
//			off. Valid values are 0-= off and 1-= on. (R,-W, set-by-create) (mandatory) (1-byte)
//
//		Codec Selection 2nd Order
//			Codec selection (2nd order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Packet Period Selection 2nd Order
//			Packet period selection (2nd order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Silence Suppression 2nd Order
//			Silence suppression (2nd order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Codec Selection 3rd Order
//			Codec selection (3rd order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Packet Period Selection 3rd Order
//			Packet period selection (3rd order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Silence Suppression 3rd Order
//			Silence suppression (3rd order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Codec Selection 4th Order
//			Codec selection (4th order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Packet Period Selection 4th Order
//			Packet period selection (4th order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Silence Suppression 4th Order
//			Silence suppression (4th order):	(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Oob Dtmf
//			OOB DTMF:	This attribute specifies out-of-band DMTF carriage. When enabled (1), DTMF signals are
//			carried out of band via RTP or the associated signalling protocol. When disabled (0), DTMF tones
//			are carried in the PCM stream. (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Rtp Profile Pointer
//			RTP profile pointer: This attribute points to the associated RTP profile data ME. (R,-W,
//			setbycreate) (mandatory) (2-bytes)
//
type VoipMediaProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	voipmediaprofileBME = &ManagedEntityDefinition{
		Name:    "VoipMediaProfile",
		ClassID: 142,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("FaxMode", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2:  Uint16Field("VoiceServiceProfilePointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  ByteField("CodecSelection1StOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 3),
			4:  ByteField("PacketPeriodSelection1StOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 4),
			5:  ByteField("SilenceSuppression1StOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 5),
			6:  ByteField("CodecSelection2NdOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 6),
			7:  ByteField("PacketPeriodSelection2NdOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 7),
			8:  ByteField("SilenceSuppression2NdOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 8),
			9:  ByteField("CodecSelection3RdOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 9),
			10: ByteField("PacketPeriodSelection3RdOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 10),
			11: ByteField("SilenceSuppression3RdOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 11),
			12: ByteField("CodecSelection4ThOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 12),
			13: ByteField("PacketPeriodSelection4ThOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 13),
			14: ByteField("SilenceSuppression4ThOrder", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 14),
			15: ByteField("OobDtmf", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 15),
			16: Uint16Field("RtpProfilePointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 16),
		},
	}
}

// NewVoipMediaProfile (class ID 142 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewVoipMediaProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*voipmediaprofileBME, params...)
}
