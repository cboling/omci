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

// VoipMediaProfileClassID is the 16-bit ID for the OMCI
// Managed entity VoIP media profile
const VoipMediaProfileClassID = ClassID(142) // 0x008e

var voipmediaprofileBME *ManagedEntityDefinition

// VoipMediaProfile (Class ID: #142 / 0x008e)
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
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Fax Mode
//			Selects the fax mode; values are as follows.
//
//			0	Passthru
//
//			1	ITU-T T.38
//
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Voice Service Profile Pointer
//			Pointer to a voice service profile, which defines parameters such as jitter buffering and echo
//			cancellation. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Codec Selection 1st Order
//			Codec selection (1st order): This attribute specifies codec selection as defined by [IETF-
//			RFC-3551].
//
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
//			Three more groups of three attributes are defined, with definitions identical to the preceding
//			three:
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
//			This attribute specifies out-of-band DMTF carriage. When enabled (1), DTMF signals are carried
//			out of band via RTP or the associated signalling protocol. When disabled (0), DTMF tones are
//			carried in the PCM stream. (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Rtp Profile Pointer
//			This attribute points to the associated RTP profile data ME. (R,-W, setbycreate) (mandatory)
//			(2-bytes)
//
type VoipMediaProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const VoipMediaProfile_FaxMode = "FaxMode"
const VoipMediaProfile_VoiceServiceProfilePointer = "VoiceServiceProfilePointer"
const VoipMediaProfile_CodecSelection1StOrder = "CodecSelection1StOrder"
const VoipMediaProfile_PacketPeriodSelection1StOrder = "PacketPeriodSelection1StOrder"
const VoipMediaProfile_SilenceSuppression1StOrder = "SilenceSuppression1StOrder"
const VoipMediaProfile_CodecSelection2NdOrder = "CodecSelection2NdOrder"
const VoipMediaProfile_PacketPeriodSelection2NdOrder = "PacketPeriodSelection2NdOrder"
const VoipMediaProfile_SilenceSuppression2NdOrder = "SilenceSuppression2NdOrder"
const VoipMediaProfile_CodecSelection3RdOrder = "CodecSelection3RdOrder"
const VoipMediaProfile_PacketPeriodSelection3RdOrder = "PacketPeriodSelection3RdOrder"
const VoipMediaProfile_SilenceSuppression3RdOrder = "SilenceSuppression3RdOrder"
const VoipMediaProfile_CodecSelection4ThOrder = "CodecSelection4ThOrder"
const VoipMediaProfile_PacketPeriodSelection4ThOrder = "PacketPeriodSelection4ThOrder"
const VoipMediaProfile_SilenceSuppression4ThOrder = "SilenceSuppression4ThOrder"
const VoipMediaProfile_OobDtmf = "OobDtmf"
const VoipMediaProfile_RtpProfilePointer = "RtpProfilePointer"

func init() {
	voipmediaprofileBME = &ManagedEntityDefinition{
		Name:    "VoipMediaProfile",
		ClassID: VoipMediaProfileClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xffff,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField(VoipMediaProfile_FaxMode, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  Uint16Field(VoipMediaProfile_VoiceServiceProfilePointer, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  ByteField(VoipMediaProfile_CodecSelection1StOrder, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4:  ByteField(VoipMediaProfile_PacketPeriodSelection1StOrder, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5:  ByteField(VoipMediaProfile_SilenceSuppression1StOrder, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 5),
			6:  ByteField(VoipMediaProfile_CodecSelection2NdOrder, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 6),
			7:  ByteField(VoipMediaProfile_PacketPeriodSelection2NdOrder, UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 7),
			8:  ByteField(VoipMediaProfile_SilenceSuppression2NdOrder, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 8),
			9:  ByteField(VoipMediaProfile_CodecSelection3RdOrder, UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 9),
			10: ByteField(VoipMediaProfile_PacketPeriodSelection3RdOrder, UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 10),
			11: ByteField(VoipMediaProfile_SilenceSuppression3RdOrder, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 11),
			12: ByteField(VoipMediaProfile_CodecSelection4ThOrder, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 12),
			13: ByteField(VoipMediaProfile_PacketPeriodSelection4ThOrder, UnsignedIntegerAttributeType, 0x0008, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 13),
			14: ByteField(VoipMediaProfile_SilenceSuppression4ThOrder, UnsignedIntegerAttributeType, 0x0004, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 14),
			15: ByteField(VoipMediaProfile_OobDtmf, UnsignedIntegerAttributeType, 0x0002, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 15),
			16: Uint16Field(VoipMediaProfile_RtpProfilePointer, UnsignedIntegerAttributeType, 0x0001, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 16),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewVoipMediaProfile (class ID 142) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewVoipMediaProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*voipmediaprofileBME, params...)
}
