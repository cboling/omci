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

// SipUserDataClassID is the 16-bit ID for the OMCI
// Managed entity SIP user data
const SipUserDataClassID = ClassID(153) // 0x0099

var sipuserdataBME *ManagedEntityDefinition

// SipUserData (Class ID: #153 / 0x0099)
//	The SIP user data defines the user specific configuration attributes associated with a specific
//	VoIP CTP. This entity is conditionally required for ONUs that offer VoIP SIP services. If a non-
//	OMCI interface is used to manage SIP for VoIP, this ME is unnecessary. The non-OMCI interface
//	supplies the necessary data, which may be read back to the OLT via the SIP config portal ME.
//
//	An instance of this ME is created and deleted by the OLT. A SIP user data instance is required
//	for each POTS UNI port using SIP protocol and configured by the OMCI.
//
//	Relationships
//		An instance of this ME is associated with one VoIP voice CTP ME and a PPTP POTS UNI.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate) (mandatory)
//			(2-bytes)
//
//		Sip Agent Pointer
//			This attribute points to the SIP agent config data ME to be used for signalling. (R,-W,
//			setbycreate) (mandatory) (2-bytes)
//
//		User Part Aor
//			This attribute points to a large string that contains the user identification part of the
//			address of record. This can take the form of an alphanumeric string or the subscriber's
//			directory number. A null pointer indicates the absence of an AOR. (R,-W, setbycreate)
//			(mandatory) (2-bytes)
//
//		Sip Display Name
//			This ASCII string attribute defines the customer ID used for the display attribute in outgoing
//			SIP messages. The default value is null (all zero bytes) (R,-W) (mandatory) (25-bytes)
//
//		Username And Password
//			This attribute points to an authentication security method ME that contains the SIP user name
//			and password used for authentication. A null pointer indicates no username and password. (R,-W,
//			setbycreate) (mandatory) (2)
//
//		Voicemail Server Sip Uri
//			This attribute points to a network address ME that contains the name (IP address or URI) of the
//			SIP voicemail server for SIP signalling messages. A null pointer indicates the absence of a SIP
//			voicemail server. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Voicemail Subscription Expiration Time
//			This attribute defines the voicemail subscription expiration time in seconds. If this value is
//			0, the SIP agent uses an implementation-specific value. This attribute is recommended to be set
//			to 3600-s by default. (R,-W, setbycreate) (mandatory) (4-bytes)
//
//		Network Dial Plan Pointer
//			This attribute points to a network dial plan table. A null pointer indicates the absence of a
//			network dial plan. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Application Services Profile Pointer
//			This attribute points to a VoIP application services profile. (R,-W, setbycreate) (mandatory)
//			(2-bytes)
//
//		Feature Code Pointer
//			This attribute points to the VoIP feature access codes ME for this subscriber. A null pointer
//			indicates the absence of a VoIP feature access codes ME. (R,-W, set-by-create) (mandatory)
//			(2-bytes)
//
//		Pptp Pointer
//			This attribute points to the PPTP POTS UNI ME that provides the analogue telephony adaptor (ATA)
//			function. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Release Timer
//			This attribute contains a release timer defined in seconds. The value 0 specifies that the ONU
//			is to use its internal default. The default value of this attribute is 10-s. (R,-W) (optional)
//			(1-byte)
//
//		Receiver Off Hook Roh Timer
//			Receiver off hook (ROH) timer:	This attribute defines the time in seconds for the ROH condition
//			before ROH tone is applied. The value 0 disables ROH timing. The value 0xFF specifies that the
//			ONU is to use its internal default, which may or may not be the same as the 15-s OMCI default
//			value. (R,-W) (optional) (1-byte)
//
type SipUserData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	sipuserdataBME = &ManagedEntityDefinition{
		Name:    "SipUserData",
		ClassID: 153,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfff0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  Uint16Field("SipAgentPointer", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2:  Uint16Field("UserPartAor", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  MultiByteField("SipDisplayName", OctetsAttributeType, 0x2000, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, Write), false, false, false, 3),
			4:  Uint16Field("UsernameAndPassword", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5:  Uint16Field("VoicemailServerSipUri", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 5),
			6:  Uint32Field("VoicemailSubscriptionExpirationTime", UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 6),
			7:  Uint16Field("NetworkDialPlanPointer", UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 7),
			8:  Uint16Field("ApplicationServicesProfilePointer", UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 8),
			9:  Uint16Field("FeatureCodePointer", UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 9),
			10: Uint16Field("PptpPointer", UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 10),
			11: ByteField("ReleaseTimer", UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, Write), false, true, false, 11),
			12: ByteField("ReceiverOffHookRohTimer", UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, true, false, 12),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "SIP-UA register auth",
			1: "SIP-UA register timeout",
			2: "SIP-UA register fail",
		},
	}
}

// NewSipUserData (class ID 153) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewSipUserData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*sipuserdataBME, params...)
}
