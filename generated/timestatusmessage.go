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

// TimeStatusMessageClassID is the 16-bit ID for the OMCI
// Managed entity Time Status Message
const TimeStatusMessageClassID = ClassID(440) // 0x01b8

var timestatusmessageBME *ManagedEntityDefinition

// TimeStatusMessage (Class ID: #440 / 0x01b8)
//	This ME provides status and characterization information for the time-transmitting node and its
//	grandmaster. An ONU that supports time synchronization automatically creates an instance of this
//	ME. The best practise is to set all the attributes at the same time.
//
//	Relationships
//		The single instance of this ME is associated with the ONU ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. There is only one instance, number
//			0. (R) (mandatory) (2 bytes)
//
//		Domain Number
//			Using the format of clause 7.1 of [IEEE 1588]. The default value is 0. (R, W) (mandatory) (1
//			byte)
//
//		Flag Field
//			The field format is given in the table. Value 1 represents "true". (R, W) (mandatory) (1 byte)
//
//		Currentutcoffset
//			Provides the UTC offset value between the TAI and UTC timescales (UTC Offset-= TAI-- UTC), as
//			specified in clause 7.2.3 of [IEEE 1588]. (R, W) (mandatory) (2 bytes)
//
//		Priority1
//			As specified in clause 7.6.2.2 of [IEEE 1588]. (R, W) (mandatory) (1 byte)
//
//		Clockclass
//			Provides the clockClass information denoting the traceability of the time distributed by the
//			grandmaster clock, as specified in clause 7.6.2.4 of [IEEE 1588]. (R, W) (mandatory) (1 byte)
//
//		Accuracy
//			Indicates the expected accuracy of a clock when it is the grandmaster, as specified in clause
//			7.6.2.5 of [IEEE 1588]. (R, W) (mandatory) (1 byte)
//
//		Offsetscaledlogvariance
//			Provides the estimate of the time variance, as specified in clause-7.6.3 of [IEEE 1588]. (R, W)
//			(mandatory) (2 bytes)
//
//		Priority2
//			As specified in clause 7.6.2.3 of [IEEE 1588]. (R, W) (mandatory) (1 byte)
//
//			Grandmaster ID: The clockIdentity attribute of the grandmaster, taken from the IEEE EUI64
//			individual assigned numbers. (R, W) (mandatory) (8 bytes)
//
//			Steps removed:	Provides the number of boundary clocks between the local clock and the master.
//			(R, W) (mandatory) (2 bytes)
//
//			Time source:	Indicates the source of time used by the grandmaster clock, as specified in clause
//			7.6.2.6 of [IEEE 1588]. (R, W) (mandatory) (1 byte)
//
type TimeStatusMessage struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	timestatusmessageBME = &ManagedEntityDefinition{
		Name:    "TimeStatusMessage",
		ClassID: 440,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xff00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField("DomainNumber", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: ByteField("FlagField", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
			3: Uint16Field("Currentutcoffset", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, false, false, 3),
			4: ByteField("Priority1", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, false, false, 4),
			5: ByteField("Clockclass", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
			6: ByteField("Accuracy", UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7: Uint16Field("Offsetscaledlogvariance", UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, Write), false, false, false, 7),
			8: ByteField("Priority2", UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, false, false, 8),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Clock unlock",
			1: "ESMC loss",
			2: "Time unlock",
		},
	}
}

// NewTimeStatusMessage (class ID 440) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTimeStatusMessage(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*timestatusmessageBME, params...)
}
