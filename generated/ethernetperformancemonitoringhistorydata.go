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

// EthernetPerformanceMonitoringHistoryDataClassId is the 16-bit ID for the OMCI
// Managed entity Ethernet performance monitoring history data
const EthernetPerformanceMonitoringHistoryDataClassId ClassID = ClassID(24)

var ethernetperformancemonitoringhistorydataBME *ManagedEntityDefinition

// EthernetPerformanceMonitoringHistoryData (class ID #24)
//	This ME collects some of the PM data for a physical Ethernet interface. Instances of this ME are
//	created and deleted by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of the PPTP Ethernet UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the PPTP Ethernet UNI. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contains PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Fcs Errors
//			FCS errors:	This attribute counts frames received on a particular interface that were an
//			integral number of octets in length but failed the FCS check. The count is incremented when the
//			MAC service returns the frameCheckError status to the link layer control (LLC) or other MAC
//			user. Received frames for which multiple error conditions are obtained are counted according to
//			the error status presented to the LLC. (R) (mandatory) (4-bytes)
//
//		Excessive Collision Counter
//			Excessive collision counter: This attribute counts frames whose transmission failed due to
//			excessive collisions.-(R) (mandatory) (4-bytes)
//
//		Late Collision Counter
//			Late collision counter: This attribute counts the number of times that a collision was detected
//			later than 512 bit times into the transmission of a packet. (R) (mandatory) (4-bytes)
//
//		Frames Too Long
//			Frames too long: This attribute counts received frames that exceeded the maximum permitted frame
//			size. The count is incremented when the MAC service returns the frameTooLong status to the LLC.
//			(R) (mandatory) (4-bytes)
//
//		Buffer Overflows On Receive
//			Buffer overflows on receive: This attribute counts the number of times that the receive buffer
//			overflowed. (R) (mandatory) (4-bytes)
//
//		Buffer Overflows On Transmit
//			Buffer overflows on transmit: This attribute counts the number of times that the transmit buffer
//			overflowed. (R) (mandatory) (4-bytes)
//
//		Single Collision Frame Counter
//			Single collision frame counter: This attribute counts successfully transmitted frames whose
//			transmission was delayed by exactly one collision. (R) (mandatory) (4-bytes)
//
//		Multiple Collisions Frame Counter
//			Multiple collisions frame counter: This attribute counts successfully transmitted frames whose
//			transmission was delayed by more than one collision. (R) (mandatory) (4-bytes)
//
//		Sqe Counter
//			SQE counter: This attribute counts the number of times that the SQE test error message was
//			generated by the PLS sublayer. (R) (mandatory) (4-bytes)
//
//		Deferred Transmission Counter
//			Deferred transmission counter: This attribute counts frames whose first transmission attempt was
//			delayed because the medium was busy. The count does not include frames involved in collisions.
//			(R) (mandatory) (4-bytes)
//
//		Internal Mac Transmit Error Counter
//			Internal MAC transmit error counter: This attribute counts frames whose transmission failed due
//			to an internal MAC sublayer transmit error. (R) (mandatory) (4-bytes)
//
//		Carrier Sense Error Counter
//			Carrier sense error counter: This attribute counts the number of times that carrier sense was
//			lost or never asserted when attempting to transmit a frame. (R) (mandatory) (4-bytes)
//
//		Alignment Error Counter
//			Alignment error counter: This attribute counts received frames that were not an integral number
//			of octets in length and did not pass the FCS check. (R) (mandatory) (4-bytes)
//
//		Internal Mac Receive Error Counter
//			Internal MAC receive error counter: This attribute counts frames whose reception failed due to
//			an internal MAC sublayer receive error. (R) (mandatory) (4-bytes)
//
type EthernetPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	ethernetperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "EthernetPerformanceMonitoringHistoryData",
		ClassID: 24,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  Uint32Field("FcsErrors", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint32Field("ExcessiveCollisionCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint32Field("LateCollisionCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  Uint32Field("FramesTooLong", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  Uint32Field("BufferOverflowsOnReceive", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint32Field("BufferOverflowsOnTransmit", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint32Field("SingleCollisionFrameCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: Uint32Field("MultipleCollisionsFrameCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 10),
			11: Uint32Field("SqeCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 11),
			12: Uint32Field("DeferredTransmissionCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 12),
			13: Uint32Field("InternalMacTransmitErrorCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 13),
			14: Uint32Field("CarrierSenseErrorCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 14),
			15: Uint32Field("AlignmentErrorCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 15),
			16: Uint32Field("InternalMacReceiveErrorCounter", 0, mapset.NewSetWith(Read), false, false, false, false, 16),
		},
	}
}

// NewEthernetPerformanceMonitoringHistoryData (class ID 24 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewEthernetPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*ethernetperformancemonitoringhistorydataBME, params...)
}
