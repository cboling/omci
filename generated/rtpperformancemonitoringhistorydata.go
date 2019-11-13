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

// RtpPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity RTP performance monitoring history data
const RtpPerformanceMonitoringHistoryDataClassID ClassID = ClassID(144)

var rtpperformancemonitoringhistorydataBME *ManagedEntityDefinition

// RtpPerformanceMonitoringHistoryData (class ID #144)
//	This ME collects PM data related to an RTP session. Instances of this ME are created and deleted
//	by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of the PPTP POTS UNI ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the PPTP POTS UNI ME. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 ME that
//			contains PM threshold values. Since no threshold value attribute number exceeds 7, a threshold
//			data 2 ME is optional. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Rtp Errors
//			RTP errors:	This attribute counts RTP packet errors. (R) (mandatory) (4-bytes)
//
//		Packet Loss
//			Packet loss:	This attribute represents the fraction of packets lost. This attribute is
//			calculated at the end of the 15-min interval, and is undefined under the get current data
//			action. The value 0 indicates no packet loss, scaling linearly to 0xFFFF FFFF to indicate 100%
//			packet loss (zero divided by zero is defined to be zero). (R) (mandatory) (4-bytes)
//
//		Maximum Jitter
//			Maximum jitter: This attribute is a high water-mark that represents the maximum jitter
//			identified during the measured interval, expressed in RTP timestamp units. (R) (mandatory)
//			(4-bytes)
//
//		Maximum Time Between Real_Time Transport Control Protocol Rtcp  Packets
//			Maximum time between real-time transport control protocol (RTCP) packets: This attribute is a
//			high water-mark that represents the maximum time between RTCP packets during the measured
//			interval, in milliseconds. (R) (mandatory) (4-bytes)
//
//		Buffer Underflows
//			Buffer underflows: This attribute counts the number of times the reassembly buffer underflows.
//			In the case of continuous underflow caused by a loss of IP packets, a single buffer underflow
//			should be counted. If the IW function is implemented with multiple buffers, such as a packet
//			level buffer and a bit level buffer, then the underflow of either buffer increments this
//			counter. (R) (mandatory) (4-bytes)
//
//		Buffer Overflows
//			Buffer overflows: This attribute counts the number of times the reassembly buffer overflows. If
//			the IW function is implemented with multiple buffers, such as a packet level buffer and a bit
//			level buffer, then the overflow of either buffer increments this counter. (R) (mandatory)
//			(4-bytes)
//
type RtpPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	rtpperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "RtpPerformanceMonitoringHistoryData",
		ClassID: 144,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFF00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2: Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3: Uint32Field("RtpErrors", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4: Uint32Field("PacketLoss", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5: Uint32Field("MaximumJitter", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6: Uint32Field("MaximumTimeBetweenRealTimeTransportControlProtocolRtcpPackets", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7: Uint32Field("BufferUnderflows", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8: Uint32Field("BufferOverflows", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
		},
	}
}

// NewRtpPerformanceMonitoringHistoryData (class ID 144 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewRtpPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*rtpperformancemonitoringhistorydataBME, params...)
}
