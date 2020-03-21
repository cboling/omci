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

// EfmBondingPortPerformanceMonitoringHistoryDataPart2ClassID is the 16-bit ID for the OMCI
// Managed entity EFM bonding port performance monitoring history data part 2
const EfmBondingPortPerformanceMonitoringHistoryDataPart2ClassID ClassID = ClassID(425)

var efmbondingportperformancemonitoringhistorydatapart2BME *ManagedEntityDefinition

// EfmBondingPortPerformanceMonitoringHistoryDataPart2 (class ID #425)
//	This ME collects PM data as seen at the xTU-C. Instances of this ME are created and deleted by
//	the OLT.
//
//	Relationships
//		An instance of this ME is associated with an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. The two MSBs of
//			the first byte are the bearer channel ID. Excluding the first 2-bits of the first byte, the
//			remaining part of the ME ID is identical to that of this ME's parent PPTP xDSL UNI part 1. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contain PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Rx Unicast Frames
//			Rx unicast frames: Number of unicast Ethernet frames received over this port. (R) (mandatory)
//			(4-bytes)
//
//		Tx Unicast Frames
//			Tx unicast frames: Number of unicast Ethernet frames transmitted over this port. (R) (mandatory)
//			(4-bytes)
//
//		Rx Unicast Bytes
//			Rx unicast bytes: Number of bytes contained in the unicast Ethernet frames received over this
//			port. (R) (mandatory) (4-bytes)
//
//		Tx Unicast Bytes
//			Tx unicast bytes: Number of bytes contained in the unicast Ethernet frames transmitted over this
//			port. (R) (mandatory) (4-bytes)
//
//		Rx Broadcast Frames
//			Rx broadcast frames: Number of broadcast Ethernet frames received over this port. (R)
//			(mandatory) (4-bytes)
//
//		Tx Broadcast Frames
//			Tx broadcast frames: Number of broadcast Ethernet frames transmitted over this port. (R)
//			(mandatory) (4-bytes)
//
//		Rx Broadcast Bytes
//			Rx broadcast bytes: Number of bytes contained in the broadcast Ethernet frames received over
//			this port. (R) (mandatory) (4-bytes)
//
//		Tx Broadcast Bytes
//			Tx broadcast bytes: Number of bytes contained in the broadcast Ethernet frames transmitted over
//			this port. (R) (mandatory) (4-bytes)
//
//		Rx Multicast Frames
//			Rx multicast frames: Number of multicast Ethernet frames received over this port. (R)
//			(mandatory) (4-bytes)
//
//		Tx Multicast Frames
//			Tx multicast frames: Number of multicast Ethernet frames transmitted over this port. (R)
//			(mandatory) (4-bytes)
//
//		Rx Multicast Bytes
//			Rx multicast bytes: Number of bytes contained in the multicast Ethernet frames received over
//			this port. (R) (mandatory) (4-bytes)
//
//		Tx Multicast Bytes
//			Tx multicast bytes: Number of bytes contained in the multicast Ethernet frames transmitted over
//			this port. (R) (mandatory) (4-bytes)
//
type EfmBondingPortPerformanceMonitoringHistoryDataPart2 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	efmbondingportperformancemonitoringhistorydatapart2BME = &ManagedEntityDefinition{
		Name:    "EfmBondingPortPerformanceMonitoringHistoryDataPart2",
		ClassID: 425,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xfffc,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field("RxUnicastFrames", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field("TxUnicastFrames", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("RxUnicastBytes", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field("TxUnicastBytes", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field("RxBroadcastFrames", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field("TxBroadcastFrames", CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field("RxBroadcastBytes", CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field("TxBroadcastBytes", CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field("RxMulticastFrames", CounterAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field("TxMulticastFrames", CounterAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: Uint32Field("RxMulticastBytes", CounterAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field("TxMulticastBytes", CounterAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, false, false, 14),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewEfmBondingPortPerformanceMonitoringHistoryDataPart2 (class ID 425) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewEfmBondingPortPerformanceMonitoringHistoryDataPart2(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*efmbondingportperformancemonitoringhistorydatapart2BME, params...)
}
