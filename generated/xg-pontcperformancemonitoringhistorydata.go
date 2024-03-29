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

// XgPonTcPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity XG-PON TC performance monitoring history data
const XgPonTcPerformanceMonitoringHistoryDataClassID = ClassID(344) // 0x0158

var xgpontcperformancemonitoringhistorydataBME *ManagedEntityDefinition

// XgPonTcPerformanceMonitoringHistoryData (Class ID: #344 / 0x0158)
//	This ME collects PM data associated with the XG-PON TC layer.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an ANI-G.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the ANI-G. (R, set-by-create) (mandatory) (2-bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. (R) (mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 ME that
//			contains PM threshold values. (R,-W, set-by-create) (mandatory) (2-bytes)
//
//		Psbd Hec Error Count
//			This attribute counts HEC errors in any of the fields of the downstream physical sync block. (R)
//			(optional) (4-bytes)
//
//		Xgtc Hec Error Count
//			This attribute counts HEC errors detected in the XGTC header. In [ITU-T G.9807.1], this
//			attribute is used for framing sublayer (FS) HEC error count management. (R) (optional) (4-bytes)
//
//		Unknown Profile Count
//			This attribute counts the number of grants received whose specified profile was not known to the
//			ONU. (R) (optional) (4-bytes)
//
//		Transmitted Xg_Pon Encapsulation Method Xgem Frames
//			Transmitted XG-PON encapsulation method (XGEM) frames: This attribute counts the number of non-
//			idle XGEM frames transmitted. If a service data unit (SDU) is fragmented, each fragment is an
//			XGEM frame and is counted as such. (R) (mandatory) (4 bytes)
//
//		Fragment Xgem Frames
//			This attribute counts the number of XGEM frames that represent fragmented SDUs, as indicated by
//			the LF bit-= 0. (R) (optional) (4-bytes)
//
//		Xgem Hec Lost Words Count
//			This attribute counts the number of 4-byte words lost because of an XGEM frame HEC error. In
//			general, all XGTC payload following the error is lost, until the next PSBd event. (R) (optional)
//			(4 bytes)
//
//		Xgem Key Errors
//			This attribute counts the number of downstream XGEM frames received with an invalid key
//			specification. The key may be invalid for several reasons, among which are:
//
//			a)	GEM port provisioned for clear text and key index not equal to 00;
//
//			b)	no multicast key of the specified key index has been provided via the OMCI for a multicast
//			GEM port;
//
//			c)	no unicast key of the specified key index has been successfully negotiated (see clause 15.5
//			of [ITU-T G.987.3] or clause C.15.5 of [ITU-T G.9807.1] for key negotiation state machine);
//
//			d)	GEM port specified to be encrypted and key index-= 00;
//
//			e)	key index-= 11, a reserved value.
//
//			(R) (mandatory) (4 bytes)
//
//		Xgem Hec Error Count
//			This attribute counts the number of instances of an XGEM frame HEC error. (R) (mandatory) (4
//			bytes)
//
//		Transmitted Bytes In Non_Idle Xgem Frames
//			Transmitted bytes in non-idle XGEM frames: This attribute counts the number of transmitted bytes
//			in non-idle XGEM frames. (R) (mandatory) (8 bytes)
//
//		Received Bytes In Non_Idle Xgem Frames
//			Received bytes in non-idle XGEM frames: This attribute counts the number of received bytes in
//			non-idle XGEM frames. (R) (optional) (8 bytes)
//
//		Loss Of Downstream Synchronization Lods Event Count
//			Loss of downstream synchronization (LODS) event count: This attribute counts the number of state
//			transitions from O5.1 to O6. (R) (optional) (4-bytes)
//
//		Lods Event Restored Count
//			This attribute counts the number of LODS cleared events. (R) (optional) (4-bytes)
//
//		Onu Reactivation By Lods Events
//			This attribute counts the number of LODS events resulting in ONU reactivation without
//			synchronization being reacquired. (R) (optional) (4-bytes)
//
type XgPonTcPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XgPonTcPerformanceMonitoringHistoryData_IntervalEndTime = "IntervalEndTime"
const XgPonTcPerformanceMonitoringHistoryData_ThresholdData12Id = "ThresholdData12Id"
const XgPonTcPerformanceMonitoringHistoryData_PsbdHecErrorCount = "PsbdHecErrorCount"
const XgPonTcPerformanceMonitoringHistoryData_XgtcHecErrorCount = "XgtcHecErrorCount"
const XgPonTcPerformanceMonitoringHistoryData_UnknownProfileCount = "UnknownProfileCount"
const XgPonTcPerformanceMonitoringHistoryData_TransmittedXgPonEncapsulationMethodXgemFrames = "TransmittedXgPonEncapsulationMethodXgemFrames"
const XgPonTcPerformanceMonitoringHistoryData_FragmentXgemFrames = "FragmentXgemFrames"
const XgPonTcPerformanceMonitoringHistoryData_XgemHecLostWordsCount = "XgemHecLostWordsCount"
const XgPonTcPerformanceMonitoringHistoryData_XgemKeyErrors = "XgemKeyErrors"
const XgPonTcPerformanceMonitoringHistoryData_XgemHecErrorCount = "XgemHecErrorCount"
const XgPonTcPerformanceMonitoringHistoryData_TransmittedBytesInNonIdleXgemFrames = "TransmittedBytesInNonIdleXgemFrames"
const XgPonTcPerformanceMonitoringHistoryData_ReceivedBytesInNonIdleXgemFrames = "ReceivedBytesInNonIdleXgemFrames"
const XgPonTcPerformanceMonitoringHistoryData_LossOfDownstreamSynchronizationLodsEventCount = "LossOfDownstreamSynchronizationLodsEventCount"
const XgPonTcPerformanceMonitoringHistoryData_LodsEventRestoredCount = "LodsEventRestoredCount"
const XgPonTcPerformanceMonitoringHistoryData_OnuReactivationByLodsEvents = "OnuReactivationByLodsEvents"

func init() {
	xgpontcperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "XgPonTcPerformanceMonitoringHistoryData",
		ClassID: XgPonTcPerformanceMonitoringHistoryDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xfffe,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField(XgPonTcPerformanceMonitoringHistoryData_IntervalEndTime, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field(XgPonTcPerformanceMonitoringHistoryData_ThresholdData12Id, PointerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_PsbdHecErrorCount, CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, true, false, 3),
			4:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_XgtcHecErrorCount, CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, true, false, 4),
			5:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_UnknownProfileCount, CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, true, false, 5),
			6:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_TransmittedXgPonEncapsulationMethodXgemFrames, CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_FragmentXgemFrames, CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, true, false, 7),
			8:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_XgemHecLostWordsCount, CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, true, false, 8),
			9:  Uint32Field(XgPonTcPerformanceMonitoringHistoryData_XgemKeyErrors, CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field(XgPonTcPerformanceMonitoringHistoryData_XgemHecErrorCount, CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint64Field(XgPonTcPerformanceMonitoringHistoryData_TransmittedBytesInNonIdleXgemFrames, CounterAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint64Field(XgPonTcPerformanceMonitoringHistoryData_ReceivedBytesInNonIdleXgemFrames, CounterAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, true, false, 12),
			13: Uint32Field(XgPonTcPerformanceMonitoringHistoryData_LossOfDownstreamSynchronizationLodsEventCount, CounterAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, true, false, 13),
			14: Uint32Field(XgPonTcPerformanceMonitoringHistoryData_LodsEventRestoredCount, CounterAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, true, false, 14),
			15: Uint32Field(XgPonTcPerformanceMonitoringHistoryData_OnuReactivationByLodsEvents, CounterAttributeType, 0x0002, 0, mapset.NewSetWith(Read), false, true, false, 15),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			1: "PSBd HEC error count",
			2: "XGTC HEC error count",
			3: "Unknown profile count",
			4: "XGEM HEC loss count",
			5: "XGEM key errors",
			6: "XGEM HEC error count",
		},
	}
}

// NewXgPonTcPerformanceMonitoringHistoryData (class ID 344) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXgPonTcPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xgpontcperformancemonitoringhistorydataBME, params...)
}
