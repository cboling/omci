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

// XdslXtuRChannelPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity xDSL xTU-R channel performance monitoring history data
const XdslXtuRChannelPerformanceMonitoringHistoryDataClassID = ClassID(115) // 0x0073

var xdslxturchannelperformancemonitoringhistorydataBME *ManagedEntityDefinition

// XdslXtuRChannelPerformanceMonitoringHistoryData (Class ID: #115 / 0x0073)
//	This ME collects PM data of the xTUC to xTUR channel as seen from the xTU-R. Instances of this
//	ME are created and deleted by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an xDSL bearer channel. Several instances may
//		therefore be associated with an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The two MSBs of the first byte are
//			the bearer channel ID. Excluding the first 2-bits of the first byte, the remaining part of the
//			ME ID is identical to that of this ME's parent PPTP xDSL UNI part 1. (R, setbycreate)
//			(mandatory) (2-bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. (R) (mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 ME that
//			contains PM threshold values. Since no threshold value attribute number exceeds 7, a threshold
//			data 2 ME is optional. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Corrected Blocks
//			This attribute counts blocks received with errors that were corrected on this channel. (R)
//			(mandatory) (4-bytes)
//
//		Uncorrected Blocks
//			This attribute counts blocks received with uncorrectable errors on this channel. (R) (mandatory)
//			(4-bytes)
//
//		Transmitted Blocks
//			This attribute counts encoded blocks transmitted on this channel. (R) (mandatory) (4-bytes)
//
//		Received Blocks
//			This attribute counts encoded blocks received on this channel. (R) (mandatory) (4-bytes)
//
//		Code Violations
//			This attribute counts FEBE anomalies reported in the downstream bearer channel. If the CRC is
//			applied over multiple bearer channels, then each related FEBE anomaly increments each of the
//			counters related to the individual bearer channels. (R) (mandatory) (2-bytes)
//
//		Forward Error Corrections
//			This attribute counts FFEC anomalies reported in the downstream bearer channel. If FEC is
//			applied over multiple bearer channels, each related FFEC anomaly increments each of the counters
//			related to the individual bearer channels. (R) (mandatory) (2-bytes)
//
type XdslXtuRChannelPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XdslXtuRChannelPerformanceMonitoringHistoryData_IntervalEndTime = "IntervalEndTime"
const XdslXtuRChannelPerformanceMonitoringHistoryData_ThresholdData12Id = "ThresholdData12Id"
const XdslXtuRChannelPerformanceMonitoringHistoryData_CorrectedBlocks = "CorrectedBlocks"
const XdslXtuRChannelPerformanceMonitoringHistoryData_UncorrectedBlocks = "UncorrectedBlocks"
const XdslXtuRChannelPerformanceMonitoringHistoryData_TransmittedBlocks = "TransmittedBlocks"
const XdslXtuRChannelPerformanceMonitoringHistoryData_ReceivedBlocks = "ReceivedBlocks"
const XdslXtuRChannelPerformanceMonitoringHistoryData_CodeViolations = "CodeViolations"
const XdslXtuRChannelPerformanceMonitoringHistoryData_ForwardErrorCorrections = "ForwardErrorCorrections"

func init() {
	xdslxturchannelperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "XdslXtuRChannelPerformanceMonitoringHistoryData",
		ClassID: XdslXtuRChannelPerformanceMonitoringHistoryDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xff00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField(XdslXtuRChannelPerformanceMonitoringHistoryData_IntervalEndTime, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field(XdslXtuRChannelPerformanceMonitoringHistoryData_ThresholdData12Id, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field(XdslXtuRChannelPerformanceMonitoringHistoryData_CorrectedBlocks, CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4: Uint32Field(XdslXtuRChannelPerformanceMonitoringHistoryData_UncorrectedBlocks, CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5: Uint32Field(XdslXtuRChannelPerformanceMonitoringHistoryData_TransmittedBlocks, CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6: Uint32Field(XdslXtuRChannelPerformanceMonitoringHistoryData_ReceivedBlocks, CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7: Uint16Field(XdslXtuRChannelPerformanceMonitoringHistoryData_CodeViolations, CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8: Uint16Field(XdslXtuRChannelPerformanceMonitoringHistoryData_ForwardErrorCorrections, CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Corrected blocks",
			1: "Uncorrected blocks",
			2: "Code violations",
			3: "Forward error corrections",
		},
	}
}

// NewXdslXtuRChannelPerformanceMonitoringHistoryData (class ID 115) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslXtuRChannelPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdslxturchannelperformancemonitoringhistorydataBME, params...)
}
