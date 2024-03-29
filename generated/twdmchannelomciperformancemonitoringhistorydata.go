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

// TwdmChannelOmciPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity TWDM channel OMCI performance monitoring history data
const TwdmChannelOmciPerformanceMonitoringHistoryDataClassID = ClassID(452) // 0x01c4

var twdmchannelomciperformancemonitoringhistorydataBME *ManagedEntityDefinition

// TwdmChannelOmciPerformanceMonitoringHistoryData (Class ID: #452 / 0x01c4)
//	This ME collects OMCI-related PM data associated with the slot/circuit pack, hosting one or more
//	ANI-G MEs, for a specific TWDM channel. Instances of this ME are created and deleted by the OLT.
//
//	The counters maintained by this ME are characterized as optional in clause 14 of [ITU-
//	T-G.989.3].
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of TWDM channel ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the TWDM channel ME. (R, setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. (R) (mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contains PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Omci Baseline Message Count
//			The counter of baseline format OMCI messages directed to the given ONU. (R) (mandatory) (4-byte)
//
//		Omci Extended Message Count
//			The counter of extended format OMCI messages directed to the given ONU. (R) (mandatory) (4-byte)
//
//		Omci Mic Error Count
//			The counter of OMCI messages received with MIC errors. (R) (mandatory) (4-byte)
//
type TwdmChannelOmciPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const TwdmChannelOmciPerformanceMonitoringHistoryData_IntervalEndTime = "IntervalEndTime"
const TwdmChannelOmciPerformanceMonitoringHistoryData_ThresholdData12Id = "ThresholdData12Id"
const TwdmChannelOmciPerformanceMonitoringHistoryData_OmciBaselineMessageCount = "OmciBaselineMessageCount"
const TwdmChannelOmciPerformanceMonitoringHistoryData_OmciExtendedMessageCount = "OmciExtendedMessageCount"
const TwdmChannelOmciPerformanceMonitoringHistoryData_OmciMicErrorCount = "OmciMicErrorCount"

func init() {
	twdmchannelomciperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "TwdmChannelOmciPerformanceMonitoringHistoryData",
		ClassID: TwdmChannelOmciPerformanceMonitoringHistoryDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xf800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField(TwdmChannelOmciPerformanceMonitoringHistoryData_IntervalEndTime, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field(TwdmChannelOmciPerformanceMonitoringHistoryData_ThresholdData12Id, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field(TwdmChannelOmciPerformanceMonitoringHistoryData_OmciBaselineMessageCount, CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4: Uint32Field(TwdmChannelOmciPerformanceMonitoringHistoryData_OmciExtendedMessageCount, CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5: Uint32Field(TwdmChannelOmciPerformanceMonitoringHistoryData_OmciMicErrorCount, CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "OMCI MIC error count",
		},
	}
}

// NewTwdmChannelOmciPerformanceMonitoringHistoryData (class ID 452) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTwdmChannelOmciPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*twdmchannelomciperformancemonitoringhistorydataBME, params...)
}
