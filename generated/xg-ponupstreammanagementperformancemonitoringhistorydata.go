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

// XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity XG-PON upstream management performance monitoring history data
const XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID = ClassID(346) // 0x015a

var xgponupstreammanagementperformancemonitoringhistorydataBME *ManagedEntityDefinition

// XgPonUpstreamManagementPerformanceMonitoringHistoryData (Class ID: #346 / 0x015a)
//	This ME collects PM data associated with the XG-PON TC layer. It counts upstream PLOAM messages
//	transmitted by the ONU.
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
//			Threshold data 1/2 ID: No thresholds are defined for this ME. For uniformity with other PM, the
//			attribute is retained and shown as mandatory, but it should be set to a null pointer. (R,-W,
//			set-by-create) (mandatory) (2-bytes)
//
//		Upstream Ploam Message Count
//			This attribute counts PLOAM messages transmitted upstream, excluding acknowledge messages. (R)
//			(optional) (4-bytes)
//
//		Serial_Number_Onu Message Count
//			This attribute counts Serial_number_ONU PLOAM messages transmitted. (R) (optional) (4-bytes)
//
//		Registration Message Count
//			This attribute counts Registration PLOAM messages transmitted. (R) (optional) (4-bytes)
//
//		Key_Report Message Count
//			This attribute counts key_report PLOAM messages transmitted. (R) (optional) (4-bytes)
//
//		Acknowledge Message Count
//			This attribute counts acknowledge PLOAM messages transmitted. It includes all forms of
//			acknowledgement (AK), including those transmitted in response to a PLOAM grant when the ONU has
//			nothing to send. (R) (optional) (4-bytes)
//
//		Sleep_Request Message Count
//			This attribute counts sleep_request PLOAM messages transmitted. (R) (optional) (4-bytes)
//
type XgPonUpstreamManagementPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XgPonUpstreamManagementPerformanceMonitoringHistoryData_IntervalEndTime = "IntervalEndTime"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_ThresholdData12Id = "ThresholdData12Id"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_UpstreamPloamMessageCount = "UpstreamPloamMessageCount"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_SerialNumberOnuMessageCount = "SerialNumberOnuMessageCount"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_RegistrationMessageCount = "RegistrationMessageCount"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_KeyReportMessageCount = "KeyReportMessageCount"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_AcknowledgeMessageCount = "AcknowledgeMessageCount"
const XgPonUpstreamManagementPerformanceMonitoringHistoryData_SleepRequestMessageCount = "SleepRequestMessageCount"

func init() {
	xgponupstreammanagementperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "XgPonUpstreamManagementPerformanceMonitoringHistoryData",
		ClassID: XgPonUpstreamManagementPerformanceMonitoringHistoryDataClassID,
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
			1: ByteField(XgPonUpstreamManagementPerformanceMonitoringHistoryData_IntervalEndTime, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_ThresholdData12Id, PointerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_UpstreamPloamMessageCount, CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, true, false, 3),
			4: Uint32Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_SerialNumberOnuMessageCount, CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, true, false, 4),
			5: Uint32Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_RegistrationMessageCount, CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, true, false, 5),
			6: Uint32Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_KeyReportMessageCount, CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, true, false, 6),
			7: Uint32Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_AcknowledgeMessageCount, CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, true, false, 7),
			8: Uint32Field(XgPonUpstreamManagementPerformanceMonitoringHistoryData_SleepRequestMessageCount, CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, true, false, 8),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewXgPonUpstreamManagementPerformanceMonitoringHistoryData (class ID 346) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXgPonUpstreamManagementPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xgponupstreammanagementperformancemonitoringhistorydataBME, params...)
}
