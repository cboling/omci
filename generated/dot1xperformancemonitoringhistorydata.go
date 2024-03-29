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

// Dot1XPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity Dot1X performance monitoring history data
const Dot1XPerformanceMonitoringHistoryDataClassID = ClassID(292) // 0x0124

var dot1xperformancemonitoringhistorydataBME *ManagedEntityDefinition

// Dot1XPerformanceMonitoringHistoryData (Class ID: #292 / 0x0124)
//	This ME collects performance statistics on an ONU's IEEE 802.1X CPE authentication operation.
//	Instances of this ME are created and deleted by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME may be associated with each UNI that can perform IEEE-802.1X
//		authentication of CPE.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of a PPTP. (R, setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. (R) (mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contains PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Eapol Frames Received
//			This attribute counts received valid EAPOL frames of any type. (R) (mandatory) (4-bytes)
//
//		Eapol Frames Transmitted
//			This attribute counts transmitted EAPOL frames of any type. (R) (mandatory) (4-bytes)
//
//		Eapol Start Frames Received
//			This attribute counts received EAPOL start frames. (R) (mandatory) (4-bytes)
//
//		Eapol Logoff Frames Received
//			This attribute counts received EAPOL logoff frames. (R) (mandatory) (4-bytes)
//
//		Invalid Eapol Frames Received
//			This attribute counts received EAPOL frames in which the frame type was not recognized. (R)
//			(mandatory) (4-bytes)
//
//		Eap Resp_Id Frames Received
//			EAP resp/id frames received: This attribute counts received EAP response frames containing an
//			identifier type field. (R) (mandatory) (4-bytes)
//
//		Eap Response Frames Received
//			This attribute counts received EAP response frames, other than resp/id frames. (R) (mandatory)
//			(4-bytes)
//
//		Eap Initial Request Frames Transmitted
//			This attribute counts transmitted request frames containing an identifier type field. In [IEEE
//			802.1X], this is also called ReqId. (R) (mandatory) (4-bytes)
//
//		Eap Request Frames Transmitted
//			This attribute counts transmitted request frames, other than request/id frames. (R) (mandatory)
//			(4-bytes)
//
//		Eap Length Error Frames Received
//			This attribute counts received EAPOL frames whose packet body length field was invalid. (R)
//			(mandatory) (4-bytes)
//
//		Eap Success Frames Generated Autonomously
//			This attribute counts EAPOL success frames generated according to the local fallback policy
//			because no radius server was available. (R) (mandatory) (4-bytes)
//
//		Eap Failure Frames Generated Autonomously
//			This attribute counts EAPOL failure frames generated according to the local fallback policy
//			because no radius server was available. (R) (mandatory) (4-bytes)
//
type Dot1XPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const Dot1XPerformanceMonitoringHistoryData_IntervalEndTime = "IntervalEndTime"
const Dot1XPerformanceMonitoringHistoryData_ThresholdData12Id = "ThresholdData12Id"
const Dot1XPerformanceMonitoringHistoryData_EapolFramesReceived = "EapolFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_EapolFramesTransmitted = "EapolFramesTransmitted"
const Dot1XPerformanceMonitoringHistoryData_EapolStartFramesReceived = "EapolStartFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_EapolLogoffFramesReceived = "EapolLogoffFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_InvalidEapolFramesReceived = "InvalidEapolFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_EapRespIdFramesReceived = "EapRespIdFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_EapResponseFramesReceived = "EapResponseFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_EapInitialRequestFramesTransmitted = "EapInitialRequestFramesTransmitted"
const Dot1XPerformanceMonitoringHistoryData_EapRequestFramesTransmitted = "EapRequestFramesTransmitted"
const Dot1XPerformanceMonitoringHistoryData_EapLengthErrorFramesReceived = "EapLengthErrorFramesReceived"
const Dot1XPerformanceMonitoringHistoryData_EapSuccessFramesGeneratedAutonomously = "EapSuccessFramesGeneratedAutonomously"
const Dot1XPerformanceMonitoringHistoryData_EapFailureFramesGeneratedAutonomously = "EapFailureFramesGeneratedAutonomously"

func init() {
	dot1xperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "Dot1XPerformanceMonitoringHistoryData",
		ClassID: Dot1XPerformanceMonitoringHistoryDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xfffc,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField(Dot1XPerformanceMonitoringHistoryData_IntervalEndTime, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field(Dot1XPerformanceMonitoringHistoryData_ThresholdData12Id, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapolFramesReceived, CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapolFramesTransmitted, CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapolStartFramesReceived, CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapolLogoffFramesReceived, CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_InvalidEapolFramesReceived, CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapRespIdFramesReceived, CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapResponseFramesReceived, CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapInitialRequestFramesTransmitted, CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapRequestFramesTransmitted, CounterAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapLengthErrorFramesReceived, CounterAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapSuccessFramesGeneratedAutonomously, CounterAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field(Dot1XPerformanceMonitoringHistoryData_EapFailureFramesGeneratedAutonomously, CounterAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, false, false, 14),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			4: "Invalid EAPOL frames received",
			9: "EAP length error frames received",
		},
	}
}

// NewDot1XPerformanceMonitoringHistoryData (class ID 292) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewDot1XPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*dot1xperformancemonitoringhistorydataBME, params...)
}
