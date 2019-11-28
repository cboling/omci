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

// Dot1XPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity Dot1X performance monitoring history data
const Dot1XPerformanceMonitoringHistoryDataClassID ClassID = ClassID(292)

var dot1xperformancemonitoringhistorydataBME *ManagedEntityDefinition

// Dot1XPerformanceMonitoringHistoryData (class ID #292)
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
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of a PPTP. (R, setbycreate)
//			(mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 and 2 MEs
//			that contains PM threshold values. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Eapol Frames Received
//			EAPOL frames received: This attribute counts received valid EAPOL frames of any type. (R)
//			(mandatory) (4-bytes)
//
//		Eapol Frames Transmitted
//			EAPOL frames transmitted: This attribute counts transmitted EAPOL frames of any type. (R)
//			(mandatory) (4-bytes)
//
//		Eapol Start Frames Received
//			EAPOL start frames received: This attribute counts received EAPOL start frames. (R) (mandatory)
//			(4-bytes)
//
//		Eapol Logoff Frames Received
//			EAPOL logoff frames received: This attribute counts received EAPOL logoff frames. (R)
//			(mandatory) (4-bytes)
//
//		Invalid Eapol Frames Received
//			Invalid EAPOL frames received: This attribute counts received EAPOL frames in which the frame
//			type was not recognized. (R) (mandatory) (4-bytes)
//
//		Eap Resp_Id Frames Received
//			EAP resp/id frames received: This attribute counts received EAP response frames containing an
//			identifier type field. (R) (mandatory) (4-bytes)
//
//		Eap Response Frames Received
//			EAP response frames received: This attribute counts received EAP response frames, other than
//			resp/id frames. (R) (mandatory) (4-bytes)
//
//		Eap Initial Request Frames Transmitted
//			EAP initial request frames transmitted: This attribute counts transmitted request frames
//			containing an identifier type field. In [IEEE 802.1X], this is also called ReqId. (R)
//			(mandatory) (4-bytes)
//
//		Eap Request Frames Transmitted
//			EAP request frames transmitted: This attribute counts transmitted request frames, other than
//			request/id frames. (R) (mandatory) (4-bytes)
//
//		Eap Length Error Frames Received
//			EAP length error frames received: This attribute counts received EAPOL frames whose packet body
//			length field was invalid. (R) (mandatory) (4-bytes)
//
//		Eap Success Frames Generated Autonomously
//			EAP success frames generated autonomously: This attribute counts EAPOL success frames generated
//			according to the local fallback policy because no radius server was available. (R) (mandatory)
//			(4-bytes)
//
//		Eap Failure Frames Generated Autonomously
//			EAP failure frames generated autonomously: This attribute counts EAPOL failure frames generated
//			according to the local fallback policy because no radius server was available. (R) (mandatory)
//			(4-bytes)
//
type Dot1XPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	dot1xperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "Dot1XPerformanceMonitoringHistoryData",
		ClassID: 292,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfffc,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  Uint32Field("EapolFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint32Field("EapolFramesTransmitted", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint32Field("EapolStartFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  Uint32Field("EapolLogoffFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  Uint32Field("InvalidEapolFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint32Field("EapRespIdFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint32Field("EapResponseFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: Uint32Field("EapInitialRequestFramesTransmitted", 0, mapset.NewSetWith(Read), false, false, false, false, 10),
			11: Uint32Field("EapRequestFramesTransmitted", 0, mapset.NewSetWith(Read), false, false, false, false, 11),
			12: Uint32Field("EapLengthErrorFramesReceived", 0, mapset.NewSetWith(Read), false, false, false, false, 12),
			13: Uint32Field("EapSuccessFramesGeneratedAutonomously", 0, mapset.NewSetWith(Read), false, false, false, false, 13),
			14: Uint32Field("EapFailureFramesGeneratedAutonomously", 0, mapset.NewSetWith(Read), false, false, false, false, 14),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewDot1XPerformanceMonitoringHistoryData (class ID 292) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewDot1XPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*dot1xperformancemonitoringhistorydataBME, params...)
}
