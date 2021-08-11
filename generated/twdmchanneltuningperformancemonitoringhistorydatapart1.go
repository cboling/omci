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

// TwdmChannelTuningPerformanceMonitoringHistoryDataPart1ClassID is the 16-bit ID for the OMCI
// Managed entity TWDM channel tuning performance monitoring history data part 1
const TwdmChannelTuningPerformanceMonitoringHistoryDataPart1ClassID ClassID = ClassID(449)

var twdmchanneltuningperformancemonitoringhistorydatapart1BME *ManagedEntityDefinition

// TwdmChannelTuningPerformanceMonitoringHistoryDataPart1 (class ID #449)
//	This ME collects certain tuning-control-related PM data associated with the slot/circuit pack,
//	hosting one or more ANI-G MEs, for a specific TWDM channel. Instances of this ME are created and
//	deleted by the OLT.
//
//	The relevant events this ME is concerned with are counted towards the PM statistics associated
//	with the source TWDM channel. The attribute descriptions refer to the ONU activation cycle
//	states and timers specified in clause 12 of [ITU-T- G.989.3]. This ME contains the counters
//	characterized as mandatory in clause 14 of [ITU-T- G.989.3].
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of TWDM channel ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the TWDM channel ME. (R,
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
//		Tuning Control Requests For Rx Only Or Rx And Tx
//			Tuning control requests for Rx only or Rx and Tx: The counter of received Tuning_Control PLOAM
//			messages with Request operation code that contain tuning instructions either for receiver only
//			or for both receiver and transmitter. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests For Tx Only
//			Tuning control requests for Tx only: The counter of received Tuning_Control PLOAM messages with
//			Request operation code that contain tuning instructions for transmitter only. (R) (mandatory)
//			(4-byte)
//
//		Tuning Control Requests Rejected_Int_Sfc
//			Tuning control requests rejected/INT_SFC: The counter of transmitted Tuning_Response PLOAM
//			messages with NACK operation code and INT_SFC response code, indicating inability to start
//			transceiver tuning by the specified time (SFC). (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rejected_Ds_Xxx
//			Tuning control requests rejected/DS_xxx: The aggregate counter of transmitted Tuning_Response
//			PLOAM messages with NACK operation code and any DS_xxx response code, indicating target
//			downstream wavelength channel inconsistency. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rejected_Us_Xxx
//			Tuning control requests rejected/US_xxx: The aggregate counter of transmitted Tuning_Response
//			PLOAM messages with NACK operation code and any US_xxx response code, indicating target upstream
//			wavelength channel inconsistency. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Fulfilled With Onu Reacquired At Target Channel
//			Tuning control requests fulfilled with ONU reacquired at target channel: The counter of
//			controlled tuning attempts for which an upstream tuning confirmation has been obtained in the
//			target channel. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Failed Due To Target Ds Wavelength Channel Not Found
//			Tuning control requests failed due to target DS wavelength channel not found: The counter of
//			controlled tuning attempts that failed due to timer TO4 expiration in the DS Tuning state (O8)
//			in the target channel. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Failed Due To No Feedback In Target Ds Wavelength Channel
//			Tuning control requests failed due to no feedback in target DS wavelength channel: The counter
//			of controlled tuning attempts that failed due to timer TO5 expiration in the US Tuning state
//			(O9) in the target channel. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Resolved With Onu Reacquired At Discretionary Channel
//			Tuning control requests resolved with ONU reacquired at discretionary channel: The counter of
//			controlled tuning attempts for which an upstream tuning confirmation has been obtained in the
//			discretionary channel. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Com_Ds
//			Tuning control requests Rollback/COM_DS: The counter of controlled tuning attempts that failed
//			due to communication condition in the target channel, as indicated by the Tuning_Response PLOAM
//			message with Rollback operation code and COM_DS response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Ds_Xxx
//			Tuning control requests Rollback/DS_xxx: The aggregate counter of controlled tuning attempts
//			that failed due to target downstream wavelength channel inconsistency, as indicated by the
//			Tuning_Response PLOAM message with Rollback operation code and any DS_xxx response code. (R)
//			(mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Xxx
//			Tuning control requests Rollback/US_xxx: The aggregate counter of controlled tuning attempts
//			that failed due to target upstream wavelength channel parameter violation, as indicated by the
//			Tuning_Response PLOAM message with Rollback operation code and US_xxx response code. (R)
//			(mandatory) (4-byte)
//
//		Tuning Control Requests Failed With Onu Reactivation
//			Tuning control requests failed with ONU reactivation: The counter of controlled tuning attempts
//			that failed on any reason, with expiration of timers TO4 or TO5 causing the ONU transition into
//			state O1. (R) (mandatory) (4-byte)
//
type TwdmChannelTuningPerformanceMonitoringHistoryDataPart1 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	twdmchanneltuningperformancemonitoringhistorydatapart1BME = &ManagedEntityDefinition{
		Name:    "TwdmChannelTuningPerformanceMonitoringHistoryDataPart1",
		ClassID: 449,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfffe,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field("TuningControlRequestsForRxOnlyOrRxAndTx", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field("TuningControlRequestsForTxOnly", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("TuningControlRequestsRejectedIntSfc", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field("TuningControlRequestsRejectedDsXxx", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field("TuningControlRequestsRejectedUsXxx", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field("TuningControlRequestsFulfilledWithOnuReacquiredAtTargetChannel", CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field("TuningControlRequestsFailedDueToTargetDsWavelengthChannelNotFound", CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field("TuningControlRequestsFailedDueToNoFeedbackInTargetDsWavelengthChannel", CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field("TuningControlRequestsResolvedWithOnuReacquiredAtDiscretionaryChannel", CounterAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field("TuningControlRequestsRollbackComDs", CounterAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: Uint32Field("TuningControlRequestsRollbackDsXxx", CounterAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field("TuningControlRequestsRollbackUsXxx", CounterAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, false, false, 14),
			15: Uint32Field("TuningControlRequestsFailedWithOnuReactivation", CounterAttributeType, 0x0002, 0, mapset.NewSetWith(Read), false, false, false, 15),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewTwdmChannelTuningPerformanceMonitoringHistoryDataPart1 (class ID 449) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTwdmChannelTuningPerformanceMonitoringHistoryDataPart1(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*twdmchanneltuningperformancemonitoringhistorydatapart1BME, params...)
}
