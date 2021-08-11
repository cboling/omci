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

// TwdmChannelPloamPerformanceMonitoringHistoryDataPart2ClassID is the 16-bit ID for the OMCI
// Managed entity TWDM channel PLOAM performance monitoring history data part 2
const TwdmChannelPloamPerformanceMonitoringHistoryDataPart2ClassID ClassID = ClassID(447)

var twdmchannelploamperformancemonitoringhistorydatapart2BME *ManagedEntityDefinition

// TwdmChannelPloamPerformanceMonitoringHistoryDataPart2 (class ID #447)
//	This ME collects additional PLOAM-related PM data associated with the slot/circuit pack, hosting
//	one or more ANI-G MEs, for a specific TWDM channel. Instances of this ME are created and deleted
//	by the OLT.
//
//	The downstream PLOAM message counts of this ME include only the received PLOAM messages
//	pertaining to the given ONU, i.e.:
//
//	-	unicast PLOAM messages, addressed by ONU-ID;
//
//	-	broadcast PLOAM messages, addressed by serial number;
//
//	-	broadcast PLOAM messages, addressed to all ONUs on the PON.
//
//	All these counters are characterized as optional in clause 14 of [ITU-T- G.989.3].
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
//		System_Profile Message Count
//			System_Profile message count: The counter of received System_Profile PLOAM messages. (R)
//			(mandatory) (4-byte)
//
//		Channel_Profile Message Count
//			Channel_Profile message count: The counter of received Channel_Profile PLOAM messages. (R)
//			(mandatory) (4-byte)
//
//		Burst_Profile Message Count
//			Burst_Profile message count: The counter of received Burst_Profile PLOAM messages. (R)
//			(mandatory) (4-byte)
//
//		Assign_Onu_Id Message Count
//			Assign_ONU-ID message count: The counter of received Assign_ONU-ID PLOAM messages. (R)
//			(mandatory) (4-byte)
//
//		Unsatisfied Adjust_Tx_Wavelength Requests
//			Unsatisfied Adjust_Tx_Wavelength requests: The counter of Adjust_Tx_Wavelength requests not
//			applied or partially applied due to target US wavelength being out of Tx tuning range.  (R)
//			(mandatory) (4-byte)
//
//		Deactivate_Onu_Id Message Count
//			Deactivate_ONU-ID message count: The counter of received Deactivate_ONU-ID PLOAM messages. (R)
//			(mandatory) (4-byte)
//
//		Disable_Serial_Number Message Count
//			Disable_Serial_Number message count: The counter of received Disable_Serial_Number PLOAM
//			messages. (R) (mandatory) (4-byte)
//
//		Request_Registration Message Count
//			Request_Registration message count: The counter of received Request_Registration PLOAM messages.
//			(R) (mandatory) (4-byte)
//
//		Assign_Alloc_Id Message Count
//			Assign_Alloc-ID message count: The counter of received Assign_Alloc-ID PLOAM messages. (R)
//			(mandatory) (4-byte)
//
//		Key_Control Message Count
//			Key_Control message count: The counter of received Key_Control PLOAM messages. (R) (mandatory)
//			(4-byte)
//
//		Sleep_Allow Message Count
//			Sleep_Allow message count: The counter of received Sleep_Allow PLOAM messages. (R) (mandatory)
//			(4-byte)
//
//		Tuning_Control_Request Message Count
//			Tuning_Control/Request message count: The counter of received Tuning_Control PLOAM messages with
//			Request operation code. (R) (mandatory) (4-byte)
//
//		Tuning_Control_Complete_D Message Count
//			Tuning_Control/Complete_d message count: The counter of received Tuning_Control PLOAM messages
//			with Complete_d operation code. (R) (mandatory) (4-byte)
//
//		Calibration_Request Message Count
//			Calibration_Request message count: The counter of received Calibration_Request PLOAM messages.
//			(R) (mandatory) (4-byte)
//
type TwdmChannelPloamPerformanceMonitoringHistoryDataPart2 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	twdmchannelploamperformancemonitoringhistorydatapart2BME = &ManagedEntityDefinition{
		Name:    "TwdmChannelPloamPerformanceMonitoringHistoryDataPart2",
		ClassID: 447,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetCurrentData,
			Set,
		),
		AllowedAttributeMask: 0xffff,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field("SystemProfileMessageCount", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field("ChannelProfileMessageCount", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("BurstProfileMessageCount", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field("AssignOnuIdMessageCount", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field("UnsatisfiedAdjustTxWavelengthRequests", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field("DeactivateOnuIdMessageCount", CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field("DisableSerialNumberMessageCount", CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field("RequestRegistrationMessageCount", CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field("AssignAllocIdMessageCount", CounterAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field("KeyControlMessageCount", CounterAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: Uint32Field("SleepAllowMessageCount", CounterAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field("TuningControlRequestMessageCount", CounterAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, false, false, 14),
			15: Uint32Field("TuningControlCompleteDMessageCount", CounterAttributeType, 0x0002, 0, mapset.NewSetWith(Read), false, false, false, 15),
			16: Uint32Field("CalibrationRequestMessageCount", CounterAttributeType, 0x0001, 0, mapset.NewSetWith(Read), false, false, false, 16),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Unsatisfied Adjust_Tx_Wavelength requests",
		},
	}
}

// NewTwdmChannelPloamPerformanceMonitoringHistoryDataPart2 (class ID 447) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTwdmChannelPloamPerformanceMonitoringHistoryDataPart2(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*twdmchannelploamperformancemonitoringhistorydatapart2BME, params...)
}
