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

// TwdmChannelTuningPerformanceMonitoringHistoryDataPart3ClassId is the 16-bit ID for the OMCI
// Managed entity TWDM channel tuning performance monitoring history data part 3
const TwdmChannelTuningPerformanceMonitoringHistoryDataPart3ClassId ClassID = ClassID(451)

var twdmchanneltuningperformancemonitoringhistorydatapart3BME *ManagedEntityDefinition

// TwdmChannelTuningPerformanceMonitoringHistoryDataPart3 (class ID #451)
//	This ME collects remaining tuning-control-related PM data associated with the slot/circuit pack,
//	hosting one or more ANI-G MEs, for a specific TWDM channel. Instances of this ME are created and
//	deleted by the OLT.
//
//	The relevant events this ME is concerned with are counted towards the PM statistics associated
//	with the source TWDM channel. This ME contains the counters characterized as optional in clause
//	14 of [ITU-T-G.989.3].
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
//		Tuning Control Requests Rollback_Ds_Albl
//			Tuning control requests Rollback/DS_ALBL: The counter of controlled tuning attempts that failed
//			due to downstream administrative label inconsistency, as indicated by the Tuning_Response PLOAM
//			message with Rollback operation code and DS_ALBL response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Ds_Lktp
//			Tuning control requests Rollback/DS_LKTP: The counter of controlled tuning attempts that failed
//			due to downstream optical link type inconsistency, as indicated by the Tuning_Response PLOAM
//			message with Rollback operation code and DS_LKTP response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Albl
//			Tuning control requests Rollback/US_ALBL: The counter of controlled tuning attempts that failed
//			due to upstream administrative label violation, as indicated by the Tuning_Response PLOAM
//			message with Rollback operation code and US_ALBL response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Void
//			Tuning control requests Rollback/US_VOID: The counter of controlled tuning attempts that failed
//			due to the target upstream wavelength channel descriptor being void, as indicated by the
//			Tuning_Response PLOAM message with Rollback operation code and US_VOID response code. (R)
//			(mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Tunr
//			Tuning control requests Rollback/US_TUNR: The counter of controlled tuning attempts that failed
//			due to the transmitter tuning range violation, as indicated by the Tuning_Response PLOAM message
//			with Rollback operation code and US_TUNR response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Lktp
//			Tuning control requests Rollback/US_LKTP: The counter of controlled tuning attempts that failed
//			due to the upstream optical link type violation, as indicated by the Tuning_Response PLOAM
//			message with Rollback operation code and US_LKTP response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Lnrt
//			Tuning control requests Rollback/US_LNRT: The counter of controlled tuning attempts that failed
//			due to the upstream line rate violation, as indicated by the Tuning_Response PLOAM message with
//			Rollback operation code and US_LNRT response code. (R) (mandatory) (4-byte)
//
//		Tuning Control Requests Rollback_Us_Lncd
//			Tuning control requests Rollback/US_LNCD: The counter of controlled tuning attempts that failed
//			due to the upstream line code violation, as indicated by the Tuning_Response PLOAM message with
//			Rollback operation code and US_LNCD response code. (R) (mandatory) (4-byte)
//
type TwdmChannelTuningPerformanceMonitoringHistoryDataPart3 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	twdmchanneltuningperformancemonitoringhistorydatapart3BME = &ManagedEntityDefinition{
		Name:    "TwdmChannelTuningPerformanceMonitoringHistoryDataPart3",
		ClassID: 451,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetCurrentData,
			Set,
		),
		AllowedAttributeMask: 0XFFC0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  Uint32Field("TuningControlRequestsRollbackDsAlbl", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint32Field("TuningControlRequestsRollbackDsLktp", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint32Field("TuningControlRequestsRollbackUsAlbl", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  Uint32Field("TuningControlRequestsRollbackUsVoid", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  Uint32Field("TuningControlRequestsRollbackUsTunr", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint32Field("TuningControlRequestsRollbackUsLktp", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint32Field("TuningControlRequestsRollbackUsLnrt", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: Uint32Field("TuningControlRequestsRollbackUsLncd", 0, mapset.NewSetWith(Read), false, false, false, false, 10),
		},
	}
}

// NewTwdmChannelTuningPerformanceMonitoringHistoryDataPart3 (class ID 451 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewTwdmChannelTuningPerformanceMonitoringHistoryDataPart3(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*twdmchanneltuningperformancemonitoringhistorydatapart3BME, params...)
}
