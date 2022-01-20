/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

// XtuDataGatheringConfigurationClassID is the 16-bit ID for the OMCI
// Managed entity xTU data gathering configuration
const XtuDataGatheringConfigurationClassID = ClassID(413) // 0x019d

var xtudatagatheringconfigurationBME *ManagedEntityDefinition

// XtuDataGatheringConfiguration (Class ID: #413 / 0x019d)
//	This ME defines configurations specific to data gathering.
//
//	An instance of this ME is created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the PPTP xDSL UNI part
//		1.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the PPTP xDSL UNI part 1 ME. (R,-set-by-create) (mandatory)
//			(2 bytes)
//
//		Logging Depth Event Percentage Per Event _ Vtu_O Logging_Depth_Event_Percentage_Oi Table
//			Logging depth event percentage per event - VTU-O (LOGGING_DEPTH_EVENT_PERCENTAGE_Oi) table: This
//			parameter is the percentage of the data gathering event buffer assigned to event type i at the
//			VTU-O. See clause 7.3.6.1 of [ITU-T G.997.1]. Each element in the table consists of 2-bytes,
//			where the first byte is event type i, and the second byte is the percentage of event type i
//			defined as the integer value multiplied by 1%. (R, W) (optional) (2- N-bytes for N event types)
//
//		Logging Depth Event Percentage Per Event _ Vtu_R Logging_Depth_Event_Percentage_Ri Table
//			Logging depth event percentage per event - VTU-R (LOGGING_DEPTH_EVENT_PERCENTAGE_Ri) table: This
//			parameter is the percentage of the data gathering event buffer assigned to event type i at the
//			VTU-R. See clause 7.3.6.2 of [ITU-T G.997.1]. Each element in the table consists of 2-bytes,
//			where the first byte is event type i, and the second byte is the percentage of event type i
//			defined as the integer value multiplied by 1%. (R, W) (optional) (2- N-bytes for N event types)
//
//		Logging Depth For Vtu_O Reporting _ Vtu_R Logging_Depth_Reporting_O
//			Logging depth for VTU-O reporting - VTU-R (LOGGING_DEPTH_REPORTING_O): This parameter is the
//			logging depth that is requested for reporting the VTU-O event trace buffer in the COMIB, in
//			number of 6-byte data gathering records. See clause 7.3.6.3 of [ITU-T G.997.1]. (R, W)
//			(optional) (2-bytes)
//
//		Logging Depth For Vtu_R Reporting _ Vtu_R Logging_Depth_Reporting_R
//			Logging depth for VTU-R reporting - VTU-R (LOGGING_DEPTH_REPORTING_R): This parameter is the
//			logging depth that is requested for reporting the VTU-R event trace buffer over the embedded
//			operations channel (eoc), in number of 6-byte data gathering records. See clause 7.3.6.4 of
//			[ITU-T G.997.1]. (R, W) (optional) (2-bytes)
//
//		Logging Data Report Newer Events First _ Vtu_R Logging_Report_Newer_First
//			Logging data report newer events first - VTU-R (LOGGING_REPORT_NEWER_FIRST): This parameter
//			determines whether the VTU-R to reports newer events first or older events first. See clause
//			7.3.6.4 of [ITU-T G.997.1]. False is mapped to 0, true is mapped to 1. (R, W) (optional)
//			(1-byte)
//
type XtuDataGatheringConfiguration struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xtudatagatheringconfigurationBME = &ManagedEntityDefinition{
		Name:    "XtuDataGatheringConfiguration",
		ClassID: 413,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
			SetTable,
		),
		AllowedAttributeMask: 0xf800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: TableField("LoggingDepthEventPercentagePerEventVtuOLoggingDepthEventPercentageOiTable", TableAttributeType, 0x8000, TableInfo{nil, 2}, mapset.NewSetWith(Read, Write), false, true, false, 1),
			2: TableField("LoggingDepthEventPercentagePerEventVtuRLoggingDepthEventPercentageRiTable", TableAttributeType, 0x4000, TableInfo{nil, 2}, mapset.NewSetWith(Read, Write), false, true, false, 2),
			3: Uint16Field("LoggingDepthForVtuOReportingVtuRLoggingDepthReportingO", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, true, false, 3),
			4: Uint16Field("LoggingDepthForVtuRReportingVtuRLoggingDepthReportingR", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, true, false, 4),
			5: ByteField("LoggingDataReportNewerEventsFirstVtuRLoggingReportNewerFirst", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, true, false, 5),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewXtuDataGatheringConfiguration (class ID 413) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXtuDataGatheringConfiguration(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xtudatagatheringconfigurationBME, params...)
}
