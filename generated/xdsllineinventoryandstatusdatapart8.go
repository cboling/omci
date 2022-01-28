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

// XdslLineInventoryAndStatusDataPart8ClassID is the 16-bit ID for the OMCI
// Managed entity xDSL line inventory and status data part 8
const XdslLineInventoryAndStatusDataPart8ClassID = ClassID(414) // 0x019e

var xdsllineinventoryandstatusdatapart8BME *ManagedEntityDefinition

// XdslLineInventoryAndStatusDataPart8 (Class ID: #414 / 0x019e)
//	This ME extends the attributes defined in the xDSL line inventory and status data parts-1..4.
//
//	Relationships
//		This is one of the status data MEs associated with an xDSL UNI. The ONU automatically creates or
//		deletes an instance of this ME upon creation or deletion of a PPTP xDSL UNI part 1 that supports
//		these attributes.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the PPTP xDSL UNI part 1 ME. (R) (mandatory) (2-bytes)
//
//		Retransmission Used Downstream Rtx_Usedds
//			Retransmission used downstream (RTX_USEDds): This parameter specifies whether [ITU-T G.998.4]
//			retransmission is used (i.e., active in showtime) in the downstream transmit direction. The
//			valid range of values is given in clause-7.5.1.38 of [ITU-T G.997.1]. (R) (mandatory) (1 byte)
//
//		Retransmission Used Upstream Rtx_Usedus
//			Retransmission used upstream (RTX_USEDus): This parameter specifies whether  [ITUT G.998.4]
//			retransmission is used (i.e., active in showtime) in the upstream transmit direction. The valid
//			range of values is given in clause 7.5.1.38 of [ITU-T G.997.1]. (R) (mandatory) (1 byte)
//
//		Date_Time_Stamping Of Near_End Test Parameters Stamp_Test_Ne
//			Date/time-stamping of near-end test parameters (STAMP-TEST-NE): This parameter indicates the
//			date/time when the near-end test parameters that can change during showtime were last updated.
//			See clause 7.5.1.36.3 of [ITUT-G.997.1]. The format of this parameter is as follows.
//
//			(R) (optional) (7-bytes)
//
//		Date_Time_Stamping Of Far_End Test Parameters Stamp_Test_Fe
//			Date/time-stamping of far-end test parameters (STAMP-TEST-FE): This parameter indicates the
//			date/time when the far-end test parameters that can change during showtime were last updated.
//			See clause 7.5.1.36.4 of [ITUT-G.997.1]. The format of this parameter is the same as STAMP-TEST-
//			NE. (R) (optional) (7-bytes)
//
//		Date_Time_Stamping Of Last Successful Downstream Olr Operation Stamp_Olr_Ds
//			Date/time-stamping of last successful downstream OLR operation (STAMP-OLR-ds): This parameter
//			indicates the date/time of the last successful OLR execution in the downstream direction that
//			has modified the bits or gains. See clause-7.5.1.37.1 of [ITU-T G.997.1]. The format of this
//			parameter is the same as STAMP-TEST-NE. (R) (optional) (7 bytes)
//
//		Date_Time_Stamping Of Last Successful Upstream Olr Operation Stamp_Olr_Us
//			Date/time-stamping of last successful upstream OLR operation (STAMP-OLR-us): This parameter
//			indicates the date/time of the last successful OLR execution in the upstream direction that has
//			modified the bits or gains. See clause-7.5.1.37.2 of [ITU-T G.997.1]. The format of this
//			parameter is the same as STAMP-TEST-NE. (R) (optional) (7 bytes)
//
type XdslLineInventoryAndStatusDataPart8 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XdslLineInventoryAndStatusDataPart8_RetransmissionUsedDownstreamRtxUsedds = "RetransmissionUsedDownstreamRtxUsedds"
const XdslLineInventoryAndStatusDataPart8_RetransmissionUsedUpstreamRtxUsedus = "RetransmissionUsedUpstreamRtxUsedus"
const XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfNearEndTestParametersStampTestNe = "DateTimeStampingOfNearEndTestParametersStampTestNe"
const XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfFarEndTestParametersStampTestFe = "DateTimeStampingOfFarEndTestParametersStampTestFe"
const XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfLastSuccessfulDownstreamOlrOperationStampOlrDs = "DateTimeStampingOfLastSuccessfulDownstreamOlrOperationStampOlrDs"
const XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfLastSuccessfulUpstreamOlrOperationStampOlrUs = "DateTimeStampingOfLastSuccessfulUpstreamOlrOperationStampOlrUs"

func init() {
	xdsllineinventoryandstatusdatapart8BME = &ManagedEntityDefinition{
		Name:    "XdslLineInventoryAndStatusDataPart8",
		ClassID: XdslLineInventoryAndStatusDataPart8ClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0xfc00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField(XdslLineInventoryAndStatusDataPart8_RetransmissionUsedDownstreamRtxUsedds, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: ByteField(XdslLineInventoryAndStatusDataPart8_RetransmissionUsedUpstreamRtxUsedus, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), false, false, false, 2),
			3: MultiByteField(XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfNearEndTestParametersStampTestNe, OctetsAttributeType, 0x2000, 7, toOctets("AAAAAAAAAA=="), mapset.NewSetWith(Read), false, true, false, 3),
			4: MultiByteField(XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfFarEndTestParametersStampTestFe, OctetsAttributeType, 0x1000, 7, toOctets("AAAAAAAAAA=="), mapset.NewSetWith(Read), false, true, false, 4),
			5: MultiByteField(XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfLastSuccessfulDownstreamOlrOperationStampOlrDs, OctetsAttributeType, 0x0800, 7, toOctets("AAAAAAAAAA=="), mapset.NewSetWith(Read), false, true, false, 5),
			6: MultiByteField(XdslLineInventoryAndStatusDataPart8_DateTimeStampingOfLastSuccessfulUpstreamOlrOperationStampOlrUs, OctetsAttributeType, 0x0400, 7, toOctets("AAAAAAAAAA=="), mapset.NewSetWith(Read), false, true, false, 6),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewXdslLineInventoryAndStatusDataPart8 (class ID 414) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslLineInventoryAndStatusDataPart8(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdsllineinventoryandstatusdatapart8BME, params...)
}
