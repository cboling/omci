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

// XdslDownstreamRfiBandsProfileClassID is the 16-bit ID for the OMCI
// Managed entity xDSL downstream RFI bands profile
const XdslDownstreamRfiBandsProfileClassID = ClassID(111) // 0x006f

var xdsldownstreamrfibandsprofileBME *ManagedEntityDefinition

// XdslDownstreamRfiBandsProfile (Class ID: #111 / 0x006f)
//	This ME contains the downstream RFI bands profile for an xDSL UNI. Instances of this ME are
//	created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the PPTP xDSL UNI part
//		1.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The value 0 is reserved. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Downstream Rfi Bands Table
//			The RFIBANDS attribute is a table where each entry comprises:
//
//			o	an entry number field (1-byte, first entry numbered 1);
//
//			o	subcarrier index 1 field (2-bytes);
//
//			o	subcarrier index 2 field (2-bytes).
//
//			For [ITU-T G.992.5], this configuration attribute defines the subset of downstream PSD mask
//			breakpoints, as specified in the downstream PSD mask, to be used to notch an RFI band. This
//			subset consists of couples of consecutive subcarrier indices belonging to breakpoints: [ti; ti-+
//			1], corresponding to the low level of the notch. Interpolation around these points is defined in
//			[ITUT G.992.5].
//
//			For [ITU-T G.993.2], this attribute defines the bands where the PSD is to be reduced as
//			specified in clause 7.2.1.2 of [ITUT G.993.2]. Each band is represented by start and stop
//			subcarrier indices with a subcarrier spacing of 4.3125-kHz. Up to 16 bands may be specified.
//			This attribute defines the RFI bands for both upstream and downstream directions.
//
//			Entries have the default value 0 for both subcarrier index 1 and subcarrier index-2. Setting an
//			entry with a non-zero subcarrier index 1 and subcarrier index-2 implies insertion into the table
//			or replacement of an existing entry. Setting an entry's subcarrier index 1 and subcarrier index
//			2 to 0 implies deletion from the table, if present.
//
//			(R,-W) (mandatory for [ITU-T G.992.5], [ITU-T G.993.2]) (5 * N bytes where N is the number of
//			RFI bands)
//
//		Bands Valid
//			This Boolean attribute controls and reports the operational status of the downstream RFI bands
//			table.
//
//			If this attribute is true, the downstream RFI bands table has been impressed on the DSL
//			equipment.
//
//			If this attribute is false, the downstream RFI bands table has not been impressed on the DSL
//			equipment. The default value is false.
//
//			This attribute can be modified by the ONU and OLT, as follows.
//
//			o	If the OLT changes any of the RFI bands table entries or sets bands valid false, then bands
//			valid is false.
//
//			o	If bands valid is false and OLT sets bands valid true, the ONU impresses the downstream RFI
//			bands data on to the DSL equipment.
//
//			(R,-W) (mandatory) (1-byte)
//
type XdslDownstreamRfiBandsProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XdslDownstreamRfiBandsProfile_DownstreamRfiBandsTable = "DownstreamRfiBandsTable"
const XdslDownstreamRfiBandsProfile_BandsValid = "BandsValid"

func init() {
	xdsldownstreamrfibandsprofileBME = &ManagedEntityDefinition{
		Name:    "XdslDownstreamRfiBandsProfile",
		ClassID: XdslDownstreamRfiBandsProfileClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
			SetTable,
		),
		AllowedAttributeMask: 0xc000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: TableField(XdslDownstreamRfiBandsProfile_DownstreamRfiBandsTable, TableAttributeType, 0x8000, TableInfo{nil, 5}, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: ByteField(XdslDownstreamRfiBandsProfile_BandsValid, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewXdslDownstreamRfiBandsProfile (class ID 111) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslDownstreamRfiBandsProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdsldownstreamrfibandsprofileBME, params...)
}
