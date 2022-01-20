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

// XdslSubcarrierMaskingDownstreamProfileClassID is the 16-bit ID for the OMCI
// Managed entity xDSL subcarrier masking downstream profile
const XdslSubcarrierMaskingDownstreamProfileClassID = ClassID(108) // 0x006c

var xdslsubcarriermaskingdownstreamprofileBME *ManagedEntityDefinition

// XdslSubcarrierMaskingDownstreamProfile (Class ID: #108 / 0x006c)
//	This ME contains the subcarrier masking downstream profile for an xDSL UNI. Instances of this ME
//	are created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of the PPTP xDSL UNI part
//		1.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The value 0 is reserved. (R, set-
//			by-create) (mandatory) (2-bytes)
//
//			The four following attributes are bit maps that represent downstream mask values for subcarriers
//			1..128 (mask 1) through 385..512 (mask 4). The MSB of the first byte corresponds to the lowest
//			numbered subcarrier, and the LSB of the last byte corresponds to the highest. Each bit position
//			defines whether the corresponding downstream subcarrier is masked (1) or not masked (0).
//
//			The number of xDSL subcarriers, downstream (NSCds) is the highest numbered subcarrier that can
//			be transmitted in the downstream direction. For [ITUT-G.992.3], [ITUT-G.992.4] and
//			[ITUT-G.992.5], it is defined in the corresponding Recommendation. For [ITUT-G.992.1], NSCds =
//			256 and for [ITUT-G.992.2], NSCds-= 128.
//
//		Downstream Subcarrier Mask 1
//			Subcarriers 1 to 128. (R,-W, set-by-create) (mandatory) (16-bytes)
//
//		Downstream Subcarrier Mask 2
//			Subcarriers 129 to 256. (R,-W) (mandatory for modems that support NSCds-> 128) (16-bytes)
//
//		Downstream Subcarrier Mask 3
//			Subcarriers 257 to 384. (R,-W) (mandatory for modems that support NSCds-> 256) (16-bytes)
//
//		Downstream Subcarrier Mask 4
//			Subcarriers 385 to 512. (R,-W) (mandatory for modems that support NSCds-> 384) (16-bytes)
//
//		Mask Valid
//			This Boolean attribute controls and reports the operational status of the downstream subcarrier
//			mask attributes.
//
//			If this attribute is true (1), the downstream subcarrier mask represented in this ME has been
//			impressed on the DSL equipment.
//
//			If this attribute is false (0), the downstream subcarrier mask represented in this ME has not
//			been impressed on the DSL equipment. The default value is false.
//
//			The value of this attribute can be modified by the ONU and OLT, as follows.
//
//			o	If the OLT changes any of the four mask attributes or sets mask valid false, then mask valid
//			is false.
//
//			o	If mask valid is false and the OLT sets mask valid true, the ONU impresses the downstream
//			subcarrier mask data on to the DSL equipment.
//
//			(R,-W) (mandatory) (1-byte)
//
type XdslSubcarrierMaskingDownstreamProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdslsubcarriermaskingdownstreamprofileBME = &ManagedEntityDefinition{
		Name:    "XdslSubcarrierMaskingDownstreamProfile",
		ClassID: 108,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xf800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: MultiByteField("DownstreamSubcarrierMask1", OctetsAttributeType, 0x8000, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: MultiByteField("DownstreamSubcarrierMask2", OctetsAttributeType, 0x4000, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, Write), false, false, false, 2),
			3: MultiByteField("DownstreamSubcarrierMask3", OctetsAttributeType, 0x2000, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, Write), false, false, false, 3),
			4: MultiByteField("DownstreamSubcarrierMask4", OctetsAttributeType, 0x1000, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, Write), false, false, false, 4),
			5: ByteField("MaskValid", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewXdslSubcarrierMaskingDownstreamProfile (class ID 108) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslSubcarrierMaskingDownstreamProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdslsubcarriermaskingdownstreamprofileBME, params...)
}
