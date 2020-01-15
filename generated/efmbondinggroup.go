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

// EfmBondingGroupClassID is the 16-bit ID for the OMCI
// Managed entity EFM bonding group
const EfmBondingGroupClassID ClassID = ClassID(419)

var efmbondinggroupBME *ManagedEntityDefinition

// EfmBondingGroup (class ID #419)
//	The EFM bonding group represents a group of links that are bonded. In [IEEE 802.3], a bonding
//	group is known as a PAF [physical medium entity (PME) aggregation function] and a link is known
//	as a PME instance of this ME are created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of an EFM bonding link.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. The value 0 is
//			reserved. (R, setbycreate) (mandatory) (2-bytes)
//
//		Group Id
//			Group ID: This attribute is the unique number representing this bonding group. See clause
//			C.3.1.1 of [ITU-T G.998.2]. (R,-W, setbycreate) (mandatory) (6-bytes)
//
//		Minimum Upstream Group Rate
//			Minimum upstream group rate: This attribute sets the minimum upstream group rate, in bits per
//			second, for this EFM Group. This attribute is used to determine the group US rate low alarm
//			status. The group US rate low alarm means that the aggregate upstream rate of all active links
//			associated with this group is less than the minimum upstream group rate. The default value for
//			this rate is zero. (R,-W) (mandatory, setbycreate) (4-bytes)
//
//		Minimum Downstream Group Rate
//			Minimum downstream group rate: This attribute sets the minimum downstream group rate, in bits
//			per second, for this EFM Group. This attribute is used to determine the group DS rate low alarm
//			status. The group DS rate low alarm means that the aggregate downstream rate of all active links
//			associated with this group is less than the minimum downstream group rate. The default value for
//			this rate is zero. (R,-W) (mandatory) (4-bytes, setbycreate)
//
//		Group Alarm Enable
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
type EfmBondingGroup struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	efmbondinggroupBME = &ManagedEntityDefinition{
		Name:    "EfmBondingGroup",
		ClassID: 419,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xf000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: MultiByteField("GroupId", OctetsAttributeType, 0x8000, 6, toOctets("AAAAAAAA"), mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: Uint32Field("MinimumUpstreamGroupRate", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
			3: Uint32Field("MinimumDownstreamGroupRate", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, false, false, 3),
			4: ByteField("GroupAlarmEnable", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewEfmBondingGroup (class ID 419) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewEfmBondingGroup(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*efmbondinggroupBME, params...)
}
