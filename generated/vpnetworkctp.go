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

// VpNetworkCtpClassId is the 16-bit ID for the OMCI
// Managed entity VP network CTP
const VpNetworkCtpClassId ClassID = ClassID(269)

var vpnetworkctpBME *ManagedEntityDefinition

// VpNetworkCtp (class ID #269)
//	NOTE - In [ITU-T G.984.4], this ME is called VP network CTP-G.
//
//	This ME represents the termination of VP links on an ONU. It aggregates connectivity
//	functionality from the network view and alarms from the network element view as well as
//	artefacts from trails. Instances of this ME are created and deleted by the OLT.
//
//	An instance of the VP network CTP ME can be deleted only when no ATM IW VCC TP is associated
//	with it. It is the responsibility of the OLT to ensure that this condition is met.
//
//	Relationships
//		Zero or more instances of the VP network CTP ME may exist for each instance of the IW VCC TP ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. (R, setbycreate)
//			(mandatory) (2-bytes)
//
//		Vpi Value
//			VPI value:	This attribute identifies the VPI value associated with the VP link being terminated.
//			(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Uni Pointer
//			UNI pointer: This pointer indicates the xDSL PPTP UNI associated with this VP TP. The bearer
//			channel may be indicated by the two MSBs of the pointer. (R,-W, setbycreate) (mandatory)
//			(2-bytes)
//
//		Direction
//			Direction:	This attribute specifies whether the VP link is used for UNI-to-ANI (value-1), ANI-
//			to-UNI (value-2), or bidirectional (value 3) connection. (R,-W, setbycreate) (mandatory)
//			(1-byte)
//
//		Deprecated 1
//			Deprecated 1: Not used; should be set to 0. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Deprecated 2
//			Deprecated 2: Not used; should be set to 0. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Deprecated 3
//			Deprecated 3: Not used; should be set to 0. (R,-W, setbycreate) (optional) (2-bytes)
//
//		Deprecated 4
//			Deprecated 4: Not used; if present, should be set to 0. (R) (optional) (1-byte)
//
type VpNetworkCtp struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	vpnetworkctpBME = &ManagedEntityDefinition{
		Name:    "VpNetworkCtp",
		ClassID: 269,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFE00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: Uint16Field("VpiValue", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2: Uint16Field("UniPointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3: ByteField("Direction", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 3),
			4: Uint16Field("Deprecated1", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, true, 4),
			5: Uint16Field("Deprecated2", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, true, 5),
			6: Uint16Field("Deprecated3", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, true, 6),
			7: ByteField("Deprecated4", 0, mapset.NewSetWith(Read), false, false, true, true, 7),
		},
	}
}

// NewVpNetworkCtp (class ID 269 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewVpNetworkCtp(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*vpnetworkctpBME, params...)
}
