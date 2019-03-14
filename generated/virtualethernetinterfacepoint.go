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

const VirtualEthernetInterfacePointClassId ClassID = ClassID(329)

var virtualethernetinterfacepointBME *ManagedEntityDefinition

// VirtualEthernetInterfacePoint (class ID #329) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type VirtualEthernetInterfacePoint struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	virtualethernetinterfacepointBME = &ManagedEntityDefinition{
		Name:    "VirtualEthernetInterfacePoint",
		ClassID: 329,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0XF800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField("AdministrativeState", 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: ByteField("OperationalState", 0, mapset.NewSetWith(Read), true, false, true, 2),
			3: MultiByteField("InterdomainName", 25, nil, mapset.NewSetWith(Read, Write), false, false, true, 3),
			4: Uint16Field("TcpUdpPointer", 0, mapset.NewSetWith(Read, Write), false, false, true, 4),
			5: Uint16Field("IanaAssignedPort", 0, mapset.NewSetWith(Read), false, false, false, 5),
		},
	}
}

// NewVirtualEthernetInterfacePoint (class ID 329 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewVirtualEthernetInterfacePoint(params ...ParamData) (*ManagedEntity, error) {
	return NewManagedEntity(virtualethernetinterfacepointBME, params...)
}
