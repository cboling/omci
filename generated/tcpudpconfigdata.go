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

const TcpUdpConfigDataClassId ClassID = ClassID(136)

var tcpudpconfigdataBME *ManagedEntityDefinition

// TcpUdpConfigData (class ID #136) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type TcpUdpConfigData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	tcpudpconfigdataBME = &ManagedEntityDefinition{
		Name:    "TcpUdpConfigData",
		ClassID: 136,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XF000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: Uint16Field("PortId", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: ByteField("Protocol", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: ByteField("TosDiffservField", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4: Uint16Field("IpHostPointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
		},
	}
}

// NewTcpUdpConfigData (class ID 136 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewTcpUdpConfigData(params ...ParamData) (*ManagedEntity, error) {
	return NewManagedEntity(tcpudpconfigdataBME, params...)
}
