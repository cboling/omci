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

const IpHostConfigDataClassId uint16 = 134

// IpHostConfigData (class ID #134) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type IpHostConfigData struct {
	BaseManagedEntityDefinition
}

// NewIpHostConfigData (class ID 134 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewIpHostConfigData(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "IpHostConfigData",
		ClassID:  134,
		EntityID: eid,
		MessageTypes: []MsgType{
			Set,
			Get,
		},
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read),
			1: ByteField("IpOptions", 0, Read|Write),
			2: UnknownField("MacAddress", 0, Read),
			3: UnknownField("OnuIdentifier", 0, Read|Write),
			4: Uint32Field("IpAddress", 0, Read|Write),
			5: Uint32Field("Mask", 0, Read|Write),
			6: Uint32Field("Gateway", 0, Read|Write),
			7: Uint32Field("PrimaryDns", 0, Read|Write),
			8: Uint32Field("SecondaryDns", 0, Read|Write),
			9: Uint32Field("CurrentAddress", 0, Read),
			10: Uint32Field("CurrentMask", 0, Read),
			11: Uint32Field("CurrentGateway", 0, Read),
			12: Uint32Field("CurrentPrimaryDns", 0, Read),
			13: Uint32Field("CurrentSecondaryDns", 0, Read),
			14: UnknownField("DomainName", 0, Read),
			15: UnknownField("HostName", 0, Read),
			16: Uint16Field("RelayAgentOptions", 0, Read|Write),
		},
	}
	entity.computeAttributeMask()
	return &IpHostConfigData{entity}, nil
}
