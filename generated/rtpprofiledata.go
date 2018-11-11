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

const RtpProfileDataClassId uint16 = 143

// RtpProfileData (class ID #143) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type RtpProfileData struct {
	BaseManagedEntityDefinition
}

// NewRtpProfileData (class ID 143 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewRtpProfileData(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "RtpProfileData",
		ClassID:  143,
		EntityID: eid,
		MessageTypes: []MsgType{
			Set,
			Get,
			Create,
			Delete,
		},
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read|SetByCreate),
			1: Uint16Field("LocalPortMin", 0, Read|Write|SetByCreate),
			2: Uint16Field("LocalPortMax", 0, Read|Write|SetByCreate),
			3: ByteField("DscpMark", 0, Read|Write|SetByCreate),
			4: ByteField("PiggybackEvents", 0, Read|Write|SetByCreate),
			5: ByteField("ToneEvents", 0, Read|Write|SetByCreate),
			6: ByteField("DtmfEvents", 0, Read|Write|SetByCreate),
			7: ByteField("CasEvents", 0, Read|Write|SetByCreate),
			8: Uint16Field("IpHostConfigPointer", 0, Read|Write),
		},
	}
	entity.computeAttributeMask()
	return &RtpProfileData{entity}, nil
}
