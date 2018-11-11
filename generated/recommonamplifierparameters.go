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

const ReCommonAmplifierParametersClassId uint16 = 328

// ReCommonAmplifierParameters (class ID #328) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type ReCommonAmplifierParameters struct {
	BaseManagedEntityDefinition
}

// NewReCommonAmplifierParameters (class ID 328 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewReCommonAmplifierParameters(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "ReCommonAmplifierParameters",
		ClassID:  328,
		EntityID: eid,
		MessageTypes: []MsgType{
			Set,
			Get,
		},
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read),
			1: ByteField("Gain", 0, Read),
			2: ByteField("LowerGainThreshold", 0, Read|Write),
			3: ByteField("UpperGainThreshold", 0, Read|Write),
			4: ByteField("TargetGain", 0, Read|Write),
			5: Uint16Field("DeviceTemperature", 0, Read),
			6: ByteField("LowerDeviceTemperatureThreshold", 0, Read|Write),
			7: ByteField("UpperDeviceTemperatureThreshold", 0, Read|Write),
			8: ByteField("DeviceBiasCurrent", 0, Read),
			9: Uint16Field("AmplifierSaturationOutputPower", 0, Read),
			10: ByteField("AmplifierNoiseFigure", 0, Read),
			11: ByteField("AmplifierSaturationGain", 0, Read),
		},
	}
	entity.computeAttributeMask()
	return &ReCommonAmplifierParameters{entity}, nil
}
