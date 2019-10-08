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

// PhysicalPathTerminationPointVideoUniClassId is the 16-bit ID for the OMCI
// Managed entity Physical path termination point video UNI
const PhysicalPathTerminationPointVideoUniClassId ClassID = ClassID(82)

var physicalpathterminationpointvideouniBME *ManagedEntityDefinition

// PhysicalPathTerminationPointVideoUni (class ID #82)
//	This ME represents an RF video UNI in the ONU, where physical paths terminate and physical path
//	level functions are performed.
//
//	The ONU automatically creates an instance of this ME per port:
//
//	o	when the ONU has RF video UNI ports built into its factory configuration;
//
//	o	when a cardholder is provisioned to expect a circuit pack of the video UNI type;
//
//	o	when a cardholder provisioned for plug-and-play is equipped with a circuit pack of the video
//	UNI type. Note that the installation of a plug-and-play card may indicate the presence of video
//	ports via equipment ID as well as its type, and indeed may cause the ONU to instantiate a port-
//	mapping package that specifies video ports.
//
//	The ONU automatically deletes instances of this ME when a cardholder is neither provisioned to
//	expect a video circuit pack, nor is it equipped with a video circuit pack.
//
//	Relationships
//		One or more instances of this ME are associated with an instance of a real or virtual circuit
//		pack classified as video type.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. This 2-byte
//			number indicates the physical position of the UNI. The first byte is the slot ID (defined in
//			clause 9.1.5). The second byte is the port ID, with the range 1..255. (R) (mandatory) (2-bytes)
//
//		Administrative State
//			Administrative state: This attribute locks (1) and unlocks (0) the functions performed by this
//			ME. Administrative state is further described in clause A.1.6. (R,-W) (mandatory) (1-byte)
//
//		Operational State
//			Operational state: This attribute indicates whether the ME is capable of performing its
//			function. Valid values are enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Arc
//			ARC:	See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			ARC interval: See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Power Control
//			Power control: This attribute controls whether power is provided from the ONU to an external
//			equipment over the video PPTP. Value 1 enables power over coaxial cable. The default value 0
//			disables power feed. (R,-W) (optional) (1-byte)
//
type PhysicalPathTerminationPointVideoUni struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	physicalpathterminationpointvideouniBME = &ManagedEntityDefinition{
		Name:    "PhysicalPathTerminationPointVideoUni",
		ClassID: 82,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0XF800,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: ByteField("AdministrativeState", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 1),
			2: ByteField("OperationalState", 0, mapset.NewSetWith(Read), true, false, true, false, 2),
			3: ByteField("Arc", 0, mapset.NewSetWith(Read, Write), true, false, true, false, 3),
			4: ByteField("ArcInterval", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 4),
			5: ByteField("PowerControl", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 5),
		},
	}
}

// NewPhysicalPathTerminationPointVideoUni (class ID 82 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPhysicalPathTerminationPointVideoUni(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*physicalpathterminationpointvideouniBME, params...)
}
