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

// GemInterworkingTerminationPointClassId is the 16-bit ID for the OMCI
// Managed entity GEM interworking termination point
const GemInterworkingTerminationPointClassId ClassID = ClassID(266)

var geminterworkingterminationpointBME *ManagedEntityDefinition

// GemInterworkingTerminationPoint (class ID #266)
//	An instance of this ME represents a point in the ONU where the IW of a bearer service (usually
//	Ethernet) to the GEM layer takes place. At this point, GEM packets are generated from the bearer
//	bit stream (e.g., Ethernet) or the bearer bit stream is reconstructed from GEM packets.
//
//	Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		One instance of this ME exists for each transformation of a data stream into GEM frames and vice
//		versa.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. (R, setbycreate)
//			(mandatory) (2-bytes)
//
//		Gem Port Network Ctp Connectivity Pointer
//			GEM port network CTP connectivity pointer: This attribute points to an instance of the GEM port
//			network CTP. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Interworking Option
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Service Profile Pointer
//			NOTE - The video return path (VRP) service profile is defined in [ITU-T G.984.4].
//
//		Interworking Termination Point Pointer
//			In all other GEM services, the relationship between the related service TP and this GEM IW TP is
//			derived from other ME relations; this attribute is set to a null pointer and not used. (R,-W,
//			setbycreate) (mandatory) (2-bytes)
//
//		Pptp Counter
//			PPTP counter: This value reports the number of PPTP ME instances associated with this GEM IW TP.
//			(R) (optional) (1-byte)
//
//		Operational State
//			Operational state: This attribute indicates whether the ME is capable of performing its
//			function. Valid values are enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Gal Profile Pointer
//			(R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Gal Loopback Configuration
//			The default value of this attribute is 0. When the IW option is 6 (downstream broadcast), this
//			attribute is not used. (R,-W) (mandatory) (1-byte)
//
type GemInterworkingTerminationPoint struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	geminterworkingterminationpointBME = &ManagedEntityDefinition{
		Name:    "GemInterworkingTerminationPoint",
		ClassID: 266,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFF00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: Uint16Field("GemPortNetworkCtpConnectivityPointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2: ByteField("InterworkingOption", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3: Uint16Field("ServiceProfilePointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 3),
			4: Uint16Field("InterworkingTerminationPointPointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 4),
			5: ByteField("PptpCounter", 0, mapset.NewSetWith(Read), false, false, true, false, 5),
			6: ByteField("OperationalState", 0, mapset.NewSetWith(Read), true, false, true, false, 6),
			7: Uint16Field("GalProfilePointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 7),
			8: ByteField("GalLoopbackConfiguration", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 8),
		},
	}
}

// NewGemInterworkingTerminationPoint (class ID 266 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewGemInterworkingTerminationPoint(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*geminterworkingterminationpointBME, params...)
}
