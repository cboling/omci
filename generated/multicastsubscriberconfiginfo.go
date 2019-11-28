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

// MulticastSubscriberConfigInfoClassID is the 16-bit ID for the OMCI
// Managed entity Multicast subscriber config info
const MulticastSubscriberConfigInfoClassID ClassID = ClassID(310)

var multicastsubscriberconfiginfoBME *ManagedEntityDefinition

// MulticastSubscriberConfigInfo (class ID #310)
//	This ME organizes data associated with multicast management at subscriber ports of IEEE-802.1
//	bridges, including IEEE-802.1p mappers when the provisioning model is mapper-based rather than
//	bridge-based. Instances of this ME are created and deleted by the OLT. Because of backward
//	compatibility considerations, a subscriber port without an associated multicast subscriber
//	config info ME would be expected to support unrestricted multicast access; this ME may therefore
//	be viewed as restrictive, rather than permissive.
//
//	Through separate attributes, this ME supports either a single multicast operations profile in
//	its backward compatible form, or a list of multicast operations profiles instead (the list may
//	of course contain a single entry). The OLT can determine whether the ONU supports the multiple
//	profile capability by performing a get operation on the optional multicast service package table
//	attribute, which exists only on ONUs that are prepared to support the feature.
//
//	Relationships
//		An instance of this ME is associated with one instance of the MAC bridge port configuration data
//		or the IEEE-802.1p mapper service profile.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the MAC bridge port configuration
//			data or IEEE-802.1p mapper ME. (R, setbycreate) (mandatory) (2-bytes)
//
//		Me Type
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Multicast Operations Profile Pointer
//			Multicast operations profile pointer: This attribute points to an instance of the multicast
//			operations profile. This attribute is ignored by the ONU if a non-empty multicast service
//			package table attribute is present. (R,W, set-by-create) (mandatory) (2 bytes)
//
//		Max Simultaneous Groups
//			Max simultaneous groups: This attribute specifies the maximum number of dynamic multicast groups
//			that may be replicated to the client port at any one time. The recommended default value 0
//			specifies that no administrative limit is to be imposed. (R,-W, setbycreate) (optional)
//			(2-bytes)
//
//		Max Multicast Bandwidth
//			Max multicast bandwidth: This attribute specifies the maximum imputed dynamic bandwidth, in
//			bytes per second, that may be delivered to the client port at any one time. The recommended
//			default value 0 specifies that no administrative limit is to be imposed. (R,-W, setbycreate)
//			(optional) (4-bytes)
//
//		Bandwidth Enforcement
//			Bandwidth enforcement: The recommended default value of this Boolean attribute is false, and
//			specifies that attempts to exceed the max multicast bandwidth be counted but honoured. The value
//			true specifies that such attempts be counted and denied. The imputed bandwidth value is taken
//			from the dynamic access control list table, both for a new join request and for pre-existing
//			groups. (R,-W, setbycreate) (optional) (1-byte)
//
//		Multicast Service Package Table
//			(R,-W) (optional) (20N bytes, where N is the number of entries in the table)
//
type MulticastSubscriberConfigInfo struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	multicastsubscriberconfiginfoBME = &ManagedEntityDefinition{
		Name:    "MulticastSubscriberConfigInfo",
		ClassID: 310,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
		),
		AllowedAttributeMask: 0xfc00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: ByteField("MeType", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2: Uint16Field("MulticastOperationsProfilePointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3: Uint16Field("MaxSimultaneousGroups", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 3),
			4: Uint32Field("MaxMulticastBandwidth", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 4),
			5: ByteField("BandwidthEnforcement", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 5),
			6: TableField("MulticastServicePackageTable", TableInfo{nil, 22}, mapset.NewSetWith(Read, Write), false, true, false, 6),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewMulticastSubscriberConfigInfo (class ID 310) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewMulticastSubscriberConfigInfo(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*multicastsubscriberconfiginfoBME, params...)
}
