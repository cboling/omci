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

// MacBridgeConfigurationDataClassID is the 16-bit ID for the OMCI
// Managed entity MAC bridge configuration data
const MacBridgeConfigurationDataClassID ClassID = ClassID(46)

var macbridgeconfigurationdataBME *ManagedEntityDefinition

// MacBridgeConfigurationData (class ID #46)
//	This ME organizes status data associated with a MAC bridge. The ONU automatically creates or
//	deletes an instance of this ME upon the creation or deletion of a MAC bridge service profile.
//
//	Relationships
//		This ME is associated with one instance of a MAC bridge service profile.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the MAC bridge service profile. (R)
//			(mandatory) (2-bytes)
//
//		Bridge Mac Address
//			Bridge MAC address: This attribute indicates the MAC address used by the bridge. The ONU sets
//			this attribute to a value based on criteria beyond the scope of this Recommendation, e.g.,
//			factory settings. (R) (mandatory) (6-bytes)
//
//		Bridge Priority
//			Bridge priority: This attribute reports the priority of the bridge. The ONU copies this
//			attribute from the priority attribute of the associated MAC bridge service profile. The value of
//			this attribute changes with updates to the MAC bridge service profile priority attribute. (R)
//			(mandatory) (2-bytes)
//
//		Designated Root
//			Designated root: This attribute identifies the bridge at the root of the spanning tree. It
//			comprises bridge priority (2-bytes) and MAC address (6-bytes). (R) (mandatory) (8-bytes)
//
//		Root Path Cost
//			Root path cost: This attribute reports the cost of the best path to the root as seen from this
//			bridge. Upon ME instantiation, the ONU sets this attribute to 0. (R) (mandatory) (4-bytes)
//
//		Bridge Port Count
//			Bridge port count: This attribute records the number of ports linked to this bridge. (R)
//			(mandatory) (1-byte)
//
//		Root Port Num
//			Root port num: This attribute contains the port number that has the lowest cost from the bridge
//			to the root bridge. The value 0 means that this bridge is itself the root. Upon ME
//			instantiation, the ONU sets this attribute to 0. (R) (mandatory) (2-bytes)
//
//		Hello Time
//			NOTE - [IEEE 802.1D] specifies the compatibility range for hello time to be 1..2-s.
//
//		Forward Delay
//			Forward delay: This attribute is the forwarding delay time received from the designated root (in
//			256ths of a second). Its range is 0x0400 to 0x1E00 (4..30-s) in accordance with [IEEE 802.1D].
//			(R) (optional) (2-bytes)
//
type MacBridgeConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	macbridgeconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "MacBridgeConfigurationData",
		ClassID: 46,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0xff00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: MultiByteField("BridgeMacAddress", 6, nil, mapset.NewSetWith(Read), false, false, false, false, 1),
			2: Uint16Field("BridgePriority", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3: Uint64Field("DesignatedRoot", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4: Uint32Field("RootPathCost", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5: ByteField("BridgePortCount", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6: Uint16Field("RootPortNum", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7: Uint16Field("HelloTime", 0, mapset.NewSetWith(Read), false, false, true, false, 7),
			8: Uint16Field("ForwardDelay", 0, mapset.NewSetWith(Read), false, false, true, false, 8),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewMacBridgeConfigurationData (class ID 46) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewMacBridgeConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*macbridgeconfigurationdataBME, params...)
}
