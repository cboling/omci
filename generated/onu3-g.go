/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
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

// Onu3GClassID is the 16-bit ID for the OMCI
// Managed entity ONU3-G
const Onu3GClassID = ClassID(441) // 0x01b9

var onu3gBME *ManagedEntityDefinition

// Onu3G (Class ID: #441 / 0x01b9)
//	This ME contains additional attributes and alarms associated with a PON ONU. The ONU
//	automatically creates an instance of this ME. Its attributes are populated according to data
//	within the ONU itself.
//
//	Upon instantiation of this ME, the Total number of status snapshots S, the Number of valid
//	status snapshots M, and Next status snapshot index K are populated from the non-volatile memory.
//	If the non-volatile memory values are not available (e.g., at the initialization of an off-the-
//	shelf ONU), the Total number of status snapshots attribute is set to the maximum size of the
//	status snapshot record table the ONU can maintain, which is a static capability parameter, while
//	both the Number of valid status snapshots and the Next status snapshot index attributes are set
//	to zero.
//
//	The Status snapshot record table is implemented as a circular buffer containing up to S records
//	of size N. The size and format of the snapshot record are vendor-specific. Each time the ONU
//	takes and stores a status snapshot, it increments the Number of valid status snapshots M,
//	saturating at S, and increments Next status snapshot index K in modulo S:
//
//	K := (K-+ 1)mod S.
//
//	By writing into the Snap action attribute, the OLT instructs the ONU to immediately take a
//	status snapshot and to store it in the Status snapshot table. By writing into Reset action
//	attribute, the OLT instructs the ONU to erase the Status snapshot record table. The OLT uses the
//	AVC indication of the Next status snapshot index and Number of valid status snapshots attributes
//	to confirm that its instructions have been executed by the ONU. If the OLT has issued no Snap
//	action instructions, a change in the value of Next status snapshot index attributes between two
//	consecutive reads indicates that a condition has arisen that has caused the ONU to record a
//	status snapshot.
//
//	Two table attributes, the Status snapshot record table, and the Most recent status snapshot,
//	provide the OLT access to the status snapshot records. The former allows the entire Status
//	snapshot record table to be retrieved, the latter provides quick access to the latest snapshot
//	record.
//
//	By performing the Get operation on the Most recent status snapshot, the OLT can obtain the
//	vendor-specific size of an individual snapshot record. The OLT is expected to pass the status
//	snapshot records transparently, without parsing or interpreting them.
//
//	Relationships
//		This ME is associated with the ONU-G ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. There is only one instance, number
//			0. (R) (mandatory) (2-bytes)
//
//		Flash Memory Performance Value
//			A number in the range from 0 to 100 that characterizes the condition of the flash memory, with 0
//			representing factory fresh device, 100 representing end of life. This attribute is vendor-
//			specific and should be calculated at the discretion of the vendor. (R) (optional) (1-byte)
//
//		Latest Restart Reason
//			The following code points are defined:
//
//		Total Number Of Status Snapshots
//			The maximum size S of the status snapshot record table. (R) (mandatory) (2-bytes)
//
//		Number Of Valid Status Snapshots
//			The number M of valid status snapshot records. (R) (mandatory) (2-bytes)
//
//		Next Status Snapshot Index
//			This attribute identifies the index (ranging from 0 to S-- 1) of the next snapshot record to be
//			taken in the snapshot record table. (R,) (mandatory) (2-bytes)
//
//		Status Snapshot Record Table
//			The table of M status snapshot records. The size N and format of the snapshot record is vendor
//			dependent. (R) (mandatory) (MxN-bytes)
//
//		Snap Action
//			Once the OLT writes this attribute, the ONU takes and records an urgent snapshot without
//			shutting down the transceiver. (W) (mandatory) (1-byte)
//
//		Most Recent Status Snapshot
//			This attribute provides access to the most recently taken status snapshot record. (R)
//			(mandatory) (N-bytes)
//
//		Reset Action
//			Once the OLT writes this attribute, the ONU sets the Number of valid status snapshots and Next
//			status snapshot index attributes to zero. (W) (mandatory) (1-byte)
//
//		Enhanced Mode
//			The Boolean value true specifies the Enhanced received frame classification and processing table
//			is supported by the Extended VLAN tagging operation configuration ME. The value false indicates
//			the Enhanced received frame classification and processing table is not supported. (R) (optional)
//			(1-byte)
//
type Onu3G struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	onu3gBME = &ManagedEntityDefinition{
		Name:    "Onu3G",
		ClassID: 441,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0xffc0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField("FlashMemoryPerformanceValue", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), true, true, false, 1),
			2:  ByteField("LatestRestartReason", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), false, false, false, 2),
			3:  Uint16Field("TotalNumberOfStatusSnapshots", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read), true, false, false, 3),
			4:  Uint16Field("NumberOfValidStatusSnapshots", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint16Field("NextStatusSnapshotIndex", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  MultiByteField("StatusSnapshotRecordTable", OctetsAttributeType, 0x0400, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 6),
			7:  ByteField("SnapAction", UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Write), false, false, false, 7),
			8:  MultiByteField("MostRecentStatusSnapshot", OctetsAttributeType, 0x0100, 25, toOctets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 8),
			9:  ByteField("ResetAction", UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Write), false, false, false, 9),
			10: ByteField("EnhancedMode", UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, true, false, 10),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			0: "Flash memory performance yellow",
			1: "Flash memory performance red",
			2: "Loss of redundant power supply",
			3: "Loss of redundant power feed",
			4: "Ground Fault",
		},
	}
}

// NewOnu3G (class ID 441) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewOnu3G(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*onu3gBME, params...)
}