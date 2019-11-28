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

// SipAgentPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity SIP agent performance monitoring history data
const SipAgentPerformanceMonitoringHistoryDataClassID ClassID = ClassID(151)

var sipagentperformancemonitoringhistorydataBME *ManagedEntityDefinition

// SipAgentPerformanceMonitoringHistoryData (class ID #151)
//	This ME collects PM data for the associated VoIP SIP agent. Instances of this ME are created and
//	deleted by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with a SIP agent config data or SIP config portal object.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the corresponding SIP agent config
//			data or to the SIP config portal. If a non-OMCI configuration method is used for VoIP, there can
//			be only one live ME instance, associated with the SIP config portal, and with ME ID 0. (R,
//			setbycreate) (mandatory) (2-bytes)
//
//		Interval End Time
//			Interval end time: This attribute identifies the most recently finished 15-min interval. (R)
//			(mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 ME that
//			contains PM threshold values. Since no threshold value attribute number exceeds 7, a threshold
//			data 2 ME is optional. (R,-W, setbycreate) (mandatory) (2-bytes)
//
//		Transactions
//			Transactions: This attribute counts the number of new transactions that were initiated. (R)
//			(optional) (4-bytes)
//
//		Rx Invite Reqs
//			Rx invite reqs: This attribute counts received invite messages, including retransmissions. (R)
//			(optional) (4-bytes)
//
//		Rx Invite Retrans
//			Rx invite retrans: This attribute counts received invite retransmission messages. (R) (optional)
//			(4-bytes)
//
//		Rx Noninvite Reqs
//			Rx noninvite reqs: This attribute counts received non-invite messages, including
//			retransmissions. (R) (optional) (4-bytes)
//
//		Rx Noninvite Retrans
//			Rx noninvite retrans: This attribute counts received non-invite retransmission messages. (R)
//			(optional) (4-bytes)
//
//		Rx Response
//			Rx response:	This attribute counts total responses received. (R) (optional) (4-bytes)
//
//		Rx Response Retransmissions
//			Rx response retransmissions: This attribute counts total response retransmissions received. (R)
//			(optional) (4-bytes)
//
//		Tx Invite Reqs
//			Tx invite reqs: This attribute counts transmitted invite messages, including retransmissions.
//			(R) (optional) (4-bytes)
//
//		Tx Invite Retrans
//			Tx invite retrans: This attribute counts transmitted invite retransmission messages. (R)
//			(optional) (4-bytes)
//
//		Tx Noninvite Reqs
//			Tx noninvite reqs: This attribute counts transmitted non-invite messages, including
//			retransmissions. (R) (optional) (4-bytes)
//
//		Tx Noninvite Retrans
//			Tx noninvite retrans: This attribute counts transmitted non-invite retransmission messages. (R)
//			(optional) (4-bytes)
//
//		Tx Response
//			Tx response: This attribute counts the total responses sent. (R) (optional) (4-bytes)
//
//		Tx Response Retransmissions
//			Tx response retransmissions: This attribute counts total response retransmissions sent. (R)
//			(optional) (4-bytes)
//
type SipAgentPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	sipagentperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "SipAgentPerformanceMonitoringHistoryData",
		ClassID: 151,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfffe,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("IntervalEndTime", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("ThresholdData12Id", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  Uint32Field("Transactions", 0, mapset.NewSetWith(Read), false, false, true, false, 3),
			4:  Uint32Field("RxInviteReqs", 0, mapset.NewSetWith(Read), false, false, true, false, 4),
			5:  Uint32Field("RxInviteRetrans", 0, mapset.NewSetWith(Read), false, false, true, false, 5),
			6:  Uint32Field("RxNoninviteReqs", 0, mapset.NewSetWith(Read), false, false, true, false, 6),
			7:  Uint32Field("RxNoninviteRetrans", 0, mapset.NewSetWith(Read), false, false, true, false, 7),
			8:  Uint32Field("RxResponse", 0, mapset.NewSetWith(Read), false, false, true, false, 8),
			9:  Uint32Field("RxResponseRetransmissions", 0, mapset.NewSetWith(Read), false, false, true, false, 9),
			10: Uint32Field("TxInviteReqs", 0, mapset.NewSetWith(Read), false, false, true, false, 10),
			11: Uint32Field("TxInviteRetrans", 0, mapset.NewSetWith(Read), false, false, true, false, 11),
			12: Uint32Field("TxNoninviteReqs", 0, mapset.NewSetWith(Read), false, false, true, false, 12),
			13: Uint32Field("TxNoninviteRetrans", 0, mapset.NewSetWith(Read), false, false, true, false, 13),
			14: Uint32Field("TxResponse", 0, mapset.NewSetWith(Read), false, false, true, false, 14),
			15: Uint32Field("TxResponseRetransmissions", 0, mapset.NewSetWith(Read), false, false, true, false, 15),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewSipAgentPerformanceMonitoringHistoryData (class ID 151) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewSipAgentPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*sipagentperformancemonitoringhistorydataBME, params...)
}
