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

// TcpUdpPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity TCP/UDP performance monitoring history data
const TcpUdpPerformanceMonitoringHistoryDataClassID ClassID = ClassID(342)

var tcpudpperformancemonitoringhistorydataBME *ManagedEntityDefinition

// TcpUdpPerformanceMonitoringHistoryData (class ID #342)
//	This ME collects PM data related to a TCP or UDP port. Instances of this ME are created and
//	deleted by the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of the TCP/UDP config data ME.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the TCP/UDP config data ME. (R,
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
//		Socket Failed
//			Socket failed:	This attribute is incremented when an attempt to create a socket associated with
//			a port fails. (R) (mandatory) (2-bytes)
//
//		Listen Failed
//			Listen failed:	This attribute is incremented when an attempt by a service to listen for a
//			request on a port fails. (R) (mandatory) (2-bytes)
//
//		Bind Failed
//			Bind failed:	This attribute is incremented when an attempt by a service to bind to a port fails.
//			(R) (mandatory) (2-bytes)
//
//		Accept Failed
//			Accept failed: This attribute is incremented when an attempt to accept a connection on a port
//			fails. (R) (mandatory) (2-bytes)
//
//		Select Failed
//			Select failed:	This attribute is incremented when an attempt to perform a select on a group of
//			ports fails. (R) (mandatory) (2-bytes)
//
type TcpUdpPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	tcpudpperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "TcpUdpPerformanceMonitoringHistoryData",
		ClassID: 342,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xfe00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field("ThresholdData12Id", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint16Field("SocketFailed", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4: Uint16Field("ListenFailed", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5: Uint16Field("BindFailed", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6: Uint16Field("AcceptFailed", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7: Uint16Field("SelectFailed", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			1: "Socket failed",
			2: "Listen failed",
			3: "Bind failed",
			4: "Accept failed",
			5: "Select failed",
		},
	}
}

// NewTcpUdpPerformanceMonitoringHistoryData (class ID 342) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTcpUdpPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*tcpudpperformancemonitoringhistorydataBME, params...)
}
