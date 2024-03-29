/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

// IpHostPerformanceMonitoringHistoryDataClassID is the 16-bit ID for the OMCI
// Managed entity IP host performance monitoring history data
const IpHostPerformanceMonitoringHistoryDataClassID = ClassID(135) // 0x0087

var iphostperformancemonitoringhistorydataBME *ManagedEntityDefinition

// IpHostPerformanceMonitoringHistoryData (Class ID: #135 / 0x0087)
//	This ME collects PM data related to an IP host. Instances of this ME are created and deleted by
//	the OLT.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME is associated with an instance of the IP host config data or IPv6 host
//		config data ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the IP host configuration data or IPv6 host configuration
//			data ME. (R, set-by-create) (mandatory) (2 bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. (R) (mandatory) (1-byte)
//
//		Threshold Data 1_2 Id
//			Threshold data 1/2 ID: This attribute points to an instance of the threshold data 1 ME that
//			contains PM threshold values. Since no threshold value attribute number exceeds 7, a threshold
//			data 2 ME is optional. (R,-W, set-by-create) (mandatory) (2-bytes)
//
//		Icmp Errors
//			This attribute counts ICMP errors received. (R) (mandatory) (4-bytes)
//
//		Dns Errors
//			This attribute counts DNS errors received. (R) (mandatory) (4-bytes)
//
//		Dhcp Timeouts
//			This attribute counts DHCP timeouts. (R) (optional) (2 bytes)
//
//		Ip Address Conflict
//			This attribute is incremented whenever the ONU detects a conflicting IP address on the network.
//			A conflicting IP address is one that has the same value as the one currently assigned to the
//			ONU. (R) (optional) (2 bytes)
//
//		Out Of Memory
//			This attribute is incremented whenever the ONU encounters an out of memory condition in the IP
//			stack. (R) (optional) (2 bytes)
//
//		Internal Error
//			This attribute is incremented whenever the ONU encounters an internal error condition such as a
//			driver interface failure in the IP stack. (R) (optional) (2-bytes)
//
type IpHostPerformanceMonitoringHistoryData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const IpHostPerformanceMonitoringHistoryData_IntervalEndTime = "IntervalEndTime"
const IpHostPerformanceMonitoringHistoryData_ThresholdData12Id = "ThresholdData12Id"
const IpHostPerformanceMonitoringHistoryData_IcmpErrors = "IcmpErrors"
const IpHostPerformanceMonitoringHistoryData_DnsErrors = "DnsErrors"
const IpHostPerformanceMonitoringHistoryData_DhcpTimeouts = "DhcpTimeouts"
const IpHostPerformanceMonitoringHistoryData_IpAddressConflict = "IpAddressConflict"
const IpHostPerformanceMonitoringHistoryData_OutOfMemory = "OutOfMemory"
const IpHostPerformanceMonitoringHistoryData_InternalError = "InternalError"

func init() {
	iphostperformancemonitoringhistorydataBME = &ManagedEntityDefinition{
		Name:    "IpHostPerformanceMonitoringHistoryData",
		ClassID: IpHostPerformanceMonitoringHistoryDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xff00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField(IpHostPerformanceMonitoringHistoryData_IntervalEndTime, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2: Uint16Field(IpHostPerformanceMonitoringHistoryData_ThresholdData12Id, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field(IpHostPerformanceMonitoringHistoryData_IcmpErrors, CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4: Uint32Field(IpHostPerformanceMonitoringHistoryData_DnsErrors, CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5: Uint16Field(IpHostPerformanceMonitoringHistoryData_DhcpTimeouts, CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, true, false, 5),
			6: Uint16Field(IpHostPerformanceMonitoringHistoryData_IpAddressConflict, CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, true, false, 6),
			7: Uint16Field(IpHostPerformanceMonitoringHistoryData_OutOfMemory, CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, true, false, 7),
			8: Uint16Field(IpHostPerformanceMonitoringHistoryData_InternalError, CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, true, false, 8),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			1: "IPNPM ICMP error",
			2: "IPNPM DNS error",
			3: "DHCP timeout",
			4: "IP address conflict",
			5: "Out of memory",
			6: "Internal error",
		},
	}
}

// NewIpHostPerformanceMonitoringHistoryData (class ID 135) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewIpHostPerformanceMonitoringHistoryData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*iphostperformancemonitoringhistorydataBME, params...)
}
