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
 *              https://github.com/cboling/OMCI-parser
 */
package generated

import (
	"../../omci"
)

type EthernetPerformanceMonitoringHistoryData3 struct {
	omci.BaseManagedEntity
}

func NewEthernetPerformanceMonitoringHistoryData3(params ...ParamData) (IManagedEntity, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntity{
		name:     "EthernetPerformanceMonitoringHistoryData3",
		classID:  296,
		entityID: eid,
		msgTypes: []omci.MsgType{
			omci.Set,
			omci.Get,
			omci.Create,
			omci.Delete,
		},
		attributeList: []omci.IAttribute{
			omci.NewUint16Field("ManagedEntityId", 0, omci.Read|omci.SetByCreate),
			omci.NewByteField("IntervalEndTime", 0, omci.Read),
			omci.NewUint16Field("ThresholdData12Id", 0, omci.Read|omci.Write|omci.SetByCreate),
			omci.NewUint32Field("DropEvents", 0, omci.Read),
			omci.NewUint32Field("Octets", 0, omci.Read),
			omci.NewUint32Field("Packets", 0, omci.Read),
			omci.NewUint32Field("BroadcastPackets", 0, omci.Read),
			omci.NewUint32Field("MulticastPackets", 0, omci.Read),
			omci.NewUint32Field("UndersizePackets", 0, omci.Read),
			omci.NewUint32Field("Fragments", 0, omci.Read),
			omci.NewUint32Field("Jabbers", 0, omci.Read),
			omci.NewUint32Field("Packets64Octets", 0, omci.Read),
			omci.NewUint32Field("Packets65To127Octets", 0, omci.Read),
			omci.NewUint32Field("Packets128To255Octets", 0, omci.Read),
			omci.NewUint32Field("Packets256To511Octets", 0, omci.Read),
			omci.NewUint32Field("Packets512To1023Octets", 0, omci.Read),
			omci.NewUint32Field("Packets1024To1518Octets", 0, omci.Read),
		},
	}
	entity.computeAttributeMask()
	return &EthernetPerformanceMonitoringHistoryData3{entity}, nil
}
