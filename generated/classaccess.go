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

// ClassAccess specifies whether the ONU, OLT, or both are responsible for creating
// this Managed Entity
type ClassAccess int

const (
	UnknownAccess = iota
	CreatedByOnu
	CreatedByOlt
	CreatedByBoth
)

func (ca ClassAccess) String() string {
	return [...]string{"Unknown", "Created by ONU", "Created by OLT", "Created by both OLT & ONU"}[ca]
}
