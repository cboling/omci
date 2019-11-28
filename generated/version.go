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

// Package generated provides code-generated OMCI types
package generated

// This file is used to track the version(s) of code used to parse the ITU
// document and create the generated code.

// VersionInfo provides information on the parser/generator version used to create
// the generated data as well as the time of code generation
type VersionInfo struct {
	Name       string  // Type (pre-parser, parser, code-generator)
	Version    string  // Version of parser project
	CreateTime float32 // UTC linux time when ran
	ItuDocName string  // ITU G.988 document name
	SHA256     string  // ITU G.988 document SHA-256 hash
}

// Version provides version information of this generated cooe
var Versions []VersionInfo

func init() {
	Versions = make([]VersionInfo, 0)

	Versions = append(Versions,
		VersionInfo{
			Name:       "parser",
			Version:    "0.12.2",
			CreateTime: 1574975555.5430431,
			ItuDocName: "T-REC-G.988-2017-11.docx",
			SHA256:     "96ffc8bca6f70175c8e281e87e1cf21662d07a7502ebf595c5c3180a9972b9ac",
		})

	Versions = append(Versions,
		VersionInfo{
			Name:       "pre-parser",
			Version:    "0.12.2",
			CreateTime: 1574973863.791287,
			ItuDocName: "T-REC-G.988-2017-11.docx",
			SHA256:     "96ffc8bca6f70175c8e281e87e1cf21662d07a7502ebf595c5c3180a9972b9ac",
		})

	Versions = append(Versions,
		VersionInfo{
			Name:       "code-generator",
			Version:    "0.12.2",
			CreateTime: 1574975972.27073,
			ItuDocName: "T-REC-G.988-2017-11.docx",
			SHA256:     "96ffc8bca6f70175c8e281e87e1cf21662d07a7502ebf595c5c3180a9972b9ac",
		})
}
