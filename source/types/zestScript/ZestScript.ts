/*
 * Zed Attack Proxy (ZAP) and its related source files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
import Browser from 'webextension-polyfill';

interface ZestScriptMessage {
  script: string;
  title: string;
}

class ZestScript {
  private zestStatements: string[] = [];

  private curIndex = 1;

  private title: string;

  constructor(title = '') {
    this.title = title;
  }

  addStatement(statement: string): string {
    const zestStatement = JSON.parse(statement);
    zestStatement.index = this.getNextIndex();
    this.zestStatements.push(JSON.stringify(zestStatement));
    return JSON.stringify(zestStatement);
  }

  getNextIndex(): number {
    this.curIndex += 1;
    return this.curIndex - 1;
  }

  reset(): void {
    this.zestStatements = [];
    this.curIndex = 1;
  }

  getZestStatementCount(): number {
    return this.zestStatements.length;
  }

  getTitle(): string {
    return this.title;
  }

  toJSON(): string {
    return JSON.stringify(
      {
        about:
          'This is a Zest script. For more details about Zest visit https://github.com/zaproxy/zest/',
        zestVersion: '0.3',
        title: this.title,
        description: '',
        prefix: '',
        type: 'StandAlone',
        parameters: {
          tokenStart: '{{',
          tokenEnd: '}}',
          tokens: {},
          elementType: 'ZestVariables',
        },
        statements: this.zestStatements.map((statement) =>
          JSON.parse(statement)
        ),
        authentication: [],
        index: 0,
        enabled: true,
        elementType: 'ZestScript',
      },
      null,
      2
    );
  }

  getZestScript(): Promise<ZestScriptMessage> {
    return new Promise((resolve) => {
      Browser.storage.sync.get({zapscriptname: this.title}).then((items) => {
        this.title = items.zapscriptname as string;
        resolve({script: this.toJSON(), title: this.title});
      });
    });
  }
}

export {ZestScript};
export type {ZestScriptMessage};
