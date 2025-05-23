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
import {BrowserContext, chromium} from 'playwright';
import {extensionPath} from '../ContentScript/constants';

class ChromeDriver {
  context: BrowserContext;

  public async getExtensionId(): Promise<string> {
    let [background] = this.context.serviceWorkers();
    if (!background)
      background = await this.context.waitForEvent('serviceworker');
    return background.url().split('/')[2];
  }

  public async configureExtension(JSONPORT: number): Promise<void> {
    const extensionId = await this.getExtensionId();
    const backgroundPage = await this.context.newPage();
    await backgroundPage.goto(`chrome-extension://${extensionId}/options.html`);
    await backgroundPage.fill('#zapurl', `http://localhost:${JSONPORT}/`);
    await backgroundPage.check('#zapenable');
    await backgroundPage.click('#save');
    await backgroundPage.close();
  }

  public async getContext(
    JSONPORT: number,
    startRecording = false
  ): Promise<BrowserContext> {
    if (this.context) return this.context;
    this.context = await chromium.launchPersistentContext('', {
      args: [
        `--headless=new`,
        `--disable-extensions-except=${extensionPath.CHROME}-ext`,
        `--load-extension=${extensionPath.CHROME}-ext`,
      ],
    });
    await this.configureExtension(JSONPORT);
    if (startRecording) {
      await this.toggleRecording();
    }
    return this.context;
  }

  public async setEnable(value: boolean): Promise<void> {
    const page = await this.context.newPage();
    await page.goto(await this.getOptionsURL());
    if (value) {
      await page.check('#zapenable');
    } else {
      await page.uncheck('#zapenable');
    }
    await page.click('#save');
    await page.close();
  }

  public async toggleRecording(): Promise<void> {
    /*
    const page = await this.context.newPage();
    await page.goto(await this.getPopupURL());
    await page.click('#record-btn');
    await page.close();
    */
    Browser.tabs.query({active: true, currentWindow: true}).then((tabs) => {
      const activeTab = tabs[0];
      if (activeTab?.id) {
        // Browser.tabs.sendMessage(activeTab.id, {type: message, data});
        activeTab.page.keyboard.press('CTRL+Shift+KeyZ');
      }
    });
  }

  public async close(): Promise<void> {
    await this.context?.close();
  }

  public async getOptionsURL(): Promise<string> {
    const extensionId = await this.getExtensionId();
    return `chrome-extension://${extensionId}/options.html`;
  }

  public async getPopupURL(): Promise<string> {
    const extensionId = await this.getExtensionId();
    return `chrome-extension://${extensionId}/popup.html`;
  }
}

export {ChromeDriver};
