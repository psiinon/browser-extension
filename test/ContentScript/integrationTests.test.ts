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
import * as http from 'http';
import {HTTPPORT, JSONPORT, BROWSERNAME} from './constants';
import {ChromeDriver} from '../drivers/ChromeDriver';
import {FirefoxDriver} from '../drivers/FirefoxDriver';
import {getFakeZapServer, getStaticHttpServer, closeServer} from './utils';

const TIMEOUT = 2000;

function integrationTests(
  browserName: string,
  _HTTPPORT: number,
  _JSONPORT: number
): void {
  let server: http.Server;
  let httpServer: http.Server;
  const actualData = new Array<string>();
  let driver: ChromeDriver | FirefoxDriver;

  beforeEach(async () => {
    actualData.length = 0;
    if (browserName === BROWSERNAME.FIREFOX) {
      driver = new FirefoxDriver();
    } else {
      driver = new ChromeDriver();
    }
    httpServer = getStaticHttpServer();
    httpServer.listen(_HTTPPORT, () => {
      console.log(`Server listening on port ${_HTTPPORT}`);
    });
  });

  afterEach(async () => {
    await driver?.close();
    await closeServer(server);
    await closeServer(httpServer);
  });

  test('Should load extension into browser', async () => {
    // Given / When
    server = getFakeZapServer(actualData, _JSONPORT, true);
    const context = await driver.getContext(_JSONPORT);
    const page = await context.newPage();
    await page.goto(
      `http://localhost:${_HTTPPORT}/webpages/integrationTest.html`
    );
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(TIMEOUT);
    await page.close();
    // Then
    const expectedData =
      '["{\\"action\\":{\\"action\\":\\"reportEvent\\"},\\"body\\":{\\"eventJson\\":\\"{TIMESTAMP,\\"eventName\\":\\"pageLoad\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"count\\":1}\\",\\"apikey\\":\\"not set\\"}}",' +
      '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"nodeAdded\\",\\"tagName\\":\\"A\\",\\"id\\":\\"\\",\\"nodeName\\":\\"A\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"href\\":\\"http://localhost:1801/webpages/integrationTest.html#test\\",\\"text\\":\\"Link\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
      '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"localStorage\\",\\"tagName\\":\\"\\",\\"id\\":\\"localzapenable\\",\\"nodeName\\":\\"\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"text\\":\\"true\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
      '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"localStorage\\",\\"tagName\\":\\"\\",\\"id\\":\\"localzapurl\\",\\"nodeName\\":\\"\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"text\\":\\"http://localhost:8080/\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
    expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
  });

  // TODO
  if (browserName !== BROWSERNAME.CHROME) {
    test('Should Disable Extension', async () => {
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      expect(JSON.stringify(Array.from(actualData))).toBe('[]');
    });

    test('Should record click', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record send keys', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page;
      await page.fill('#input-1', 'testinput');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinput\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record overwrite existing input text', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page;
      await page.fill('#input-3-filled', 'testinput');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-3-filled\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinput\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-3-filled\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record inserting before existing input text', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page;
      const inputElement = page.locator('#input-3-filled');
      await inputElement.focus();
      // Playwright always appends to the start of a field, apparently due to browser inconsistencies
      await inputElement.type('testinput');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-3-filled\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinputExisting text\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-3-filled\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record overwrite existing input textarea', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page;
      await page.fill('#textarea-1', 'testinput');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"textarea-1\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinput\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"textarea-1\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record inserting before existing input textarea', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page;
      const inputElement = page.locator('#textarea-1');
      await inputElement.focus();
      // Playwright always appends to the start of a field, apparently due to browser inconsistencies
      await inputElement.type('testinput');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"textarea-1\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinputExisting text\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"textarea-1\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record option select', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page;
      await page.locator("//select[@id='cars']").selectOption('audi');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"cars\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"audi\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"cars\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should record return key', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.type('#input-1', 'testinput');
      await page.keyboard.press('Enter');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinput\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSubmit\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should stop recording', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      await driver.toggleRecording();
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.fill('#input-1', 'testinput');
      await page.click('#click');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      expect(JSON.stringify(Array.from(actualData))).toBe('[]');
    });

    test('Should download the script', async () => {
      // Given
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(await driver.getPopupURL());
      await page.fill('#script-name-input', 'recordedScript');
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.click('#click');
      await page.goto(await driver.getPopupURL());
      let actualOutcome = '';
      page.on('download', async (download) => {
        actualOutcome = download.suggestedFilename();
        await download.delete();
      });
      // When
      await page.click('#save-script');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      expect(actualOutcome).toBe('recordedScript.zst');
    });

    test('Should send window handle close script when enabled', async () => {
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(await driver.getOptionsURL());
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.fill('#input-1', 'testinput');
      await page.click('#click');
      await page.goto(await driver.getPopupURL());
      await page.click('#record-btn');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinput\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"index\\":5,\\"sleepInSeconds\\":0,\\"enabled\\":true,\\"elementType\\":\\"ZestClientWindowClose\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(Array.from(actualData).length).toBe(5);
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should send window handle close script when directly pressed save script', async () => {
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(await driver.getOptionsURL());
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.fill('#input-1', 'testinput');
      await page.click('#click');
      await page.goto(await driver.getPopupURL());
      await page.click('#save-script');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":1,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"value\\":\\"testinput\\",\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"input-1\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementSendKeys\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"click\\",\\"index\\":4,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"index\\":5,\\"sleepInSeconds\\":0,\\"enabled\\":true,\\"elementType\\":\\"ZestClientWindowClose\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(Array.from(actualData).length).toBe(5);
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });

    test('Should configure downloaded script name', async () => {
      // Given
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.click('#click');
      await page.goto(await driver.getPopupURL());
      await page.fill('#script-name-input', 'test-name');
      let actualOutcome = '';
      page.on('download', async (download) => {
        actualOutcome = download.suggestedFilename();
        await download.delete();
      });
      // When
      await page.click('#save-script');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      expect(actualOutcome).toBe('test-name.zst');
    });

    test('Should record frame switches', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      const frame = await page.frame('frame1');
      frame?.click('#test-btn');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      expect(JSON.stringify(Array.from(actualData))).toBe(
        '["{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"frameIndex\\":0,\\"frameName\\":\\"\\",\\"parent\\":false,\\"index\\":1,\\"enabled\\":true,\\"elementType\\":\\"ZestClientSwitchToFrame\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
          '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"test-btn\\",\\"index\\":2,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementScrollTo\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
          '"{\\"action\\":{\\"action\\":\\"reportZestStatement\\"},\\"body\\":{\\"statementJson\\":\\"{\\"windowHandle\\":\\"windowHandle1\\",\\"type\\":\\"id\\",\\"element\\":\\"test-btn\\",\\"index\\":3,\\"waitForMsec\\":5000,\\"enabled\\":true,\\"elementType\\":\\"ZestClientElementClick\\"}\\",\\"apikey\\":\\"not set\\"}}"]'
      );
    });

    test('Should not record interactions on floating container', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT, true);
      await driver.setEnable(false);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/interactions.html`
      );
      await page.click('#ZapfloatingDiv');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      expect(JSON.stringify(Array.from(actualData))).toBe('[]');
    });

    test('Should record set localStorage', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT, true);
      const context = await driver.getContext(_JSONPORT);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/localStorage.html`
      );
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"localStorage\\",\\"tagName\\":\\"\\",\\"id\\":\\"test\\",\\"nodeName\\":\\"\\",\\"url\\":\\"http://localhost:1801/webpages/localStorage.html\\",\\"text\\":\\"localData\\"}\\",\\"apikey\\":\\"not set\\"}}"';
      expect(JSON.stringify(Array.from(actualData))).toContain(expectedData);
    });

    test('Should record set sessionStorage', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/sessionStorage.html`
      );
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"sessionStorage\\",\\"tagName\\":\\"\\",\\"id\\":\\"test\\",\\"nodeName\\":\\"\\",\\"url\\":\\"http://localhost:1801/webpages/sessionStorage.html\\",\\"text\\":\\"sessionData\\"}\\",\\"apikey\\":\\"not set\\"}}"';
      expect(JSON.stringify(Array.from(actualData))).toContain(expectedData);
    });

    test('Should record set localStorage with page open', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT, true);
      const context = await driver.getContext(_JSONPORT);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/localStorageDelay.html`
      );
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      // Then
      const expectedData =
        '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"localStorage\\",\\"tagName\\":\\"\\",\\"id\\":\\"test\\",\\"nodeName\\":\\"\\",\\"url\\":\\"http://localhost:1801/webpages/localStorageDelay.html\\",\\"text\\":\\"localData\\"}\\",\\"apikey\\":\\"not set\\"}}"';
      expect(JSON.stringify(Array.from(actualData))).toContain(expectedData);
      // Tidy up
      await page.close();
    });

    test('Should record set sessionStorage with page open', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/sessionStorageDelay.html`
      );
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(TIMEOUT);
      // Then
      const expectedData =
        '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"sessionStorage\\",\\"tagName\\":\\"\\",\\"id\\":\\"test\\",\\"nodeName\\":\\"\\",\\"url\\":\\"http://localhost:1801/webpages/sessionStorageDelay.html\\",\\"text\\":\\"sessionData\\"}\\",\\"apikey\\":\\"not set\\"}}"';
      expect(JSON.stringify(Array.from(actualData))).toContain(expectedData);
      // Tidy up
      await page.close();
    });

    test('Should record dup added link once ', async () => {
      // Given / When
      server = getFakeZapServer(actualData, _JSONPORT);
      const context = await driver.getContext(_JSONPORT);
      const page = await context.newPage();
      await page.goto(
        `http://localhost:${_HTTPPORT}/webpages/integrationTest.html`
      );
      await page.waitForLoadState('networkidle');

      await page.evaluate(() => {
        // eslint-disable-next-line func-names
        const addLink = function (): void {
          const aTag = document.createElement('a');
          aTag.innerHTML = 'Test link';
          aTag.href = 'https://www.example.com';
          aTag.title = 'Test link';
          document.body.appendChild(aTag);
        };
        addLink();
        addLink();
      });
      await page.waitForTimeout(TIMEOUT);
      await page.close();
      // Then
      const expectedData =
        '["{\\"action\\":{\\"action\\":\\"reportEvent\\"},\\"body\\":{\\"eventJson\\":\\"{TIMESTAMP,\\"eventName\\":\\"pageLoad\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"count\\":1}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"nodeAdded\\",\\"tagName\\":\\"A\\",\\"id\\":\\"\\",\\"nodeName\\":\\"A\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"href\\":\\"http://localhost:1801/webpages/integrationTest.html#test\\",\\"text\\":\\"Link\\"}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportEvent\\"},\\"body\\":{\\"eventJson\\":\\"{TIMESTAMP,\\"eventName\\":\\"domMutation\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"count\\":1}\\",\\"apikey\\":\\"not set\\"}}",' +
        '"{\\"action\\":{\\"action\\":\\"reportObject\\"},\\"body\\":{\\"objectJson\\":\\"{TIMESTAMP,\\"type\\":\\"nodeAdded\\",\\"tagName\\":\\"A\\",\\"id\\":\\"\\",\\"nodeName\\":\\"A\\",\\"url\\":\\"http://localhost:1801/webpages/integrationTest.html\\",\\"href\\":\\"https://www.example.com/\\",\\"text\\":\\"Test link\\"}\\",\\"apikey\\":\\"not set\\"}}"]';
      expect(JSON.stringify(Array.from(actualData))).toBe(expectedData);
    });
  }
}

describe('Chrome Integration Test', () => {
  integrationTests(BROWSERNAME.CHROME, HTTPPORT, JSONPORT);
});

/* Using Playwright to test Firefox extensions is proving _very_ problematic
describe('Firefox Integration Test', () => {
  integrationTests(BROWSERNAME.FIREFOX, HTTPPORT, JSONPORT);
});
*/
