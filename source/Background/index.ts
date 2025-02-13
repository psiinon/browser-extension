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
import 'emoji-log';
import Browser, {Cookies, Runtime} from 'webextension-polyfill';
import {ReportedStorage} from '../types/ReportedModel';
import {ZestScript, ZestScriptMessage} from '../types/zestScript/ZestScript';
import {ZestStatementWindowClose} from '../types/zestScript/ZestStatement';
import {
  LOCAL_STORAGE,
  REPORT_EVENT,
  REPORT_OBJECT,
  RESET_ZEST_SCRIPT,
  SAVE_ZEST_SCRIPT,
  SESSION_STORAGE,
  SET_SAVE_SCRIPT_ENABLE,
  STOP_RECORDING,
  ZEST_SCRIPT,
} from '../utils/constants';

console.log('ZAP Service Worker 👋');

/*
  We check the storage on every page, so need to record which storage events we have reported to ZAP here so that we dont keep sending the same events.
*/
const reportedStorage = new Set<string>();
const zestScript = new ZestScript();
/*
  A callback URL will only be available if the browser has been launched from ZAP, otherwise call the individual endpoints
*/

function zapApiUrl(zapurl: string, action: string): string {
  if (zapurl.indexOf('/zapCallBackUrl/') > 0) {
    return zapurl;
  }
  return `${zapurl}JSON/client/action/${action}/`;
}

function getUrlFromCookieDomain(domain: string): string {
  return domain.startsWith('.')
    ? `http://${domain.substring(1)}`
    : `http://${domain}`;
}

function getCookieTabUrl(cookie: Cookies.Cookie): Promise<string> {
  const getAllTabs = Browser.tabs.query({
    currentWindow: true,
  });
  return new Promise((resolve, reject) => {
    getAllTabs
      .then((allTabs) => {
        for (const tab of allTabs) {
          if (tab.url) {
            const getAllCookiesForTab = Browser.cookies.getAll({url: tab.url});
            getAllCookiesForTab.then((cookies) => {
              for (const c of cookies) {
                if (
                  c.name === cookie.name &&
                  c.value === cookie.value &&
                  c.domain === cookie.domain &&
                  c.storeId === cookie.storeId
                ) {
                  resolve(
                    tab.url ? tab.url : getUrlFromCookieDomain(cookie.domain)
                  );
                }
              }
            });
          }
        }
      })
      .catch((error) => {
        console.error(`Could not fetch tabs: ${error.message}`);
        reject(getUrlFromCookieDomain(cookie.domain));
      });
  });
}

function reportCookies(
  cookie: Cookies.Cookie,
  zapurl: string,
  zapkey: string
): boolean {
  let cookieString = `${cookie.name}=${cookie.value}; path=${cookie.path}; domain=${cookie.domain}`;
  if (cookie.expirationDate) {
    cookieString = cookieString.concat(
      `; expires=${new Date(cookie.expirationDate * 1000).toUTCString()}`
    );
  }
  if (cookie.secure) {
    cookieString = cookieString.concat(`; secure`);
  }
  if (cookie.sameSite === 'lax' || cookie.sameSite === 'strict') {
    cookieString = cookieString.concat(`; SameSite=${cookie.sameSite}`);
  }
  if (cookie.httpOnly) {
    cookieString = cookieString.concat(`; HttpOnly`);
  }

  getCookieTabUrl(cookie)
    .then((cookieUrl) => {
      const repStorage = new ReportedStorage(
        'Cookies',
        '',
        cookie.name,
        '',
        cookieString,
        cookieUrl
      );
      const repStorStr: string = repStorage.toShortString();
      if (
        !reportedStorage.has(repStorStr) &&
        repStorage.url.startsWith('http')
      ) {
        const body = `objectJson=${encodeURIComponent(
          repStorage.toString()
        )}&apikey=${encodeURIComponent(zapkey)}`;

        fetch(zapApiUrl(zapurl, REPORT_OBJECT), {
          method: 'POST',
          body,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        });

        reportedStorage.add(repStorStr);
      }
    })
    .catch((error) => {
      console.log(error);
      return false;
    });

  return true;
}

function sendZestScriptToZAP(
  data: string,
  zapkey: string,
  zapurl: string
): void {
  const body = `statementJson=${encodeURIComponent(
    data
  )}&apikey=${encodeURIComponent(zapkey)}`;
  console.log(`body = ${body}`);
  fetch(zapApiUrl(zapurl, 'reportZestStatement'), {
    method: 'POST',
    body,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
}

async function handleMessage(
  request: MessageEvent,
  zapurl: string,
  zapkey: string
): Promise<boolean | ZestScriptMessage> {
  console.log(`ZAP Service worker calling ZAP on ${zapurl}`);
  console.log(zapApiUrl(zapurl, REPORT_OBJECT));
  console.log(encodeURIComponent(zapkey));
  console.log(`Type: ${request.type}`);
  console.log(`Data: ${request.data}`);
  switch (request.type) {
    case REPORT_OBJECT: {
      const repObj = JSON.parse(request.data);
      if (repObj.type === LOCAL_STORAGE || repObj.type === SESSION_STORAGE) {
        const repStorage = new ReportedStorage('', '', '', '', '', '');
        Object.assign(repStorage, repObj);
        const repStorStr = repStorage.toShortString();
        if (reportedStorage.has(repStorStr)) {
          return true;
        }
        reportedStorage.add(repStorStr);
      }
      const repObjBody = `objectJson=${encodeURIComponent(
        request.data
      )}&apikey=${encodeURIComponent(zapkey)}`;
      console.log(`body = ${repObjBody}`);
      fetch(zapApiUrl(zapurl, REPORT_OBJECT), {
        method: 'POST',
        body: repObjBody,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });
      break;
    }

    case REPORT_EVENT: {
      const eventBody = `eventJson=${encodeURIComponent(
        request.data
      )}&apikey=${encodeURIComponent(zapkey)}`;
      console.log(`body = ${eventBody}`);
      fetch(zapApiUrl(zapurl, REPORT_EVENT), {
        method: 'POST',
        body: eventBody,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });
      break;
    }

    case ZEST_SCRIPT: {
      const data = zestScript.addStatement(request.data);
      sendZestScriptToZAP(data, zapkey, zapurl);
      break;
    }

    case SAVE_ZEST_SCRIPT:
      return zestScript.getZestScript();

    case RESET_ZEST_SCRIPT:
      zestScript.reset();
      break;

    case STOP_RECORDING: {
      if (zestScript.getZestStatementCount() > 0) {
        const {zapclosewindowhandle} = await Browser.storage.sync.get({
          zapclosewindowhandle: false,
        });
        if (zapclosewindowhandle) {
          const stmt = new ZestStatementWindowClose(0);
          const data = zestScript.addStatement(stmt.toJSON());
          sendZestScriptToZAP(data, zapkey, zapurl);
        }
      }
      break;
    }

    case SET_SAVE_SCRIPT_ENABLE:
      Browser.storage.sync.set({
        zapenablesavescript: zestScript.getZestStatementCount() > 0,
      });
      break;

    default:
      // Handle unknown request type
      break;
  }

  return true;
}

async function onMessageHandler(
  message: unknown,
  _sender: Runtime.MessageSender
): Promise<number | ZestScriptMessage> {
  let val: number | ZestScriptMessage = 2;
  const items = await Browser.storage.sync.get({
    zapurl: 'http://zap/',
    zapkey: 'not set',
  });
  const msg = await handleMessage(
    message as MessageEvent,
    items.zapurl as string,
    items.zapkey as string
  );
  if (!(typeof msg === 'boolean')) {
    val = msg;
  }
  return Promise.resolve(val);
}

function cookieChangeHandler(
  changeInfo: Cookies.OnChangedChangeInfoType
): void {
  Browser.storage.sync
    .get({
      zapurl: 'http://zap/',
      zapkey: 'not set',
    })
    .then((items) => {
      reportCookies(
        changeInfo.cookie,
        items.zapurl as string,
        items.zapkey as string
      );
    });
}

Browser.action.onClicked.addListener((_tab: Browser.Tabs.Tab) => {
  Browser.runtime.openOptionsPage();
});

Browser.cookies.onChanged.addListener(cookieChangeHandler);
Browser.runtime.onMessage.addListener(onMessageHandler);

Browser.runtime.onInstalled.addListener((): void => {
  console.emoji('🦄', 'extension installed');
  Browser.storage.sync.set({
    zapurl: 'http://zap/',
    zapkey: 'not set',
  });
});

export {reportCookies};
