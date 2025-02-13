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
import {ZAP_ENABLE, ZAP_KEY, ZAP_URL} from '../utils/constants';

console.log('Options loading');

// Saves options to chrome.storage
function saveOptions(): void {
  console.log('Options save_options');
  const zapurl = (document.getElementById(ZAP_URL) as HTMLInputElement).value;
  const zapkey = (document.getElementById(ZAP_KEY) as HTMLInputElement).value;
  const zapenable = (document.getElementById(ZAP_ENABLE) as HTMLInputElement)
    .checked;
  const zapclosewindowhandle = (
    document.getElementById('window-close-input') as HTMLInputElement
  ).checked;
  Browser.storage.sync.set({
    zapurl,
    zapkey,
    zapenable,
    zapclosewindowhandle,
  });
}

// Restores options from chrome.storage.
function restoreOptions(): void {
  console.log('Options restore_options');

  Browser.storage.sync
    .get({
      zapurl: 'http://zap/',
      zapkey: 'not set',
      zapenable: false,
      zaprecordingactive: false,
      zapclosewindowhandle: true,
    })
    .then((items) => {
      (document.getElementById(ZAP_URL) as HTMLInputElement).value =
        items.zapurl as string;
      (document.getElementById(ZAP_KEY) as HTMLInputElement).value =
        items.zapkey as string;
      (document.getElementById(ZAP_ENABLE) as HTMLInputElement).checked =
        items.zapenable as boolean;
      (
        document.getElementById('window-close-input') as HTMLInputElement
      ).checked = items.zapclosewindowhandle as boolean;
    });
}
document.addEventListener('DOMContentLoaded', restoreOptions);
document.getElementById('save')?.addEventListener('click', saveOptions);

export {saveOptions};
