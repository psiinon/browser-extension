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
import './styles.scss';
import i18n from './i18n';
import {
  RESET_ZEST_SCRIPT,
  SAVE_ZEST_SCRIPT,
  SET_SAVE_SCRIPT_ENABLE,
  STOP_RECORDING,
  UPDATE_TITLE,
  ZAP_START_RECORDING,
  ZAP_STOP_RECORDING,
} from '../utils/constants';
import {ZestScriptMessage} from '../types/zestScript/ZestScript';

const STOP = i18n.t('stop');
const START = i18n.t('start');
const OPTIONS = i18n.t('options');
const DOWNLOAD = i18n.t('download');

const play = document.querySelector('.play');
const pause = document.querySelector('.pause');
const wave1 = document.querySelector('.record__back-1');
const wave2 = document.querySelector('.record__back-2');
const done = document.querySelector('.done');
const optionsIcon = document.querySelector('.settings') as HTMLImageElement;
const downloadIcon = document.querySelector('.download') as HTMLImageElement;

const recordButton = document.getElementById('record-btn');
const configureButton = document.getElementById('configure-btn');
const saveScript = document.getElementById('save-script');
const scriptNameInput = document.getElementById(
  'script-name-input'
) as HTMLInputElement;
const saveScriptButton = document.getElementById(
  'save-script'
) as HTMLButtonElement;

function sendMessageToContentScript(message: string, data = ''): void {
  Browser.tabs.query({active: true, currentWindow: true}).then((tabs) => {
    const activeTab = tabs[0];
    if (activeTab?.id) {
      Browser.tabs.sendMessage(activeTab.id, {type: message, data});
    }
  });
}

function stoppedAnimation(): void {
  pause?.classList.add('visibility');
  play?.classList.add('visibility');
  recordButton?.classList.add('shadow');
  wave1?.classList.add('paused');
  wave2?.classList.add('paused');
  (play as HTMLImageElement).title = START;
}

function startedAnimation(): void {
  pause?.classList.remove('visibility');
  play?.classList.remove('visibility');
  recordButton?.classList.remove('shadow');
  wave1?.classList.remove('paused');
  wave2?.classList.remove('paused');
  (play as HTMLImageElement).title = STOP;
}

async function restoreState(): Promise<void> {
  console.log('Restore state');
  await Browser.runtime.sendMessage({type: SET_SAVE_SCRIPT_ENABLE});
  optionsIcon.title = OPTIONS;
  downloadIcon.title = DOWNLOAD;
  Browser.storage.sync
    .get({
      zaprecordingactive: false,
      zapscriptname: '',
      zapenablesavescript: false,
    })
    .then((items) => {
      if (items.zaprecordingactive) {
        startedAnimation();
      } else {
        stoppedAnimation();
      }
      scriptNameInput.value = items.zapscriptname as string;
      if (items.zapclosewindowhandle) {
        done?.classList.remove('invisible');
      } else {
        done?.classList.add('invisible');
      }
      if (!items.zapenablesavescript) {
        saveScriptButton.classList.add('disabled');
      } else {
        saveScriptButton.classList.remove('disabled');
      }
    });
}

function closePopup(): void {
  setTimeout(() => {
    window.close();
  }, 500);
}

function stopRecording(): void {
  console.log('Recording stopped ...');
  stoppedAnimation();
  sendMessageToContentScript(ZAP_STOP_RECORDING);
  Browser.runtime.sendMessage({type: STOP_RECORDING});
  Browser.storage.sync.set({
    zaprecordingactive: false,
  });
}

function startRecording(): void {
  startedAnimation();
  sendMessageToContentScript(ZAP_START_RECORDING);
  Browser.runtime.sendMessage({type: RESET_ZEST_SCRIPT});
  Browser.storage.sync.set({
    zaprecordingactive: true,
  });
}

function toggleRecording(e: Event): void {
  e.preventDefault();
  Browser.storage.sync.get({zaprecordingactive: false}).then((items) => {
    if (items.zaprecordingactive) {
      stopRecording();
      console.log('active');
    } else {
      startRecording();
      closePopup();
    }
  });
}

function openOptionsPage(): void {
  Browser.tabs.create({url: 'options.html'}).then((tab) => {
    Browser.tabs.update(tab.id, {active: true});
  });
  closePopup();
}

function downloadZestScript(zestScriptJSON: string, title: string): void {
  if (title === '') {
    scriptNameInput?.focus();
    return;
  }
  const blob = new Blob([zestScriptJSON], {type: 'application/json'});
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = title + (title.slice(-4) === '.zst' ? '' : '.zst');
  link.style.display = 'none';

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  URL.revokeObjectURL(url);
  Browser.runtime.sendMessage({type: RESET_ZEST_SCRIPT});
  Browser.storage.sync.set({
    zaprecordingactive: false,
  });
  closePopup();
}

async function handleSaveScript(): Promise<void> {
  const storageItems = await Browser.storage.sync.get({
    zaprecordingactive: false,
  });
  if (storageItems.zaprecordingactive) {
    await Browser.runtime.sendMessage({type: STOP_RECORDING});
  }
  Browser.runtime.sendMessage({type: SAVE_ZEST_SCRIPT}).then((items) => {
    const msg = items as ZestScriptMessage;
    downloadZestScript(msg.script, msg.title);
  });
}

function handleScriptNameChange(e: Event): void {
  const {value} = e.target as HTMLInputElement;
  Browser.storage.sync.set({
    zapscriptname: value,
  });
  sendMessageToContentScript(UPDATE_TITLE, value);
}

document.addEventListener('DOMContentLoaded', restoreState);
document.addEventListener('load', restoreState);

recordButton?.addEventListener('click', toggleRecording);
configureButton?.addEventListener('click', openOptionsPage);
saveScript?.addEventListener('click', handleSaveScript);
scriptNameInput?.addEventListener('input', handleScriptNameChange);
