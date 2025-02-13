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
import Browser, {Runtime} from 'webextension-polyfill';
import {
  ReportedElement,
  ReportedObject,
  ReportedStorage,
  ReportedEvent,
} from '../types/ReportedModel';
import Recorder from './recorder';
import {
  LOCAL_STORAGE,
  LOCAL_ZAP_ENABLE,
  LOCAL_ZAP_RECORD,
  REPORT_EVENT,
  REPORT_OBJECT,
  SESSION_STORAGE,
  URL_ZAP_ENABLE,
  URL_ZAP_RECORD,
  ZAP_START_RECORDING,
  ZAP_STOP_RECORDING,
} from '../utils/constants';

const reportedObjects = new Set<string>();

const reportedEvents: {[key: string]: ReportedEvent} = {};

const recorder = new Recorder();

function reportStorage(
  name: string,
  storage: Storage,
  fn: (re: ReportedStorage) => void
): void {
  const url = window.location.href;
  for (const key of Object.keys(storage)) {
    fn(new ReportedStorage(name, '', key, '', storage.getItem(key), url));
  }
}

async function sendEventToZAP(obj: ReportedEvent): Promise<number> {
  return Browser.runtime.sendMessage({
    type: REPORT_EVENT,
    data: obj.toString(),
  });
}

async function sendObjectToZAP(obj: ReportedObject): Promise<number> {
  return Browser.runtime.sendMessage({
    type: REPORT_OBJECT,
    data: obj.toString(),
  });
}

function reportObject(repObj: ReportedObject): void {
  const repObjStr = repObj.toShortString();
  if (!reportedObjects.has(repObjStr)) {
    sendObjectToZAP(repObj);
    reportedObjects.add(repObjStr);
  }
}

function reportAllStorage(): void {
  reportStorage(LOCAL_STORAGE, localStorage, reportObject);
  reportStorage(SESSION_STORAGE, sessionStorage, reportObject);
}

function withZapEnableSetting(fn: () => void): void {
  Browser.storage.sync.get({zapenable: false}).then((items) => {
    if (items.zapenable) {
      fn();
    }
  });
}

function withZapRecordingActive(fn: () => void): void {
  Browser.storage.sync.get({zaprecordingactive: false}).then((items) => {
    if (items.zaprecordingactive) {
      fn();
    }
  });
}

function reportPageUnloaded(): void {
  withZapEnableSetting(() => {
    Browser.runtime.sendMessage({
      type: REPORT_EVENT,
      data: new ReportedEvent('pageUnload').toString(),
    });
    for (const value of Object.values(reportedEvents)) {
      sendEventToZAP(value);
    }
    reportAllStorage();
  });
}

function reportEvent(event: ReportedEvent): void {
  let existingEvent: ReportedEvent;
  existingEvent = reportedEvents[event.eventName];
  if (!existingEvent) {
    existingEvent = new ReportedEvent(event.eventName);
    reportedEvents[event.eventName] = event;
    sendEventToZAP(existingEvent);
  } else if (existingEvent.url !== window.location.href) {
    // The fragment has changed - report the old one and start a new count
    sendEventToZAP(existingEvent);
    existingEvent = new ReportedEvent(event.eventName);
    reportedEvents[event.eventName] = event;
    sendEventToZAP(existingEvent);
  } else {
    // eslint-disable-next-line no-plusplus
    existingEvent.count++;
  }
}

function reportPageForms(
  doc: Document,
  fn: (re: ReportedObject) => void
): void {
  const url = window.location.href;
  Array.prototype.forEach.call(doc.forms, (form: HTMLFormElement) => {
    fn(new ReportedElement(form, url));
  });
}

function reportPageLinks(
  doc: Document,
  fn: (re: ReportedObject) => void
): void {
  const url = window.location.href;
  Array.prototype.forEach.call(
    doc.links,
    (link: HTMLAnchorElement | HTMLAreaElement) => {
      fn(new ReportedElement(link, url));
    }
  );
}

function reportElements(
  collection: HTMLCollection,
  fn: (re: ReportedObject) => void
): void {
  const url = window.location.href;
  Array.prototype.forEach.call(collection, (element: Element) => {
    fn(new ReportedElement(element, url));
  });
}

function reportNodeElements(
  node: Node,
  tagName: string,
  fn: (re: ReportedObject) => void
): void {
  if (node.nodeType === Node.ELEMENT_NODE) {
    reportElements((node as Element).getElementsByTagName(tagName), fn);
  }
}

function reportPageLoaded(
  doc: Document,
  fn: (re: ReportedObject) => void
): void {
  Browser.runtime.sendMessage({
    type: REPORT_EVENT,
    data: new ReportedEvent('pageLoad').toString(),
  });

  reportPageLinks(doc, fn);
  reportPageForms(doc, fn);
  reportElements(doc.getElementsByTagName('input'), fn);
  reportElements(doc.getElementsByTagName('button'), fn);
  reportStorage(LOCAL_STORAGE, localStorage, fn);
  reportStorage(SESSION_STORAGE, sessionStorage, fn);
}

const domMutated = function domMutation(
  mutationList: MutationRecord[],
  _obs: MutationObserver
): void {
  withZapEnableSetting(() => {
    reportEvent(new ReportedEvent('domMutation'));
    reportPageLinks(document, reportObject);
    reportPageForms(document, reportObject);
    for (const mutation of mutationList) {
      if (mutation.type === 'childList') {
        reportNodeElements(mutation.target, 'input', reportObject);
        reportNodeElements(mutation.target, 'button', reportObject);
      }
    }
  });
};

function isConfigurationRequest(): boolean {
  return window.location.href.startsWith('https://zap/zapCallBackUrl/');
}

function onLoadEventListener(): void {
  Browser.storage.sync.set({zaprecordingactive: false});
  if (isConfigurationRequest()) {
    return;
  }

  withZapEnableSetting(() => {
    reportPageLoaded(document, reportObject);
  });
}

function enableExtension(): void {
  window.addEventListener('load', onLoadEventListener, false);
  window.onbeforeunload = reportPageUnloaded;

  const observer = new MutationObserver(domMutated);
  observer.observe(document, {
    attributes: false,
    childList: true,
    subtree: true,
  });

  setInterval(() => {
    // Have to poll to pickup storage changes in a timely fashion
    reportAllStorage();
  }, 500);

  // This is needed for more traditional apps
  reportPageLoaded(document, reportObject);
}

function configureExtension(): void {
  if (isConfigurationRequest()) {
    // The Browser has been launched from ZAP - use this URL for configuration
    const params = new URLSearchParams(window.location.search);
    const enable =
      localStorage.getItem(LOCAL_ZAP_ENABLE) === 'true' ||
      params.has(URL_ZAP_ENABLE);
    const record =
      localStorage.getItem(LOCAL_ZAP_RECORD) === 'true' ||
      params.has(URL_ZAP_RECORD);

    console.log('ZAP Configure', enable, record);
    Browser.storage.sync.set({
      zapurl: window.location.href.split('?')[0],
      zapenable: enable,
      zaprecordingactive: record,
    });
  }
}

function injectScript(): Promise<boolean> {
  return new Promise((resolve) => {
    configureExtension();
    withZapRecordingActive(() => {
      recorder.recordUserInteractions();
    });
    withZapEnableSetting(() => {
      enableExtension();
      resolve(true);
    });
    resolve(false);
  });
}

injectScript();

/* eslint-disable  @typescript-eslint/no-explicit-any */
Browser.runtime.onMessage.addListener(
  (
    message: any,
    _sender: Runtime.MessageSender,
    _sendResponse: (response?: any) => void
  ) => {
    if (message.type === ZAP_START_RECORDING) {
      configureExtension();
      recorder.recordUserInteractions();
      recorder.initializationScript();
    } else if (message.type === ZAP_STOP_RECORDING) {
      recorder.stopRecordingUserInteractions();
    }

    // Returning `true` keeps the message channel open for async responses
    return true;
  }
);

export {
  reportPageLinks,
  reportPageLoaded,
  reportPageForms,
  reportNodeElements,
  reportStorage,
  ReportedElement,
  ReportedObject,
  ReportedStorage,
  ReportedEvent,
  injectScript,
  enableExtension,
};
