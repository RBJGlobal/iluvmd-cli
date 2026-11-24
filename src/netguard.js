'use strict';
// iluvmd never talks to the network. This replaces every outbound network
// entry point with a function that throws, before any converter code loads.
// It runs in the main thread and again inside each conversion worker.
let installed = false;

function install() {
  if (installed) return;
  installed = true;
  const deny = (what) => function blocked() {
    throw new Error('iluvmd makes no network calls (' + what + ' is blocked)');
  };
  const set = (obj, key, what) => {
    try { Object.defineProperty(obj, key, { value: deny(what), writable: false, configurable: false }); }
    catch (e) { obj[key] = deny(what); }
  };
  for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource']) set(globalThis, name, name);

  const net = require('net');
  set(net.Socket.prototype, 'connect', 'net.connect');
  set(net, 'connect', 'net.connect');
  set(net, 'createConnection', 'net.createConnection');
  const tls = require('tls');
  set(tls, 'connect', 'tls.connect');
  const dgram = require('dgram');
  set(dgram, 'createSocket', 'dgram.createSocket');
  for (const mod of ['http', 'https']) {
    const m = require(mod);
    set(m, 'request', mod + '.request');
    set(m, 'get', mod + '.get');
  }
  set(require('http2'), 'connect', 'http2.connect');
  const dns = require('dns');
  for (const key of Object.keys(dns)) {
    if (typeof dns[key] === 'function' && /^(lookup|resolve|reverse)/.test(key)) set(dns, key, 'dns.' + key);
  }
  if (dns.promises) {
    for (const key of Object.keys(dns.promises)) {
      if (typeof dns.promises[key] === 'function' && /^(lookup|resolve|reverse)/.test(key)) set(dns.promises, key, 'dns.' + key);
    }
  }
}

module.exports = { install };
