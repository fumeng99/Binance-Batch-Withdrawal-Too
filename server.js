/**
 * Binance 批量提币工具 - 后端服务 (安全增强版)
 * 使用 HTTPS + Session Token 保护本地通信
 * 纯 JavaScript 实现，无需 OpenSSL
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const { URL } = require('url');

// 端口 0 表示自动分配可用端口
const MAX_BODY_SIZE = 1024 * 10; // 10KB

// 代理配置 (格式: http://host:port 或 http://user:pass@host:port)
// 留空则不使用代理
const PROXY_URL = process.env.PROXY_URL || '';

// 生成随机 Session Token
const SESSION_TOKEN = crypto.randomBytes(16).toString('hex');

// 生成随机 AES 加密密钥 (32 bytes = AES-256)
const ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

// 🔒 传输层加密配置（每次启动随机生成）
const TRANSPORT_KEY = crypto.randomBytes(32).toString('hex');
const TRANSPORT_IV = crypto.randomBytes(16).toString('hex').slice(0, 16);
const HMAC_SECRET = crypto.randomBytes(32).toString('hex'); // HMAC 密钥
const REQUEST_TIMEOUT = 300000; // 请求有效期 5 分钟（防重放攻击）

// 🔒 PBKDF2 密钥派生（超高强度：600,000 次迭代）
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');
}

// 🔒 HMAC 消息认证
function generateHMAC(data) {
    return crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
}

function verifyHMAC(data, hmac) {
    const expected = generateHMAC(data);
    if (hmac.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expected));
}

// 🔒 请求签名验证（防重放攻击）
const usedNonces = new Map(); // 已使用的 nonce
setInterval(() => {
    // 每分钟清理过期 nonce
    const now = Date.now();
    for (const [nonce, timestamp] of usedNonces) {
        if (now - timestamp > REQUEST_TIMEOUT) {
            usedNonces.delete(nonce);
        }
    }
}, 60000);

function verifyRequestSignature(data, timestamp, nonce, signature) {
    // 检查时间戳有效性
    const now = Date.now();
    if (Math.abs(now - timestamp) > REQUEST_TIMEOUT) {
        return { valid: false, error: '请求已过期' };
    }

    // 检查 nonce 是否已使用（防重放）
    if (usedNonces.has(nonce)) {
        return { valid: false, error: '重复请求' };
    }

    // 验证签名
    const payload = `${data}|${timestamp}|${nonce}`;
    if (!verifyHMAC(payload, signature)) {
        return { valid: false, error: '签名验证失败' };
    }

    // 记录 nonce
    usedNonces.set(nonce, now);
    return { valid: true };
}

// 🔒 敏感日志脱敏
function sanitizeForLog(str) {
    if (!str || typeof str !== 'string') return str;
    if (str.length <= 8) return '***';
    return str.slice(0, 4) + '***' + str.slice(-4);
}

function logSafe(message, data = null) {
    if (data) {
        const sanitized = { ...data };
        if (sanitized.apiKey) sanitized.apiKey = sanitizeForLog(sanitized.apiKey);
        if (sanitized.secretKey) sanitized.secretKey = sanitizeForLog(sanitized.secretKey);
        if (sanitized.passphrase) sanitized.passphrase = sanitizeForLog(sanitized.passphrase);
        if (sanitized.signature) sanitized.signature = sanitizeForLog(sanitized.signature);
        console.log(message, sanitized);
    } else {
        console.log(message);
    }
}

// 🔒 传输层加密（加密 API 响应）- 使用 scrypt 派生密钥
function encryptTransport(plainText) {
    try {
        const salt = TRANSPORT_IV;
        const key = deriveKey(TRANSPORT_KEY, salt);
        const ivBuffer = Buffer.from(TRANSPORT_IV, 'utf8');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, ivBuffer);
        cipher.setAutoPadding(true);
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const hmac = generateHMAC(encrypted.toString('base64'));
        return JSON.stringify({ data: encrypted.toString('base64'), hmac });
    } catch (e) {
        return null;
    }
}

// 🔒 传输层解密（解密 API 请求）- 带 HMAC 验证
function decryptTransport(encryptedData) {
    try {
        let data, hmac;

        // 兼容旧格式（纯 base64）和新格式（带 HMAC）
        if (typeof encryptedData === 'string') {
            try {
                const parsed = JSON.parse(encryptedData);
                data = parsed.data;
                hmac = parsed.hmac;
            } catch {
                data = encryptedData;
                hmac = null;
            }
        } else if (typeof encryptedData === 'object') {
            data = encryptedData.data || encryptedData;
            hmac = encryptedData.hmac;
        }

        // 验证 HMAC（如果提供）
        if (hmac && !verifyHMAC(data, hmac)) {
            console.error('HMAC 验证失败：数据可能被篡改');
            return null;
        }

        const salt = TRANSPORT_IV;
        const key = deriveKey(TRANSPORT_KEY, salt);
        const ivBuffer = Buffer.from(TRANSPORT_IV, 'utf8');
        const encrypted = Buffer.from(data, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer);
        decipher.setAutoPadding(true);
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        return null;
    }
}

// AES-256-CBC 解密函数
function decryptAES(encryptedHex) {
    try {
        if (!encryptedHex || typeof encryptedHex !== 'string') {
            console.error('decryptAES: 输入无效 (空或非字符串)');
            return null;
        }
        if (encryptedHex.length < 32) {
            console.error('decryptAES: 输入太短，至少需要32字符作为IV');
            return null;
        }
        // 格式: iv(32hex) + encrypted(hex)
        const iv = Buffer.from(encryptedHex.slice(0, 32), 'hex');
        const encrypted = Buffer.from(encryptedHex.slice(32), 'hex');
        const key = Buffer.from(ENCRYPTION_KEY, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        console.error('decryptAES 解密失败:', e.message);
        return null; // 解密失败返回 null
    }
}

// ============================================
// 纯 JavaScript 自签名证书生成 (无需 OpenSSL)
// ============================================

// ASN.1 DER 编码工具
const asn1 = {
    // 编码长度
    encodeLength(len) {
        if (len < 128) return Buffer.from([len]);
        const bytes = [];
        let temp = len;
        while (temp > 0) {
            bytes.unshift(temp & 0xff);
            temp >>= 8;
        }
        return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
    },

    // 编码 TLV (Type-Length-Value)
    encodeTLV(tag, value) {
        const len = this.encodeLength(value.length);
        return Buffer.concat([Buffer.from([tag]), len, value]);
    },

    // SEQUENCE
    sequence(...items) {
        const content = Buffer.concat(items);
        return this.encodeTLV(0x30, content);
    },

    // SET
    set(...items) {
        const content = Buffer.concat(items);
        return this.encodeTLV(0x31, content);
    },

    // INTEGER
    integer(value) {
        if (Buffer.isBuffer(value)) {
            // 确保正数的高位不是1
            if (value[0] & 0x80) {
                value = Buffer.concat([Buffer.from([0x00]), value]);
            }
            return this.encodeTLV(0x02, value);
        }
        const bytes = [];
        let v = BigInt(value);
        do {
            bytes.unshift(Number(v & 0xffn));
            v >>= 8n;
        } while (v > 0n);
        if (bytes[0] & 0x80) bytes.unshift(0);
        return this.encodeTLV(0x02, Buffer.from(bytes));
    },

    // BIT STRING
    bitString(value) {
        return this.encodeTLV(0x03, Buffer.concat([Buffer.from([0x00]), value]));
    },

    // OCTET STRING
    octetString(value) {
        return this.encodeTLV(0x04, value);
    },

    // NULL
    null() {
        return Buffer.from([0x05, 0x00]);
    },

    // OBJECT IDENTIFIER
    oid(oidString) {
        const parts = oidString.split('.').map(Number);
        const bytes = [parts[0] * 40 + parts[1]];
        for (let i = 2; i < parts.length; i++) {
            let n = parts[i];
            if (n === 0) {
                bytes.push(0);
            } else {
                const temp = [];
                while (n > 0) {
                    temp.unshift((n & 0x7f) | (temp.length ? 0x80 : 0));
                    n >>= 7;
                }
                bytes.push(...temp);
            }
        }
        return this.encodeTLV(0x06, Buffer.from(bytes));
    },

    // UTF8 String
    utf8String(str) {
        return this.encodeTLV(0x0c, Buffer.from(str, 'utf8'));
    },

    // PrintableString
    printableString(str) {
        return this.encodeTLV(0x13, Buffer.from(str, 'ascii'));
    },

    // UTCTime
    utcTime(date) {
        const y = date.getUTCFullYear() % 100;
        const m = String(date.getUTCMonth() + 1).padStart(2, '0');
        const d = String(date.getUTCDate()).padStart(2, '0');
        const h = String(date.getUTCHours()).padStart(2, '0');
        const min = String(date.getUTCMinutes()).padStart(2, '0');
        const s = String(date.getUTCSeconds()).padStart(2, '0');
        const str = `${String(y).padStart(2, '0')}${m}${d}${h}${min}${s}Z`;
        return this.encodeTLV(0x17, Buffer.from(str, 'ascii'));
    },

    // Context-specific tag
    contextTag(tagNum, value, constructed = true) {
        const tag = 0xa0 | tagNum | (constructed ? 0x20 : 0);
        return this.encodeTLV(tag, value);
    }
};

// 生成自签名证书
function generateSelfSignedCertificate() {
    // 生成 RSA 2048 密钥对
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // 证书有效期
    const notBefore = new Date();
    const notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000);

    // 序列号
    const serialNumber = crypto.randomBytes(8);
    serialNumber[0] &= 0x7f; // 确保是正数

    // 颁发者和主题 (CN=localhost)
    const issuerName = asn1.sequence(
        asn1.set(
            asn1.sequence(
                asn1.oid('2.5.4.3'), // commonName
                asn1.utf8String('localhost')
            )
        )
    );

    // 签名算法: sha256WithRSAEncryption
    const signatureAlgorithm = asn1.sequence(
        asn1.oid('1.2.840.113549.1.1.11'),
        asn1.null()
    );

    // 有效期
    const validity = asn1.sequence(
        asn1.utcTime(notBefore),
        asn1.utcTime(notAfter)
    );

    // 扩展: Subject Alternative Name (127.0.0.1, localhost)
    const sanExtension = asn1.sequence(
        asn1.oid('2.5.29.17'), // subjectAltName
        asn1.octetString(
            asn1.sequence(
                // DNSName: localhost
                Buffer.concat([Buffer.from([0x82]), asn1.encodeLength(9), Buffer.from('localhost')]),
                // IP: 127.0.0.1
                Buffer.concat([Buffer.from([0x87, 0x04, 127, 0, 0, 1])])
            )
        )
    );

    // 基本约束
    const basicConstraints = asn1.sequence(
        asn1.oid('2.5.29.19'),
        asn1.octetString(asn1.sequence())
    );

    // 扩展容器
    const extensions = asn1.contextTag(3,
        asn1.sequence(basicConstraints, sanExtension)
    );

    // TBS (To Be Signed) 证书
    const tbsCertificate = asn1.sequence(
        asn1.contextTag(0, asn1.integer(2), false), // version v3
        asn1.integer(serialNumber),
        signatureAlgorithm,
        issuerName,
        validity,
        issuerName, // subject = issuer (自签名)
        Buffer.from(publicKey), // subjectPublicKeyInfo (已经是 DER 格式)
        extensions
    );

    // 使用私钥签名
    const sign = crypto.createSign('SHA256');
    sign.update(tbsCertificate);
    const signature = sign.sign(privateKey);

    // 完整证书
    const certificate = asn1.sequence(
        tbsCertificate,
        signatureAlgorithm,
        asn1.bitString(signature)
    );

    // 转换为 PEM 格式
    const certPem = '-----BEGIN CERTIFICATE-----\n' +
        certificate.toString('base64').match(/.{1,64}/g).join('\n') +
        '\n-----END CERTIFICATE-----\n';

    return {
        cert: certPem,
        key: privateKey
    };
}

// HMAC-SHA256 签名
function sign(queryString, secretKey) {
    return crypto.createHmac('sha256', secretKey)
        .update(queryString)
        .digest('hex');
}

// 解析代理字符串，支持多种格式
function parseProxy(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();

    // 格式1: URL格式 http://host:port, socks5://host:port, http://user:pass@host:port
    if (/^(https?|socks5?):\/\//i.test(proxyStr)) {
        try {
            const url = new URL(proxyStr);
            return {
                host: url.hostname,
                port: parseInt(url.port) || 80,
                username: url.username ? decodeURIComponent(url.username) : null,
                password: url.password ? decodeURIComponent(url.password) : null,
                protocol: url.protocol.replace(':', '')
            };
        } catch (e) {
            return null;
        }
    }

    // 格式2: user:pass@host:port
    if (proxyStr.includes('@')) {
        const [auth, hostPort] = proxyStr.split('@');
        const [user, pass] = auth.split(':');
        const [host, port] = hostPort.split(':');
        if (host && port) {
            return {
                host: host,
                port: parseInt(port) || 80,
                username: user || null,
                password: pass || null
            };
        }
    }

    // 检测是否是 IP 地址 (用于判断格式)
    const isIpLike = (str) => /^\d{1,3}(\.\d{1,3}){0,3}$/.test(str) || /^[a-zA-Z0-9]+([\-\.][a-zA-Z0-9]+)*$/.test(str);

    const parts = proxyStr.split(':');

    // 格式3: host:port:user:pass (IP/域名开头)
    if (parts.length === 4 && isIpLike(parts[0])) {
        return {
            host: parts[0],
            port: parseInt(parts[1]) || 80,
            username: parts[2] || null,
            password: parts[3] || null
        };
    }

    // 格式4: user:pass:host:port (用户名开头，端口结尾是数字)
    if (parts.length === 4 && !isNaN(parseInt(parts[3]))) {
        return {
            host: parts[2],
            port: parseInt(parts[3]) || 80,
            username: parts[0] || null,
            password: parts[1] || null
        };
    }

    // 格式5: host:port (无认证)
    if (parts.length === 2) {
        return {
            host: parts[0],
            port: parseInt(parts[1]) || 80,
            username: null,
            password: null
        };
    }

    // 格式6: 其他4段格式，默认按 host:port:user:pass 处理
    if (parts.length >= 4) {
        return {
            host: parts[0],
            port: parseInt(parts[1]) || 80,
            username: parts[2] || null,
            password: parts.slice(3).join(':') || null  // 密码可能包含冒号
        };
    }

    return null;
}

// 发起 HTTPS 请求 (到 Binance, 支持代理)
function httpsRequest(options, postData = null, proxyUrl = null) {
    // 优先使用传入的代理，否则使用环境变量
    const effectiveProxy = proxyUrl || PROXY_URL;

    return new Promise((resolve, reject) => {
        const makeRequest = (socket = null) => {
            const reqOptions = { ...options };
            if (socket) {
                reqOptions.socket = socket;
                reqOptions.agent = false;
            }

            const req = https.request(reqOptions, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        resolve({ status: res.statusCode, data: json });
                    } catch (e) {
                        resolve({ status: res.statusCode, data: data });
                    }
                });
            });
            req.on('error', reject);
            if (postData) req.write(postData);
            req.end();
        };

        // 如果配置了代理，使用 HTTP CONNECT 隧道
        const proxyConfig = parseProxy(effectiveProxy);
        if (proxyConfig) {
            console.log(`🌐 使用代理: ${proxyConfig.host}:${proxyConfig.port} -> ${options.hostname}`);
            try {
                const connectOptions = {
                    host: proxyConfig.host,
                    port: proxyConfig.port,
                    method: 'CONNECT',
                    path: `${options.hostname}:${options.port || 443}`,
                    headers: { 'Host': `${options.hostname}:${options.port || 443}` }
                };

                // 添加代理认证
                if (proxyConfig.username) {
                    const auth = Buffer.from(`${proxyConfig.username}:${proxyConfig.password || ''}`).toString('base64');
                    connectOptions.headers['Proxy-Authorization'] = `Basic ${auth}`;
                }

                const proxyReq = http.request(connectOptions);
                proxyReq.on('connect', (res, socket) => {
                    if (res.statusCode === 200) {
                        makeRequest(socket);
                    } else {
                        reject(new Error(`代理连接失败: ${res.statusCode}`));
                    }
                });
                proxyReq.on('error', (e) => reject(new Error(`代理错误: ${e.message}`)));
                proxyReq.end();
            } catch (e) {
                reject(new Error(`代理配置错误: ${e.message}`));
            }
        } else {
            makeRequest();
        }
    });
}

// 获取 Binance 服务器时间
async function getServerTime(proxyUrl = null) {
    try {
        const result = await httpsRequest({
            hostname: 'api.binance.com',
            port: 443,
            path: '/api/v3/time',
            method: 'GET'
        }, null, proxyUrl);
        if (result.status === 200 && result.data.serverTime) {
            return result.data.serverTime;
        }
    } catch (e) {
        console.error('获取服务器时间失败:', e.message);
    }
    return Date.now();
}

// 🔒 生成请求 ID
function generateRequestId() {
    return `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

// 🔒 安全的 Session Token 验证（防止时序攻击）
function validateSessionToken(req, res) {
    const token = req.headers['x-session-token'];
    if (!token || token.length !== SESSION_TOKEN.length) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session Token 无效或缺失' }));
        return false;
    }

    // 使用时序安全比较防止时序攻击
    try {
        const tokenBuffer = Buffer.from(token, 'utf8');
        const sessionBuffer = Buffer.from(SESSION_TOKEN, 'utf8');
        if (!crypto.timingSafeEqual(tokenBuffer, sessionBuffer)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Session Token 无效' }));
            return false;
        }
    } catch (e) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session Token 验证失败' }));
        return false;
    }
    return true;
}

// 清除敏感信息 (尽可能从内存中移除)
function clearSensitiveData(obj) {
    if (obj && typeof obj === 'object') {
        if (obj.apiKey) obj.apiKey = null;
        if (obj.secretKey) obj.secretKey = null;
        if (obj.signature) obj.signature = null;
    }
}

// 设置安全响应头
function setSecurityHeaders(res) {
    // 防止点击劫持
    res.setHeader('X-Frame-Options', 'DENY');
    // 防止 MIME 类型嗅探
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // XSS 保护
    res.setHeader('X-XSS-Protection', '1; mode=block');
    // 内容安全策略
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; img-src 'self' data:");
    // Referrer 策略
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // 禁止缓存敏感数据
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
}

// 🔒 发送加密响应
function sendEncryptedResponse(res, statusCode, data) {
    const jsonStr = JSON.stringify(data);
    const encrypted = encryptTransport(jsonStr);
    if (encrypted) {
        res.writeHead(statusCode);
        res.end(JSON.stringify({ encrypted: true, data: encrypted }));
    } else {
        // 加密失败时回退到明文（不应发生）
        res.writeHead(statusCode);
        res.end(jsonStr);
    }
}

// API 请求处理
async function handleApiRequest(req, res, body) {
    const requestId = generateRequestId();

    setSecurityHeaders(res);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Request-ID', requestId);
    const origin = req.headers.origin || `https://${req.headers.host}`;
    res.setHeader('Access-Control-Allow-Origin', origin);

    if (!validateSessionToken(req, res)) return;

    let sensitiveData = null;
    try {
        let data = JSON.parse(body);

        // 🔒 传输层解密
        if (data.encrypted && data.data) {
            const decrypted = decryptTransport(data.data);
            if (!decrypted) {
                sendEncryptedResponse(res, 400, { error: '传输解密失败' });
                return;
            }
            data = JSON.parse(decrypted);
        }

        sensitiveData = data; // 保存引用以便清理
        const { action, apiKey: encApiKey, secretKey: encSecretKey, proxyUrl, params } = data;

        if (!encApiKey || !encSecretKey) {
            sendEncryptedResponse(res, 400, { error: '缺少 API Key 或 Secret Key' });
            return;
        }

        // 解密 API Key 和 Secret Key
        const apiKey = decryptAES(encApiKey);
        const secretKey = decryptAES(encSecretKey);

        if (!apiKey || !secretKey) {
            sendEncryptedResponse(res, 400, { error: '解密失败，请检查加密密钥是否正确' });
            return;
        }

        const timestamp = await getServerTime(proxyUrl);

        if (action === 'withdraw') {
            const { coin, network, address, amount, withdrawOrderId } = params;
            const reqParams = {
                coin, network, address,
                amount: parseFloat(amount).toFixed(8),
                timestamp: timestamp.toString()
            };
            if (withdrawOrderId) reqParams.withdrawOrderId = withdrawOrderId;

            const queryString = Object.entries(reqParams)
                .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
                .join('&');
            const signature = sign(queryString, secretKey);

            const result = await httpsRequest({
                hostname: 'api.binance.com',
                port: 443,
                path: `/sapi/v1/capital/withdraw/apply?${queryString}&signature=${signature}`,
                method: 'POST',
                headers: { 'X-MBX-APIKEY': apiKey }
            }, null, proxyUrl);

            sendEncryptedResponse(res, result.status !== 200 || result.data.code ? (result.status || 400) : 200, result.data.code ? { error: result.data.msg || '提币失败', code: result.data.code } : result.data);

        } else if (action === 'balance') {
            const queryString = `timestamp=${timestamp}`;
            const signature = sign(queryString, secretKey);

            const result = await httpsRequest({
                hostname: 'api.binance.com',
                port: 443,
                path: `/sapi/v1/capital/config/getall?${queryString}&signature=${signature}`,
                method: 'GET',
                headers: { 'X-MBX-APIKEY': apiKey }
            }, null, proxyUrl);

            sendEncryptedResponse(res, result.status !== 200 ? (result.status || 400) : 200, result.status !== 200 ? { error: result.data.msg || '查询失败' } : result.data);

        } else if (action === 'account') {
            const queryString = `timestamp=${timestamp}`;
            const signature = sign(queryString, secretKey);

            const result = await httpsRequest({
                hostname: 'api.binance.com',
                port: 443,
                path: `/api/v3/account?${queryString}&signature=${signature}`,
                method: 'GET',
                headers: { 'X-MBX-APIKEY': apiKey }
            }, null, proxyUrl);

            sendEncryptedResponse(res, result.status !== 200 ? (result.status || 400) : 200, result.status !== 200 ? { error: result.data.msg || '查询失败' } : result.data);

        } else if (action === 'price') {
            // 查询币种价格（不需要签名，公开 API）
            const { symbol } = params;
            if (!symbol) {
                sendEncryptedResponse(res, 400, { error: '缺少币种参数' });
                return;
            }

            // 稳定币直接返回 1
            const stableCoins = ['USDT', 'USDC', 'BUSD', 'DAI', 'TUSD', 'FDUSD'];
            if (stableCoins.includes(symbol.toUpperCase())) {
                sendEncryptedResponse(res, 200, { symbol: symbol.toUpperCase(), price: '1' });
                return;
            }

            const result = await httpsRequest({
                hostname: 'api.binance.com',
                port: 443,
                path: `/api/v3/ticker/price?symbol=${symbol.toUpperCase()}USDT`,
                method: 'GET',
                headers: {}
            }, null, proxyUrl);

            if (result.status === 200 && result.data.price) {
                sendEncryptedResponse(res, 200, { symbol: result.data.symbol, price: result.data.price });
            } else {
                // 尝试用 BUSD 查询
                const result2 = await httpsRequest({
                    hostname: 'api.binance.com',
                    port: 443,
                    path: `/api/v3/ticker/price?symbol=${symbol.toUpperCase()}BUSD`,
                    method: 'GET',
                    headers: {}
                }, null, proxyUrl);

                if (result2.status === 200 && result2.data.price) {
                    sendEncryptedResponse(res, 200, { symbol: result2.data.symbol, price: result2.data.price });
                } else {
                    sendEncryptedResponse(res, 200, { symbol, price: null, error: '无法获取价格' });
                }
            }

        } else {
            sendEncryptedResponse(res, 400, { error: '未知操作' });
        }

    } catch (e) {
        console.error(`[${requestId}] API 错误:`, e);
        sendEncryptedResponse(res, 500, { error: e.message, requestId });
    } finally {
        // 清理敏感数据
        clearSensitiveData(sensitiveData);
        body = null;
    }
}

// 请求处理函数
function handleRequest(req, res) {
    const parsedUrl = new URL(req.url, `https://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // CORS 预检
    if (req.method === 'OPTIONS') {
        const origin = req.headers.origin || `https://${req.headers.host}`;
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');
        res.writeHead(204);
        res.end();
        return;
    }

    // API 接口
    if (pathname === '/api' && req.method === 'POST') {
        let body = '';
        let bodyTooLarge = false;
        req.on('data', chunk => {
            body += chunk;
            if (body.length > MAX_BODY_SIZE) {
                bodyTooLarge = true;
                res.writeHead(413);
                res.end(JSON.stringify({ error: '请求体过大' }));
                req.destroy();
            }
        });
        req.on('end', () => {
            if (!bodyTooLarge) handleApiRequest(req, res, body);
        });
        return;
    }

    // 代理测试接口
    if (pathname === '/api/proxy-test' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            setSecurityHeaders(res);
            res.setHeader('Content-Type', 'application/json');
            const origin = req.headers.origin || `https://${req.headers.host}`;
            res.setHeader('Access-Control-Allow-Origin', origin);

            if (!validateSessionToken(req, res)) return;

            try {
                let data = JSON.parse(body);

                // 🔒 传输层解密
                if (data.encrypted && data.data) {
                    const decrypted = decryptTransport(data.data);
                    if (!decrypted) {
                        sendEncryptedResponse(res, 400, { success: false, error: '传输解密失败' });
                        return;
                    }
                    data = JSON.parse(decrypted);
                }

                const { proxyUrl } = data;
                const proxyConfig = parseProxy(proxyUrl);

                if (!proxyConfig) {
                    sendEncryptedResponse(res, 400, { success: false, error: '代理格式无效' });
                    return;
                }

                const startTime = Date.now();

                // 通过代理获取出口 IP
                const ipResult = await httpsRequest({
                    hostname: 'httpbin.org',
                    port: 443,
                    path: '/ip',
                    method: 'GET'
                }, null, proxyUrl);

                const latency = Date.now() - startTime;

                if (ipResult.status === 200 && ipResult.data.origin) {
                    const ip = ipResult.data.origin.split(',')[0].trim();

                    // 查询 IP 地理位置 (直连，使用 ip-api.com)
                    let country = '未知';
                    try {
                        const geoResult = await new Promise((resolve, reject) => {
                            const geoReq = http.request({
                                hostname: 'ip-api.com',
                                port: 80,
                                path: `/json/${ip}?fields=country`,
                                method: 'GET'
                            }, (res) => {
                                let data = '';
                                res.on('data', chunk => data += chunk);
                                res.on('end', () => {
                                    try { resolve(JSON.parse(data)); }
                                    catch (e) { reject(e); }
                                });
                            });
                            geoReq.on('error', reject);
                            geoReq.end();
                        });
                        if (geoResult.country) {
                            country = geoResult.country;
                        }
                    } catch (e) { /* 地理位置查询失败不影响结果 */ }

                    sendEncryptedResponse(res, 200, { success: true, latency, ip, country });
                } else {
                    sendEncryptedResponse(res, 200, { success: false, error: '无法获取代理IP' });
                }
            } catch (e) {
                sendEncryptedResponse(res, 200, { success: false, error: e.message });
            }
        });
        return;
    }

    // 获取加密密钥接口 (需要 Session Token 验证)
    if (pathname === '/api/key' && req.method === 'GET') {
        setSecurityHeaders(res);
        res.setHeader('Content-Type', 'application/json');
        const origin = req.headers.origin || `https://${req.headers.host}`;
        res.setHeader('Access-Control-Allow-Origin', origin);
        if (!validateSessionToken(req, res)) return;
        res.writeHead(200);
        res.end(JSON.stringify({ encryptionKey: ENCRYPTION_KEY }));
        return;
    }

    // 🔒 传输层密钥配置 API（前端获取动态生成的密钥）
    if (pathname === '/api/transport-config' && req.method === 'GET') {
        setSecurityHeaders(res);
        res.setHeader('Content-Type', 'application/json');
        const origin = req.headers.origin || `https://${req.headers.host}`;
        res.setHeader('Access-Control-Allow-Origin', origin);
        if (!validateSessionToken(req, res)) return;
        res.writeHead(200);
        res.end(JSON.stringify({
            key: TRANSPORT_KEY,
            iv: TRANSPORT_IV,
            hmacSecret: HMAC_SECRET
        }));
        return;
    }

    // 静态文件服务
    let filePath = pathname === '/' ? '/index.html' : pathname;
    const baseDir = process.pkg ? __dirname : __dirname;
    filePath = path.resolve(path.join(baseDir, filePath));

    if (!filePath.startsWith(path.resolve(baseDir))) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }

    const contentTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.ico': 'image/x-icon'
    };

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(err.code === 'ENOENT' ? 404 : 500);
            res.end(err.code === 'ENOENT' ? '404 Not Found' : 'Server Error');
        } else {
            res.setHeader('Content-Type', contentTypes[path.extname(filePath)] || 'text/plain');
            res.writeHead(200);
            res.end(content);
        }
    });
}

// 启动服务器
function startServer() {
    let server;
    let protocol = 'https';

    try {
        console.log('🔑 正在生成自签名证书...');
        const { cert, key } = generateSelfSignedCertificate();
        server = https.createServer({ cert, key }, handleRequest);
        console.log('✅ 证书生成成功 (纯 JavaScript 实现)');
    } catch (e) {
        console.log('⚠️  HTTPS 初始化失败，使用 HTTP 模式');
        console.log('   错误:', e.message);
        server = http.createServer(handleRequest);
        protocol = 'http';
    }

    const tokenDisplay = SESSION_TOKEN.match(/.{1,4}/g).join('-');

    server.listen(0, '127.0.0.1', () => {
        const PORT = server.address().port;
        console.clear();
        console.log(`
============================================================
  Binance 批量提币工具 v3.0
============================================================

  访问地址: ${protocol}://127.0.0.1:${PORT}

  Session Token: ${tokenDisplay}

============================================================
  Twitter: @Nadiinn5 | 按 Ctrl+C 停止服务
============================================================
`);
        if (protocol === 'https') {
            console.log('💡 首次访问时浏览器会提示证书不受信任，点击"继续访问"即可\n');
        }
    });
}

startServer();
