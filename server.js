/**
 * Binance 批量提币工具 - 后端服务
 * 解决浏览器 CORS 限制问题
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const PORT = 7754;

// HMAC-SHA256 签名
function sign(queryString, secretKey) {
    return crypto.createHmac('sha256', secretKey)
        .update(queryString)
        .digest('hex');
}

// 发起 HTTPS 请求
function httpsRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
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
    });
}

// 获取 Binance 服务器时间
async function getServerTime() {
    const options = {
        hostname: 'api.binance.com',
        port: 443,
        path: '/api/v3/time',
        method: 'GET'
    };

    try {
        const result = await httpsRequest(options);
        if (result.status === 200 && result.data.serverTime) {
            return result.data.serverTime;
        }
    } catch (e) {
        console.error('获取服务器时间失败:', e.message);
    }

    // 如果获取失败，返回本地时间
    return Date.now();
}

// API 请求处理
async function handleApiRequest(req, res, body) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');

    try {
        const data = JSON.parse(body);
        const { action, apiKey, secretKey, params } = data;

        if (!apiKey || !secretKey) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: '缺少 API Key 或 Secret Key' }));
            return;
        }

        // 使用服务器时间而非本地时间
        const timestamp = await getServerTime();

        if (action === 'withdraw') {
            // 提币
            const { coin, network, address, amount, withdrawOrderId } = params;

            const reqParams = {
                coin,
                network,
                address,
                amount: amount.toString(),
                timestamp: timestamp.toString()
            };

            if (withdrawOrderId) {
                reqParams.withdrawOrderId = withdrawOrderId;
            }

            // 注意: transactionFeeFlag 参数仅对币安内部转账有效
            // 外部提币手续费总是从转账金额中扣除

            const queryString = Object.entries(reqParams)
                .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
                .join('&');

            const signature = sign(queryString, secretKey);
            const fullQuery = `${queryString}&signature=${signature}`;

            const options = {
                hostname: 'api.binance.com',
                port: 443,
                path: `/sapi/v1/capital/withdraw/apply?${fullQuery}`,
                method: 'POST',
                headers: {
                    'X-MBX-APIKEY': apiKey
                }
            };

            const result = await httpsRequest(options);

            if (result.status !== 200 || result.data.code) {
                res.writeHead(result.status || 400);
                res.end(JSON.stringify({ error: result.data.msg || '提币失败', code: result.data.code }));
            } else {
                res.writeHead(200);
                res.end(JSON.stringify(result.data));
            }

        } else if (action === 'balance') {
            // 查询余额
            const queryString = `timestamp=${timestamp}`;
            const signature = sign(queryString, secretKey);

            const options = {
                hostname: 'api.binance.com',
                port: 443,
                path: `/sapi/v1/capital/config/getall?${queryString}&signature=${signature}`,
                method: 'GET',
                headers: {
                    'X-MBX-APIKEY': apiKey
                }
            };

            const result = await httpsRequest(options);

            if (result.status !== 200) {
                res.writeHead(result.status || 400);
                res.end(JSON.stringify({ error: result.data.msg || '查询失败' }));
            } else {
                res.writeHead(200);
                res.end(JSON.stringify(result.data));
            }

        } else if (action === 'account') {
            // 查询账户信息
            const queryString = `timestamp=${timestamp}`;
            const signature = sign(queryString, secretKey);

            const options = {
                hostname: 'api.binance.com',
                port: 443,
                path: `/api/v3/account?${queryString}&signature=${signature}`,
                method: 'GET',
                headers: {
                    'X-MBX-APIKEY': apiKey
                }
            };

            const result = await httpsRequest(options);

            if (result.status !== 200) {
                res.writeHead(result.status || 400);
                res.end(JSON.stringify({ error: result.data.msg || '查询失败' }));
            } else {
                res.writeHead(200);
                res.end(JSON.stringify(result.data));
            }

        } else {
            res.writeHead(400);
            res.end(JSON.stringify({ error: '未知操作' }));
        }

    } catch (e) {
        console.error('API 错误:', e);
        res.writeHead(500);
        res.end(JSON.stringify({ error: e.message }));
    }
}

// HTTP 服务器
const server = http.createServer((req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;

    // CORS 预检
    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.writeHead(204);
        res.end();
        return;
    }

    // API 接口
    if (pathname === '/api' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => handleApiRequest(req, res, body));
        return;
    }

    // 静态文件服务
    let filePath = pathname === '/' ? '/index.html' : pathname;
    // pkg 打包后使用 __dirname（指向快照目录），否则使用当前目录
    const baseDir = process.pkg ? __dirname : __dirname;
    filePath = path.join(baseDir, filePath);

    const extname = path.extname(filePath);
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
            if (err.code === 'ENOENT') {
                res.writeHead(404);
                res.end('404 Not Found');
            } else {
                res.writeHead(500);
                res.end('Server Error');
            }
        } else {
            res.setHeader('Content-Type', contentTypes[extname] || 'text/plain');
            res.writeHead(200);
            res.end(content);
        }
    });
});

server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║         Binance 批量提币工具 - 服务已启动                    ║
╠═══════════════════════════════════════════════════════════╣
║  📢 关注 Twitter: @Nadiinn5 获取更多工具！                  ║
╠═══════════════════════════════════════════════════════════╣
║  访问地址: http://localhost:${PORT}                          ║
║                                                           ║
║  ✅ 已启用服务器时间同步                                      ║
║                                                           ║
║  ⚠️ 安全提醒:                                              ║
║  - 请勿在公共网络运行此服务                                  ║
║  - API Key 应开启提现权限并设置地址白名单                    ║
║  - 使用完毕后请关闭服务                                      ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
