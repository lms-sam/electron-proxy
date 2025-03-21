const httpProxy = require('http-proxy');
const http = require('http');
const https = require('https');
const net = require('net');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const { exec } = require('child_process');
const os = require('os');

class ProxyServer extends EventEmitter {
  constructor(config = {}) {
    super();
    this.port = config.port || 8888;
    this.certDir = path.join(__dirname, 'certs');
    this.caPath = path.join(this.certDir, 'ca.crt');
    this.caKeyPath = path.join(this.certDir, 'ca.key');
    
    // 过滤规则
    this.filters = {
      url: null,      // URL过滤规则
      method: null,   // 请求方法过滤规则
      contentType: null // 内容类型过滤规则
    };
    
    // 如果初始化时提供了过滤规则，设置它
    if (config.filters) {
      this.setFilters(config.filters);
    }
    
    // 确保证书目录存在
    if (!fs.existsSync(this.certDir)) {
      fs.mkdirSync(this.certDir, { recursive: true });
    }

    // 初始化证书
    this.setupCertificates();
    
    // 读取CA证书和私钥
    try {
      if (fs.existsSync(this.caPath) && fs.existsSync(this.caKeyPath)) {
        const caCertPem = fs.readFileSync(this.caPath, 'utf8');
        const caKeyPem = fs.readFileSync(this.caKeyPath, 'utf8');
        this.caCert = forge.pki.certificateFromPem(caCertPem);
        this.caKey = forge.pki.privateKeyFromPem(caKeyPem);
      } else {
        throw new Error('CA证书文件不存在');
      }
    } catch (error) {
      throw new Error(`初始化CA证书失败: ${error.message}`);
    }

    // 检查必要的依赖
    try {
      require('http-proxy');
      require('node-forge');
    } catch (error) {
      throw new Error(`缺少必要的依赖: ${error.message}`);
    }
  }

  /**
   * 设置过滤规则
   * @param {Object} filters 过滤规则对象
   */
  setFilters(filters = {}) {
    this.filters = {
      url: filters.url || null,
      method: filters.method || null,
      contentType: filters.contentType || null
    };
    console.log('已更新过滤规则:', this.filters);
  }

  /**
   * 检查请求是否匹配过滤规则
   * @param {Object} request 请求对象
   * @returns {boolean} 是否匹配
   */
  matchesFilters(request) {
    // 如果没有设置任何过滤规则，返回true
    if (!this.filters.url && !this.filters.method && !this.filters.contentType) {
      return true;
    }

    // URL过滤
    if (this.filters.url) {
      const url = request.url || '';
      const host = request.headers?.host || '';
      
      // 检查URL或主机名是否包含过滤字符串
      if (!url.includes(this.filters.url) && !host.includes(this.filters.url)) {
        console.log(`URL不匹配过滤规则: ${url}, host: ${host}, 过滤规则: ${this.filters.url}`);
        return false;
      }
    }

    // 请求方法过滤
    if (this.filters.method && request.method) {
      if (request.method.toUpperCase() !== this.filters.method.toUpperCase()) {
        console.log(`方法不匹配过滤规则: ${request.method}, 过滤规则: ${this.filters.method}`);
        return false;
      }
    }

    // 内容类型过滤
    if (this.filters.contentType && request.headers) {
      const contentType = request.headers['content-type'] || '';
      if (!contentType.includes(this.filters.contentType)) {
        console.log(`内容类型不匹配过滤规则: ${contentType}, 过滤规则: ${this.filters.contentType}`);
        return false;
      }
    }

    return true;
  }

  /**
   * 检查证书是否已安装到系统信任存储
   * @returns {Promise<boolean>} 证书是否已安装
   */
  async isCertificateTrusted() {
    const platform = os.platform();
    
    return new Promise((resolve) => {
      if (platform === 'win32') {
        // Windows - 使用certutil检查证书
        exec('certutil -verifystore -user Root "Electron Proxy Monitor CA"', (error, stdout) => {
          resolve(!error && stdout.includes('Electron Proxy Monitor CA'));
        });
      } else if (platform === 'darwin') {
        // macOS - 使用security命令检查证书
        exec('security find-certificate -c "Electron Proxy Monitor CA" -a', (error, stdout) => {
          resolve(!error && stdout.includes('1 identities found'));
        });
      } else if (platform === 'linux') {
        // Linux - 检查证书是否在NSS数据库中
        exec('certutil -L -d sql:$HOME/.pki/nssdb -n "Electron Proxy Monitor CA"', (error) => {
          resolve(!error);
        });
      } else {
        // 不支持的平台
        resolve(false);
      }
    });
  }

  /**
   * 安装CA证书到系统信任存储
   * @returns {Promise<{success: boolean, message: string}>} 安装结果
   */
  async installCertificate() {
    const platform = os.platform();
    
    return new Promise((resolve) => {
      if (platform === 'win32') {
        // Windows - 使用certutil安装证书
        exec(`certutil -addstore -user Root "${this.caPath}"`, (error, stdout) => {
          if (error) {
            resolve({ success: false, message: `安装证书失败: ${error.message}` });
          } else {
            resolve({ success: true, message: '证书已成功安装到系统信任存储' });
          }
        });
      } else if (platform === 'darwin') {
        // macOS - 使用security命令安装证书并信任
        exec(`security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${this.caPath}"`, (error) => {
          if (error) {
            resolve({ success: false, message: `安装证书失败: ${error.message}` });
          } else {
            resolve({ success: true, message: '证书已成功安装到系统信任存储' });
          }
        });
      } else if (platform === 'linux') {
        // Linux - 尝试安装到NSS数据库和系统CA存储
        exec(`certutil -A -n "Electron Proxy Monitor CA" -t "C,," -d sql:$HOME/.pki/nssdb -i "${this.caPath}" && ` +
             `sudo cp "${this.caPath}" /usr/local/share/ca-certificates/electron-proxy-ca.crt && ` +
             `sudo update-ca-certificates`, (error) => {
          if (error) {
            resolve({ success: false, message: `安装证书失败: ${error.message}` });
          } else {
            resolve({ success: true, message: '证书已成功安装到系统信任存储' });
          }
        });
      } else {
        // 不支持的平台
        resolve({ success: false, message: `不支持在 ${platform} 平台上自动安装证书` });
      }
    });
  }

  /**
   * 获取CA证书路径
   * @returns {string} CA证书路径
   */
  getCertificatePath() {
    return this.caPath;
  }

  setupCertificates() {
    try {
      // 如果CA证书已存在，直接加载
      if (fs.existsSync(this.caKeyPath) && fs.existsSync(this.caPath)) {
        const caCertPem = fs.readFileSync(this.caPath, 'utf8');
        const caKeyPem = fs.readFileSync(this.caKeyPath, 'utf8');
        this.caCert = forge.pki.certificateFromPem(caCertPem);
        this.caKey = forge.pki.privateKeyFromPem(caKeyPem);
        return;
      }

      // 生成新的CA证书
      const keys = forge.pki.rsa.generateKeyPair(2048);
      const cert = forge.pki.createCertificate();
      
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01';
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
      
      const attrs = [{
        name: 'commonName',
        value: 'Electron Proxy Monitor CA'
      }, {
        name: 'countryName',
        value: 'US'
      }, {
        name: 'stateOrProvinceName',
        value: 'California'
      }, {
        name: 'localityName',
        value: 'San Francisco'
      }, {
        name: 'organizationName',
        value: 'Electron Proxy Monitor'
      }, {
        shortName: 'OU',
        value: 'CA'
      }];
      
      cert.setSubject(attrs);
      cert.setIssuer(attrs);
      cert.setExtensions([{
        name: 'basicConstraints',
        cA: true
      }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
      }, {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true
      }]);
      
      cert.sign(keys.privateKey, forge.md.sha256.create());
      
      // 保存证书和私钥
      fs.writeFileSync(this.caKeyPath, forge.pki.privateKeyToPem(keys.privateKey));
      fs.writeFileSync(this.caPath, forge.pki.certificateToPem(cert));
      
      this.caCert = cert;
      this.caKey = keys.privateKey;
    } catch (error) {
      console.error('设置证书时出错:', error);
      throw new Error(`设置证书失败: ${error.message}`);
    }
  }

  generateCertificateForHost(hostname) {
    // 生成RSA密钥对
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '02';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    
    // 设置证书主体信息
    const attrs = [{
      name: 'commonName',
      value: hostname
    }, {
      name: 'organizationName',
      value: 'Electron Proxy Monitor'
    }, {
      shortName: 'OU',
      value: 'Proxy Server'
    }];
    
    cert.setSubject(attrs);
    
    // 设置证书颁发者（使用CA证书信息）
    cert.setIssuer(this.caCert.subject.attributes);
    
    // 设置证书扩展
    cert.setExtensions([{
      name: 'basicConstraints',
      cA: false
    }, {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true
    }, {
      name: 'extKeyUsage',
      serverAuth: true
    }, {
      name: 'subjectAltName',
      altNames: [{
        type: 2, // DNS
        value: hostname
      }]
    }]);
    
    // 使用CA私钥签名证书
    cert.sign(this.caKey, forge.md.sha256.create());
    
    console.log(`已为域名 ${hostname} 生成证书`);
    
    // 返回证书和私钥
    return {
      key: forge.pki.privateKeyToPem(keys.privateKey),
      cert: forge.pki.certificateToPem(cert)
    };
  }

  start() {
    return new Promise((resolve, reject) => {
      try {
        // 创建HTTP代理服务器
        const proxy = httpProxy.createProxyServer({
          xfwd: true,
          secure: false,
          changeOrigin: true
        });

        // 处理代理错误
        proxy.on('error', (err, req, res) => {
          console.error('代理错误:', err);
          console.error('出错的请求URL:', req.url);
          console.error('出错的请求方法:', req.method);
          console.error('出错的请求头:', req.headers);
          
          if (res.writeHead) {
            res.writeHead(500, {
              'Content-Type': 'text/plain'
            });
            res.end('代理请求失败: ' + err.message);
          }
        });

        // 记录请求和响应
        proxy.on('proxyReq', (proxyReq, req, res) => {
          let requestBody = '';
          if (req.body) {
            requestBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
          }

          const requestData = {
            timestamp: new Date().toISOString(),
            protocol: req.protocol || (req.socket?.encrypted ? 'HTTPS' : 'HTTP'),
            method: req.method,
            url: req.url,
            headers: req.headers,
            body: requestBody
          };

          // 存储请求数据以便后续匹配响应
          req._requestData = requestData;
        });

        proxy.on('proxyRes', (proxyRes, req, res) => {
          let responseBody = '';
          proxyRes.on('data', chunk => {
            responseBody += chunk;
          });

          proxyRes.on('end', () => {
            const responseData = {
              timestamp: new Date().toISOString(),
              statusCode: proxyRes.statusCode,
              headers: proxyRes.headers,
              body: responseBody
            };

            // 合并请求和响应数据
            const fullData = {
              request: req._requestData,
              response: responseData
            };

            // 发送事件 - 我们在HTTP服务器和HTTPS服务器中已经过滤了请求
            // 所以这里直接发送事件即可
            this.emit('request-completed', fullData);
          });
        });

        // 创建主服务器
        this.server = http.createServer(async (req, res) => {
          try {
            // 解析请求体
            let body = '';
            req.on('data', chunk => {
              body += chunk.toString();
            });

            req.on('end', () => {
              if (body) {
                try {
                  req.body = JSON.parse(body);
                } catch {
                  req.body = body;
                }
              }

              // 检查是否匹配过滤规则
              if (!this.matchesFilters(req)) {
                console.log(`请求被过滤: ${req.method} ${req.url}`);
                // 对于被过滤的请求，我们仍然要转发，只是不记录
                let target;
                try {
                  if (req.url.startsWith('http')) {
                    target = new URL(req.url).origin;
                  } else if (req.headers.host) {
                    target = `http://${req.headers.host}`;
                  } else {
                    throw new Error('无法确定目标服务器');
                  }
                  
                  proxy.web(req, res, {
                    target: target,
                    secure: false,
                    changeOrigin: true
                  });
                } catch (error) {
                  console.error('处理被过滤的HTTP请求时出错:', error);
                  res.writeHead(500, { 'Content-Type': 'text/plain' });
                  res.end('内部服务器错误');
                }
                return;
              }

              console.log(`处理HTTP请求: ${req.method} ${req.url}`);
              
              // 处理HTTP请求
              let target;
              try {
                if (req.url.startsWith('http')) {
                  target = new URL(req.url).origin;
                } else if (req.headers.host) {
                  target = `http://${req.headers.host}`;
                } else {
                  throw new Error('无法确定目标服务器');
                }
                
                console.log(`代理请求到: ${target}`);
                proxy.web(req, res, {
                  target: target,
                  secure: false,
                  changeOrigin: true
                });
              } catch (error) {
                console.error('处理HTTP请求时出错:', error);
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('内部服务器错误');
              }
            });
          } catch (error) {
            console.error('处理HTTP请求时出错:', error);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('内部服务器错误');
          }
        });

        // 处理HTTPS CONNECT请求
        this.server.on('connect', (req, socket, head) => {
          try {
            console.log('收到HTTPS CONNECT请求:', req.url);
            const [hostname, port] = req.url.split(':');
            const targetPort = parseInt(port) || 443;

            // 为HTTPS请求添加更多信息以便过滤
            req.headers = req.headers || {};
            req.headers.host = hostname;
            
            // 检查是否匹配过滤规则
            const shouldMonitor = this.matchesFilters(req);
            
            // 不管是否匹配过滤规则，我们都需要建立隧道
            // 但如果不匹配，我们就直接连接到目标服务器，不进行中间人拦截
            if (!shouldMonitor) {
              console.log(`HTTPS请求不匹配过滤规则，直接转发: ${req.url}`);
              // 直接建立到目标服务器的隧道
              const targetConnection = net.connect(targetPort, hostname, () => {
                socket.write('HTTP/1.1 200 Connection Established\r\n' +
                           'Proxy-agent: Electron-Proxy-Monitor\r\n' +
                           '\r\n');
                targetConnection.pipe(socket);
                socket.pipe(targetConnection);
              });
              
              targetConnection.on('error', (err) => {
                console.error('目标连接错误:', err);
                socket.end();
              });
              
              socket.on('error', (err) => {
                console.error('客户端连接错误:', err);
                targetConnection.end();
              });
              
              return;
            }

            console.log(`处理HTTPS请求: ${hostname}:${targetPort}`);

            // 为目标域名生成证书
            const { key, cert } = this.generateCertificateForHost(hostname);

            // 创建HTTPS服务器
            const httpsServer = https.createServer({ key, cert }, (req, res) => {
              // 为请求添加协议信息
              req.protocol = 'https';
              
              // 解析请求体
              let body = '';
              req.on('data', chunk => {
                body += chunk.toString();
              });

              req.on('end', () => {
                if (body) {
                  try {
                    req.body = JSON.parse(body);
                  } catch {
                    req.body = body;
                  }
                }

                // 转发HTTPS请求
                proxy.web(req, res, {
                  target: `https://${hostname}:${targetPort}`,
                  secure: false
                });
              });
            });

            // 建立HTTPS隧道
            socket.write('HTTP/1.1 200 Connection Established\r\n' +
                        'Proxy-agent: Electron-Proxy-Monitor\r\n' +
                        '\r\n');

            // 将客户端socket连接到HTTPS服务器
            const serverSocket = httpsServer.listen(0, () => {
              const serverPort = serverSocket.address().port;
              console.log(`HTTPS服务器监听在本地端口: ${serverPort}`);
              
              // 创建到目标服务器的连接
              const conn = net.connect({
                port: serverPort,
                host: 'localhost',
                allowHalfOpen: true
              }, () => {
                console.log(`成功建立到本地HTTPS服务器的连接: ${serverPort}`);
                socket.pipe(conn).pipe(socket);
              });

              conn.on('error', (err) => {
                console.error('代理连接错误:', err);
                socket.end();
              });
            });

            serverSocket.on('error', (err) => {
              console.error('HTTPS服务器错误:', err);
              socket.end();
            });

            socket.on('error', (err) => {
              console.error('客户端连接错误:', err);
              socket.end();
            });

          } catch (error) {
            console.error('处理HTTPS请求时出错:', error);
            socket.end();
          }
        });

        // 启动服务器
        this.server.listen(this.port, () => {
          console.log(`代理服务器成功启动并监听端口 ${this.port} (HTTP/HTTPS)`);
          
          // 验证端口是否真的在监听
          const server = net.createServer();
          server.once('error', (err) => {
            if (err.code === 'EADDRINUSE') {
              console.log(`确认：端口 ${this.port} 已被占用，说明代理服务器正在运行`);
              resolve();
            } else {
              console.error('验证端口监听时出错:', err);
              reject(err);
            }
            server.close();
          });
          
          server.once('listening', () => {
            console.error(`错误：端口 ${this.port} 未被占用，代理服务器可能未正确启动`);
            server.close();
            reject(new Error('代理服务器未能正确监听端口'));
          });
          
          server.listen(this.port);
        });
      } catch (error) {
        console.error('启动代理服务器时出错:', error);
        reject(error);
      }
    });

    // 错误处理
    this.server.on('error', (err) => {
      console.error('代理服务器错误:', err);
      if (err.code === 'EADDRINUSE') {
        console.error(`端口 ${this.port} 已被占用`);
      }
    });
  }

  stop() {
    if (this.server) {
      this.server.close();
    }
  }

  /**
   * 导出CA证书到指定路径
   * @param {string} exportPath 导出路径
   * @returns {boolean} 是否成功导出
   */
  exportCACertificate(exportPath) {
    try {
      fs.copyFileSync(this.caPath, exportPath);
      return true;
    } catch (error) {
      console.error('导出证书失败:', error);
      return false;
    }
  }
}

module.exports = ProxyServer;