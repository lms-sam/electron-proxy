const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const url = require('url');
const fs = require('fs');
const ProxyServer = require('./proxy-server');

let mainWindow;
let proxyServer = null;
let isProxyRunning = false;

// 创建主窗口
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1024,
    height: 768,
    title: "网络请求监控工具",
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    }
  });

  mainWindow.loadURL(url.format({
    pathname: path.join(__dirname, 'index.html'),
    protocol: 'file:',
    slashes: true
  }));

  // 打开开发者工具
  // mainWindow.webContents.openDevTools();

  mainWindow.on('closed', () => {
    mainWindow = null;
    if (isProxyRunning && proxyServer) {
      proxyServer.stop();
    }
  });
}

app.on('ready', createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});

// IPC 通信处理
ipcMain.on('start-proxy', async (event, config) => {
  console.log('收到启动代理请求:', config);
  
  // 先检查端口是否被占用
  const isPortInUse = await new Promise(resolve => {
    const server = require('net').createServer();
    server.once('error', err => {
      if (err.code === 'EADDRINUSE') {
        resolve(true);
      }
    });
    server.once('listening', () => {
      server.close();
      resolve(false);
    });
    server.listen(config.port);
  });

  if (isPortInUse) {
    console.error(`端口 ${config.port} 已被占用`);
    event.reply('proxy-error', { message: `端口 ${config.port} 已被占用，请选择其他端口或关闭占用的程序。` });
    return;
  }
  
  if (!isProxyRunning) {
    try {
      // 打开开发者工具以便调试
      mainWindow.webContents.openDevTools();
      
      console.log('创建代理服务器实例...');
      // 创建代理服务器实例
      proxyServer = new ProxyServer(config);
      
      // 设置过滤规则（如果有）
      if (config.filters) {
        proxyServer.setFilters(config.filters);
      }
      
      // 注册请求捕获事件
      proxyServer.on('request-completed', (data) => {
        console.log('捕获到请求:', data.request.url);
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('request-completed', data);
        }
      });
      
      // 启动代理服务器
      console.log('正在启动代理服务器...');
      try {
        await proxyServer.start();
        
        isProxyRunning = true;
        console.log('代理服务器已成功启动，通知渲染进程...');
        event.reply('proxy-status', { running: true, port: config.port });
        console.log('通知已发送');
      } catch (startError) {
        console.error('启动代理服务器时出错:', startError);
        event.reply('proxy-error', { message: `启动代理服务器失败: ${startError.message}` });
        
        // 尝试清理资源
        if (proxyServer) {
          try {
            proxyServer.stop();
          } catch (stopError) {
            console.error('停止失败的代理服务器时出错:', stopError);
          }
          proxyServer = null;
        }
      }
      
    } catch (error) {
      console.error('启动代理服务器失败:', error);
      event.reply('proxy-error', { message: error.message });
    }
  } else {
    console.log('代理服务器已经在运行中');
    event.reply('proxy-status', { running: true, port: proxyServer.port });
  }
});

// 更新过滤规则
ipcMain.on('update-filters', (event, filters) => {
  if (isProxyRunning && proxyServer) {
    proxyServer.setFilters(filters);
    event.reply('filters-updated', { success: true });
  } else {
    event.reply('filters-updated', { 
      success: false, 
      message: '代理服务器未运行'
    });
  }
});

ipcMain.on('stop-proxy', (event) => {
  if (isProxyRunning && proxyServer) {
    proxyServer.stop();
    isProxyRunning = false;
    event.reply('proxy-status', { running: false });
  }
});

ipcMain.on('export-data', (event, data) => {
  dialog.showSaveDialog({
    title: '导出捕获的请求',
    defaultPath: path.join(app.getPath('downloads'), '捕获的请求.json'),
    filters: [{ name: 'JSON文件', extensions: ['json'] }]
  }).then(result => {
    if (!result.canceled && result.filePath) {
      fs.writeFileSync(result.filePath, JSON.stringify(data, null, 2));
      event.reply('export-complete', { success: true });
    }
  }).catch(err => {
    event.reply('export-complete', { success: false, error: err.message });
  });
});

// 检查证书是否已安装
ipcMain.on('check-certificate', async (event) => {
  if (!proxyServer) {
    event.reply('certificate-status', { installed: false, message: '代理服务器未启动' });
    return;
  }
  
  const isInstalled = await proxyServer.isCertificateTrusted();
  event.reply('certificate-status', { 
    installed: isInstalled,
    message: isInstalled ? '证书已安装' : '证书未安装'
  });
});

// 安装证书
ipcMain.on('install-certificate', async (event) => {
  if (!proxyServer) {
    event.reply('certificate-install-result', { 
      success: false, 
      message: '代理服务器未启动'
    });
    return;
  }

  const result = await proxyServer.installCertificate();
  event.reply('certificate-install-result', result);
});

// 导出证书
ipcMain.on('export-certificate', (event) => {
  if (!proxyServer) {
    event.reply('certificate-export-result', { 
      success: false, 
      message: '代理服务器未启动'
    });
    return;
  }

  dialog.showSaveDialog({
    title: '导出CA证书',
    defaultPath: path.join(app.getPath('downloads'), 'electron-proxy-ca.crt'),
    filters: [{ name: '证书文件', extensions: ['crt'] }]
  }).then(result => {
    if (!result.canceled && result.filePath) {
      const success = proxyServer.exportCACertificate(result.filePath);
      event.reply('certificate-export-result', {
        success,
        message: success ? '证书导出成功' : '证书导出失败',
        path: success ? result.filePath : null
      });

      if (success) {
        shell.showItemInFolder(result.filePath);
      }
    }
  }).catch(err => {
    event.reply('certificate-export-result', {
      success: false,
      message: `证书导出失败: ${err.message}`
    });
  });
});