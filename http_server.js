const http = require('http');

const server = http.createServer();

server.on('request', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 200;
    res.end(JSON.stringify({
        id: 1,
        username: 'test',
        password: 'testing123',
        ip: '192.168.43.58',
        upSpeedLimit: '128k',
        downSpeedLimit: '128k',
        timeout: 0,
    }));
});

server.listen(3000);
